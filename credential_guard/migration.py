"""Safe migration from v1 dual files to credential-guard.json."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import re
import os
import secrets
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from .config import (
    CONFIG_FILENAME,
    ConfigError,
    CredentialGuardConfig,
    NAME_RE,
    _loads_strict,
    _mode_bits,
)
from .config_lock import ConfigLockError, exclusive_config_lock

# ---------------------------------------------------------------------------
# Private v1 dual-file parser (migrated out of file_backend for R5 deletion).
# These constants/rules apply only to explicit migrate-config inputs.
# Do NOT import from file_backend or bindings.validate_ssh_alias.
# ---------------------------------------------------------------------------
_V1_CRED_TYPES = frozenset({"mysql"})
_V1_TARGET_TYPES = frozenset({"mysql", "ssh_config"})
_V1_CREDENTIAL_FIELDS = frozenset({"type", "username", "password"})
_V1_MYSQL_TARGET_FIELDS = frozenset(
    {"type", "host", "port", "database", "credential_ref"}
)
_V1_SSH_TARGET_FIELDS = frozenset({"type", "ssh_alias"})
# Conservative Host-alias charset: no leading dash, no wildcards, no whitespace.
_V1_SSH_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_V1_SSH_ALIAS_MAX_LEN = 64


def _v1_validate_ssh_alias(alias: Any) -> str:
    if not isinstance(alias, str) or not alias:
        raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
    if len(alias) > _V1_SSH_ALIAS_MAX_LEN:
        raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
    if any(ord(ch) < 32 for ch in alias):
        raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
    if alias[0] == "-":
        raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
    if any(ch.isspace() for ch in alias):
        raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
    if any(ch in alias for ch in "*?%;&|'\"`/\\:@$(){}[]<>"):
        raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
    if not _V1_SSH_ALIAS_RE.fullmatch(alias):
        raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
    return alias


CREDENTIALS_FILENAME = "credentials.json"
TARGETS_FILENAME = "targets.json"
CREDENTIALS_BAK = "credentials.json.v1.bak"
TARGETS_BAK = "targets.json.v1.bak"
JOURNAL_NAME = ".cg-migrate.journal"
LOCK_NAME = ".cg-migrate.lock"
# Legacy fixed temp names (pre-txid); still rejected if present at start.
CRED_BAK_TMP = ".cg-migrate-cred.bak.tmp"
TGT_BAK_TMP = ".cg-migrate-tgt.bak.tmp"
MAX_V1_FILE_BYTES = 1_048_576

_PHASE_PREPARED = "prepared"
_PHASE_PUBLISHED = "published"
_PHASE_BAKS = "baks"
_PHASE_ISOLATED = "isolated"
_PHASE_SWAP = "swap"

_RENAME_EXCL = 0x00000004


class MigrationError(Exception):
    """Fail-closed migration error without secrets or paths."""

    def __init__(self, code: str, message: str = "migration error") -> None:
        self.code = code
        super().__init__(message)

    def __repr__(self) -> str:
        return f"MigrationError(code={self.code!r})"


@dataclass(frozen=True)
class MigrationResult:
    ok: bool
    config_digest: str = ""


def resolve_config_dir(explicit: Optional[Path | str] = None) -> Path:
    """Resolve config directory from explicit path or current HERMES_HOME/HOME."""
    if explicit is not None:
        return Path(explicit).expanduser().resolve()
    hermes = os.environ.get("HERMES_HOME", "").strip()
    if hermes:
        return (Path(hermes) / "credential-guard").resolve()
    return (Path.home() / ".hermes" / "credential-guard").resolve()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _assert_secure_store_dir(root: Path) -> None:
    err: Optional[str] = None
    lst = None
    try:
        lst = os.lstat(root)
    except OSError:
        err = "MIGRATION_DIR_UNAVAILABLE"
    if err is not None:
        raise MigrationError(err, "migration error")
    assert lst is not None
    if stat.S_ISLNK(lst.st_mode):
        raise MigrationError("MIGRATION_DIR_SYMLINK", "migration error")
    if not stat.S_ISDIR(lst.st_mode):
        raise MigrationError("MIGRATION_DIR_UNAVAILABLE", "migration error")
    if _mode_bits(lst.st_mode) != 0o700:
        raise MigrationError("MIGRATION_DIR_INSECURE_MODE", "migration error")
    if lst.st_uid != os.geteuid():
        raise MigrationError("MIGRATION_DIR_OWNER", "migration error")


def _reject_symlink_or_bad_file(path: Path) -> os.stat_result:
    err: Optional[str] = None
    lst = None
    try:
        lst = os.lstat(path)
    except FileNotFoundError:
        err = "MIGRATION_MISSING_SOURCE"
    except OSError:
        err = "MIGRATION_SOURCE_UNAVAILABLE"
    if err is not None:
        raise MigrationError(err, "migration error")
    assert lst is not None
    if stat.S_ISLNK(lst.st_mode):
        raise MigrationError("MIGRATION_SOURCE_SYMLINK", "migration error")
    if not stat.S_ISREG(lst.st_mode):
        raise MigrationError("MIGRATION_SOURCE_NOT_FILE", "migration error")
    if _mode_bits(lst.st_mode) != 0o600:
        raise MigrationError("MIGRATION_SOURCE_INSECURE_MODE", "migration error")
    if lst.st_uid != os.geteuid():
        raise MigrationError("MIGRATION_SOURCE_OWNER", "migration error")
    if lst.st_size > MAX_V1_FILE_BYTES:
        raise MigrationError("MIGRATION_SOURCE_TOO_LARGE", "migration error")
    return lst


@dataclass(frozen=True)
class _SourceIdentity:
    raw: bytes
    st_dev: int
    st_ino: int
    st_mode: int
    st_uid: int
    st_size: int

    @property
    def sha256(self) -> str:
        return _sha256_bytes(self.raw)


def _read_secure_bytes(path: Path) -> _SourceIdentity:
    lst = _reject_symlink_or_bad_file(path)
    open_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    open_err: Optional[str] = None
    fd = -1
    try:
        fd = os.open(path, open_flags | nofollow if nofollow else open_flags)
    except OSError as exc:
        if getattr(exc, "errno", None) in {
            getattr(os, "ELOOP", -1),
            getattr(__import__("errno"), "ELOOP", -1),
        }:
            open_err = "MIGRATION_SOURCE_SYMLINK"
        else:
            open_err = "MIGRATION_SOURCE_UNAVAILABLE"
    if open_err is not None:
        raise MigrationError(open_err, "migration error")
    try:
        fstat_err: Optional[str] = None
        st = None
        try:
            st = os.fstat(fd)
        except OSError:
            fstat_err = "MIGRATION_SOURCE_UNAVAILABLE"
        if fstat_err is not None:
            raise MigrationError(fstat_err, "migration error")
        assert st is not None
        if not stat.S_ISREG(st.st_mode):
            raise MigrationError("MIGRATION_SOURCE_NOT_FILE", "migration error")
        if _mode_bits(st.st_mode) != 0o600:
            raise MigrationError("MIGRATION_SOURCE_INSECURE_MODE", "migration error")
        if st.st_uid != os.geteuid():
            raise MigrationError("MIGRATION_SOURCE_OWNER", "migration error")
        if st.st_ino != lst.st_ino or st.st_dev != lst.st_dev:
            raise MigrationError("MIGRATION_SOURCE_TOCTOU", "migration error")
        post_err: Optional[str] = None
        lst2 = None
        try:
            lst2 = os.lstat(path)
        except OSError:
            post_err = "MIGRATION_SOURCE_UNAVAILABLE"
        if post_err is not None:
            raise MigrationError(post_err, "migration error")
        assert lst2 is not None
        if stat.S_ISLNK(lst2.st_mode):
            raise MigrationError("MIGRATION_SOURCE_SYMLINK", "migration error")
        if lst2.st_ino != st.st_ino or lst2.st_dev != st.st_dev:
            raise MigrationError("MIGRATION_SOURCE_TOCTOU", "migration error")

        chunks = []
        total = 0
        while True:
            read_err: Optional[str] = None
            block = None
            try:
                block = os.read(fd, 65536)
            except OSError:
                read_err = "MIGRATION_SOURCE_UNAVAILABLE"
            if read_err is not None:
                raise MigrationError(read_err, "migration error")
            assert block is not None
            if not block:
                break
            total += len(block)
            if total > MAX_V1_FILE_BYTES:
                raise MigrationError("MIGRATION_SOURCE_TOO_LARGE", "migration error")
            chunks.append(block)
        raw = b"".join(chunks)

        post3_err: Optional[str] = None
        lst3 = None
        try:
            lst3 = os.lstat(path)
        except OSError:
            post3_err = "MIGRATION_SOURCE_UNAVAILABLE"
        if post3_err is not None:
            raise MigrationError(post3_err, "migration error")
        assert lst3 is not None
        if stat.S_ISLNK(lst3.st_mode):
            raise MigrationError("MIGRATION_SOURCE_SYMLINK", "migration error")
        if lst3.st_ino != st.st_ino or lst3.st_dev != st.st_dev:
            raise MigrationError("MIGRATION_SOURCE_TOCTOU", "migration error")
        return _SourceIdentity(
            raw=raw,
            st_dev=st.st_dev,
            st_ino=st.st_ino,
            st_mode=st.st_mode,
            st_uid=st.st_uid,
            st_size=st.st_size,
        )
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _assert_source_identity(path: Path, identity: _SourceIdentity) -> None:
    """Re-verify path still points at the same validated source inode."""
    err: Optional[str] = None
    lst = None
    try:
        lst = os.lstat(path)
    except FileNotFoundError:
        err = "MIGRATION_SOURCE_TOCTOU"
    except OSError:
        err = "MIGRATION_SOURCE_UNAVAILABLE"
    if err is not None:
        raise MigrationError(err, "migration error")
    assert lst is not None
    if stat.S_ISLNK(lst.st_mode):
        raise MigrationError("MIGRATION_SOURCE_SYMLINK", "migration error")
    if not stat.S_ISREG(lst.st_mode):
        raise MigrationError("MIGRATION_SOURCE_NOT_FILE", "migration error")
    if (
        lst.st_ino != identity.st_ino
        or lst.st_dev != identity.st_dev
        or _mode_bits(lst.st_mode) != _mode_bits(identity.st_mode)
        or lst.st_uid != identity.st_uid
        or lst.st_size != identity.st_size
    ):
        raise MigrationError("MIGRATION_SOURCE_TOCTOU", "migration error")


def _read_secure_json(path: Path) -> Tuple[Any, _SourceIdentity]:
    identity = _read_secure_bytes(path)
    err: Optional[str] = None
    text: Optional[str] = None
    try:
        text = identity.raw.decode("utf-8")
    except UnicodeDecodeError:
        err = "MIGRATION_SOURCE_UTF8"
    if err is not None:
        raise MigrationError(err, "migration error")
    assert text is not None
    data = None
    parse_err: Optional[str] = None
    try:
        data = _loads_strict(text)
    except ConfigError as exc:
        if getattr(exc, "code", None) == "CONFIG_DUPLICATE_KEY":
            parse_err = "MIGRATION_DUPLICATE_KEY"
        else:
            parse_err = "MIGRATION_SOURCE_JSON"
    if parse_err is not None:
        raise MigrationError(parse_err, "migration error")
    return data, identity


def _require_mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
    return value


def _validate_v1_credentials(doc: Any) -> Dict[str, Dict[str, str]]:
    data = _require_mapping(doc)
    version = data.get("version")
    if type(version) is not int or version != 1:
        raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
    if set(data) - {"version", "credentials"}:
        raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
    cred_map = _require_mapping(data.get("credentials"))
    out: Dict[str, Dict[str, str]] = {}
    for cid, entry in cred_map.items():
        if not isinstance(cid, str) or not NAME_RE.fullmatch(cid):
            raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
        item = _require_mapping(entry)
        if set(item) - _V1_CREDENTIAL_FIELDS:
            raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
        if _V1_CREDENTIAL_FIELDS - set(item):
            raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
        if item.get("type") not in _V1_CRED_TYPES:
            raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
        username = item["username"]
        password = item["password"]
        if not isinstance(username, str) or not username:
            raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
        if not isinstance(password, str) or not password:
            raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
        out[cid] = {
            "type": str(item["type"]),
            "username": username,
            "password": password,
        }
    return out


def _validate_v1_targets(doc: Any) -> Dict[str, Dict[str, Any]]:
    data = _require_mapping(doc)
    version = data.get("version")
    if type(version) is not int or version != 1:
        raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
    if set(data) - {"version", "targets"}:
        raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
    tgt_map = _require_mapping(data.get("targets"))
    out: Dict[str, Dict[str, Any]] = {}
    for tid, entry in tgt_map.items():
        if not isinstance(tid, str) or not NAME_RE.fullmatch(tid):
            raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
        item = _require_mapping(entry)
        ttype = item.get("type")
        if ttype not in _V1_TARGET_TYPES:
            raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
        if ttype == "mysql":
            if set(item) - _V1_MYSQL_TARGET_FIELDS or _V1_MYSQL_TARGET_FIELDS - set(item):
                raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
            out[tid] = {
                "type": "mysql",
                "host": item["host"],
                "port": item["port"],
                "database": item["database"],
                "credential_ref": item["credential_ref"],
            }
        elif ttype == "ssh_config":
            if set(item) - _V1_SSH_TARGET_FIELDS or _V1_SSH_TARGET_FIELDS - set(item):
                raise MigrationError("MIGRATION_SOURCE_SCHEMA", "migration error")
            alias = _v1_validate_ssh_alias(item["ssh_alias"])
            out[tid] = {"type": "ssh_config", "ssh_alias": alias}
    return out


def _build_v2_document(
    credentials: Mapping[str, Dict[str, str]],
    targets: Mapping[str, Dict[str, Any]],
) -> Dict[str, Any]:
    if any(c.get("type") == "mysql" for c in credentials.values()):
        raise MigrationError(
            "MIGRATION_REQUIRES_MANUAL_REVIEW", "migration error"
        )
    if any(t.get("type") == "mysql" for t in targets.values()):
        raise MigrationError(
            "MIGRATION_REQUIRES_MANUAL_REVIEW", "migration error"
        )
    if credentials:
        raise MigrationError(
            "MIGRATION_REQUIRES_MANUAL_REVIEW", "migration error"
        )
    # No v1 entry type survives in the v2 schema; a non-empty source always needs
    # a human to restate it. Only an already-empty v1 pair migrates automatically.
    if targets:
        raise MigrationError(
            "MIGRATION_REQUIRES_MANUAL_REVIEW", "migration error"
        )

    return {
        "version": 2,
        "credentials": {},
        "bindings": {},
    }


def _exists(path: Path) -> bool:
    err = False
    try:
        os.lstat(path)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        err = True
    if err:
        raise MigrationError("MIGRATION_FS", "migration error")
    return False


def _try_unlink(path: Path) -> bool:
    """Pathname unlink for non-shared exclusive names only (e.g. high-entropy isol)."""
    try:
        os.unlink(path)
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False


def _fsync_dir(dir_path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    err = False
    fd = -1
    try:
        fd = os.open(dir_path, flags)
        os.fsync(fd)
    except OSError:
        err = True
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                err = True
    if err:
        raise MigrationError("MIGRATION_DIR_FSYNC", "migration error")


@dataclass(frozen=True)
class _OwnedArtifactIdentity:
    """Immutable ownership record for a self-created temp/journal artifact."""

    name: str
    st_dev: int
    st_ino: int
    sha256: str
    mode: int
    owner: int
    purpose: str


def _artifact_meta(identity: _OwnedArtifactIdentity) -> Dict[str, Any]:
    return {
        "name": identity.name,
        "dev": identity.st_dev,
        "ino": identity.st_ino,
        "sha256": identity.sha256,
        "mode": identity.mode,
        "owner": identity.owner,
        "purpose": identity.purpose,
    }


def _parse_artifact_identity(entry: Any) -> Optional[_OwnedArtifactIdentity]:
    if entry is None:
        return None
    if isinstance(entry, str):
        # Legacy name-only — insufficient for identity-bound delete.
        return None
    if not isinstance(entry, dict):
        return None
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        return None
    required = ("dev", "ino", "sha256", "mode", "owner", "purpose")
    if not all(k in entry for k in required):
        return None
    try:
        return _OwnedArtifactIdentity(
            name=name,
            st_dev=int(entry["dev"]),
            st_ino=int(entry["ino"]),
            sha256=str(entry["sha256"]),
            mode=int(entry["mode"]),
            owner=int(entry["owner"]),
            purpose=str(entry["purpose"]),
        )
    except (TypeError, ValueError):
        return None


def _capture_owned_artifact(
    path: Path, *, purpose: str, expected_sha: Optional[str] = None
) -> _OwnedArtifactIdentity:
    err: Optional[str] = None
    lst = None
    raw = None
    try:
        lst = os.lstat(path)
        if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
            err = "bad"
        elif _mode_bits(lst.st_mode) != 0o600 or lst.st_uid != os.geteuid():
            err = "bad"
        else:
            raw = path.read_bytes()
    except OSError:
        err = "bad"
    if err is not None or lst is None or raw is None:
        raise MigrationError("MIGRATION_TEMP_WRITE", "migration error")
    digest = _sha256_bytes(raw)
    if expected_sha is not None and digest != expected_sha:
        raise MigrationError("MIGRATION_TEMP_WRITE", "migration error")
    return _OwnedArtifactIdentity(
        name=path.name,
        st_dev=lst.st_dev,
        st_ino=lst.st_ino,
        sha256=digest,
        mode=_mode_bits(lst.st_mode),
        owner=lst.st_uid,
        purpose=purpose,
    )


def _matches_artifact_identity(path: Path, expected: _OwnedArtifactIdentity) -> bool:
    err = False
    lst = None
    raw = None
    try:
        lst = os.lstat(path)
        if (
            stat.S_ISLNK(lst.st_mode)
            or not stat.S_ISREG(lst.st_mode)
            or lst.st_dev != expected.st_dev
            or lst.st_ino != expected.st_ino
            or _mode_bits(lst.st_mode) != expected.mode
            or lst.st_uid != expected.owner
        ):
            return False
        raw = path.read_bytes()
    except OSError:
        err = True
    if err or lst is None or raw is None:
        return False
    return _sha256_bytes(raw) == expected.sha256


def _exclusive_isol_name(txid: str, purpose: str) -> str:
    return f".cg-migrate-isol-{purpose}-{txid}-{secrets.token_hex(16)}"


def _identity_bound_isolate(
    path: Path,
    expected: _OwnedArtifactIdentity,
    isol_path: Path,
) -> None:
    """Atomically move path→isol_path and prove isol inode matches expected."""
    if not _matches_artifact_identity(path, expected):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    if _exists(isol_path):
        raise MigrationError("MIGRATION_CONFLICT", "migration error")
    _atomic_rename_no_clobber(path, isol_path)
    if not _matches_artifact_identity(isol_path, expected):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")


def _identity_bound_delete_isolated(
    isol_path: Path, expected: _OwnedArtifactIdentity
) -> None:
    """Remove an already-isolated exclusive name only if it still matches identity."""
    if not _exists(isol_path):
        return
    if not _matches_artifact_identity(isol_path, expected):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    if not _try_unlink(isol_path):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    if _exists(isol_path):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")


def _identity_bound_restore(
    isol_path: Path,
    formal_path: Path,
    expected: _OwnedArtifactIdentity,
) -> None:
    """Restore isolated owned bytes to formal name without clobbering competitors."""
    if not _matches_artifact_identity(isol_path, expected):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    if _exists(formal_path):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    _atomic_rename_no_clobber(isol_path, formal_path)
    if not _matches_artifact_identity(formal_path, expected):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")


def _identity_bound_cleanup(
    store_dir: Path,
    identity: _OwnedArtifactIdentity,
    *,
    txid: str,
) -> None:
    """Atomically isolate then delete a shared-dir pathname only if identity matches.

    On mismatch: leave foreign bytes untouched and raise MIGRATION_RECOVERY_REQUIRED.
    If delete of the isolated name fails, attempt to restore it to the original name
    so the last owned copy is not stranded under an untracked isol pathname.
    """
    path = store_dir / identity.name
    if not _exists(path):
        return
    if not _matches_artifact_identity(path, identity):
        # Foreign inode at our temp name — never delete.
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    isol = store_dir / _exclusive_isol_name(txid, f"cleanup-{identity.purpose}")
    isolate_err: Optional[str] = None
    try:
        _identity_bound_isolate(path, identity, isol)
    except MigrationError as exc:
        isolate_err = exc.code
    if isolate_err is not None:
        raise MigrationError(
            isolate_err
            if isolate_err
            in {"MIGRATION_RECOVERY_REQUIRED", "MIGRATION_CONFLICT"}
            else "MIGRATION_RECOVERY_REQUIRED",
            "migration error",
        )
    delete_err = False
    try:
        _identity_bound_delete_isolated(isol, identity)
    except MigrationError:
        delete_err = True
    if delete_err:
        # Restore owned bytes to the original shared name when possible.
        restore_err = False
        try:
            if not _exists(path):
                _identity_bound_restore(isol, path, identity)
        except MigrationError:
            restore_err = True
        del restore_err
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    # Competitor may have recreated the original name; leave it.
    if _exists(path) and not _matches_artifact_identity(path, identity):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")


def _cleanup_owned_optional(
    store_dir: Path,
    identity: Optional[_OwnedArtifactIdentity],
    *,
    txid: str,
) -> None:
    if identity is None:
        return
    _identity_bound_cleanup(store_dir, identity, txid=txid)


def _write_bytes_temp(
    store_dir: Path,
    name: str,
    data: bytes,
    *,
    purpose: str,
    txid: str,
) -> _OwnedArtifactIdentity:
    tmp_path = store_dir / name
    if _exists(tmp_path):
        raise MigrationError("MIGRATION_TEMP_WRITE", "migration error")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    open_err = False
    fd = -1
    early: Optional[_OwnedArtifactIdentity] = None
    try:
        fd = os.open(tmp_path, flags, 0o600)
    except OSError:
        open_err = True
    if open_err:
        raise MigrationError("MIGRATION_TEMP_WRITE", "migration error")
    # Capture inode identity immediately after O_EXCL create for failure cleanup.
    st_err = False
    st = None
    try:
        st = os.fstat(fd)
        os.fchmod(fd, 0o600)
    except OSError:
        st_err = True
    if st_err or st is None:
        try:
            os.close(fd)
        except OSError:
            pass
        # Best-effort: path was created by us; try identity cleanup if capturable.
        cap_err = False
        try:
            early = _OwnedArtifactIdentity(
                name=name,
                st_dev=0,
                st_ino=0,
                sha256=_sha256_bytes(b""),
                mode=0o600,
                owner=os.geteuid(),
                purpose=purpose,
            )
            # Without reliable identity, refuse pathname unlink of shared names.
        except Exception:
            cap_err = True
        del cap_err
        raise MigrationError("MIGRATION_TEMP_WRITE", "migration error")
    early = _OwnedArtifactIdentity(
        name=name,
        st_dev=st.st_dev,
        st_ino=st.st_ino,
        sha256=_sha256_bytes(data),  # expected final digest
        mode=0o600,
        owner=st.st_uid,
        purpose=purpose,
    )
    write_err = False
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.fsync(fd)
    except OSError:
        write_err = True
    if write_err:
        try:
            os.close(fd)
        except OSError:
            pass
        # Identity-bound cleanup: only delete if same inode we created.
        cleanup_id = _OwnedArtifactIdentity(
            name=name,
            st_dev=early.st_dev,
            st_ino=early.st_ino,
            sha256=early.sha256,
            mode=0o600,
            owner=early.owner,
            purpose=purpose,
        )
        # Digest may not match yet — match on inode/dev/mode/owner only for failed writes.
        _cleanup_failed_temp_inode(store_dir, cleanup_id, txid=txid)
        raise MigrationError("MIGRATION_TEMP_WRITE", "migration error")
    close_err = False
    try:
        os.close(fd)
    except OSError:
        close_err = True
    if close_err:
        _cleanup_failed_temp_inode(store_dir, early, txid=txid)
        raise MigrationError("MIGRATION_TEMP_WRITE", "migration error")
    verify_err: Optional[MigrationError] = None
    identity = None
    try:
        identity = _capture_owned_artifact(
            tmp_path, purpose=purpose, expected_sha=_sha256_bytes(data)
        )
    except MigrationError as exc:
        verify_err = exc
    if verify_err is not None:
        _cleanup_failed_temp_inode(store_dir, early, txid=txid)
        raise MigrationError(verify_err.code, "migration error")
    assert identity is not None
    if identity.st_dev != early.st_dev or identity.st_ino != early.st_ino:
        _cleanup_failed_temp_inode(store_dir, early, txid=txid)
        raise MigrationError("MIGRATION_TEMP_WRITE", "migration error")
    return identity


def _cleanup_failed_temp_inode(
    store_dir: Path, identity: _OwnedArtifactIdentity, *, txid: str
) -> None:
    """Clean a just-created temp only when pathname still names the same inode.

    Digest may be incomplete after write failure; bind on dev/ino/mode/owner.
    """
    path = store_dir / identity.name
    if not _exists(path):
        return
    lst = None
    try:
        lst = os.lstat(path)
    except OSError:
        return
    if (
        stat.S_ISLNK(lst.st_mode)
        or not stat.S_ISREG(lst.st_mode)
        or lst.st_dev != identity.st_dev
        or lst.st_ino != identity.st_ino
        or _mode_bits(lst.st_mode) != identity.mode
        or lst.st_uid != identity.owner
    ):
        # Foreign replacement — retain.
        return
    isol = store_dir / _exclusive_isol_name(txid, f"fail-{identity.purpose}")
    rename_err = False
    try:
        _atomic_rename_no_clobber(path, isol)
    except MigrationError:
        rename_err = True
    if rename_err:
        return
    # Re-check isol inode before delete.
    try:
        ist = os.lstat(isol)
    except OSError:
        return
    if ist.st_dev != identity.st_dev or ist.st_ino != identity.st_ino:
        return
    _try_unlink(isol)


def _journal_path(store_dir: Path) -> Path:
    return store_dir / JOURNAL_NAME


def _write_temp_config(
    store_dir: Path, txid: str, canonical: bytes
) -> _OwnedArtifactIdentity:
    name = _temp_name(txid, "new")
    return _write_bytes_temp(
        store_dir, name, canonical, purpose="new", txid=txid
    )


def _assert_success_contract(
    store_dir: Path,
    *,
    new_sha: str,
    cred_bak_sha: str,
    tgt_bak_sha: str,
    txid: str,
) -> None:
    """Success requires new+2 baks present; old formal names absent; no owned leftovers."""
    new_path = store_dir / CONFIG_FILENAME
    cred_path = store_dir / CREDENTIALS_FILENAME
    tgt_path = store_dir / TARGETS_FILENAME
    cred_bak = store_dir / CREDENTIALS_BAK
    tgt_bak = store_dir / TARGETS_BAK
    if _exists(cred_path) or _exists(tgt_path):
        raise MigrationError("MIGRATION_CONFLICT", "migration error")
    _verify_published_artifact(new_path, new_sha)
    _verify_published_artifact(cred_bak, cred_bak_sha)
    _verify_published_artifact(tgt_bak, tgt_bak_sha)
    for kind in ("cred", "tgt"):
        isol = store_dir / _isol_name(txid, kind)
        if _exists(isol):
            raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    if _exists(_journal_path(store_dir)):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")


def migrate_config(store_dir: Path | str) -> MigrationResult:
    """Atomically migrate v1 dual files in store_dir to credential-guard.json."""
    root = Path(store_dir)
    cred_path = root / CREDENTIALS_FILENAME
    tgt_path = root / TARGETS_FILENAME
    new_path = root / CONFIG_FILENAME
    cred_bak = root / CREDENTIALS_BAK
    tgt_bak = root / TARGETS_BAK

    _assert_secure_store_dir(root)

    lock_token: Optional[_LockToken] = None
    success_digest: Optional[str] = None
    lock_release_failed = False
    _cfg_lock_cm = None
    _cfg_lock_held = False
    try:
        lock_token = _acquire_lock(root)
        # Exclusive unified-config lock covers publish/replace/recovery write txn.
        # Order: migrate flock → exclusive config lock (readers never take migrate lock).
        _cfg_lock_cm = exclusive_config_lock(root)
        _cfg_lock_err: Optional[str] = None
        try:
            _cfg_lock_cm.__enter__()
            _cfg_lock_held = True
        except ConfigLockError as exc:
            # Capture code only — re-raise MigrationError outside except so
            # __cause__/__context__ stay empty (migration exception graph contract).
            _cfg_lock_err = getattr(exc, "code", "") or "CONFIG_LOCK_FS"
        if _cfg_lock_err is not None:
            code = (
                "MIGRATION_LOCKED"
                if _cfg_lock_err == "CONFIG_LOCK_TIMEOUT"
                else "MIGRATION_FS"
            )
            raise MigrationError(code, "migration error")

        if _exists(_journal_path(root)):
            _recover_journal_or_raise(root)

        if _exists(new_path):
            raise MigrationError("MIGRATION_TARGET_EXISTS", "migration error")
        if _exists(cred_bak) or _exists(tgt_bak):
            raise MigrationError("MIGRATION_BACKUP_EXISTS", "migration error")
        # Reject legacy fixed temp names and any leftover journal.
        if _exists(root / CRED_BAK_TMP) or _exists(root / TGT_BAK_TMP):
            raise MigrationError("MIGRATION_BACKUP_EXISTS", "migration error")

        cred_doc, cred_id = _read_secure_json(cred_path)
        tgt_doc, tgt_id = _read_secure_json(tgt_path)
        credentials = _validate_v1_credentials(cred_doc)
        targets = _validate_v1_targets(tgt_doc)

        v2_err: Optional[str] = None
        cfg = None
        try:
            v2_doc = _build_v2_document(credentials, targets)
            cfg = CredentialGuardConfig.from_mapping(v2_doc)
        except MigrationError:
            raise
        except ConfigError:
            v2_err = "MIGRATION_V2_INVALID"
        except Exception:
            v2_err = "MIGRATION_V2_INVALID"
        if v2_err is not None:
            raise MigrationError(v2_err, "migration error")
        assert cfg is not None

        canonical = cfg.to_canonical_json()
        new_sha = _sha256_bytes(canonical)
        cred_sha = cred_id.sha256
        tgt_sha = tgt_id.sha256
        txid = secrets.token_hex(16)
        cred_tmp_name = _temp_name(txid, "cred-bak")
        tgt_tmp_name = _temp_name(txid, "tgt-bak")
        new_tmp_name = _temp_name(txid, "new")
        journal = _new_journal(
            txid=txid,
            phase=_PHASE_PREPARED,
            new_sha256=new_sha,
            credentials_bak_sha256=cred_sha,
            targets_bak_sha256=tgt_sha,
            source_credentials=_source_meta(cred_id),
            source_targets=_source_meta(tgt_id),
            temps={
                "new": {"name": new_tmp_name, "sha256": new_sha},
                "credentials_bak": {"name": cred_tmp_name, "sha256": cred_sha},
                "targets_bak": {"name": tgt_tmp_name, "sha256": tgt_sha},
                "journal": None,
            },
        )

        new_tmp: Optional[_OwnedArtifactIdentity] = None
        cred_tmp: Optional[_OwnedArtifactIdentity] = None
        tgt_tmp: Optional[_OwnedArtifactIdentity] = None
        journal_id: Optional[_JournalIdentity] = None
        op_err: Optional[str] = None
        try:
            new_tmp = _write_temp_config(root, txid, canonical)
            journal["temps"]["new"] = _artifact_meta(new_tmp)
            reread_err = False
            try:
                verified = CredentialGuardConfig.load(root / new_tmp.name)
                if verified.config_digest != cfg.config_digest:
                    reread_err = True
            except Exception:
                reread_err = True
            if reread_err:
                raise MigrationError("MIGRATION_REREAD", "migration error")

            _assert_source_identity(cred_path, cred_id)
            _assert_source_identity(tgt_path, tgt_id)

            cred_tmp = _write_bytes_temp(
                root, cred_tmp_name, cred_id.raw, purpose="credentials_bak", txid=txid
            )
            journal["temps"]["credentials_bak"] = _artifact_meta(cred_tmp)
            tgt_tmp = _write_bytes_temp(
                root, tgt_tmp_name, tgt_id.raw, purpose="targets_bak", txid=txid
            )
            journal["temps"]["targets_bak"] = _artifact_meta(tgt_tmp)
            _assert_source_identity(cred_path, cred_id)
            _assert_source_identity(tgt_path, tgt_id)

            journal_id = _write_journal(root, journal, expected=None)

            # Publish new file.
            _publish_no_clobber(
                root / new_tmp.name,
                new_path,
                exists_code="MIGRATION_TARGET_EXISTS",
                fail_code="MIGRATION_PUBLISH",
            )
            journal["published"]["new"] = True
            journal["phase"] = _PHASE_PUBLISHED
            journal_id = _write_journal(root, journal, expected=journal_id)
            _unlink_temp_after_publish(
                root, new_tmp, txid=txid, fail_code="MIGRATION_PUBLISH"
            )
            new_tmp = None
            journal["temps"]["new"] = None

            # Publish backups.
            _publish_no_clobber(
                root / cred_tmp.name,
                cred_bak,
                exists_code="MIGRATION_BACKUP_EXISTS",
                fail_code="MIGRATION_BACKUP",
            )
            journal["published"]["credentials_bak"] = True
            journal_id = _write_journal(root, journal, expected=journal_id)
            _unlink_temp_after_publish(
                root, cred_tmp, txid=txid, fail_code="MIGRATION_BACKUP"
            )
            cred_tmp = None
            journal["temps"]["credentials_bak"] = None

            _publish_no_clobber(
                root / tgt_tmp.name,
                tgt_bak,
                exists_code="MIGRATION_BACKUP_EXISTS",
                fail_code="MIGRATION_BACKUP",
            )
            journal["published"]["targets_bak"] = True
            journal["phase"] = _PHASE_BAKS
            journal_id = _write_journal(root, journal, expected=journal_id)
            _unlink_temp_after_publish(
                root, tgt_tmp, txid=txid, fail_code="MIGRATION_BACKUP"
            )
            tgt_tmp = None
            journal["temps"]["targets_bak"] = None

            # Re-read three formal products and fsync directory.
            _verify_published_artifact(new_path, new_sha)
            _verify_published_artifact(cred_bak, cred_sha)
            _verify_published_artifact(tgt_bak, tgt_sha)
            _fsync_dir(root)

            # Isolate old sources (bound to journal identity), then drop isolation
            # once bak copies are durable.
            journal["phase"] = _PHASE_SWAP
            journal_id = _write_journal(root, journal, expected=journal_id)

            cred_isol = root / _isol_name(txid, "cred")
            tgt_isol = root / _isol_name(txid, "tgt")
            _isolate_owned_source(
                cred_path,
                cred_isol,
                expected_dev=cred_id.st_dev,
                expected_ino=cred_id.st_ino,
                expected_sha=cred_sha,
            )
            journal["published"]["credentials_old_removed"] = True
            journal["phase"] = _PHASE_ISOLATED
            journal_id = _write_journal(root, journal, expected=journal_id)

            _isolate_owned_source(
                tgt_path,
                tgt_isol,
                expected_dev=tgt_id.st_dev,
                expected_ino=tgt_id.st_ino,
                expected_sha=tgt_sha,
            )
            journal["published"]["targets_old_removed"] = True
            journal_id = _write_journal(root, journal, expected=journal_id)

            # Before dropping isolation / clearing journal: old formal names must
            # still be absent (competitor recreation → fail closed).
            if _exists(cred_path) or _exists(tgt_path):
                raise MigrationError("MIGRATION_CONFLICT", "migration error")

            _verify_published_artifact(new_path, new_sha)
            _verify_published_artifact(cred_bak, cred_sha)
            _verify_published_artifact(tgt_bak, tgt_sha)

            # Drop isolation names (bak holds verified bytes) — identity-bound.
            cred_isol_id = _capture_owned_artifact(
                cred_isol, purpose="cred-isol", expected_sha=cred_sha
            )
            tgt_isol_id = _capture_owned_artifact(
                tgt_isol, purpose="tgt-isol", expected_sha=tgt_sha
            )
            _identity_bound_delete_isolated(cred_isol, cred_isol_id)
            _identity_bound_delete_isolated(tgt_isol, tgt_isol_id)

            # Re-check old names under the same lock before clearing journal.
            if _exists(cred_path) or _exists(tgt_path):
                raise MigrationError("MIGRATION_CONFLICT", "migration error")

            _fsync_dir(root)
            _clear_journal(root, expected=journal_id)
            journal_id = None
            _fsync_dir(root)

            _assert_success_contract(
                root,
                new_sha=new_sha,
                cred_bak_sha=cred_sha,
                tgt_bak_sha=tgt_sha,
                txid=txid,
            )
            success_digest = cfg.config_digest
        except MigrationError as exc:
            op_err = exc.code
        except Exception:
            op_err = "MIGRATION_FAILED"

        if op_err is not None:
            cleanup_err = False
            try:
                _cleanup_owned_optional(root, new_tmp, txid=txid)
                _cleanup_owned_optional(root, cred_tmp, txid=txid)
                _cleanup_owned_optional(root, tgt_tmp, txid=txid)
            except MigrationError:
                cleanup_err = True
            j = None
            journal_read_failed = False
            try:
                j = _read_journal(root)
            except MigrationError:
                journal_read_failed = True
            recovery_failed = False
            if j is not None:
                # On conflict after partial success, keep journal/bak as evidence
                # when recovery cannot safely restore without destroying competitor.
                if op_err in {"MIGRATION_CONFLICT", "MIGRATION_RECOVERY_REQUIRED"}:
                    raise MigrationError(op_err, "migration error")
                try:
                    _compensate_to_prestate(root, j)
                except MigrationError:
                    recovery_failed = True
            if recovery_failed or journal_read_failed or cleanup_err:
                raise MigrationError(
                    "MIGRATION_RECOVERY_REQUIRED", "migration error"
                )
            raise MigrationError(op_err, "migration error")
    finally:
        # Release exclusive config lock before migrate flock (reverse acquire order).
        if _cfg_lock_held and _cfg_lock_cm is not None:
            try:
                _cfg_lock_cm.__exit__(None, None, None)
            except Exception:
                pass
            _cfg_lock_held = False
        release_err = False
        try:
            _release_lock(root, lock_token)
        except MigrationError:
            release_err = True
        if release_err:
            lock_release_failed = True

    if lock_release_failed:
        raise MigrationError("MIGRATION_LOCK_RELEASE", "migration error")
    assert success_digest is not None
    return MigrationResult(ok=True, config_digest=success_digest)


def _empty_published() -> Dict[str, bool]:
    return {
        "new": False,
        "credentials_bak": False,
        "targets_bak": False,
        "credentials_old_removed": False,
        "targets_old_removed": False,
    }


def _empty_temps() -> Dict[str, Any]:
    return {
        "new": None,
        "credentials_bak": None,
        "targets_bak": None,
        "journal": None,
    }


def _temp_name(txid: str, kind: str) -> str:
    return f".cg-migrate-{kind}-{txid}.tmp"


def _source_meta(identity: _SourceIdentity) -> Dict[str, Any]:
    return {
        "dev": identity.st_dev,
        "ino": identity.st_ino,
        "sha256": identity.sha256,
    }


def _new_journal(
    *,
    txid: str,
    phase: str,
    new_sha256: str,
    credentials_bak_sha256: str,
    targets_bak_sha256: str,
    source_credentials: Dict[str, Any],
    source_targets: Dict[str, Any],
    published: Optional[Dict[str, bool]] = None,
    temps: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "v": 2,
        "txid": txid,
        "phase": phase,
        "new_sha256": new_sha256,
        "credentials_bak_sha256": credentials_bak_sha256,
        "targets_bak_sha256": targets_bak_sha256,
        "source_credentials": dict(source_credentials),
        "source_targets": dict(source_targets),
        "published": dict(published or _empty_published()),
        "temps": dict(temps or _empty_temps()),
    }


def _validate_journal_doc(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict) or data.get("v") != 2:
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    required = {
        "txid",
        "phase",
        "new_sha256",
        "credentials_bak_sha256",
        "targets_bak_sha256",
        "source_credentials",
        "source_targets",
        "published",
    }
    if not required.issubset(set(data)):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    if data["phase"] not in {
        _PHASE_PREPARED,
        _PHASE_PUBLISHED,
        _PHASE_BAKS,
        _PHASE_ISOLATED,
        _PHASE_SWAP,
    }:
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    pub = data["published"]
    if not isinstance(pub, dict):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    for key in _empty_published():
        if key not in pub or type(pub[key]) is not bool:
            raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    for side in ("source_credentials", "source_targets"):
        meta = data[side]
        if not isinstance(meta, dict):
            raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
        if not {"dev", "ino", "sha256"}.issubset(set(meta)):
            raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    temps = data.get("temps")
    if temps is not None and not isinstance(temps, dict):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    return data


def _read_journal(store_dir: Path) -> Optional[Dict[str, Any]]:
    path = _journal_path(store_dir)
    if not _exists(path):
        return None
    err = False
    raw = None
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        err = True
        data = None
    if err:
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    return _validate_journal_doc(data)


@dataclass(frozen=True)
class _JournalIdentity:
    st_dev: int
    st_ino: int
    sha256: str
    txid: str


def _stat_journal_identity(store_dir: Path, txid: str) -> _JournalIdentity:
    path = _journal_path(store_dir)
    err: Optional[str] = None
    lst = None
    raw = None
    try:
        lst = os.lstat(path)
        if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
            err = "bad"
        elif _mode_bits(lst.st_mode) != 0o600 or lst.st_uid != os.geteuid():
            err = "bad"
        else:
            raw = path.read_bytes()
    except OSError:
        err = "bad"
    if err is not None or lst is None or raw is None:
        raise MigrationError("MIGRATION_JOURNAL", "migration error")
    parse_err = False
    data = None
    try:
        data = _validate_journal_doc(json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, MigrationError):
        parse_err = True
    if parse_err or data is None or data.get("txid") != txid:
        raise MigrationError("MIGRATION_JOURNAL", "migration error")
    return _JournalIdentity(
        st_dev=lst.st_dev,
        st_ino=lst.st_ino,
        sha256=_sha256_bytes(raw),
        txid=txid,
    )


def _journal_identity_as_artifact(jid: _JournalIdentity) -> _OwnedArtifactIdentity:
    return _OwnedArtifactIdentity(
        name=JOURNAL_NAME,
        st_dev=jid.st_dev,
        st_ino=jid.st_ino,
        sha256=jid.sha256,
        mode=0o600,
        owner=os.geteuid(),
        purpose="journal",
    )


def _write_journal(
    store_dir: Path,
    journal: Dict[str, Any],
    *,
    expected: Optional[_JournalIdentity] = None,
) -> _JournalIdentity:
    """Identity-bound journal create/update. Never os.replace on the shared journal name."""
    _validate_journal_doc(journal)
    txid = journal["txid"]
    if not isinstance(txid, str) or not txid:
        raise MigrationError("MIGRATION_JOURNAL", "migration error")
    generation = secrets.token_hex(8)
    tmp_name = _temp_name(txid, f"journal-{generation}")
    temps = journal.setdefault("temps", _empty_temps())
    if not isinstance(temps, dict):
        raise MigrationError("MIGRATION_JOURNAL", "migration error")
    temps["journal"] = {"name": tmp_name, "purpose": "journal"}
    _validate_journal_doc(journal)
    payload = json.dumps(journal, separators=(",", ":"), sort_keys=True).encode("utf-8")

    tmp_id = _write_bytes_temp(
        store_dir, tmp_name, payload, purpose="journal", txid=txid
    )
    temps["journal"] = _artifact_meta(tmp_id)
    dst = _journal_path(store_dir)

    if expected is None:
        # First create: atomic no-clobber link.
        if _exists(dst):
            _cleanup_owned_optional(store_dir, tmp_id, txid=txid)
            raise MigrationError("MIGRATION_JOURNAL", "migration error")
        link_err: Optional[str] = None
        try:
            os.link(store_dir / tmp_id.name, dst)
        except FileExistsError:
            link_err = "exists"
        except OSError as exc:
            if getattr(exc, "errno", None) == errno.EEXIST:
                link_err = "exists"
            else:
                link_err = "fail"
        if link_err is not None:
            _cleanup_owned_optional(store_dir, tmp_id, txid=txid)
            raise MigrationError("MIGRATION_JOURNAL", "migration error")
        cleanup_err = False
        try:
            _identity_bound_cleanup(store_dir, tmp_id, txid=txid)
        except MigrationError:
            cleanup_err = True
        if cleanup_err:
            raise MigrationError("MIGRATION_JOURNAL", "migration error")
    else:
        # Update: isolate expected journal → verify → no-clobber publish → cleanup isol.
        expected_art = _journal_identity_as_artifact(expected)
        isol = store_dir / _exclusive_isol_name(txid, "journal")
        isol_err: Optional[str] = None
        try:
            _identity_bound_isolate(dst, expected_art, isol)
        except MigrationError as exc:
            isol_err = exc.code
        if isol_err is not None:
            try:
                _cleanup_owned_optional(store_dir, tmp_id, txid=txid)
            except MigrationError:
                pass
            raise MigrationError(
                isol_err
                if isol_err
                in {"MIGRATION_RECOVERY_REQUIRED", "MIGRATION_CONFLICT"}
                else "MIGRATION_RECOVERY_REQUIRED",
                "migration error",
            )
        # Publish new journal via no-clobber link (never replace/clobber).
        pub_err: Optional[str] = None
        try:
            _publish_no_clobber(
                store_dir / tmp_id.name,
                dst,
                exists_code="MIGRATION_CONFLICT",
                fail_code="MIGRATION_JOURNAL",
            )
        except MigrationError as exc:
            pub_err = exc.code
        if pub_err is not None:
            # Prefer restoring expected old journal; on conflict keep both.
            restore_err = False
            try:
                _identity_bound_restore(isol, dst, expected_art)
            except MigrationError:
                restore_err = True
            try:
                _cleanup_owned_optional(store_dir, tmp_id, txid=txid)
            except MigrationError:
                pass
            if restore_err:
                raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
            raise MigrationError(
                pub_err
                if pub_err
                in {"MIGRATION_CONFLICT", "MIGRATION_RECOVERY_REQUIRED"}
                else "MIGRATION_RECOVERY_REQUIRED",
                "migration error",
            )
        fsync_err = False
        try:
            _fsync_dir(store_dir)
        except MigrationError:
            fsync_err = True
        if fsync_err:
            raise MigrationError("MIGRATION_JOURNAL", "migration error")
        # Identity-bound cleanup of isolated old journal + temp hardlink name.
        try:
            _identity_bound_delete_isolated(isol, expected_art)
        except MigrationError:
            raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
        try:
            _identity_bound_cleanup(store_dir, tmp_id, txid=txid)
        except MigrationError:
            raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
        # If formal was replaced after our publish link... publish used no-clobber so
        # dst is our inode. Competitor cannot replace without unlink first.
        return _stat_journal_identity(store_dir, txid)

    fsync_err = False
    try:
        _fsync_dir(store_dir)
    except MigrationError:
        fsync_err = True
    if fsync_err:
        raise MigrationError("MIGRATION_JOURNAL", "migration error")
    return _stat_journal_identity(store_dir, txid)


def _clear_journal(
    store_dir: Path, *, expected: Optional[_JournalIdentity] = None
) -> None:
    """Identity-bound journal clear: isolate → verify → delete isol only."""
    path = _journal_path(store_dir)
    if not _exists(path):
        return
    if expected is None:
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    expected_art = _journal_identity_as_artifact(expected)
    isol = store_dir / _exclusive_isol_name(expected.txid, "journal-clear")
    try:
        _identity_bound_isolate(path, expected_art, isol)
    except MigrationError:
        # Foreign or mismatched — do not delete; leave evidence.
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    try:
        _identity_bound_delete_isolated(isol, expected_art)
    except MigrationError:
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    _fsync_dir(store_dir)
    # Competitor may have recreated formal journal name — retain and fail closed.
    if _exists(path):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")


def _file_sha256_if_regular(path: Path) -> Optional[str]:
    if not _exists(path):
        return None
    try:
        lst = os.lstat(path)
    except OSError:
        return None
    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
        return None
    try:
        return _sha256_bytes(path.read_bytes())
    except OSError:
        return None


def _matches_owned(path: Path, expected_sha: str) -> bool:
    got = _file_sha256_if_regular(path)
    return got is not None and got == expected_sha


def _publish_no_clobber(
    src: Path,
    dst: Path,
    *,
    exists_code: str,
    fail_code: str,
) -> None:
    """Atomically publish src→dst without replacing an existing destination.

    Uses os.link (O_EXCL-equivalent on the destination name). Never os.replace.
    Marks: caller must set published=true immediately after link succeeds,
    before temp unlink (temp unlink is an independent step).
    """
    link_err: Optional[str] = None
    try:
        os.link(src, dst)
    except FileExistsError:
        link_err = "exists"
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.EEXIST:
            link_err = "exists"
        else:
            link_err = "fail"
    if link_err == "exists":
        raise MigrationError(exists_code, "migration error")
    if link_err == "fail":
        raise MigrationError(fail_code, "migration error")
    # Temp unlink is independent — caller handles failure after marking published.


def _unlink_temp_after_publish(
    store_dir: Path,
    identity: _OwnedArtifactIdentity,
    *,
    txid: str,
    fail_code: str,
) -> None:
    """Identity-bound temp cleanup after hardlink publish; never pathname-unlink blindly."""
    cleanup_err = False
    try:
        _identity_bound_cleanup(store_dir, identity, txid=txid)
    except MigrationError:
        cleanup_err = True
    if cleanup_err:
        raise MigrationError(fail_code, "migration error")


@dataclass(frozen=True)
class _LockToken:
    """Held advisory lock (persistent lock file + flock on fd)."""

    fd: int
    st_dev: int
    st_ino: int


def _acquire_lock(store_dir: Path) -> _LockToken:
    path = store_dir / LOCK_NAME
    cloexec = getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    created = False
    open_err: Optional[str] = None

    create_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | cloexec | nofollow
    try:
        fd = os.open(path, create_flags, 0o600)
        created = True
    except FileExistsError:
        created = False
    except OSError as exc:
        en = getattr(exc, "errno", None)
        if en == errno.EEXIST:
            created = False
        elif en in {getattr(os, "ELOOP", -1), getattr(errno, "ELOOP", -1)}:
            open_err = "symlink"
        else:
            open_err = "fs"
    if open_err is not None:
        raise MigrationError("MIGRATION_FS", "migration error")

    if not created:
        exist_flags = os.O_RDWR | cloexec | nofollow
        try:
            fd = os.open(path, exist_flags)
        except OSError as exc:
            en = getattr(exc, "errno", None)
            if en in {getattr(os, "ELOOP", -1), getattr(errno, "ELOOP", -1)}:
                open_err = "symlink"
            else:
                open_err = "fs"
        if open_err is not None:
            raise MigrationError("MIGRATION_FS", "migration error")

    # Only the creator may fchmod the new inode.
    if created:
        chmod_err = False
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            chmod_err = True
        if chmod_err:
            try:
                os.close(fd)
            except OSError:
                pass
            raise MigrationError("MIGRATION_FS", "migration error")

    verify_err: Optional[str] = None
    st = None
    lst = None
    try:
        st = os.fstat(fd)
        lst = os.lstat(path)
    except OSError:
        verify_err = "fs"
    if verify_err is not None or st is None or lst is None:
        try:
            os.close(fd)
        except OSError:
            pass
        raise MigrationError("MIGRATION_FS", "migration error")
    if (
        stat.S_ISLNK(lst.st_mode)
        or not stat.S_ISREG(st.st_mode)
        or not stat.S_ISREG(lst.st_mode)
        or st.st_ino != lst.st_ino
        or st.st_dev != lst.st_dev
        or st.st_uid != os.geteuid()
        or lst.st_uid != os.geteuid()
        or _mode_bits(st.st_mode) != 0o600
        or _mode_bits(lst.st_mode) != 0o600
    ):
        try:
            os.close(fd)
        except OSError:
            pass
        raise MigrationError("MIGRATION_FS", "migration error")

    lock_err = False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, OSError):
        lock_err = True
    if lock_err:
        try:
            os.close(fd)
        except OSError:
            pass
        raise MigrationError("MIGRATION_LOCKED", "migration error")

    # Re-check path identity after flock (replacement race).
    post_err: Optional[str] = None
    lst2 = None
    try:
        lst2 = os.lstat(path)
    except OSError:
        post_err = "fs"
    if (
        post_err is not None
        or lst2 is None
        or lst2.st_ino != st.st_ino
        or lst2.st_dev != st.st_dev
        or stat.S_ISLNK(lst2.st_mode)
        or _mode_bits(lst2.st_mode) != 0o600
        or lst2.st_uid != os.geteuid()
    ):
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass
        raise MigrationError("MIGRATION_FS", "migration error")
    return _LockToken(fd=fd, st_dev=st.st_dev, st_ino=st.st_ino)


def _release_lock(store_dir: Path, token: Optional[_LockToken]) -> None:
    """Release advisory lock only. Never unlink the persistent lock file."""
    if token is None:
        return
    unlock_failed = False
    close_failed = False
    try:
        fcntl.flock(token.fd, fcntl.LOCK_UN)
    except OSError:
        unlock_failed = True
    try:
        os.close(token.fd)
    except OSError:
        close_failed = True
    if unlock_failed or close_failed:
        raise MigrationError("MIGRATION_LOCK_RELEASE", "migration error")


def _isol_name(txid: str, kind: str) -> str:
    return f".cg-migrate-isol-{kind}-{txid}"


def _atomic_rename_no_clobber(src: Path, dst: Path) -> None:
    """Atomically move src→dst failing if dst exists. Prefer renamex_np on Darwin."""
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        renamex_np = libc.renamex_np
        renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex_np.restype = ctypes.c_int
        rc = renamex_np(
            str(src).encode("utf-8"),
            str(dst).encode("utf-8"),
            _RENAME_EXCL,
        )
        if rc == 0:
            return
        err = ctypes.get_errno()
        if err in {errno.EEXIST, getattr(errno, "ENOTEMPTY", -1)}:
            raise MigrationError("MIGRATION_CONFLICT", "migration error")
        raise MigrationError("MIGRATION_SOURCE_TOCTOU", "migration error")
    # Portable fallback: link + verify + unlink source name if still owned inode.
    link_err: Optional[str] = None
    try:
        os.link(src, dst)
    except FileExistsError:
        link_err = "exists"
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.EEXIST:
            link_err = "exists"
        else:
            link_err = "fail"
    if link_err == "exists":
        raise MigrationError("MIGRATION_CONFLICT", "migration error")
    if link_err == "fail":
        raise MigrationError("MIGRATION_SOURCE_TOCTOU", "migration error")
    stat_err: Optional[str] = None
    src_st = None
    dst_st = None
    try:
        src_st = os.lstat(src)
        dst_st = os.lstat(dst)
    except OSError:
        stat_err = "toctou"
    if stat_err is not None or src_st is None or dst_st is None:
        raise MigrationError("MIGRATION_SOURCE_TOCTOU", "migration error")
    if src_st.st_ino != dst_st.st_ino or src_st.st_dev != dst_st.st_dev:
        # Competitor at src; keep both, do not delete competitor.
        raise MigrationError("MIGRATION_CONFLICT", "migration error")
    if not _try_unlink(src):
        raise MigrationError("MIGRATION_SOURCE_TOCTOU", "migration error")


def _isolate_owned_source(
    path: Path,
    isol_path: Path,
    *,
    expected_dev: int,
    expected_ino: int,
    expected_sha: str,
) -> None:
    """Move owned source to isolation name; never delete a competitor."""
    err: Optional[str] = None
    lst = None
    try:
        lst = os.lstat(path)
    except FileNotFoundError:
        err = "MIGRATION_SOURCE_TOCTOU"
    except OSError:
        err = "MIGRATION_SOURCE_UNAVAILABLE"
    if err is not None:
        raise MigrationError(err, "migration error")
    assert lst is not None
    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
        raise MigrationError("MIGRATION_SOURCE_TOCTOU", "migration error")
    if lst.st_dev != expected_dev or lst.st_ino != expected_ino:
        raise MigrationError("MIGRATION_CONFLICT", "migration error")
    got = _file_sha256_if_regular(path)
    if got != expected_sha:
        raise MigrationError("MIGRATION_CONFLICT", "migration error")
    if _exists(isol_path):
        raise MigrationError("MIGRATION_CONFLICT", "migration error")
    _atomic_rename_no_clobber(path, isol_path)
    # Verify isolation target is still owned bytes.
    if not _matches_owned(isol_path, expected_sha):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    ist_err: Optional[str] = None
    ist = None
    try:
        ist = os.lstat(isol_path)
    except OSError:
        ist_err = "recover"
    if ist_err is not None or ist is None:
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    if ist.st_dev != expected_dev or ist.st_ino != expected_ino:
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")


def _verify_published_artifact(path: Path, expected_sha: str) -> None:
    err: Optional[str] = None
    lst = None
    try:
        lst = os.lstat(path)
    except OSError:
        err = "MIGRATION_REREAD"
    if err is not None:
        raise MigrationError(err, "migration error")
    assert lst is not None
    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
        raise MigrationError("MIGRATION_REREAD", "migration error")
    if _mode_bits(lst.st_mode) != 0o600:
        raise MigrationError("MIGRATION_REREAD", "migration error")
    if lst.st_uid != os.geteuid():
        raise MigrationError("MIGRATION_REREAD", "migration error")
    if not _matches_owned(path, expected_sha):
        raise MigrationError("MIGRATION_REREAD", "migration error")


def _temp_entry_name(entry: Any) -> Optional[str]:
    if entry is None:
        return None
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        name = entry.get("name")
        if isinstance(name, str) and name:
            return name
    return None


def _cleanup_listed_temp(
    store_dir: Path, entry: Any, *, txid: str, expected_sha: Optional[str] = None
) -> None:
    """Identity-bound cleanup of a journal-listed temp; foreign exact-name → recovery required."""
    name = _temp_entry_name(entry)
    if not name:
        return
    if not name.startswith(".cg-migrate-") or not name.endswith(".tmp"):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    path = store_dir / name
    if not _exists(path):
        return
    identity = _parse_artifact_identity(entry)
    if identity is not None:
        if not _matches_artifact_identity(path, identity):
            raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
        _identity_bound_cleanup(store_dir, identity, txid=txid)
        return
    # Legacy / partial entry: require digest match then capture full identity.
    sha = expected_sha
    if sha is None and isinstance(entry, dict) and isinstance(entry.get("sha256"), str):
        sha = entry["sha256"]
    if sha is None or not _matches_owned(path, sha):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    captured = _capture_owned_artifact(path, purpose="temp", expected_sha=sha)
    _identity_bound_cleanup(store_dir, captured, txid=txid)


def _identity_bound_remove_if_owned(
    store_dir: Path,
    path: Path,
    *,
    expected_sha: str,
    purpose: str,
    txid: str,
) -> None:
    """Remove shared pathname only when it matches expected owned digest/identity."""
    if not _exists(path):
        return
    if not _matches_owned(path, expected_sha):
        # Foreign — retain; caller decides whether prestate allows recovered.
        return
    identity = _capture_owned_artifact(path, purpose=purpose, expected_sha=expected_sha)
    _identity_bound_cleanup(store_dir, identity, txid=txid)


def _verify_exact_prestate(
    store_dir: Path,
    journal: Dict[str, Any],
    *,
    journal_id: _JournalIdentity,
) -> None:
    """Require exact pre-migration filesystem state before clearing journal."""
    cred_path = store_dir / CREDENTIALS_FILENAME
    tgt_path = store_dir / TARGETS_FILENAME
    new_path = store_dir / CONFIG_FILENAME
    cred_bak = store_dir / CREDENTIALS_BAK
    tgt_bak = store_dir / TARGETS_BAK
    src_c = journal["source_credentials"]
    src_t = journal["source_targets"]
    cred_sha = journal["credentials_bak_sha256"]
    tgt_sha = journal["targets_bak_sha256"]
    txid = journal["txid"]
    temps = journal.get("temps") if isinstance(journal.get("temps"), dict) else {}

    for path, meta, sha in (
        (cred_path, src_c, cred_sha),
        (tgt_path, src_t, tgt_sha),
    ):
        if not _exists(path):
            raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
        err = False
        lst = None
        try:
            lst = os.lstat(path)
        except OSError:
            err = True
        if err or lst is None:
            raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
        if (
            stat.S_ISLNK(lst.st_mode)
            or not stat.S_ISREG(lst.st_mode)
            or _mode_bits(lst.st_mode) != 0o600
            or lst.st_uid != os.geteuid()
            or not _matches_owned(path, sha)
        ):
            raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")

    if _exists(new_path):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    if _exists(cred_bak) or _exists(tgt_bak):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")

    for kind in ("cred", "tgt"):
        if _exists(store_dir / _isol_name(txid, kind)):
            raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")

    for key in ("new", "credentials_bak", "targets_bak", "journal"):
        entry = temps.get(key) if temps else None
        name = _temp_entry_name(entry)
        if name and _exists(store_dir / name):
            raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")

    # Journal itself must still be the expected identity/txid.
    cur = _stat_journal_identity(store_dir, journal_id.txid)
    if (
        cur.st_dev != journal_id.st_dev
        or cur.st_ino != journal_id.st_ino
        or cur.sha256 != journal_id.sha256
        or cur.txid != journal_id.txid
    ):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")


def _compensate_to_prestate(store_dir: Path, journal: Dict[str, Any]) -> None:
    """Restore pre-migration formal state using journal ownership only."""
    new_path = store_dir / CONFIG_FILENAME
    cred_path = store_dir / CREDENTIALS_FILENAME
    tgt_path = store_dir / TARGETS_FILENAME
    cred_bak = store_dir / CREDENTIALS_BAK
    tgt_bak = store_dir / TARGETS_BAK
    new_sha = journal["new_sha256"]
    cred_bak_sha = journal["credentials_bak_sha256"]
    tgt_bak_sha = journal["targets_bak_sha256"]
    txid = journal["txid"]
    temps = journal.get("temps") if isinstance(journal.get("temps"), dict) else {}

    # Capture journal identity before any mutation; required for exact prestate + clear.
    journal_id = _stat_journal_identity(store_dir, txid)

    # Restore missing olds from owned bak or isolation names.
    for formal, bak, sha, kind in (
        (cred_path, cred_bak, cred_bak_sha, "cred"),
        (tgt_path, tgt_bak, tgt_bak_sha, "tgt"),
    ):
        isol = store_dir / _isol_name(txid, kind)
        if _exists(formal):
            if not _matches_owned(formal, sha):
                # Competitor occupies formal — never delete/overwrite; keep evidence.
                raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
            continue
        if _exists(isol) and _matches_owned(isol, sha):
            rename_err = False
            try:
                _atomic_rename_no_clobber(isol, formal)
            except MigrationError:
                rename_err = True
            if rename_err:
                raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
        elif _exists(bak) and _matches_owned(bak, sha):
            tmp_id = None
            restore_err = False
            restore_name = _temp_name(txid, f"restore-{kind}")
            try:
                tmp_id = _write_bytes_temp(
                    store_dir,
                    restore_name,
                    _read_secure_bytes(bak).raw,
                    purpose=f"restore-{kind}",
                    txid=txid,
                )
                _publish_no_clobber(
                    store_dir / tmp_id.name,
                    formal,
                    exists_code="MIGRATION_CONFLICT",
                    fail_code="MIGRATION_RESTORE",
                )
                _unlink_temp_after_publish(
                    store_dir, tmp_id, txid=txid, fail_code="MIGRATION_RESTORE"
                )
                tmp_id = None
            except MigrationError:
                restore_err = True
            if restore_err:
                if tmp_id is not None:
                    try:
                        _cleanup_owned_optional(store_dir, tmp_id, txid=txid)
                    except MigrationError:
                        pass
                raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
        else:
            raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")

    if not _exists(cred_path) or not _exists(tgt_path):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    if not _matches_owned(cred_path, cred_bak_sha) or not _matches_owned(
        tgt_path, tgt_bak_sha
    ):
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")

    # Remove owned published new only when digest matches journal commitment.
    if _exists(new_path):
        if _matches_owned(new_path, new_sha):
            _identity_bound_remove_if_owned(
                store_dir,
                new_path,
                expected_sha=new_sha,
                purpose="new-formal",
                txid=txid,
            )
        else:
            # Competitor new file — cannot claim clean prestate.
            raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")

    # Remove owned baks only when formal path already holds the owned bytes.
    if _exists(cred_bak):
        if _matches_owned(cred_bak, cred_bak_sha) and _matches_owned(
            cred_path, cred_bak_sha
        ):
            _identity_bound_remove_if_owned(
                store_dir,
                cred_bak,
                expected_sha=cred_bak_sha,
                purpose="credentials_bak",
                txid=txid,
            )
        else:
            # Owned bak residual with mismatched formal, or foreign bak.
            raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")

    if _exists(tgt_bak):
        if _matches_owned(tgt_bak, tgt_bak_sha) and _matches_owned(
            tgt_path, tgt_bak_sha
        ):
            _identity_bound_remove_if_owned(
                store_dir,
                tgt_bak,
                expected_sha=tgt_bak_sha,
                purpose="targets_bak",
                txid=txid,
            )
        else:
            raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")

    # Clean owned isolation leftovers; foreign isol → recovery required.
    for kind in ("cred", "tgt"):
        isol = store_dir / _isol_name(txid, kind)
        if not _exists(isol):
            continue
        sha = cred_bak_sha if kind == "cred" else tgt_bak_sha
        if not _matches_owned(isol, sha):
            raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
        isol_id = _capture_owned_artifact(isol, purpose=f"{kind}-isol", expected_sha=sha)
        _identity_bound_delete_isolated(isol, isol_id)

    # Clean only journal-listed temps (never prefix-scan).
    for key in ("new", "credentials_bak", "targets_bak", "journal"):
        entry = temps.get(key)
        expected_sha = None
        if key == "new":
            expected_sha = new_sha
        elif key == "credentials_bak":
            expected_sha = cred_bak_sha
        elif key == "targets_bak":
            expected_sha = tgt_bak_sha
        _cleanup_listed_temp(
            store_dir, entry, txid=txid, expected_sha=expected_sha
        )

    fsync_err = False
    try:
        _fsync_dir(store_dir)
    except MigrationError:
        fsync_err = True
    if fsync_err:
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")

    _verify_exact_prestate(store_dir, journal, journal_id=journal_id)
    _clear_journal(store_dir, expected=journal_id)
    fsync2_err = False
    try:
        _fsync_dir(store_dir)
    except MigrationError:
        fsync2_err = True
    if fsync2_err:
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")


def _recover_journal_or_raise(store_dir: Path) -> None:
    journal = _read_journal(store_dir)
    if journal is None:
        return
    recovery_err = False
    try:
        _compensate_to_prestate(store_dir, journal)
    except MigrationError:
        recovery_err = True
    if recovery_err:
        raise MigrationError("MIGRATION_RECOVERY_REQUIRED", "migration error")
    raise MigrationError("MIGRATION_RECOVERED", "migration error")


def run_migrate_config(store_dir: Optional[Path | str] = None) -> int:
    """CLI entry: migrate using explicit dir or HERMES_HOME-resolved store."""
    root = resolve_config_dir(store_dir)
    run_err: Optional[str] = None
    result = None
    try:
        result = migrate_config(root)
    except MigrationError as exc:
        run_err = exc.code
    except Exception:
        run_err = "failed"
    if run_err is not None:
        if run_err == "failed":
            print("credential-guard: migrate-config failed")
        else:
            print(f"credential-guard: migrate-config failed ({run_err})")
        return 1
    assert result is not None
    print("credential-guard: migrate-config ok")
    print(f"config_digest={result.config_digest}")
    return 0


__all__ = [
    "CREDENTIALS_BAK",
    "TARGETS_BAK",
    "JOURNAL_NAME",
    "LOCK_NAME",
    "MigrationError",
    "MigrationResult",
    "migrate_config",
    "resolve_config_dir",
    "run_migrate_config",
]
