"""Safe target catalog sidecar for model-visible binding lists.

``credential-guard.json`` remains the sole authoritative config (secrets).
``credential-guard.targets.json`` is a plugin-generated sidecar with only
model-safe binding metadata. Hermes startup / tool registration reads the
sidecar only (plus ``lstat`` of the main config for identity matching) and
never opens the main config body. Formal egress still uses ``runtime_config``.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Union

from .bindings import (
    ALLOWED_HTTP_METHODS,
    MAX_ALLOWED_HTTP_PATHS,
    validate_exact_http_path,
)
from .config import CONFIG_FILENAME, ConfigError, CredentialGuardConfig, NAME_RE
from . import store_location
from .config_lock import (
    ConfigLockError,
    exclusive_atomic_replace_config,
    shared_config_lock,
)

PathLike = Union[str, Path]

TARGET_CATALOG_FILENAME = "credential-guard.targets.json"
TARGET_CATALOG_VERSION = 1
MAX_TARGET_CATALOG_BYTES = 262_144

_TOP_FIELDS = frozenset({"version", "source_identity", "bindings"})
_IDENTITY_FIELDS = frozenset({"device", "inode", "size", "mtime_ns"})
_HTTP_BINDING_FIELDS = frozenset(
    {"type", "credential_ref", "allowed_methods", "allowed_paths"}
)
_PROCESS_BINDING_FIELDS = frozenset({"type", "credential_ref"})
_PROCESS_TYPES = frozenset({"process_env", "stdin"})

# Registration-time catalog state (sidecar only). Never published to
# runtime_config._PUBLISHED and never used for egress/approval/execution.
#
# Three states (internal sentinel never exposed in descriptions/logs/errors):
# - UNPREPARED: ``_REGISTRATION_STATE is None`` — schema builders may fall
#   back to ``get_runtime_view().bindings`` for non-register call sites.
# - READY: ``_REGISTRATION_STATE`` is a frozen bindings mapping.
# - PREPARED_INVALID: ``_REGISTRATION_STATE is _PREPARED_INVALID`` — register
#   must use static descriptions; must NOT read RuntimeView.
_PREPARED_INVALID = object()
_REGISTRATION_STATE: Any = None


class TargetCatalogError(Exception):
    """Fail-closed catalog error. Never embed secrets, hosts, or paths."""

    __slots__ = ("code",)

    def __init__(self, code: str, message: str = "target catalog error") -> None:
        object.__setattr__(self, "code", code)
        super().__init__(message)

    def __repr__(self) -> str:
        return f"TargetCatalogError(code={self.code!r})"


class TargetCatalogPartialCommitError(Exception):
    """Main config committed; target catalog unavailable. Never embed secrets/paths."""

    __slots__ = ("code",)

    def __init__(
        self,
        code: str = "CONFIG_COMMITTED_TARGET_CATALOG_UNAVAILABLE",
        message: str = "configuration committed; target catalog unavailable",
    ) -> None:
        object.__setattr__(self, "code", code)
        super().__init__(message)

    def __repr__(self) -> str:
        return f"TargetCatalogPartialCommitError(code={self.code!r})"


def reset_registration_catalog_for_tests() -> None:
    """Return registration catalog to UNPREPARED (tests only)."""
    global _REGISTRATION_STATE
    _REGISTRATION_STATE = None


def get_registration_bindings() -> Optional[Mapping[str, Any]]:
    """Return READY bindings, or ``None`` for UNPREPARED / PREPARED_INVALID."""
    state = _REGISTRATION_STATE
    if state is None or state is _PREPARED_INVALID:
        return None
    return state


def resolve_registration_catalog() -> tuple[bool, Optional[Mapping[str, Any]]]:
    """Public three-state read API that never exposes the internal sentinel.

    Returns ``(prepared, bindings)``:

    - ``(False, None)`` — UNPREPARED; callers may fall back to RuntimeView.
    - ``(True, mapping)`` — READY; use sidecar bindings.
    - ``(True, None)`` — PREPARED_INVALID; static schema only (no RuntimeView).
    """
    state = _REGISTRATION_STATE
    if state is None:
        return (False, None)
    if state is _PREPARED_INVALID:
        return (True, None)
    return (True, state)


def prepare_registration_catalog(store_dir: Optional[PathLike] = None) -> None:
    """Load sidecar for tool schema descriptions. Never reads main config body.

    Enters PREPARED_INVALID immediately; only a strictly successful sidecar
    load promotes the state to READY. Missing/invalid/stale → stay invalid.
    """
    global _REGISTRATION_STATE
    _REGISTRATION_STATE = _PREPARED_INVALID
    try:
        loaded = load_safe_bindings_from_sidecar(store_dir)
        if loaded is not None:
            _REGISTRATION_STATE = loaded
    except Exception:
        _REGISTRATION_STATE = _PREPARED_INVALID


def _store_dir() -> Path:
    """The one configuration directory, derived from the install layout.

    Delegates to :mod:`credential_guard.store_location`; this module keeps no
    private copy of the lookup. See that module for why the former
    ``$HERMES_HOME`` guess was removed.
    """
    return store_location.resolve_store_dir()


def _mode_bits(mode: int) -> int:
    return stat.S_IMODE(mode)


def _file_identity(path: Path) -> Dict[str, int]:
    st = path.lstat()
    return {
        "device": int(st.st_dev),
        "inode": int(st.st_ino),
        "size": int(st.st_size),
        "mtime_ns": int(st.st_mtime_ns),
    }


def _assert_secure_store_dir(store_dir: Path) -> None:
    try:
        lst = os.lstat(store_dir)
    except OSError as exc:
        raise TargetCatalogError("TARGET_CATALOG_FS") from exc
    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISDIR(lst.st_mode):
        raise TargetCatalogError("TARGET_CATALOG_FS")
    if lst.st_uid != os.geteuid():
        raise TargetCatalogError("TARGET_CATALOG_FS")
    if _mode_bits(lst.st_mode) != 0o700:
        raise TargetCatalogError("TARGET_CATALOG_FS")


def build_catalog_document(
    cfg: CredentialGuardConfig, source_identity: Mapping[str, int]
) -> Dict[str, Any]:
    """Build strict sidecar document from a validated Schema v2 config."""
    bindings_out: Dict[str, Any] = {}
    for name in sorted(cfg.bindings):
        entry = cfg.bindings[name]
        btype = entry.get("type")
        if btype == "http":
            req = entry.get("request") or {}
            bindings_out[name] = {
                "type": "http",
                "credential_ref": entry.get("credential_ref"),
                "allowed_methods": list(req.get("allowed_methods") or ()),
                "allowed_paths": list(req.get("allowed_paths") or ()),
            }
        elif btype in _PROCESS_TYPES:
            bindings_out[name] = {
                "type": btype,
                "credential_ref": entry.get("credential_ref"),
            }
        else:
            raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
    return {
        "version": TARGET_CATALOG_VERSION,
        "source_identity": {
            "device": int(source_identity["device"]),
            "inode": int(source_identity["inode"]),
            "size": int(source_identity["size"]),
            "mtime_ns": int(source_identity["mtime_ns"]),
        },
        "bindings": bindings_out,
    }


def _reject_duplicate_keys(pairs: list) -> dict:
    out: Dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
        out[key] = value
    return out


def _validate_identity(raw: Any) -> Dict[str, int]:
    if not isinstance(raw, dict) or set(raw.keys()) != _IDENTITY_FIELDS:
        raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
    out: Dict[str, int] = {}
    for key in ("device", "inode", "size", "mtime_ns"):
        val = raw[key]
        if isinstance(val, bool) or not isinstance(val, int):
            raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
        out[key] = int(val)
    return out


def _validate_binding_entry(name: Any, entry: Any) -> Dict[str, Any]:
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
    if not isinstance(entry, dict):
        raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
    btype = entry.get("type")
    if btype == "http":
        if set(entry.keys()) - _HTTP_BINDING_FIELDS:
            raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
        if set(entry.keys()) != _HTTP_BINDING_FIELDS:
            raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
        cred = entry["credential_ref"]
        if not isinstance(cred, str) or not NAME_RE.fullmatch(cred):
            raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
        methods_raw = entry["allowed_methods"]
        paths_raw = entry["allowed_paths"]
        if not isinstance(methods_raw, list) or not isinstance(paths_raw, list):
            raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
        if not methods_raw or not paths_raw:
            raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
        if len(paths_raw) > MAX_ALLOWED_HTTP_PATHS:
            raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
        methods: list[str] = []
        seen_m: set[str] = set()
        for item in methods_raw:
            if not isinstance(item, str) or item not in ALLOWED_HTTP_METHODS:
                raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
            if item in seen_m:
                raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
            seen_m.add(item)
            methods.append(item)
        paths: list[str] = []
        seen_p: set[str] = set()
        for item in paths_raw:
            try:
                path = validate_exact_http_path(item)
            except ConfigError as exc:
                raise TargetCatalogError("TARGET_CATALOG_SCHEMA") from exc
            if path in seen_p:
                raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
            seen_p.add(path)
            paths.append(path)
        return {
            "type": "http",
            "credential_ref": cred,
            "allowed_methods": tuple(methods),
            "allowed_paths": tuple(paths),
        }
    if btype in _PROCESS_TYPES:
        if set(entry.keys()) - _PROCESS_BINDING_FIELDS:
            raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
        if set(entry.keys()) != _PROCESS_BINDING_FIELDS:
            raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
        cred = entry["credential_ref"]
        if not isinstance(cred, str) or not NAME_RE.fullmatch(cred):
            raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
        return {"type": btype, "credential_ref": cred}
    raise TargetCatalogError("TARGET_CATALOG_SCHEMA")


def parse_catalog_document(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict) or set(data.keys()) != _TOP_FIELDS:
        raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
    version = data.get("version")
    if type(version) is not int or version != TARGET_CATALOG_VERSION:
        raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
    identity = _validate_identity(data.get("source_identity"))
    raw_bindings = data.get("bindings")
    if not isinstance(raw_bindings, dict):
        raise TargetCatalogError("TARGET_CATALOG_SCHEMA")
    bindings: Dict[str, Any] = {}
    for name, entry in raw_bindings.items():
        bindings[name] = _validate_binding_entry(name, entry)
    return {
        "version": TARGET_CATALOG_VERSION,
        "source_identity": identity,
        "bindings": bindings,
    }


def _open_and_read_catalog(path: Path) -> bytes:
    _assert_secure_store_dir(path.parent)
    try:
        lst = os.lstat(path)
    except FileNotFoundError as exc:
        raise TargetCatalogError("TARGET_CATALOG_NOT_FOUND") from exc
    except OSError as exc:
        raise TargetCatalogError("TARGET_CATALOG_FS") from exc
    if stat.S_ISLNK(lst.st_mode):
        raise TargetCatalogError("TARGET_CATALOG_SYMLINK")
    if not stat.S_ISREG(lst.st_mode):
        raise TargetCatalogError("TARGET_CATALOG_FS")
    if _mode_bits(lst.st_mode) != 0o600:
        raise TargetCatalogError("TARGET_CATALOG_INSECURE_MODE")
    if lst.st_uid != os.geteuid():
        raise TargetCatalogError("TARGET_CATALOG_FS")
    if lst.st_size > MAX_TARGET_CATALOG_BYTES:
        raise TargetCatalogError("TARGET_CATALOG_TOO_LARGE")

    open_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    try:
        if nofollow:
            fd = os.open(path, open_flags | nofollow)
        else:
            fd = os.open(path, open_flags)
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or _mode_bits(st.st_mode) != 0o600
            or st.st_uid != os.geteuid()
            or st.st_size > MAX_TARGET_CATALOG_BYTES
            or st.st_ino != lst.st_ino
            or st.st_dev != lst.st_dev
        ):
            raise TargetCatalogError("TARGET_CATALOG_FS")
        chunks: list[bytes] = []
        remaining = int(st.st_size)
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != st.st_size:
            raise TargetCatalogError("TARGET_CATALOG_FS")
        return data
    except TargetCatalogError:
        raise
    except OSError as exc:
        raise TargetCatalogError("TARGET_CATALOG_FS") from exc
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def atomic_write_catalog(store_dir: PathLike, document: Mapping[str, Any]) -> None:
    """Atomically write sidecar (temp 0600 → fsync → replace → best-effort dir fsync).

    Directory fsync is best-effort only: OSError is swallowed. Callers must not
    treat a successful return as a crash-durable guarantee for the directory
    entry; identity mismatch still forces static registration fallback.
    """
    root = Path(store_dir)
    _assert_secure_store_dir(root)
    formal = root / TARGET_CATALOG_FILENAME
    payload = json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(payload) > MAX_TARGET_CATALOG_BYTES:
        raise TargetCatalogError("TARGET_CATALOG_TOO_LARGE")

    tmp_path: Optional[Path] = None
    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix=".cg-targets-",
            suffix=".tmp",
            dir=str(root),
        )
        tmp_path = Path(tmp_name)
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(payload)
            while len(view) > 0:
                n = os.write(fd, view)
                if n <= 0:
                    raise OSError("short write")
                view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(str(tmp_path), str(formal))
        tmp_path = None
        try:
            dir_fd = os.open(str(root), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except TargetCatalogError:
        raise
    except OSError as exc:
        raise TargetCatalogError("TARGET_CATALOG_WRITE") from exc
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except OSError:
                pass


def generate_and_write_target_catalog(store_dir: PathLike) -> None:
    """Read+validate main config, capture identity, write sidecar under shared lock."""
    root = Path(store_dir)
    _assert_secure_store_dir(root)
    cfg_path = root / CONFIG_FILENAME
    try:
        with shared_config_lock(root):
            cfg = CredentialGuardConfig.load(cfg_path)
            identity = _file_identity(cfg_path)
            document = build_catalog_document(cfg, identity)
            atomic_write_catalog(root, document)
    except ConfigLockError as exc:
        raise TargetCatalogError(
            getattr(exc, "code", None) or "CONFIG_LOCK_TIMEOUT"
        ) from None


def replace_config_and_refresh_targets(
    store_dir: PathLike,
    new_text: str,
    *,
    timeout_seconds: float = 5.0,
) -> None:
    """Strict-parse ``new_text``, exclusive replace config, then refresh sidecar.

    Does not claim that hand-edited configs auto-refresh; callers must use this
    helper or ``refresh-targets`` explicitly.

    Partial-commit semantics: if the main config replace succeeds but sidecar
    generation fails, raises ``TargetCatalogPartialCommitError`` with code
    ``CONFIG_COMMITTED_TARGET_CATALOG_UNAVAILABLE``. The new main config remains
    in effect; any prior sidecar becomes identity-stale and registration falls
    back to static descriptions. Failures before the config replace keep the
    original Config/Lock error (config not committed).

    Directory fsync during sidecar write is best-effort only (see
    ``atomic_write_catalog``).
    """
    root = Path(store_dir)
    try:
        data = json.loads(new_text)
    except json.JSONDecodeError as exc:
        raise ConfigError("CONFIG_INVALID_JSON", "configuration error") from exc
    cfg = CredentialGuardConfig.from_mapping(data)
    exclusive_atomic_replace_config(
        root, new_text, timeout_seconds=timeout_seconds
    )
    try:
        generate_and_write_target_catalog(root)
    except TargetCatalogPartialCommitError:
        raise
    except (TargetCatalogError, ConfigError, ConfigLockError, OSError):
        raise TargetCatalogPartialCommitError() from None
    except Exception:
        raise TargetCatalogPartialCommitError() from None
    _ = cfg.config_digest


def load_safe_bindings_from_sidecar(
    store_dir: Optional[PathLike] = None,
) -> Optional[Mapping[str, Any]]:
    """Startup path: lstat main config only; read/validate sidecar; match identity.

    Returns frozen bindings mapping, or ``None`` for static description fallback.
    Never opens ``credential-guard.json`` body. Never publishes runtime.

    Under ``shared_config_lock``, captures main-config identity before and after
    the sidecar read; requires before == after == sidecar identity.
    """
    root = Path(store_dir) if store_dir is not None else _store_dir()
    try:
        _assert_secure_store_dir(root)
    except TargetCatalogError:
        return None

    cfg_path = root / CONFIG_FILENAME
    cat_path = root / TARGET_CATALOG_FILENAME
    try:
        with shared_config_lock(root):
            try:
                before = _file_identity(cfg_path)
            except OSError:
                return None

            try:
                raw = _open_and_read_catalog(cat_path)
                text = raw.decode("utf-8")
                data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
                parsed = parse_catalog_document(data)
            except (
                TargetCatalogError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                TypeError,
            ):
                return None
            except Exception:
                return None

            try:
                after = _file_identity(cfg_path)
            except OSError:
                return None

            if before != after:
                return None
            if parsed["source_identity"] != before:
                return None

            cleaned = {
                name: MappingProxyType(dict(entry))
                for name, entry in parsed["bindings"].items()
            }
            return MappingProxyType(cleaned)
    except ConfigLockError:
        return None


def run_refresh_targets(store_dir: Optional[PathLike] = None) -> int:
    """CLI entry: refresh sidecar from validated main config. No config dump."""
    root = Path(store_dir) if store_dir is not None else _store_dir()
    try:
        generate_and_write_target_catalog(root)
    except ConfigError as exc:
        code = getattr(exc, "code", "") or "CONFIG_ERROR"
        print(f"credential-guard: refresh-targets failed ({code})")
        return 1
    except TargetCatalogPartialCommitError as exc:
        print(f"credential-guard: refresh-targets failed ({exc.code})")
        return 1
    except TargetCatalogError as exc:
        print(f"credential-guard: refresh-targets failed ({exc.code})")
        return 1
    except ConfigLockError as exc:
        print(f"credential-guard: refresh-targets failed ({exc.code})")
        return 1
    except Exception:
        print("credential-guard: refresh-targets failed")
        return 1
    print("credential-guard: refresh-targets ok")
    return 0


__all__ = [
    "MAX_TARGET_CATALOG_BYTES",
    "TARGET_CATALOG_VERSION",
    "TARGET_CATALOG_FILENAME",
    "TargetCatalogError",
    "TargetCatalogPartialCommitError",
    "atomic_write_catalog",
    "build_catalog_document",
    "generate_and_write_target_catalog",
    "get_registration_bindings",
    "load_safe_bindings_from_sidecar",
    "parse_catalog_document",
    "prepare_registration_catalog",
    "replace_config_and_refresh_targets",
    "reset_registration_catalog_for_tests",
    "resolve_registration_catalog",
    "run_refresh_targets",
]
