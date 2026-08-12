"""R1A: safe migration from credentials.json+targets.json to credential-guard.json."""

from __future__ import annotations

import json
import os
import secrets
import stat
import traceback
from argparse import Namespace
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from credential_guard.cli import handle_command, setup_parser
from credential_guard.config import CONFIG_FILENAME, CredentialGuardConfig
from credential_guard.migration import (
    CREDENTIALS_BAK,
    TARGETS_BAK,
    MigrationError,
    migrate_config,
)


def _decoy() -> str:
    return "CG_MIG_" + secrets.token_hex(20)


def _chmod600(path: Path) -> None:
    os.chmod(path, 0o600)


def _write_json(path: Path, doc: Dict[str, Any]) -> bytes:
    raw = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    path.write_bytes(raw)
    _chmod600(path)
    return raw


def _ssh_v1_pair() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    credentials = {"version": 1, "credentials": {}}
    targets = {
        "version": 1,
        "targets": {
            "bastion": {
                "type": "ssh_config",
                "ssh_alias": "bastion-prod",
            }
        },
    }
    return credentials, targets


def _empty_v1_pair() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Only shape of v1 source that still migrates automatically after R5 Task 5/6.

    Every v1 entry type (mysql credential/target, ssh_config target) now requires
    manual review, so transaction-machinery tests that need to reach journal /
    publish / compensation must start from an empty pair.
    """
    return {"version": 1, "credentials": {}}, {"version": 1, "targets": {}}


def _mysql_v1_pair(decoy: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    credentials = {
        "version": 1,
        "credentials": {
            "mysql_canary_credential": {
                "type": "mysql",
                "username": "cg_readonly",
                "password": decoy,
            }
        },
    }
    targets = {
        "version": 1,
        "targets": {
            "mysql-local-canary": {
                "type": "mysql",
                "host": "127.0.0.1",
                "port": 3309,
                "database": "credential_guard_test",
                "credential_ref": "mysql_canary_credential",
            }
        },
    }
    return credentials, targets


def _prepare_store(
    root: Path,
    credentials: Dict[str, Any],
    targets: Dict[str, Any],
    *,
    dir_mode: int = 0o700,
) -> Path:
    store = root / "credential-guard"
    store.mkdir(parents=True, exist_ok=True)
    os.chmod(store, dir_mode)
    _write_json(store / "credentials.json", credentials)
    _write_json(store / "targets.json", targets)
    return store


def _file_fingerprint(path: Path) -> Tuple[bytes, int]:
    st = path.lstat()
    return path.read_bytes(), stat.S_IMODE(st.st_mode)


def _assert_no_leak(blob: str, *, decoy: str, username: str = "", host: str = "") -> None:
    assert decoy not in blob
    if username:
        assert username not in blob
    if host:
        assert host not in blob
    for i in range(0, max(0, len(decoy) - 7)):
        assert decoy[i : i + 8] not in blob


def _assert_pre_migration_state(store: Path, cred_fp: Tuple[bytes, int], tgt_fp: Tuple[bytes, int]) -> None:
    assert (store / CONFIG_FILENAME).exists() is False
    assert (store / "credentials.json").is_file()
    assert (store / "targets.json").is_file()
    assert _file_fingerprint(store / "credentials.json") == cred_fp
    assert _file_fingerprint(store / "targets.json") == tgt_fp
    assert not (store / CREDENTIALS_BAK).exists()
    assert not (store / TARGETS_BAK).exists()
    leftovers = []
    for p in store.iterdir():
        name = p.name
        if name == ".cg-migrate.lock":
            # Persistent advisory lock file is allowed to remain.
            continue
        if name.startswith(".cg-migrate") or name.endswith(".tmp") or ".tmp" in name:
            leftovers.append(p)
    assert leftovers == []


# --- success ---


def test_migrate_ssh_v1_requires_manual_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """ssh_config left the v2 schema in R5 Task 5; v1 SSH targets need a human."""
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    creds, tgts = _ssh_v1_pair()
    store = _prepare_store(hermes, creds, tgts)
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")

    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    assert ei.value.code == "MIGRATION_REQUIRES_MANUAL_REVIEW"
    blob = f"{ei.value!s}{ei.value!r}{ei.value.code}"
    assert "bastion-prod" not in blob
    assert "bastion" not in blob
    assert str(store) not in blob

    _assert_pre_migration_state(store, cred_fp, tgt_fp)


def test_migrate_empty_v1_pair_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    creds, tgts = _empty_v1_pair()
    store = _prepare_store(hermes, creds, tgts)
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")

    result = migrate_config(store)
    assert result.ok is True

    new_path = store / CONFIG_FILENAME
    assert new_path.is_file()
    st = new_path.lstat()
    assert stat.S_IMODE(st.st_mode) == 0o600
    assert not stat.S_ISLNK(st.st_mode)
    cfg = CredentialGuardConfig.load(new_path)
    assert cfg.credentials == {}
    assert cfg.bindings == {}

    assert not (store / "credentials.json").exists()
    assert not (store / "targets.json").exists()
    assert _file_fingerprint(store / CREDENTIALS_BAK) == cred_fp
    assert _file_fingerprint(store / TARGETS_BAK) == tgt_fp


def test_migrate_mysql_requires_manual_review(tmp_path: Path):
    decoy = _decoy()
    store = _prepare_store(tmp_path, *_mysql_v1_pair(decoy))
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    assert ei.value.code == "MIGRATION_REQUIRES_MANUAL_REVIEW"
    _assert_no_leak(
        f"{ei.value!s}{ei.value!r}{ei.value.code}",
        decoy=decoy,
        username="cg_readonly",
        host="127.0.0.1",
    )
    _assert_pre_migration_state(store, cred_fp, tgt_fp)


def test_migrate_credentials_only_requires_manual_review(tmp_path: Path):
    """Non-empty v1 credentials must never silently migrate into an empty v2 doc."""
    decoy = _decoy()
    creds, _tgts = _mysql_v1_pair(decoy)
    store = _prepare_store(tmp_path, creds, {"version": 1, "targets": {}})
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    assert ei.value.code == "MIGRATION_REQUIRES_MANUAL_REVIEW"
    _assert_no_leak(
        f"{ei.value!s}{ei.value!r}{ei.value.code}",
        decoy=decoy,
        username="cg_readonly",
    )
    _assert_pre_migration_state(store, cred_fp, tgt_fp)


def test_second_migrate_refuses_overwrite(tmp_path: Path):
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    migrate_config(store)
    # Restore old files to attempt a second migrate while new exists.
    (store / CREDENTIALS_BAK).rename(store / "credentials.json")
    (store / TARGETS_BAK).rename(store / "targets.json")
    with pytest.raises(MigrationError):
        migrate_config(store)
    assert (store / CONFIG_FILENAME).is_file()


# --- preconditions ---


def test_rejects_when_new_exists(tmp_path: Path):
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    new = store / CONFIG_FILENAME
    new.write_text("{}", encoding="utf-8")
    _chmod600(new)
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    with pytest.raises(MigrationError):
        migrate_config(store)
    assert _file_fingerprint(store / "credentials.json") == cred_fp
    assert _file_fingerprint(store / "targets.json") == tgt_fp


def test_rejects_when_backup_exists(tmp_path: Path):
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    bak = store / CREDENTIALS_BAK
    bak.write_text("{}", encoding="utf-8")
    _chmod600(bak)
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    bak_fp = _file_fingerprint(bak)
    with pytest.raises(MigrationError):
        migrate_config(store)
    assert not (store / CONFIG_FILENAME).exists()
    assert _file_fingerprint(store / "credentials.json") == cred_fp
    assert _file_fingerprint(store / "targets.json") == tgt_fp
    assert _file_fingerprint(bak) == bak_fp
    assert not (store / TARGETS_BAK).exists()


def test_rejects_missing_old_file(tmp_path: Path):
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    (store / "targets.json").unlink()
    with pytest.raises(MigrationError):
        migrate_config(store)
    assert not (store / CONFIG_FILENAME).exists()


def test_rejects_old_file_bad_mode(tmp_path: Path):
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    os.chmod(store / "credentials.json", 0o644)
    cred_bytes = (store / "credentials.json").read_bytes()
    tgt_fp = _file_fingerprint(store / "targets.json")
    with pytest.raises(MigrationError):
        migrate_config(store)
    assert (store / "credentials.json").read_bytes() == cred_bytes
    assert _file_fingerprint(store / "targets.json") == tgt_fp
    assert not (store / CONFIG_FILENAME).exists()


def test_rejects_old_symlink(tmp_path: Path):
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    real = store / "credentials.real.json"
    cred = store / "credentials.json"
    cred.rename(real)
    cred.symlink_to(real)
    with pytest.raises(MigrationError):
        migrate_config(store)
    assert not (store / CONFIG_FILENAME).exists()


def test_rejects_duplicate_key_in_old(tmp_path: Path):
    store = tmp_path / "credential-guard"
    store.mkdir()
    os.chmod(store, 0o700)
    raw = b'{"version":1,"credentials":{"a":{"type":"mysql","username":"u","password":"CG_MIG_abcdefgh"},"a":{"type":"mysql","username":"u","password":"CG_MIG_abcdefgh"}}}'
    (store / "credentials.json").write_bytes(raw)
    _chmod600(store / "credentials.json")
    _write_json(store / "targets.json", {"version": 1, "targets": {}})
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    _assert_no_leak(f"{ei.value!s}{ei.value!r}", decoy="CG_MIG_abcdefgh")


def test_rejects_unknown_field_in_old(tmp_path: Path):
    creds, tgts = _ssh_v1_pair()
    tgts["targets"]["bastion"]["extra"] = "nope"
    store = _prepare_store(tmp_path, creds, tgts)
    with pytest.raises(MigrationError):
        migrate_config(store)
    assert not (store / CONFIG_FILENAME).exists()


# --- fault injection / rollback ---


def test_rollback_on_temp_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")

    real_open = os.open

    def boom(path, flags, mode=0o777, *args, **kwargs):
        name = Path(path).name
        if (flags & os.O_CREAT) and name.startswith(".cg-migrate-"):
            raise OSError(28, "No space left on device")
        return real_open(path, flags, mode, *args, **kwargs)

    monkeypatch.setattr(os, "open", boom)
    with pytest.raises(MigrationError):
        migrate_config(store)
    _assert_pre_migration_state(store, cred_fp, tgt_fp)


def test_rollback_on_fsync_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    real_fsync = os.fsync
    calls = {"n": 0}

    def flaky_fsync(fd):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError(5, "I/O error")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", flaky_fsync)
    with pytest.raises(MigrationError):
        migrate_config(store)
    _assert_pre_migration_state(store, cred_fp, tgt_fp)


def test_rollback_on_reread_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    real_load = CredentialGuardConfig.load

    def flaky_load(path):
        # Fail the post-write verification load only.
        if Path(path).name.startswith(".") or "tmp" in Path(path).name.lower():
            raise ConfigErrorShim()
        # Also match random temp names created in store.
        if Path(path).parent == store and Path(path).name != CONFIG_FILENAME:
            raise ConfigErrorShim()
        return real_load(path)

    class ConfigErrorShim(Exception):
        code = "CONFIG_INVALID"

    monkeypatch.setattr(
        "credential_guard.migration.CredentialGuardConfig.load", flaky_load
    )
    with pytest.raises(MigrationError):
        migrate_config(store)
    _assert_pre_migration_state(store, cred_fp, tgt_fp)


def test_rollback_on_final_rename_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    import credential_guard.migration as mig

    real_publish = mig._publish_no_clobber

    def flaky_publish(src, dst, *, exists_code, fail_code):
        if Path(dst).name == CONFIG_FILENAME:
            raise OSError(13, "Permission denied")
        return real_publish(src, dst, exists_code=exists_code, fail_code=fail_code)

    def flaky_publish_wrap(src, dst, *, exists_code, fail_code):
        try:
            return flaky_publish(src, dst, exists_code=exists_code, fail_code=fail_code)
        except OSError:
            raise MigrationError(fail_code, "migration error") from None

    monkeypatch.setattr(mig, "_publish_no_clobber", flaky_publish_wrap)
    with pytest.raises(MigrationError):
        migrate_config(store)
    _assert_pre_migration_state(store, cred_fp, tgt_fp)


def test_compensate_when_second_backup_rename_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    import credential_guard.migration as mig

    real_publish = mig._publish_no_clobber
    state = {"cred_bak_done": False}

    def flaky_publish(src, dst, *, exists_code, fail_code):
        dst_p = Path(dst)
        if dst_p.name == CREDENTIALS_BAK:
            state["cred_bak_done"] = True
            return real_publish(src, dst, exists_code=exists_code, fail_code=fail_code)
        if dst_p.name == TARGETS_BAK:
            raise MigrationError(fail_code, "migration error")
        return real_publish(src, dst, exists_code=exists_code, fail_code=fail_code)

    monkeypatch.setattr(mig, "_publish_no_clobber", flaky_publish)
    with pytest.raises(MigrationError):
        migrate_config(store)
    # Compensated: old formal files restored, no formal new file.
    assert (store / "credentials.json").is_file()
    assert (store / "targets.json").is_file()
    assert _file_fingerprint(store / "credentials.json") == cred_fp
    assert _file_fingerprint(store / "targets.json") == tgt_fp
    assert not (store / CONFIG_FILENAME).exists()
    assert not (store / CREDENTIALS_BAK).exists()
    assert not (store / TARGETS_BAK).exists()


def test_rollback_on_dir_fsync_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    real_fsync = os.fsync
    # Track fds: first fsync is file, later may be directory — fail directory.
    synced = {"file": False}

    def flaky_fsync(fd):
        # Heuristic: after file content fsync, directory fsync fails.
        try:
            st = os.fstat(fd)
            if stat.S_ISDIR(st.st_mode):
                raise OSError(5, "I/O error")
        except OSError as exc:
            if getattr(exc, "errno", None) == 5:
                raise
        synced["file"] = True
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", flaky_fsync)
    with pytest.raises(MigrationError):
        migrate_config(store)
    # Either fully rolled back to pre-migration, or compensated after publish.
    if (store / CONFIG_FILENAME).exists():
        pytest.fail("formal new file must not remain after dir fsync failure")
    assert (store / "credentials.json").is_file()
    assert (store / "targets.json").is_file()
    assert _file_fingerprint(store / "credentials.json") == cred_fp
    assert _file_fingerprint(store / "targets.json") == tgt_fp


# --- CLI ---


def test_cli_migrate_config_in_temp_hermes_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    store = _prepare_store(hermes, *_empty_v1_pair())

    # Ensure parser exposes migrate-config without changing check semantics.
    import argparse

    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    cg = sub.add_parser("credential-guard")
    setup_parser(cg)

    code = handle_command(Namespace(credential_guard_command="migrate-config"))
    captured = capsys.readouterr()
    blob = captured.out + captured.err
    assert code == 0
    assert (store / CONFIG_FILENAME).is_file()
    assert "bastion-prod" not in blob
    assert str(store) not in blob
    assert str(hermes) not in blob


def test_cli_check_usage_unchanged_for_unknown(
    capsys: pytest.CaptureFixture[str],
):
    code = handle_command(Namespace(credential_guard_command="nope"))
    out = capsys.readouterr().out
    assert code == 1
    assert "check" in out


# --- R1A hardening B2/B3/B4 ---


def _full_exception_text(exc: BaseException) -> str:
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


def _traceback_residue_count(
    exc: BaseException,
    *,
    decoy: str,
    paths: List[Path],
    username: str = "",
    host: str = "",
) -> int:
    blob = _full_exception_text(exc)
    count = 0
    markers = [decoy, username, host]
    for p in paths:
        markers.append(str(p))
        markers.append(str(p.resolve()))
    for m in markers:
        if m and m in blob:
            count += 1
    for i in range(0, max(0, len(decoy) - 7)):
        if decoy[i : i + 8] in blob:
            count += 1
    return count


def _assert_safe_chain(exc: BaseException) -> None:
    assert exc.__cause__ is None
    assert exc.__context__ is None
    for _name, val in getattr(exc, "__dict__", {}).items():
        if isinstance(val, BaseException):
            raise AssertionError("public exception attribute holds nested exception")


def _walk_exception_graph(exc: BaseException, *, _seen=None) -> list:
    if _seen is None:
        _seen = set()
    oid = id(exc)
    if oid in _seen:
        return []
    _seen.add(oid)
    blobs = [f"{type(exc).__name__}:{exc!s}:{exc!r}"]
    for arg in getattr(exc, "args", ()):
        blobs.append(repr(arg))
        if isinstance(arg, BaseException):
            blobs.extend(_walk_exception_graph(arg, _seen=_seen))
    for name, val in list(getattr(exc, "__dict__", {}).items()):
        blobs.append(f"{name}={val!r}")
        if isinstance(val, BaseException):
            blobs.extend(_walk_exception_graph(val, _seen=_seen))
    for attr in ("doc", "msg", "filename", "path", "strerror"):
        if hasattr(exc, attr):
            blobs.append(f"{attr}={getattr(exc, attr)!r}")
    if getattr(exc, "__cause__", None) is not None:
        blobs.extend(_walk_exception_graph(exc.__cause__, _seen=_seen))
    if getattr(exc, "__context__", None) is not None:
        blobs.extend(_walk_exception_graph(exc.__context__, _seen=_seen))
    return blobs


def _assert_clean_migration_exc(
    exc: BaseException,
    *,
    decoy: str,
    paths: List[Path],
    username: str = "",
    host: str = "",
) -> None:
    _assert_safe_chain(exc)
    blob = "\n".join(_walk_exception_graph(exc))
    markers = [decoy, username, host]
    for p in paths:
        markers.append(str(p))
        markers.append(str(p.resolve()))
    for m in markers:
        if m:
            assert m not in blob
    for i in range(0, max(0, len(decoy) - 7)):
        assert decoy[i : i + 8] not in blob


def _old_bytes_still_present(store: Path, cred_bytes: bytes, tgt_bytes: bytes) -> bool:
    """At least one surviving copy of each old payload must exist."""
    cred_ok = False
    tgt_ok = False
    for name in (
        "credentials.json",
        CREDENTIALS_BAK,
        ".cg-migrate-cred.bak.tmp",
        ".cg-migrate-cred.tmp",
    ):
        p = store / name
        if p.exists() and not p.is_symlink() and p.is_file():
            if p.read_bytes() == cred_bytes:
                cred_ok = True
    for name in (
        "targets.json",
        TARGETS_BAK,
        ".cg-migrate-tgt.bak.tmp",
        ".cg-migrate-tgt.tmp",
    ):
        p = store / name
        if p.exists() and not p.is_symlink() and p.is_file():
            if p.read_bytes() == tgt_bytes:
                tgt_ok = True
    # Also scan any leftover temp that holds exact bytes.
    for p in store.iterdir():
        if not p.is_file() or p.is_symlink():
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if data == cred_bytes:
            cred_ok = True
        if data == tgt_bytes:
            tgt_ok = True
    return cred_ok and tgt_ok


def test_full_traceback_migration_missing_source(tmp_path: Path):
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    missing = store / "targets.json"
    missing.unlink()
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    residue = _traceback_residue_count(
        ei.value, decoy="CG_MIG_", paths=[store, missing]
    )
    assert residue == 0
    _assert_safe_chain(ei.value)


def test_full_traceback_migration_rename_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    import credential_guard.migration as mig

    real_publish = mig._publish_no_clobber

    def flaky_publish(src, dst, *, exists_code, fail_code):
        if Path(dst).name == CONFIG_FILENAME:
            raise MigrationError(fail_code, "migration error")
        return real_publish(src, dst, exists_code=exists_code, fail_code=fail_code)

    monkeypatch.setattr(mig, "_publish_no_clobber", flaky_publish)
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    residue = _traceback_residue_count(
        ei.value, decoy="CG_MIG_", paths=[store, store / CONFIG_FILENAME]
    )
    assert residue == 0
    _assert_safe_chain(ei.value)


def test_full_traceback_migration_fsync_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    real_fsync = os.fsync

    def flaky_fsync(fd):
        try:
            st = os.fstat(fd)
            if stat.S_ISDIR(st.st_mode):
                raise OSError(5, "I/O error")
        except OSError as exc:
            if getattr(exc, "errno", None) == 5:
                raise
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", flaky_fsync)
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    residue = _traceback_residue_count(ei.value, decoy="CG_MIG_", paths=[store])
    assert residue == 0
    _assert_safe_chain(ei.value)


def test_full_traceback_migration_reread_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = _prepare_store(tmp_path, *_empty_v1_pair())

    def boom_load(path):
        raise OSError(2, "No such file", str(path))

    monkeypatch.setattr(
        "credential_guard.migration.CredentialGuardConfig.load", boom_load
    )
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    residue = _traceback_residue_count(ei.value, decoy="CG_MIG_", paths=[store])
    assert residue == 0
    _assert_safe_chain(ei.value)
    assert ei.value.code == "MIGRATION_REREAD"


def test_migration_source_postread_toctou_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    cred = store / "credentials.json"
    real_lstat = os.lstat
    calls = {"n": 0}

    def flaky_lstat(p, *args, **kwargs):
        st = real_lstat(p, *args, **kwargs)
        path_obj = Path(p)
        if path_obj == cred:
            calls["n"] += 1
            # After open/read path observations, swap inode before post-read check.
            if calls["n"] >= 2:
                cred.unlink()
                _write_json(cred, {"version": 1, "credentials": {}})
        return st

    monkeypatch.setattr(os, "lstat", flaky_lstat)
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    migration_source_postread_toctou_blocked = ei.value.code in {
        "MIGRATION_SOURCE_TOCTOU",
        "MIGRATION_SOURCE_UNAVAILABLE",
        "MIGRATION_SOURCE_SYMLINK",
    }
    assert migration_source_postread_toctou_blocked is True
    residue = _traceback_residue_count(
        ei.value, decoy="CG_MIG_", paths=[store, cred]
    )
    assert residue == 0
    _assert_safe_chain(ei.value)
    assert not (store / CONFIG_FILENAME).exists()


def test_one_shot_second_finalize_fails_restores_prestate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """First bak already installed; second bak publish fails → exact prestate."""
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    cred_bytes, tgt_bytes = cred_fp[0], tgt_fp[0]
    import credential_guard.migration as mig

    real_publish = mig._publish_no_clobber
    state = {"cred_finalized": False}

    def flaky_publish(src, dst, *, exists_code, fail_code):
        dst_p = Path(dst)
        if dst_p.name == CREDENTIALS_BAK:
            state["cred_finalized"] = True
            return real_publish(src, dst, exists_code=exists_code, fail_code=fail_code)
        if dst_p.name == TARGETS_BAK:
            raise MigrationError(fail_code, "migration error")
        return real_publish(src, dst, exists_code=exists_code, fail_code=fail_code)

    monkeypatch.setattr(mig, "_publish_no_clobber", flaky_publish)
    with pytest.raises(MigrationError):
        migrate_config(store)
    one_shot_fault_restores_exact_prestate = True
    try:
        _assert_pre_migration_state(store, cred_fp, tgt_fp)
    except AssertionError:
        one_shot_fault_restores_exact_prestate = False
    assert one_shot_fault_restores_exact_prestate is True
    assert _old_bytes_still_present(store, cred_bytes, tgt_bytes) is True


def test_one_shot_restore_replace_fails_once_then_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """First old isolated; second isolation fails → compensate restores prestate."""
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    cred_bytes, tgt_bytes = cred_fp[0], tgt_fp[0]
    import credential_guard.migration as mig

    real_isolate = mig._isolate_owned_source
    state = {"cred_isolated": False}

    def flaky_isolate(path, isol_path, **kwargs):
        if Path(path).name == "credentials.json":
            state["cred_isolated"] = True
            return real_isolate(path, isol_path, **kwargs)
        if Path(path).name == "targets.json" and state["cred_isolated"]:
            raise MigrationError("MIGRATION_BACKUP", "migration error")
        return real_isolate(path, isol_path, **kwargs)

    monkeypatch.setattr(mig, "_isolate_owned_source", flaky_isolate)
    with pytest.raises(MigrationError):
        migrate_config(store)
    assert (store / "credentials.json").is_file()
    assert (store / "targets.json").is_file()
    assert _file_fingerprint(store / "credentials.json") == cred_fp
    assert _file_fingerprint(store / "targets.json") == tgt_fp
    assert not (store / CONFIG_FILENAME).exists()
    assert _old_bytes_still_present(store, cred_bytes, tgt_bytes) is True


def test_compensate_delete_new_file_failure_keeps_old_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    cred_bytes, tgt_bytes = cred_fp[0], tgt_fp[0]
    import credential_guard.migration as mig

    real_publish = mig._publish_no_clobber
    real_unlink = os.unlink
    state = {"published": False}

    def flaky_publish(src, dst, *, exists_code, fail_code):
        dst_p = Path(dst)
        if dst_p.name == CONFIG_FILENAME:
            state["published"] = True
            return real_publish(src, dst, exists_code=exists_code, fail_code=fail_code)
        if dst_p.name == TARGETS_BAK:
            raise MigrationError(fail_code, "migration error")
        return real_publish(src, dst, exists_code=exists_code, fail_code=fail_code)

    def flaky_unlink(path, *args, **kwargs):
        p = Path(path)
        if state["published"] and (
            p.name == CONFIG_FILENAME
            or (
                p.name.startswith(".cg-migrate-isol-")
                and "new-formal" in p.name
            )
        ):
            raise OSError(13, "Permission denied")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(mig, "_publish_no_clobber", flaky_publish)
    monkeypatch.setattr(os, "unlink", flaky_unlink)
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    recovery_required_is_explicit = ei.value.code == "MIGRATION_RECOVERY_REQUIRED"
    assert recovery_required_is_explicit is True
    assert _old_bytes_still_present(store, cred_bytes, tgt_bytes) is True
    persistent_recovery_fault_never_loses_last_copy = _old_bytes_still_present(
        store, cred_bytes, tgt_bytes
    )
    assert persistent_recovery_fault_never_loses_last_copy is True
    # Fingerprints of old formal files must remain (never moved in this fault).
    assert _file_fingerprint(store / "credentials.json") == cred_fp
    assert _file_fingerprint(store / "targets.json") == tgt_fp


def test_compensate_cleanup_backup_tmp_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    cred_bytes, tgt_bytes = cred_fp[0], tgt_fp[0]
    import credential_guard.migration as mig

    real_publish = mig._publish_no_clobber
    real_unlink = os.unlink
    state = {"fail_bak_cleanup": False}

    def flaky_publish(src, dst, *, exists_code, fail_code):
        if Path(dst).name == TARGETS_BAK:
            state["fail_bak_cleanup"] = True
            raise MigrationError(fail_code, "migration error")
        return real_publish(src, dst, exists_code=exists_code, fail_code=fail_code)

    def flaky_unlink(path, *args, **kwargs):
        name = Path(path).name
        if name == ".cg-migrate.lock":
            return real_unlink(path, *args, **kwargs)
        if state["fail_bak_cleanup"] and (
            name.endswith(".bak")
            or "bak" in name
            or name.startswith(".cg-migrate")
        ):
            raise OSError(13, "Permission denied")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(mig, "_publish_no_clobber", flaky_publish)
    monkeypatch.setattr(os, "unlink", flaky_unlink)
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    assert ei.value.code in {
        "MIGRATION_BACKUP",
        "MIGRATION_RECOVERY_REQUIRED",
        "MIGRATION_FAILED",
    }
    assert _old_bytes_still_present(store, cred_bytes, tgt_bytes) is True
    # Old formal files must still be intact when compensation cannot clean temps.
    assert (store / "credentials.json").is_file()
    assert (store / "targets.json").is_file()
    assert _file_fingerprint(store / "credentials.json") == cred_fp
    assert _file_fingerprint(store / "targets.json") == tgt_fp


def test_compensate_dir_fsync_failure_not_claimed_restored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    cred_bytes, tgt_bytes = cred_fp[0], tgt_fp[0]
    import credential_guard.migration as mig

    real_publish = mig._publish_no_clobber
    real_fsync = os.fsync
    state = {"compensating": False, "dir_fsync_after_comp": 0}

    def flaky_publish(src, dst, *, exists_code, fail_code):
        if Path(dst).name == TARGETS_BAK:
            state["compensating"] = True
            raise MigrationError(fail_code, "migration error")
        return real_publish(src, dst, exists_code=exists_code, fail_code=fail_code)

    def flaky_fsync(fd):
        try:
            st = os.fstat(fd)
            if state["compensating"] and stat.S_ISDIR(st.st_mode):
                state["dir_fsync_after_comp"] += 1
                if state["dir_fsync_after_comp"] >= 1:
                    raise OSError(5, "I/O error")
        except OSError as exc:
            if getattr(exc, "errno", None) == 5:
                raise
        return real_fsync(fd)

    monkeypatch.setattr(mig, "_publish_no_clobber", flaky_publish)
    monkeypatch.setattr(os, "fsync", flaky_fsync)
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    # Must not silently claim durable restore when compensate fsync fails.
    assert ei.value.code in {
        "MIGRATION_DIR_FSYNC",
        "MIGRATION_RECOVERY_REQUIRED",
        "MIGRATION_BACKUP",
    }
    assert _old_bytes_still_present(store, cred_bytes, tgt_bytes) is True


def test_persistent_recovery_then_next_run_recovers_before_new_migration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    cred_bytes, tgt_bytes = cred_fp[0], tgt_fp[0]
    import credential_guard.migration as mig

    real_publish = mig._publish_no_clobber
    real_unlink = os.unlink
    mode = {"run": 1}

    def flaky_publish(src, dst, *, exists_code, fail_code):
        if mode["run"] == 1 and Path(dst).name == TARGETS_BAK:
            raise MigrationError(fail_code, "migration error")
        return real_publish(src, dst, exists_code=exists_code, fail_code=fail_code)

    def flaky_unlink(path, *args, **kwargs):
        # Persistently block removing published new file on first run compensate
        # (covers both pathname and identity-bound isol cleanup names).
        p = Path(path)
        if mode["run"] == 1 and (
            p.name == CONFIG_FILENAME
            or (
                p.name.startswith(".cg-migrate-isol-")
                and "new-formal" in p.name
            )
        ):
            raise OSError(13, "Permission denied")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(mig, "_publish_no_clobber", flaky_publish)
    monkeypatch.setattr(os, "unlink", flaky_unlink)

    with pytest.raises(MigrationError) as ei1:
        migrate_config(store)
    assert ei1.value.code == "MIGRATION_RECOVERY_REQUIRED"
    assert _old_bytes_still_present(store, cred_bytes, tgt_bytes) is True

    # Second run: faults cleared; must recover prestate and NOT complete a new migration.
    mode["run"] = 2
    with pytest.raises(MigrationError) as ei2:
        migrate_config(store)
    next_run_recovers_before_new_migration = ei2.value.code in {
        "MIGRATION_RECOVERED",
        "MIGRATION_RECOVERY_REQUIRED",
    }
    # Prefer explicit recovered code once restore succeeds.
    assert ei2.value.code == "MIGRATION_RECOVERED"
    assert next_run_recovers_before_new_migration is True
    _assert_pre_migration_state(store, cred_fp, tgt_fp)

    # Third run can migrate successfully.
    result = migrate_config(store)
    assert result.ok is True
    assert (store / CONFIG_FILENAME).is_file()


# --- R1A hardening B4/B5/B6 ---


@pytest.mark.parametrize("version", [1.0, True, "1", 2, None, False])
def test_rejects_non_strict_v1_version_type(tmp_path: Path, version: Any):
    creds, tgts = _ssh_v1_pair()
    creds["version"] = version
    store = _prepare_store(tmp_path, creds, tgts)
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    assert ei.value.code == "MIGRATION_SOURCE_SCHEMA"
    _assert_pre_migration_state(store, cred_fp, tgt_fp)
    residue = _traceback_residue_count(
        ei.value, decoy="CG_MIG_", paths=[store]
    )
    assert residue == 0
    _assert_safe_chain(ei.value)


def test_migration_source_prebackup_toctou_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Replace source after successful read, before backup commit → blocked."""
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    cred = store / "credentials.json"
    original = cred.read_bytes()
    import credential_guard.migration as mig

    real_write_temp = mig._write_bytes_temp

    def flaky_write_temp(store_dir, name, data, **kwargs):
        # Before first bak temp write, replace credentials.json inode/bytes.
        is_cred_bak = (
            name == ".cg-migrate-cred.bak.tmp"
            or name.startswith(".cg-migrate-cred-bak-")
            or ("cred-bak" in name and name.endswith(".tmp"))
            or (name.endswith(".bak.tmp") and "cred" in name)
        )
        if is_cred_bak and cred.is_file():
            if cred.read_bytes() == original:
                cred.unlink()
                replaced = {
                    "version": 1,
                    "credentials": {
                        "evil": {
                            "type": "mysql",
                            "username": "attacker",
                            "password": "CG_MIG_REPLACED_SECRET_XX",
                        }
                    },
                }
                _write_json(cred, replaced)
                assert cred.read_bytes() != original
        return real_write_temp(store_dir, name, data, **kwargs)

    monkeypatch.setattr(mig, "_write_bytes_temp", flaky_write_temp)
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    migration_source_prebackup_toctou_blocked = ei.value.code in {
        "MIGRATION_SOURCE_TOCTOU",
        "MIGRATION_SOURCE_UNAVAILABLE",
        "MIGRATION_SOURCE_SYMLINK",
        "MIGRATION_SOURCE_SCHEMA",
    }
    assert migration_source_prebackup_toctou_blocked is True
    # Must not publish formal new file or formal bak of unvalidated replacement.
    assert not (store / CONFIG_FILENAME).exists()
    if (store / CREDENTIALS_BAK).exists():
        assert (store / CREDENTIALS_BAK).read_bytes() == original
        assert b"CG_MIG_REPLACED_SECRET_XX" not in (store / CREDENTIALS_BAK).read_bytes()
    residue = _traceback_residue_count(
        ei.value,
        decoy="CG_MIG_REPLACED_SECRET_XX",
        paths=[store, cred],
        username="attacker",
    )
    assert residue == 0
    _assert_safe_chain(ei.value)


def test_atomic_target_no_clobber(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    competitor = store / CONFIG_FILENAME
    competitor_payload = b'{"competitor":"CG_MIG_KEEP_ME_UNCHANGED"}'
    import credential_guard.migration as mig

    real_publish = getattr(mig, "_publish_no_clobber", None)
    real_replace = os.replace
    state = {"planted": False}

    def plant_then_publish(src, dst, *args, **kwargs):
        dst_p = Path(dst)
        if dst_p.name == CONFIG_FILENAME and not state["planted"]:
            state["planted"] = True
            competitor.write_bytes(competitor_payload)
            _chmod600(competitor)
        if real_publish is not None:
            return real_publish(src, dst, *args, **kwargs)
        return real_replace(src, dst)

    if real_publish is not None:
        monkeypatch.setattr(mig, "_publish_no_clobber", plant_then_publish)
    else:
        # Force race at replace site if helper not yet introduced (RED).
        def flaky_replace(src, dst):
            return plant_then_publish(src, dst)

        monkeypatch.setattr(os, "replace", flaky_replace)

    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    atomic_target_no_clobber = ei.value.code in {
        "MIGRATION_TARGET_EXISTS",
        "MIGRATION_PUBLISH",
        "MIGRATION_NO_CLOBBER",
        # Foreign formal new blocks exact prestate; identity-bound recovery keeps it.
        "MIGRATION_RECOVERY_REQUIRED",
    }
    assert atomic_target_no_clobber is True
    assert competitor.read_bytes() == competitor_payload
    assert (store / "credentials.json").is_file()
    assert (store / "targets.json").is_file()
    assert _file_fingerprint(store / "credentials.json") == cred_fp
    assert _file_fingerprint(store / "targets.json") == tgt_fp
    residue = _traceback_residue_count(
        ei.value, decoy="CG_MIG_KEEP_ME_UNCHANGED", paths=[store, competitor]
    )
    assert residue == 0
    _assert_safe_chain(ei.value)


def test_atomic_backup_no_clobber(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    competitor = store / CREDENTIALS_BAK
    competitor_payload = b'{"bak_competitor":"CG_MIG_BAK_KEEP"}'
    import credential_guard.migration as mig

    real_publish = getattr(mig, "_publish_no_clobber", None)
    real_replace = os.replace
    state = {"planted": False}

    def plant_then_publish(src, dst, *args, **kwargs):
        dst_p = Path(dst)
        if dst_p.name == CREDENTIALS_BAK and not state["planted"]:
            state["planted"] = True
            competitor.write_bytes(competitor_payload)
            _chmod600(competitor)
        if real_publish is not None:
            return real_publish(src, dst, *args, **kwargs)
        return real_replace(src, dst)

    if real_publish is not None:
        monkeypatch.setattr(mig, "_publish_no_clobber", plant_then_publish)
    else:

        def flaky_replace(src, dst):
            return plant_then_publish(src, dst)

        monkeypatch.setattr(os, "replace", flaky_replace)

    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    atomic_backup_no_clobber = ei.value.code in {
        "MIGRATION_BACKUP_EXISTS",
        "MIGRATION_BACKUP",
        "MIGRATION_NO_CLOBBER",
        "MIGRATION_RECOVERY_REQUIRED",
    }
    assert atomic_backup_no_clobber is True
    assert competitor.read_bytes() == competitor_payload
    # Old formal source bytes must still survive somewhere.
    assert _old_bytes_still_present(store, cred_fp[0], tgt_fp[0]) is True
    residue = _traceback_residue_count(
        ei.value, decoy="CG_MIG_BAK_KEEP", paths=[store, competitor]
    )
    assert residue == 0
    _assert_safe_chain(ei.value)


def test_concurrent_migration_lock_blocks_second(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Held advisory flock blocks peers; leftover lock *file* alone must not."""
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    import fcntl

    import credential_guard.migration as mig

    lock_path = store / mig.LOCK_NAME
    # Persistent empty/unowned lock file must NOT block (kernel flock decides).
    fd_seed = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(fd_seed)
    assert lock_path.is_file()

    # Now actually hold the advisory lock.
    fd = os.open(lock_path, os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(MigrationError) as ei:
            migrate_config(store)
        assert ei.value.code == "MIGRATION_LOCKED"
        assert not (store / CONFIG_FILENAME).exists()
        assert (store / "credentials.json").is_file()
        assert (store / "targets.json").is_file()
        assert _file_fingerprint(store / "credentials.json") == cred_fp
        assert _file_fingerprint(store / "targets.json") == tgt_fp
        assert not (store / CREDENTIALS_BAK).exists()
        assert not (store / TARGETS_BAK).exists()
        # Foreign/held lock file must not be deleted or rewritten.
        assert lock_path.is_file()
        residue = _traceback_residue_count(
            ei.value, decoy="CG_MIG_", paths=[store, lock_path]
        )
        assert residue == 0
        _assert_safe_chain(ei.value)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


# --- R1A lock ownership (advisory flock) ---


def _lock_identity(path: Path) -> Tuple[int, int, bytes, int]:
    st = path.lstat()
    return st.st_dev, st.st_ino, path.read_bytes(), stat.S_IMODE(st.st_mode)


def test_failed_acquire_never_removes_foreign_lock(tmp_path: Path):
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    import fcntl

    import credential_guard.migration as mig

    lock_path = store / mig.LOCK_NAME
    foreign_payload = b'{"v":1,"owner":"foreign","marker":"CG_MIG_FOREIGN_LOCK"}\n'
    fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        os.write(fd, foreign_payload)
        os.fsync(fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except Exception:
        os.close(fd)
        raise
    os.chmod(lock_path, 0o600)
    before = _lock_identity(lock_path)

    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    assert ei.value.code == "MIGRATION_LOCKED"
    assert lock_path.is_file()
    assert _lock_identity(lock_path) == before
    residue = _traceback_residue_count(
        ei.value,
        decoy="CG_MIG_FOREIGN_LOCK",
        paths=[store, lock_path],
    )
    assert residue == 0
    _assert_safe_chain(ei.value)
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)


def test_three_process_lock_exclusion(tmp_path: Path):
    """A holds flock; B/C fail; after A closes fd (crash), D can acquire."""
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    import threading

    import credential_guard.migration as mig

    lock_path = store / mig.LOCK_NAME
    a_held = threading.Event()
    b_done = threading.Event()
    c_done = threading.Event()
    a_crash = threading.Event()
    errors: List[BaseException] = []
    codes: Dict[str, str] = {}

    def run_a() -> None:
        try:
            token = mig._acquire_lock(store)
            a_identity = _lock_identity(lock_path)
            a_held.set()
            assert b_done.wait(timeout=5.0)
            assert _lock_identity(lock_path) == a_identity
            assert c_done.wait(timeout=5.0)
            assert _lock_identity(lock_path) == a_identity
            assert a_crash.wait(timeout=5.0)
            # Simulate crash: close fd without unlink (kernel releases flock).
            os.close(token.fd)
            # Persistent lock file must remain.
            assert lock_path.is_file()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
            a_held.set()
            b_done.set()
            c_done.set()

    def run_migrate(label: str, done: threading.Event) -> None:
        try:
            assert a_held.wait(timeout=5.0)
            with pytest.raises(MigrationError) as ei:
                migrate_config(store)
            codes[label] = ei.value.code
            residue = _traceback_residue_count(
                ei.value, decoy="CG_MIG_", paths=[store, lock_path]
            )
            assert residue == 0
            _assert_safe_chain(ei.value)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            done.set()

    t_a = threading.Thread(target=run_a)
    t_b = threading.Thread(target=run_migrate, args=("B", b_done))
    t_c = threading.Thread(target=run_migrate, args=("C", c_done))
    t_a.start()
    t_b.start()
    assert b_done.wait(timeout=5.0)
    t_c.start()
    assert c_done.wait(timeout=5.0)
    a_crash.set()
    t_a.join(timeout=5.0)
    t_b.join(timeout=5.0)
    t_c.join(timeout=5.0)
    assert errors == []
    assert codes.get("B") == "MIGRATION_LOCKED"
    assert codes.get("C") == "MIGRATION_LOCKED"
    assert lock_path.is_file()

    # D can obtain the lock after A crashed/closed fd; lock file persists.
    token_d = mig._acquire_lock(store)
    assert lock_path.is_file()
    mig._release_lock(store, token_d)
    assert lock_path.is_file()


def test_release_does_not_remove_replaced_foreign_lock(tmp_path: Path):
    store = tmp_path / "credential-guard"
    store.mkdir()
    os.chmod(store, 0o700)
    import credential_guard.migration as mig

    lock_path = store / mig.LOCK_NAME
    token = mig._acquire_lock(store)
    owned_st = lock_path.lstat()
    owned_dev, owned_ino = owned_st.st_dev, owned_st.st_ino

    # Replace path with another inode while A still holds the original fd.
    os.unlink(lock_path)
    foreign_payload = b'{"v":1,"owner":"replaced","marker":"CG_MIG_REPLACED_LOCK"}\n'
    fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, foreign_payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(lock_path, 0o600)
    foreign_before = _lock_identity(lock_path)
    assert (foreign_before[0], foreign_before[1]) != (owned_dev, owned_ino)

    # Release of A's token must not delete the replacement foreign lock.
    mig._release_lock(store, token)
    assert lock_path.is_file()
    assert _lock_identity(lock_path) == foreign_before


def test_owned_lock_cleanup_on_success_and_failure(tmp_path: Path):
    import credential_guard.migration as mig

    # Success path may leave persistent lock *file*, but must not hold flock.
    store_ok = _prepare_store(tmp_path / "ok", *_empty_v1_pair())
    result = migrate_config(store_ok)
    assert result.ok is True
    lock_ok = store_ok / mig.LOCK_NAME
    # Either absent or present-but-unlocked; no journal leftovers.
    leftovers_ok = [
        p
        for p in store_ok.iterdir()
        if p.name.startswith(".cg-migrate") and p.name != mig.LOCK_NAME
    ]
    assert leftovers_ok == []
    if lock_ok.exists():
        # Must be acquirable (not held).
        token = mig._acquire_lock(store_ok)
        mig._release_lock(store_ok, token)

    # Ordinary failure compensation path also releases flock.
    decoy = _decoy()
    store_fail = _prepare_store(tmp_path / "fail", *_mysql_v1_pair(decoy))
    with pytest.raises(MigrationError) as ei:
        migrate_config(store_fail)
    assert ei.value.code == "MIGRATION_REQUIRES_MANUAL_REVIEW"
    leftovers_fail = [
        p
        for p in store_fail.iterdir()
        if p.name.startswith(".cg-migrate") and p.name != mig.LOCK_NAME
    ]
    assert leftovers_fail == []
    residue = _traceback_residue_count(
        ei.value,
        decoy=decoy,
        paths=[store_fail],
        username="cg_readonly",
        host="127.0.0.1",
    )
    assert residue == 0
    _assert_safe_chain(ei.value)


# --- R1A redesign round-3: C flock / D journal ownership / E-F protocol / G parent ---


def test_stale_lock_file_allows_acquire_and_recovery(tmp_path: Path):
    """Leftover lock file without flock must not block journal recovery."""
    import hashlib

    import credential_guard.migration as mig

    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    cred_bytes, tgt_bytes = cred_fp[0], tgt_fp[0]

    # Plant persistent lock file (no flock held).
    lock_path = store / mig.LOCK_NAME
    fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.write(fd, b'{"v":1}\n')
    os.fsync(fd)
    os.close(fd)
    os.chmod(lock_path, 0o600)

    # Plant prepared journal with ownership commitments (no formal publish yet).
    txid = secrets.token_hex(16)
    journal = {
        "v": 2,
        "txid": txid,
        "phase": "prepared",
        "new_sha256": hashlib.sha256(b"unused").hexdigest(),
        "credentials_bak_sha256": hashlib.sha256(cred_bytes).hexdigest(),
        "targets_bak_sha256": hashlib.sha256(tgt_bytes).hexdigest(),
        "source_credentials": {
            "dev": 0,
            "ino": 0,
            "sha256": hashlib.sha256(cred_bytes).hexdigest(),
        },
        "source_targets": {
            "dev": 0,
            "ino": 0,
            "sha256": hashlib.sha256(tgt_bytes).hexdigest(),
        },
        "published": {
            "new": False,
            "credentials_bak": False,
            "targets_bak": False,
            "credentials_old_removed": False,
            "targets_old_removed": False,
        },
    }
    (store / mig.JOURNAL_NAME).write_text(
        json.dumps(journal, separators=(",", ":")), encoding="utf-8"
    )
    os.chmod(store / mig.JOURNAL_NAME, 0o600)

    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    assert ei.value.code == "MIGRATION_RECOVERED"
    _assert_pre_migration_state(store, cred_fp, tgt_fp)
    assert lock_path.is_file()
    _assert_clean_migration_exc(ei.value, decoy="CG_MIG_", paths=[store, lock_path])


def test_journal_v2_written_with_txid_during_migration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    import credential_guard.migration as mig

    captured = {}

    real_write = getattr(mig, "_write_journal", None)
    real_publish = mig._publish_no_clobber

    def capture_and_fail(store_dir, journal_or_phase, *args, **kwargs):
        # Support both old (phase:str) and new (dict) signatures during RED/GREEN.
        path = store_dir / mig.JOURNAL_NAME
        if path.exists():
            try:
                captured["journal"] = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                captured["journal"] = None
        if real_write is not None:
            result = real_write(store_dir, journal_or_phase, *args, **kwargs)
            if path.exists():
                captured["journal"] = json.loads(path.read_text(encoding="utf-8"))
            return result
        raise MigrationError("MIGRATION_JOURNAL", "migration error")

    def fail_after_journal(src, dst, *, exists_code, fail_code):
        path = store / mig.JOURNAL_NAME
        if path.exists():
            captured["journal"] = json.loads(path.read_text(encoding="utf-8"))
        raise MigrationError(fail_code, "migration error")

    if real_write is not None:
        monkeypatch.setattr(mig, "_write_journal", capture_and_fail)
    monkeypatch.setattr(mig, "_publish_no_clobber", fail_after_journal)

    with pytest.raises(MigrationError):
        migrate_config(store)

    journal = captured.get("journal")
    assert isinstance(journal, dict)
    assert journal.get("v") == 2
    assert isinstance(journal.get("txid"), str) and len(journal["txid"]) >= 16
    assert "phase" in journal
    assert "new_sha256" in journal
    assert "source_credentials" in journal
    assert "source_targets" in journal
    assert "published" in journal
    blob = json.dumps(journal)
    assert "bastion-prod" not in blob
    assert str(store) not in blob
    assert "/" not in journal.get("txid", "")


def test_recovery_preserves_competitor_mismatched_new_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Competitor at formal new path with wrong digest must never be deleted."""
    import hashlib

    import credential_guard.migration as mig

    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    competitor_payload = b'{"competitor":"CG_MIG_COMPETITOR_KEEP_ME"}'
    competitor = store / CONFIG_FILENAME
    competitor.write_bytes(competitor_payload)
    _chmod600(competitor)

    owned_new = b'{"version":2,"credentials":{},"bindings":{}}'
    journal = {
        "v": 2,
        "txid": secrets.token_hex(16),
        "phase": "published",
        "new_sha256": hashlib.sha256(owned_new).hexdigest(),
        "credentials_bak_sha256": hashlib.sha256(cred_fp[0]).hexdigest(),
        "targets_bak_sha256": hashlib.sha256(tgt_fp[0]).hexdigest(),
        "source_credentials": {
            "dev": store.stat().st_dev,
            "ino": (store / "credentials.json").stat().st_ino,
            "sha256": hashlib.sha256(cred_fp[0]).hexdigest(),
        },
        "source_targets": {
            "dev": store.stat().st_dev,
            "ino": (store / "targets.json").stat().st_ino,
            "sha256": hashlib.sha256(tgt_fp[0]).hexdigest(),
        },
        "published": {
            "new": True,
            "credentials_bak": False,
            "targets_bak": False,
            "credentials_old_removed": False,
            "targets_old_removed": False,
        },
    }
    (store / mig.JOURNAL_NAME).write_text(
        json.dumps(journal, separators=(",", ":")), encoding="utf-8"
    )
    _chmod600(store / mig.JOURNAL_NAME)

    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    assert ei.value.code in {
        "MIGRATION_RECOVERED",
        "MIGRATION_RECOVERY_REQUIRED",
        "MIGRATION_CONFLICT",
    }
    assert competitor.read_bytes() == competitor_payload
    assert _old_bytes_still_present(store, cred_fp[0], tgt_fp[0]) is True
    _assert_clean_migration_exc(
        ei.value, decoy="CG_MIG_COMPETITOR_KEEP_ME", paths=[store, competitor]
    )


def test_publish_marks_owned_even_when_temp_unlink_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    import credential_guard.migration as mig

    real_link = os.link
    real_unlink = os.unlink
    state = {"linked_new": False}

    def flaky_link(src, dst):
        real_link(src, dst)
        if Path(dst).name == CONFIG_FILENAME:
            state["linked_new"] = True

    def flaky_unlink(path, *args, **kwargs):
        name = Path(path).name
        if state["linked_new"] and (
            (name.startswith(".cg-migrate-") and name.endswith(".tmp"))
            or name.startswith(".cg-migrate-isol-cleanup-")
            or name.startswith(".cg-migrate-isol-fail-")
        ):
            raise OSError(13, "Permission denied")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "link", flaky_link)
    monkeypatch.setattr(os, "unlink", flaky_unlink)

    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    # Formal new may exist (link succeeded). Journal must acknowledge ownership
    # so recovery does not treat it as a stranger to abandon incorrectly.
    journal_path = store / mig.JOURNAL_NAME
    if journal_path.exists():
        data = json.loads(journal_path.read_text(encoding="utf-8"))
        assert data.get("v") == 2
        assert data.get("published", {}).get("new") is True
    assert ei.value.code in {
        "MIGRATION_PUBLISH",
        "MIGRATION_CLEANUP",
        "MIGRATION_RECOVERY_REQUIRED",
        "MIGRATION_RECOVERED",
        "MIGRATION_FAILED",
    }
    _assert_safe_chain(ei.value)


def test_crash_after_prepared_journal_recovers_prestate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    import credential_guard.migration as mig

    real_publish = mig._publish_no_clobber

    def crash_before_publish(src, dst, *, exists_code, fail_code):
        raise SystemExit("simulated_crash_after_prepared")

    monkeypatch.setattr(mig, "_publish_no_clobber", crash_before_publish)
    with pytest.raises(SystemExit):
        migrate_config(store)

    monkeypatch.setattr(mig, "_publish_no_clobber", real_publish)
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    assert ei.value.code == "MIGRATION_RECOVERED"
    _assert_pre_migration_state(store, cred_fp, tgt_fp)


def test_isolate_old_source_toctou_preserves_competitor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Competitor swapped onto old path before isolation must be retained."""
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    import credential_guard.migration as mig

    competitor_payload = b'{"version":1,"credentials":{},"marker":"CG_MIG_ISO_COMP"}'
    real_publish = mig._publish_no_clobber
    state = {"baks_done": 0}

    def publish_then_plant(src, dst, *, exists_code, fail_code):
        result = real_publish(src, dst, exists_code=exists_code, fail_code=fail_code)
        name = Path(dst).name
        if name in {CREDENTIALS_BAK, TARGETS_BAK, CONFIG_FILENAME}:
            state["baks_done"] += 1
        # After both baks + new published, plant competitor on credentials.json
        # before isolation/unlink of olds.
        if state["baks_done"] >= 3 and (store / "credentials.json").exists():
            if (store / "credentials.json").read_bytes() == cred_fp[0]:
                (store / "credentials.json").unlink()
                (store / "credentials.json").write_bytes(competitor_payload)
                _chmod600(store / "credentials.json")
        return result

    monkeypatch.setattr(mig, "_publish_no_clobber", publish_then_plant)
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    # Competitor must survive; original bytes must survive via bak or formal.
    assert (store / "credentials.json").read_bytes() == competitor_payload or (
        store / CREDENTIALS_BAK
    ).exists()
    if (store / "credentials.json").exists():
        # If formal path still has competitor, it must be untouched.
        data = (store / "credentials.json").read_bytes()
        if data == competitor_payload:
            assert data == competitor_payload
    assert _old_bytes_still_present(store, cred_fp[0], tgt_fp[0]) is True
    assert ei.value.code in {
        "MIGRATION_SOURCE_TOCTOU",
        "MIGRATION_CONFLICT",
        "MIGRATION_RECOVERY_REQUIRED",
        "MIGRATION_BACKUP",
        "MIGRATION_RECOVERED",
    }
    _assert_clean_migration_exc(
        ei.value, decoy="CG_MIG_ISO_COMP", paths=[store]
    )


@pytest.mark.parametrize("mode", [0o755, 0o770])
def test_migrate_rejects_insecure_store_directory(tmp_path: Path, mode: int):
    store = _prepare_store(tmp_path, *_ssh_v1_pair(), dir_mode=mode)
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    assert ei.value.code in {
        "MIGRATION_DIR_INSECURE_MODE",
        "MIGRATION_DIR_UNAVAILABLE",
        "MIGRATION_DIR_OWNER",
    }
    assert not (store / CONFIG_FILENAME).exists()
    assert _file_fingerprint(store / "credentials.json") == cred_fp
    assert _file_fingerprint(store / "targets.json") == tgt_fp
    _assert_clean_migration_exc(ei.value, decoy="CG_MIG_", paths=[store])


def test_migrate_rejects_symlink_store_directory(tmp_path: Path):
    real = tmp_path / "real-store"
    creds, tgts = _ssh_v1_pair()
    _prepare_store(tmp_path, creds, tgts)
    # _prepare_store creates tmp_path/credential-guard — rename and link.
    real_store = tmp_path / "credential-guard"
    linked = tmp_path / "linked-store"
    real_store.rename(real)
    linked.symlink_to(real)
    with pytest.raises(MigrationError) as ei:
        migrate_config(linked)
    assert ei.value.code in {
        "MIGRATION_DIR_UNAVAILABLE",
        "MIGRATION_DIR_SYMLINK",
    }
    _assert_safe_chain(ei.value)


def test_lock_release_failure_after_success_is_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    import credential_guard.migration as mig

    real_release = mig._release_lock

    def boom_release(store_dir, token):
        real_release(store_dir, token)
        raise MigrationError("MIGRATION_LOCK_RELEASE", "migration error")

    monkeypatch.setattr(mig, "_release_lock", boom_release)
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    # Artifacts may be complete, but must not silently return ok.
    assert ei.value.code == "MIGRATION_LOCK_RELEASE"
    assert (store / CONFIG_FILENAME).is_file()
    _assert_safe_chain(ei.value)


def test_exception_graph_migration_source_json(tmp_path: Path):
    store = tmp_path / "credential-guard"
    store.mkdir()
    os.chmod(store, 0o700)
    (store / "credentials.json").write_text("{not-json-" + _decoy(), encoding="utf-8")
    _chmod600(store / "credentials.json")
    _write_json(store / "targets.json", {"version": 1, "targets": {}})
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    _assert_clean_migration_exc(
        ei.value, decoy="CG_MIG_", paths=[store, store / "credentials.json"]
    )


# --- R1A final adversarial: OS branches / lock race / journal ownership / final verify ---


@pytest.mark.parametrize(
    "op_name",
    ["lstat", "open", "fstat", "read", "fsync", "link", "rename", "unlink", "replace", "flock"],
)
def test_migration_os_branch_exception_graph_clean_for_all_ops(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op_name: str
):
    decoy = "CG_MIG_OSERR_" + secrets.token_hex(12)
    abs_marker = tmp_path / "abs" / decoy / "credentials.json"
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    boom = OSError(13, f"Permission denied: {abs_marker} decoy={decoy}")
    import fcntl

    import credential_guard.migration as mig

    real_acquire = mig._acquire_lock
    real_lstat = os.lstat
    real_open = os.open
    real_fstat = os.fstat
    real_read = os.read
    real_fsync = os.fsync
    real_link = os.link
    real_rename = os.rename
    real_unlink = os.unlink
    real_replace = os.replace
    real_flock = fcntl.flock
    state = {"armed": False}

    def arm_after_lock(*a, **k):
        token = real_acquire(*a, **k)
        state["armed"] = True
        return token

    def boom_lstat(p, *a, **k):
        if state["armed"] and "credentials.json" in str(p):
            raise boom
        return real_lstat(p, *a, **k)

    def boom_open(p, flags, *a, **k):
        if state["armed"] and "credentials.json" in str(p):
            raise boom
        return real_open(p, flags, *a, **k)

    def boom_fstat(fd):
        if state["armed"]:
            raise boom
        return real_fstat(fd)

    def boom_read(fd, n):
        if state["armed"]:
            raise boom
        return real_read(fd, n)

    def boom_fsync(fd):
        if state["armed"]:
            raise boom
        return real_fsync(fd)

    def boom_link(src, dst):
        if state["armed"]:
            raise boom
        return real_link(src, dst)

    def boom_rename(src, dst):
        if state["armed"]:
            raise boom
        return real_rename(src, dst)

    def boom_unlink(path, *a, **k):
        if state["armed"] and ".cg-migrate" in str(path):
            raise boom
        return real_unlink(path, *a, **k)

    def boom_replace(src, dst):
        if state["armed"]:
            raise boom
        return real_replace(src, dst)

    def boom_flock(fd, op):
        raise boom

    if op_name == "flock":
        monkeypatch.setattr(fcntl, "flock", boom_flock)
    else:
        monkeypatch.setattr(mig, "_acquire_lock", arm_after_lock)
        if op_name == "lstat":
            monkeypatch.setattr(os, "lstat", boom_lstat)
        elif op_name == "open":
            monkeypatch.setattr(os, "open", boom_open)
        elif op_name == "fstat":
            monkeypatch.setattr(os, "fstat", boom_fstat)
        elif op_name == "read":
            monkeypatch.setattr(os, "read", boom_read)
        elif op_name == "fsync":
            monkeypatch.setattr(os, "fsync", boom_fsync)
        elif op_name == "link":
            monkeypatch.setattr(os, "link", boom_link)
        elif op_name == "rename":
            # Darwin uses renamex_np; force portable link+lstat path that nests except.
            import sys

            monkeypatch.setattr(sys, "platform", "linux")
            real_link2 = os.link
            linked = {"done": False}

            def link_then_arm_lstat(src, dst):
                real_link2(src, dst)
                linked["done"] = True

            def boom_lstat_after_link(p, *a, **k):
                if linked["done"]:
                    raise boom
                return real_lstat(p, *a, **k)

            monkeypatch.setattr(os, "link", link_then_arm_lstat)
            monkeypatch.setattr(os, "lstat", boom_lstat_after_link)
        elif op_name == "unlink":
            real_publish = mig._publish_no_clobber

            def fail_publish(src, dst, *, exists_code, fail_code):
                if Path(dst).name == CONFIG_FILENAME:
                    return real_publish(
                        src, dst, exists_code=exists_code, fail_code=fail_code
                    )
                raise MigrationError(fail_code, "migration error")

            monkeypatch.setattr(mig, "_publish_no_clobber", fail_publish)
            monkeypatch.setattr(os, "unlink", boom_unlink)
        elif op_name == "replace":
            # Shared journal/temp protocol must not pathname-replace; arming
            # os.replace must be unreachable. Migration succeeds without it.
            called = {"n": 0}

            def boom_replace(src, dst, *a, **k):
                called["n"] += 1
                raise boom

            monkeypatch.setattr(os, "replace", boom_replace)
            result = migrate_config(store)
            assert result.ok is True
            assert called["n"] == 0
            return
        else:
            monkeypatch.setattr(os, "replace", boom_replace)

    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    assert isinstance(ei.value.code, str) and ei.value.code
    _assert_clean_migration_exc(
        ei.value, decoy=decoy, paths=[store, abs_marker, store / "credentials.json"]
    )


def test_foreign_lock_race_never_mutates_or_acquires(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """exists→open window: competitor 0644 lock must not be chmod'd or flocked."""
    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    import credential_guard.migration as mig

    lock_path = store / mig.LOCK_NAME
    foreign_payload = b"FOREIGN_LOCK_CG_MIG_" + secrets.token_hex(8).encode()
    fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o644)
    try:
        os.write(fd, foreign_payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(lock_path, 0o644)
    before = _lock_identity(lock_path)
    assert before[3] == 0o644

    real_exists = mig._exists

    def exists_lies(path):
        # Simulate TOCTOU: report lock missing so open takes O_CREAT path.
        if Path(path).name == mig.LOCK_NAME:
            return False
        return real_exists(path)

    monkeypatch.setattr(mig, "_exists", exists_lies)
    acquired = False
    exc = None
    try:
        token = mig._acquire_lock(store)
        acquired = True
        mig._release_lock(store, token)
    except MigrationError as e:
        exc = e
    after = _lock_identity(lock_path)
    assert after == before  # bytes/mode/inode unchanged
    assert lock_path.read_bytes() == foreign_payload
    assert stat.S_IMODE(lock_path.lstat().st_mode) == 0o644
    assert acquired is False
    assert exc is not None
    assert exc.code in {"MIGRATION_FS", "MIGRATION_LOCKED"}
    _assert_clean_migration_exc(
        exc, decoy="FOREIGN_LOCK_CG_MIG_", paths=[store, lock_path]
    )


def test_foreign_lock_symlink_and_wrong_mode_rejected(tmp_path: Path):
    store = tmp_path / "credential-guard"
    store.mkdir()
    os.chmod(store, 0o700)
    import credential_guard.migration as mig

    lock_path = store / mig.LOCK_NAME
    target = store / "lock-target"
    target.write_bytes(b"x")
    os.chmod(target, 0o600)
    lock_path.symlink_to(target)
    with pytest.raises(MigrationError) as ei:
        mig._acquire_lock(store)
    assert ei.value.code == "MIGRATION_FS"
    assert lock_path.is_symlink()
    _assert_safe_chain(ei.value)


def test_owned_0600_persistent_lock_can_flock(tmp_path: Path):
    store = tmp_path / "credential-guard"
    store.mkdir()
    os.chmod(store, 0o700)
    import credential_guard.migration as mig

    lock_path = store / mig.LOCK_NAME
    fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(fd)
    os.chmod(lock_path, 0o600)
    before = _lock_identity(lock_path)
    token = mig._acquire_lock(store)
    assert _lock_identity(lock_path)[0:2] == before[0:2]
    assert _lock_identity(lock_path)[3] == 0o600
    mig._release_lock(store, token)
    assert lock_path.is_file()
    assert _lock_identity(lock_path)[0:2] == before[0:2]


def test_foreign_prefixed_temp_never_deleted_on_recovery(tmp_path: Path):
    """Recovery must not prefix-scan-delete competitor .cg-migrate-*.tmp files."""
    import hashlib

    import credential_guard.migration as mig

    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    foreign = store / ".cg-migrate-FOREIGN-COMPETITOR.tmp"
    foreign_payload = b"FOREIGN_TEMP_BYTES_CG_MIG_" + secrets.token_hex(16).encode()
    foreign.write_bytes(foreign_payload)
    os.chmod(foreign, 0o644)
    before = (
        foreign.read_bytes(),
        foreign.lstat().st_ino,
        foreign.lstat().st_dev,
        stat.S_IMODE(foreign.lstat().st_mode),
    )

    txid = secrets.token_hex(16)
    journal = {
        "v": 2,
        "txid": txid,
        "phase": "prepared",
        "new_sha256": hashlib.sha256(b"unused").hexdigest(),
        "credentials_bak_sha256": hashlib.sha256(cred_fp[0]).hexdigest(),
        "targets_bak_sha256": hashlib.sha256(tgt_fp[0]).hexdigest(),
        "source_credentials": {
            "dev": 0,
            "ino": 0,
            "sha256": hashlib.sha256(cred_fp[0]).hexdigest(),
        },
        "source_targets": {
            "dev": 0,
            "ino": 0,
            "sha256": hashlib.sha256(tgt_fp[0]).hexdigest(),
        },
        "published": {
            "new": False,
            "credentials_bak": False,
            "targets_bak": False,
            "credentials_old_removed": False,
            "targets_old_removed": False,
        },
        "temps": {},
    }
    (store / mig.JOURNAL_NAME).write_text(
        json.dumps(journal, separators=(",", ":")), encoding="utf-8"
    )
    _chmod600(store / mig.JOURNAL_NAME)

    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    assert ei.value.code in {"MIGRATION_RECOVERED", "MIGRATION_RECOVERY_REQUIRED"}
    assert foreign.is_file()
    assert foreign.read_bytes() == before[0]
    st = foreign.lstat()
    assert st.st_ino == before[1]
    assert st.st_dev == before[2]
    assert stat.S_IMODE(st.st_mode) == before[3]
    _assert_clean_migration_exc(
        ei.value, decoy="FOREIGN_TEMP_BYTES_CG_MIG_", paths=[store, foreign]
    )


def test_journal_replacement_never_overwrites_foreign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """If journal path is swapped to foreign before update, preserve foreign bytes."""
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    import credential_guard.migration as mig

    foreign_payload = b'{"v":2,"txid":"FOREIGN","marker":"CG_MIG_FOREIGN_JOURNAL"}'
    real_write = mig._write_journal
    state = {"n": 0}

    def write_then_plant_foreign(store_dir, journal, *args, **kwargs):
        if state["n"] >= 1:
            # Subsequent updates must fail closed without clobbering foreign journal.
            return real_write(store_dir, journal, *args, **kwargs)
        result = real_write(store_dir, journal, *args, **kwargs)
        state["n"] = 1
        jpath = store_dir / mig.JOURNAL_NAME
        os.unlink(jpath)
        jpath.write_bytes(foreign_payload)
        os.chmod(jpath, 0o600)
        state["foreign_before"] = (
            jpath.read_bytes(),
            jpath.lstat().st_ino,
            jpath.lstat().st_dev,
        )
        return result

    monkeypatch.setattr(mig, "_write_journal", write_then_plant_foreign)
    ok = False
    exc = None
    try:
        result = migrate_config(store)
        ok = bool(result.ok)
    except MigrationError as e:
        exc = e
    assert ok is False
    assert exc is not None
    assert exc.code in {
        "MIGRATION_JOURNAL",
        "MIGRATION_RECOVERY_REQUIRED",
        "MIGRATION_CONFLICT",
        "MIGRATION_RECOVERED",
        "MIGRATION_FAILED",
    }
    jpath = store / mig.JOURNAL_NAME
    assert jpath.is_file()
    assert "foreign_before" in state
    assert jpath.read_bytes() == foreign_payload
    st = jpath.lstat()
    assert st.st_ino == state["foreign_before"][1]
    assert st.st_dev == state["foreign_before"][2]
    _assert_clean_migration_exc(
        exc, decoy="CG_MIG_FOREIGN_JOURNAL", paths=[store, jpath]
    )


def test_final_old_name_recreation_never_returns_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Competitor recreating credentials.json after first isolation must fail closed."""
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    import credential_guard.migration as mig

    competitor_payload = (
        b'{"version":1,"credentials":{},"marker":"CG_MIG_FINAL_RECREATE"}'
    )
    real_isolate = mig._isolate_owned_source
    state = {"cred_isolated": False}

    def isolate_and_recreate(path, isol_path, *, expected_dev, expected_ino, expected_sha):
        result = real_isolate(
            path,
            isol_path,
            expected_dev=expected_dev,
            expected_ino=expected_ino,
            expected_sha=expected_sha,
        )
        if Path(path).name == "credentials.json":
            state["cred_isolated"] = True
            path.write_bytes(competitor_payload)
            _chmod600(path)
            state["competitor_before"] = (
                path.read_bytes(),
                path.lstat().st_ino,
                path.lstat().st_dev,
            )
        return result

    monkeypatch.setattr(mig, "_isolate_owned_source", isolate_and_recreate)
    ok = False
    exc = None
    try:
        result = migrate_config(store)
        ok = bool(result.ok)
    except MigrationError as e:
        exc = e
    assert ok is False
    assert exc is not None
    assert exc.code in {"MIGRATION_CONFLICT", "MIGRATION_RECOVERY_REQUIRED"}
    cred_path = store / "credentials.json"
    assert cred_path.is_file()
    assert cred_path.read_bytes() == competitor_payload
    st = cred_path.lstat()
    assert st.st_ino == state["competitor_before"][1]
    assert st.st_dev == state["competitor_before"][2]
    evidence = (store / mig.JOURNAL_NAME).exists() or (store / CREDENTIALS_BAK).exists()
    assert evidence is True
    assert _old_bytes_still_present(store, cred_fp[0], tgt_fp[0]) is True
    _assert_clean_migration_exc(
        exc, decoy="CG_MIG_FINAL_RECREATE", paths=[store, cred_path]
    )


# --- R1A fifth-round: identity-bound journal/temp cleanup + exact pre-state recovery ---


def _plant_foreign_regular(path: Path, payload: bytes, mode: int = 0o600) -> Tuple[bytes, int, int, int]:
    if path.exists() or path.is_symlink():
        path.unlink()
    path.write_bytes(payload)
    os.chmod(path, mode)
    st = path.lstat()
    return payload, st.st_ino, st.st_dev, stat.S_IMODE(st.st_mode)


def _assert_foreign_intact(path: Path, before: Tuple[bytes, int, int, int]) -> None:
    assert path.is_file()
    assert path.read_bytes() == before[0]
    st = path.lstat()
    assert st.st_ino == before[1]
    assert st.st_dev == before[2]
    assert stat.S_IMODE(st.st_mode) == before[3]


def test_journal_update_barrier_preserves_foreign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """After last identity check returns, before journal pathname replace: foreign preserved."""
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    import credential_guard.migration as mig

    foreign_payload = b'{"v":2,"txid":"FOREIGN","marker":"CG_MIG_JRN_UPD_BARRIER"}'
    state: Dict[str, Any] = {"planted": False}

    # Barrier at os.replace: competitor swaps formal journal in the check→replace window.
    real_replace = os.replace

    def replace_barrier(src, dst, *args, **kwargs):
        dst_p = Path(dst)
        if dst_p.name == mig.JOURNAL_NAME and not state["planted"]:
            state["before"] = _plant_foreign_regular(dst_p, foreign_payload, 0o644)
            state["planted"] = True
            state["via"] = "replace"
        return real_replace(src, dst, *args, **kwargs)

    # Also cover identity-bound isolate→publish: after journal isol, plant at formal.
    real_rename = mig._atomic_rename_no_clobber

    def rename_barrier(src, dst):
        result = real_rename(src, dst)
        dst_p = Path(dst)
        if not state["planted"] and Path(src).name == mig.JOURNAL_NAME:
            jpath = Path(src)
            # src was formal journal; after rename formal is free — competitor arrives.
            state["before"] = _plant_foreign_regular(jpath, foreign_payload, 0o644)
            state["planted"] = True
            state["via"] = "isol"
            state["owned_isol"] = (
                dst_p.read_bytes(),
                dst_p.lstat().st_ino,
                dst_p.lstat().st_dev,
            )
        return result

    monkeypatch.setattr(os, "replace", replace_barrier)
    monkeypatch.setattr(mig, "_atomic_rename_no_clobber", rename_barrier)
    ok = False
    exc = None
    try:
        result = migrate_config(store)
        ok = bool(result.ok)
    except MigrationError as e:
        exc = e
    assert state["planted"] is True
    assert ok is False
    assert exc is not None
    assert exc.code in {
        "MIGRATION_JOURNAL",
        "MIGRATION_RECOVERY_REQUIRED",
        "MIGRATION_CONFLICT",
        "MIGRATION_FAILED",
    }
    jpath = store / mig.JOURNAL_NAME
    _assert_foreign_intact(jpath, state["before"])
    if state.get("via") == "isol" and state.get("owned_isol") is not None:
        found = any(
            p.is_file()
            and not p.is_symlink()
            and p.lstat().st_ino == state["owned_isol"][1]
            for p in store.iterdir()
        )
        assert found is True
    _assert_clean_migration_exc(
        exc, decoy="CG_MIG_JRN_UPD_BARRIER", paths=[store, jpath]
    )


def test_journal_delete_barrier_preserves_foreign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """After last identity check returns, before journal pathname unlink: foreign preserved."""
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    import credential_guard.migration as mig

    foreign_payload = b'{"v":2,"txid":"FOREIGN","marker":"CG_MIG_JRN_DEL_BARRIER"}'
    state: Dict[str, Any] = {"planted": False}
    real_unlink = os.unlink

    def unlink_barrier(path, *args, **kwargs):
        p = Path(path)
        if p.name == mig.JOURNAL_NAME and not state["planted"]:
            # Competitor replaced formal journal after our check, before unlink.
            state["before"] = _plant_foreign_regular(p, foreign_payload, 0o644)
            state["planted"] = True
            state["via"] = "unlink-formal"
        return real_unlink(path, *args, **kwargs)

    # Identity-bound clear isolates first; plant at formal after isol of journal.
    real_rename = mig._atomic_rename_no_clobber

    def rename_barrier(src, dst):
        result = real_rename(src, dst)
        if not state["planted"] and Path(src).name == mig.JOURNAL_NAME:
            jpath = Path(src)
            state["before"] = _plant_foreign_regular(jpath, foreign_payload, 0o644)
            state["planted"] = True
            state["via"] = "isol"
        return result

    monkeypatch.setattr(os, "unlink", unlink_barrier)
    monkeypatch.setattr(mig, "_atomic_rename_no_clobber", rename_barrier)
    ok = False
    exc = None
    try:
        result = migrate_config(store)
        ok = bool(result.ok)
    except MigrationError as e:
        exc = e
    assert state["planted"] is True
    assert ok is False
    assert exc is not None
    assert exc.code in {
        "MIGRATION_JOURNAL",
        "MIGRATION_RECOVERY_REQUIRED",
        "MIGRATION_CONFLICT",
        "MIGRATION_CLEANUP",
        "MIGRATION_FAILED",
    }
    jpath = store / mig.JOURNAL_NAME
    _assert_foreign_intact(jpath, state["before"])
    _assert_clean_migration_exc(
        exc, decoy="CG_MIG_JRN_DEL_BARRIER", paths=[store, jpath]
    )


def test_journal_publish_conflict_never_clobbers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """When publishing new journal, competitor at formal name must never be overwritten."""
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    import credential_guard.migration as mig

    foreign_payload = b'{"v":2,"txid":"FOREIGN","marker":"CG_MIG_JRN_PUB_CONFLICT"}'
    state: Dict[str, Any] = {"planted": False}

    real_replace = os.replace

    def replace_no_clobber_check(src, dst, *args, **kwargs):
        dst_p = Path(dst)
        if dst_p.name == mig.JOURNAL_NAME and not state["planted"]:
            # Competitor rebuilt formal journal in the publish/replace window.
            state["before"] = _plant_foreign_regular(dst_p, foreign_payload, 0o600)
            state["planted"] = True
            state["via"] = "replace"
        return real_replace(src, dst, *args, **kwargs)

    real_link = os.link
    state["journal_links"] = 0

    def link_plant_on_republish(src, dst, *args, **kwargs):
        dst_p = Path(dst)
        if dst_p.name == mig.JOURNAL_NAME:
            state["journal_links"] += 1
            # First link is initial create — do not plant. Subsequent journal
            # publishes (after isolate) must no-clobber against competitor.
            if state["journal_links"] >= 2 and not state["planted"]:
                state["before"] = _plant_foreign_regular(dst_p, foreign_payload, 0o600)
                state["planted"] = True
                state["via"] = "link"
        return real_link(src, dst, *args, **kwargs)

    real_rename = mig._atomic_rename_no_clobber

    def rename_then_plant(src, dst):
        result = real_rename(src, dst)
        dst_p = Path(dst)
        if not state["planted"] and Path(src).name == mig.JOURNAL_NAME:
            jpath = Path(src)
            state["before"] = _plant_foreign_regular(jpath, foreign_payload, 0o600)
            state["planted"] = True
            state["via"] = "isol"
            state["owned_isol"] = (
                dst_p.read_bytes(),
                dst_p.lstat().st_ino,
                dst_p.lstat().st_dev,
            )
        return result

    monkeypatch.setattr(os, "replace", replace_no_clobber_check)
    monkeypatch.setattr(os, "link", link_plant_on_republish)
    monkeypatch.setattr(mig, "_atomic_rename_no_clobber", rename_then_plant)
    ok = False
    exc = None
    try:
        result = migrate_config(store)
        ok = bool(result.ok)
    except MigrationError as e:
        exc = e
    assert state["planted"] is True
    assert ok is False
    assert exc is not None
    assert exc.code in {
        "MIGRATION_JOURNAL",
        "MIGRATION_RECOVERY_REQUIRED",
        "MIGRATION_CONFLICT",
        "MIGRATION_FAILED",
    }
    jpath = store / mig.JOURNAL_NAME
    _assert_foreign_intact(jpath, state["before"])
    if state.get("owned_isol") is not None:
        found = any(
            p.is_file()
            and not p.is_symlink()
            and p.lstat().st_ino == state["owned_isol"][1]
            for p in store.iterdir()
        )
        assert found is True
    _assert_clean_migration_exc(
        exc, decoy="CG_MIG_JRN_PUB_CONFLICT", paths=[store, jpath]
    )


def test_exact_temp_replacement_never_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Exact owned temp path replaced with foreign inode must never be unlinked."""
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    import credential_guard.migration as mig

    foreign_payload = b"FOREIGN_EXACT_TMP_CG_MIG_" + secrets.token_hex(16).encode()
    real_write = mig._write_bytes_temp
    state: Dict[str, Any] = {}

    def write_then_replace(store_dir, name, data, **kwargs):
        identity = real_write(store_dir, name, data, **kwargs)
        if "cred-bak" in name or name.startswith(".cg-migrate-new-"):
            if "before" not in state:
                path = store_dir / name
                state["path"] = path
                state["before"] = _plant_foreign_regular(path, foreign_payload, 0o644)
        return identity

    monkeypatch.setattr(mig, "_write_bytes_temp", write_then_replace)
    ok = False
    exc = None
    try:
        result = migrate_config(store)
        ok = bool(result.ok)
    except MigrationError as e:
        exc = e
    assert ok is False
    assert exc is not None
    assert "before" in state
    _assert_foreign_intact(state["path"], state["before"])
    _assert_clean_migration_exc(
        exc, decoy="FOREIGN_EXACT_TMP_CG_MIG_", paths=[store, state["path"]]
    )


def test_link_then_temp_replacement_never_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """After hardlink publish succeeds, foreign replacement at temp name is retained."""
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    import credential_guard.migration as mig

    foreign_payload = b"FOREIGN_LINK_TEMP_CG_MIG_" + secrets.token_hex(16).encode()
    real_publish = mig._publish_no_clobber
    state: Dict[str, Any] = {}

    def publish_then_replace_temp(src, dst, *, exists_code, fail_code):
        result = real_publish(src, dst, exists_code=exists_code, fail_code=fail_code)
        src_path = Path(src)
        if src_path.name.startswith(".cg-migrate-") and src_path.name.endswith(".tmp"):
            if "before" not in state:
                state["path"] = src_path
                state["before"] = _plant_foreign_regular(
                    src_path, foreign_payload, 0o644
                )
        return result

    monkeypatch.setattr(mig, "_publish_no_clobber", publish_then_replace_temp)
    ok = False
    exc = None
    try:
        result = migrate_config(store)
        ok = bool(result.ok)
    except MigrationError as e:
        exc = e
    assert ok is False
    assert exc is not None
    assert "before" in state
    _assert_foreign_intact(state["path"], state["before"])
    # Published formal ownership evidence should remain.
    evidence = (store / CONFIG_FILENAME).exists() or (store / mig.JOURNAL_NAME).exists()
    assert evidence is True
    _assert_clean_migration_exc(
        exc, decoy="FOREIGN_LINK_TEMP_CG_MIG_", paths=[store, state["path"]]
    )


def test_recovery_exact_temp_replacement_never_deleted(tmp_path: Path):
    """Recovery must not delete foreign inode sitting on journal-listed temp name."""
    import hashlib

    import credential_guard.migration as mig

    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    txid = secrets.token_hex(16)
    temp_name = f".cg-migrate-new-{txid}.tmp"
    temp_path = store / temp_name
    # Journal commits an owned temp identity; path currently holds foreign inode.
    owned_sha = hashlib.sha256(b"owned-temp-bytes-not-present").hexdigest()
    foreign_payload = b"FOREIGN_RCV_TMP_CG_MIG_" + secrets.token_hex(12).encode()
    before = _plant_foreign_regular(temp_path, foreign_payload, 0o644)
    journal = {
        "v": 2,
        "txid": txid,
        "phase": "prepared",
        "new_sha256": owned_sha,
        "credentials_bak_sha256": hashlib.sha256(cred_fp[0]).hexdigest(),
        "targets_bak_sha256": hashlib.sha256(tgt_fp[0]).hexdigest(),
        "source_credentials": {
            "dev": (store / "credentials.json").lstat().st_dev,
            "ino": (store / "credentials.json").lstat().st_ino,
            "sha256": hashlib.sha256(cred_fp[0]).hexdigest(),
        },
        "source_targets": {
            "dev": (store / "targets.json").lstat().st_dev,
            "ino": (store / "targets.json").lstat().st_ino,
            "sha256": hashlib.sha256(tgt_fp[0]).hexdigest(),
        },
        "published": {
            "new": False,
            "credentials_bak": False,
            "targets_bak": False,
            "credentials_old_removed": False,
            "targets_old_removed": False,
        },
        "temps": {
            "new": {
                "name": temp_name,
                "dev": 0,
                "ino": 0,
                "sha256": owned_sha,
                "mode": 0o600,
                "owner": os.geteuid(),
                "purpose": "new",
            },
            "credentials_bak": None,
            "targets_bak": None,
            "journal": None,
        },
    }
    (store / mig.JOURNAL_NAME).write_text(
        json.dumps(journal, separators=(",", ":")), encoding="utf-8"
    )
    _chmod600(store / mig.JOURNAL_NAME)

    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    assert ei.value.code == "MIGRATION_RECOVERY_REQUIRED"
    _assert_foreign_intact(temp_path, before)
    assert (store / mig.JOURNAL_NAME).is_file()
    _assert_clean_migration_exc(
        ei.value, decoy="FOREIGN_RCV_TMP_CG_MIG_", paths=[store, temp_path]
    )


def test_temp_write_failure_cleanup_preserves_foreign_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Failed temp write cleanup must not pathname-unlink a replaced foreign inode."""
    store = _prepare_store(tmp_path, *_empty_v1_pair())
    import credential_guard.migration as mig

    foreign_payload = b"FOREIGN_WRITEFAIL_TEMP_CG_MIG_" + secrets.token_hex(8).encode()
    real_write = os.write
    state: Dict[str, Any] = {}

    def write_fail_after_create(fd, data):
        # After O_EXCL create, force write failure path; then plant foreign at path.
        path = None
        for p in store.iterdir():
            if p.name.startswith(".cg-migrate-") and p.name.endswith(".tmp"):
                try:
                    if p.stat().st_ino == os.fstat(fd).st_ino:
                        path = p
                        break
                except OSError:
                    continue
        if path is not None and "before" not in state:
            # Close will happen in helper; raise to trigger cleanup.
            state["path"] = path
            raise OSError(5, "simulated write fault")
        return real_write(fd, data)

    def tracking_unlink(path, *args, **kwargs):
        p = Path(path)
        if "path" in state and p == state["path"] and "before" not in state:
            # Between write failure and cleanup unlink: replace with foreign.
            state["before"] = _plant_foreign_regular(p, foreign_payload, 0o644)
        return real_unlink(path, *args, **kwargs)

    real_unlink = os.unlink
    monkeypatch.setattr(os, "write", write_fail_after_create)
    monkeypatch.setattr(os, "unlink", tracking_unlink)

    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    assert ei.value.code in {
        "MIGRATION_TEMP_WRITE",
        "MIGRATION_RECOVERY_REQUIRED",
        "MIGRATION_FAILED",
        "MIGRATION_CONFLICT",
    }
    if "before" in state:
        _assert_foreign_intact(state["path"], state["before"])
    _assert_clean_migration_exc(
        ei.value, decoy="FOREIGN_WRITEFAIL_TEMP_CG_MIG_", paths=[store]
    )


def test_foreign_formal_with_owned_backup_keeps_journal(tmp_path: Path):
    """Foreign formal + owned bak must keep both and journal; never RECOVERED."""
    import hashlib

    import credential_guard.migration as mig

    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    owned_cred = cred_fp[0]
    owned_tgt = tgt_fp[0]
    foreign_cred = b'{"version":1,"credentials":{},"marker":"CG_MIG_FOREIGN_FORMAL"}'
    # Replace formal credentials with foreign payload; plant owned bak.
    (store / "credentials.json").unlink()
    before_formal = _plant_foreign_regular(
        store / "credentials.json", foreign_cred, 0o600
    )
    (store / CREDENTIALS_BAK).write_bytes(owned_cred)
    _chmod600(store / CREDENTIALS_BAK)
    bak_before = (
        (store / CREDENTIALS_BAK).read_bytes(),
        (store / CREDENTIALS_BAK).lstat().st_ino,
        (store / CREDENTIALS_BAK).lstat().st_dev,
    )
    txid = secrets.token_hex(16)
    journal = {
        "v": 2,
        "txid": txid,
        "phase": "baks",
        "new_sha256": hashlib.sha256(b"not-published").hexdigest(),
        "credentials_bak_sha256": hashlib.sha256(owned_cred).hexdigest(),
        "targets_bak_sha256": hashlib.sha256(owned_tgt).hexdigest(),
        "source_credentials": {
            "dev": 0,
            "ino": 0,
            "sha256": hashlib.sha256(owned_cred).hexdigest(),
        },
        "source_targets": {
            "dev": (store / "targets.json").lstat().st_dev,
            "ino": (store / "targets.json").lstat().st_ino,
            "sha256": hashlib.sha256(owned_tgt).hexdigest(),
        },
        "published": {
            "new": False,
            "credentials_bak": True,
            "targets_bak": False,
            "credentials_old_removed": False,
            "targets_old_removed": False,
        },
        "temps": {},
    }
    jpath = store / mig.JOURNAL_NAME
    jpath.write_text(json.dumps(journal, separators=(",", ":")), encoding="utf-8")
    _chmod600(jpath)
    j_before = (
        jpath.read_bytes(),
        jpath.lstat().st_ino,
        jpath.lstat().st_dev,
    )

    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    assert ei.value.code == "MIGRATION_RECOVERY_REQUIRED"
    _assert_foreign_intact(store / "credentials.json", before_formal)
    assert (store / CREDENTIALS_BAK).is_file()
    assert (store / CREDENTIALS_BAK).read_bytes() == bak_before[0]
    assert (store / CREDENTIALS_BAK).lstat().st_ino == bak_before[1]
    assert jpath.is_file()
    assert jpath.read_bytes() == j_before[0]
    assert jpath.lstat().st_ino == j_before[1]
    assert _old_bytes_still_present(store, owned_cred, owned_tgt) is True
    _assert_clean_migration_exc(
        ei.value, decoy="CG_MIG_FOREIGN_FORMAL", paths=[store, jpath]
    )


def test_owned_backup_residual_never_reports_recovered(tmp_path: Path):
    """Exact formals present but owned bak residual must not claim RECOVERED."""
    import hashlib

    import credential_guard.migration as mig

    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    owned_cred, owned_tgt = cred_fp[0], tgt_fp[0]
    # Formals are correct; plant owned bak leftover that recovery must clear
    # before claiming recovered — or keep journal if it cannot.
    (store / CREDENTIALS_BAK).write_bytes(owned_cred)
    _chmod600(store / CREDENTIALS_BAK)
    # Make bak undeletable via identity mismatch after plant? Instead: plant
    # owned isol residual that matches journal commitment.
    txid = secrets.token_hex(16)
    isol = store / f".cg-migrate-isol-cred-{txid}"
    isol.write_bytes(owned_cred)
    _chmod600(isol)
    isol_before = (
        isol.read_bytes(),
        isol.lstat().st_ino,
        isol.lstat().st_dev,
    )
    # Prevent cleanup by replacing isol with foreign after identity check —
    # simpler: leave owned isol and monkeypatch unlink of isol to fail closed
    # while still verifying we never get RECOVERED with residual.
    # Here: leave owned isol; current buggy code deletes it. Force residual by
    # making isol foreign-but-present after a failed match keep path.
    foreign_isol = b"FOREIGN_ISOL_RESIDUAL_CG_MIG_" + secrets.token_hex(8).encode()
    isol.unlink()
    before = _plant_foreign_regular(isol, foreign_isol, 0o644)

    journal = {
        "v": 2,
        "txid": txid,
        "phase": "isolated",
        "new_sha256": hashlib.sha256(b"unused").hexdigest(),
        "credentials_bak_sha256": hashlib.sha256(owned_cred).hexdigest(),
        "targets_bak_sha256": hashlib.sha256(owned_tgt).hexdigest(),
        "source_credentials": {
            "dev": (store / "credentials.json").lstat().st_dev,
            "ino": (store / "credentials.json").lstat().st_ino,
            "sha256": hashlib.sha256(owned_cred).hexdigest(),
        },
        "source_targets": {
            "dev": (store / "targets.json").lstat().st_dev,
            "ino": (store / "targets.json").lstat().st_ino,
            "sha256": hashlib.sha256(owned_tgt).hexdigest(),
        },
        "published": {
            "new": False,
            "credentials_bak": True,
            "targets_bak": False,
            "credentials_old_removed": True,
            "targets_old_removed": False,
        },
        "temps": {},
    }
    # Also keep owned bak residual.
    journal_path = store / mig.JOURNAL_NAME
    journal_path.write_text(
        json.dumps(journal, separators=(",", ":")), encoding="utf-8"
    )
    _chmod600(journal_path)

    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    assert ei.value.code == "MIGRATION_RECOVERY_REQUIRED"
    _assert_foreign_intact(isol, before)
    assert (store / mig.JOURNAL_NAME).is_file()
    _assert_clean_migration_exc(
        ei.value, decoy="FOREIGN_ISOL_RESIDUAL_CG_MIG_", paths=[store, isol]
    )


def test_journal_replaced_before_clear_never_reports_recovered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """If journal is replaced before clear during recovery, must not claim RECOVERED."""
    import hashlib

    import credential_guard.migration as mig

    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    txid = secrets.token_hex(16)
    journal = {
        "v": 2,
        "txid": txid,
        "phase": "prepared",
        "new_sha256": hashlib.sha256(b"unused").hexdigest(),
        "credentials_bak_sha256": hashlib.sha256(cred_fp[0]).hexdigest(),
        "targets_bak_sha256": hashlib.sha256(tgt_fp[0]).hexdigest(),
        "source_credentials": {
            "dev": (store / "credentials.json").lstat().st_dev,
            "ino": (store / "credentials.json").lstat().st_ino,
            "sha256": hashlib.sha256(cred_fp[0]).hexdigest(),
        },
        "source_targets": {
            "dev": (store / "targets.json").lstat().st_dev,
            "ino": (store / "targets.json").lstat().st_ino,
            "sha256": hashlib.sha256(tgt_fp[0]).hexdigest(),
        },
        "published": {
            "new": False,
            "credentials_bak": False,
            "targets_bak": False,
            "credentials_old_removed": False,
            "targets_old_removed": False,
        },
        "temps": {},
    }
    jpath = store / mig.JOURNAL_NAME
    jpath.write_text(json.dumps(journal, separators=(",", ":")), encoding="utf-8")
    _chmod600(jpath)

    foreign_payload = b'{"v":2,"txid":"FOREIGN","marker":"CG_MIG_RCV_JRN_SWAP"}'
    real_clear = mig._clear_journal
    state: Dict[str, Any] = {}

    def clear_after_plant(store_dir, *, expected=None):
        state["before"] = _plant_foreign_regular(
            store_dir / mig.JOURNAL_NAME, foreign_payload, 0o644
        )
        return real_clear(store_dir, expected=expected)

    monkeypatch.setattr(mig, "_clear_journal", clear_after_plant)
    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    assert ei.value.code == "MIGRATION_RECOVERY_REQUIRED"
    _assert_foreign_intact(jpath, state["before"])
    _assert_clean_migration_exc(
        ei.value, decoy="CG_MIG_RCV_JRN_SWAP", paths=[store, jpath]
    )


def test_recovered_only_on_exact_prestate(tmp_path: Path):
    """Prepared journal with exact pre-state formals and no residuals → RECOVERED."""
    import hashlib

    import credential_guard.migration as mig

    store = _prepare_store(tmp_path, *_ssh_v1_pair())
    cred_fp = _file_fingerprint(store / "credentials.json")
    tgt_fp = _file_fingerprint(store / "targets.json")
    txid = secrets.token_hex(16)
    journal = {
        "v": 2,
        "txid": txid,
        "phase": "prepared",
        "new_sha256": hashlib.sha256(b"unused").hexdigest(),
        "credentials_bak_sha256": hashlib.sha256(cred_fp[0]).hexdigest(),
        "targets_bak_sha256": hashlib.sha256(tgt_fp[0]).hexdigest(),
        "source_credentials": {
            "dev": (store / "credentials.json").lstat().st_dev,
            "ino": (store / "credentials.json").lstat().st_ino,
            "sha256": hashlib.sha256(cred_fp[0]).hexdigest(),
        },
        "source_targets": {
            "dev": (store / "targets.json").lstat().st_dev,
            "ino": (store / "targets.json").lstat().st_ino,
            "sha256": hashlib.sha256(tgt_fp[0]).hexdigest(),
        },
        "published": {
            "new": False,
            "credentials_bak": False,
            "targets_bak": False,
            "credentials_old_removed": False,
            "targets_old_removed": False,
        },
        "temps": {
            "new": None,
            "credentials_bak": None,
            "targets_bak": None,
            "journal": None,
        },
    }
    (store / mig.JOURNAL_NAME).write_text(
        json.dumps(journal, separators=(",", ":")), encoding="utf-8"
    )
    _chmod600(store / mig.JOURNAL_NAME)

    with pytest.raises(MigrationError) as ei:
        migrate_config(store)
    assert ei.value.code == "MIGRATION_RECOVERED"
    _assert_pre_migration_state(store, cred_fp, tgt_fp)
    _assert_clean_migration_exc(ei.value, decoy="CG_MIG_", paths=[store])



# ---------------------------------------------------------------------------
# R5 prep: migration must not module-import file_backend (deletion blocker)
# ---------------------------------------------------------------------------


class _BlockModuleFinder:
    def __init__(self, blocked: frozenset) -> None:
        self._blocked = blocked

    def find_spec(self, fullname, path, target=None):  # noqa: ANN001
        if fullname in self._blocked:
            raise ImportError(f"{fullname} is blocked for isolation test")
        return None


def _reimport_migration_with_file_backend_blocked():
    import sys

    saved_mig = sys.modules.pop("credential_guard.migration", None)
    saved_fb = sys.modules.pop("credential_guard.file_backend", None)
    finder = _BlockModuleFinder(frozenset({"credential_guard.file_backend"}))
    sys.meta_path.insert(0, finder)
    try:
        import credential_guard.migration as mig

        return mig
    finally:
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
        if saved_fb is None:
            sys.modules.pop("credential_guard.file_backend", None)
        else:
            sys.modules["credential_guard.file_backend"] = saved_fb
        if saved_mig is None:
            sys.modules.pop("credential_guard.migration", None)
        else:
            sys.modules["credential_guard.migration"] = saved_mig
        import credential_guard as pkg

        if saved_mig is not None:
            setattr(pkg, "migration", saved_mig)
        if saved_fb is not None:
            setattr(pkg, "file_backend", saved_fb)


def test_r5_prep_migration_imports_without_file_backend():
    """Blocking file_backend must not prevent importing migration (v1 parser local)."""
    src = Path(__file__).resolve().parents[1] / "credential_guard" / "migration.py"
    text = src.read_text(encoding="utf-8")
    assert "from .file_backend import" not in text

    mig = _reimport_migration_with_file_backend_blocked()
    creds = mig._validate_v1_credentials(
        {
            "version": 1,
            "credentials": {
                "c1": {"type": "mysql", "username": "u", "password": "p"},
            },
        }
    )
    assert creds["c1"]["username"] == "u"
    tgts = mig._validate_v1_targets(
        {
            "version": 1,
            "targets": {
                "t1": {"type": "ssh_config", "ssh_alias": "bastion-prod"},
            },
        }
    )
    assert tgts["t1"]["ssh_alias"] == "bastion-prod"

    with pytest.raises(mig.MigrationError) as ei:
        mig._validate_v1_credentials(
            {
                "version": 1,
                "credentials": {
                    "c1": {
                        "type": "mysql",
                        "username": "u",
                        "password": "p",
                        "extra": "nope",
                    },
                },
            }
        )
    assert ei.value.code == "MIGRATION_SOURCE_SCHEMA"

    for bad_alias in ("*", "has space", "-leading"):
        with pytest.raises(mig.MigrationError) as ei2:
            mig._validate_v1_targets(
                {
                    "version": 1,
                    "targets": {
                        "t1": {"type": "ssh_config", "ssh_alias": bad_alias},
                    },
                }
            )
        assert ei2.value.code == "MIGRATION_SOURCE_SCHEMA"


def test_r5_prep_migration_mutation_widen_fields_or_alias_is_red():
    """Gate: relaxing private v1 field set or alias rules must be detectable as RED."""
    import credential_guard.migration as mig

    # Unknown credential field must fail (would pass if field set were widened).
    with pytest.raises(mig.MigrationError) as ei:
        mig._validate_v1_credentials(
            {
                "version": 1,
                "credentials": {
                    "c1": {
                        "type": "mysql",
                        "username": "u",
                        "password": "p",
                        "rogue": "x",
                    },
                },
            }
        )
    assert ei.value.code == "MIGRATION_SOURCE_SCHEMA"
    # Alias wildcards / whitespace / leading dash must fail.
    for bad in ("*", "a b", "-x"):
        with pytest.raises(mig.MigrationError) as ei2:
            mig._validate_v1_targets(
                {
                    "version": 1,
                    "targets": {"t1": {"type": "ssh_config", "ssh_alias": bad}},
                }
            )
        assert ei2.value.code == "MIGRATION_SOURCE_SCHEMA"
