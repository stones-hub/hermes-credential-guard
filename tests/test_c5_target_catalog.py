"""C5 safe target catalog sidecar: startup never reads credential plaintext."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

import pytest

import credential_guard
from credential_guard import register
from credential_guard.config import CONFIG_FILENAME, ConfigError, CredentialGuardConfig
from credential_guard.process_tools import TOOL_DESCRIPTION as PROCESS_STATIC
from credential_guard.reference_tools import TOOL_DESCRIPTION as HTTP_STATIC
from credential_guard.runtime_config import (
    RuntimeConfigError,
    get_execution_secret_resolve_count,
    get_runtime_view,
    reset_execution_secret_resolve_count_for_tests,
    reset_runtime_for_tests,
)
from credential_guard.state import get_registry

REPO = Path(__file__).resolve().parents[1]
PY = str(REPO / ".venv" / "bin" / "python")
ENV_BASE = {
    "PYTHONPATH": str(REPO),
    "PYTHONDONTWRITEBYTECODE": "1",
}

_C5_COLLISION_SECRET = "secretvalue12345"
_C5_OTHER_SECRET = "othersecret99999"


class _RegisterCaptureCtx:
    def __init__(self) -> None:
        self.tools: list[dict[str, Any]] = []

    def register_middleware(self, *_a, **_k):
        return None

    def register_hook(self, *_a, **_k):
        return None

    def register_cli_command(self, **_k):
        return None

    def register_tool(self, **kwargs):
        self.tools.append(kwargs)


def _tool_descs(ctx: _RegisterCaptureCtx) -> dict[str, str]:
    out: dict[str, str] = {}
    for tool in ctx.tools:
        schema = tool.get("schema") or {}
        name = tool.get("name") or schema.get("name")
        desc = tool.get("description")
        if desc is None:
            desc = schema.get("description")
        assert isinstance(name, str) and isinstance(desc, str)
        out[name] = desc
    return out


def _v2_doc() -> dict[str, Any]:
    return {
        "version": 2,
        "credentials": {
            "ci-token": {"type": "token", "value": "decoy-ci-abc123-min8chars"},
            "report-token": {"type": "token", "value": "decoy-report-xyz789-min8"},
        },
        "bindings": {
            "ci-api": {
                "type": "http",
                "credential_ref": "ci-token",
                "target": {"scheme": "https", "host": "ci.example.test", "port": 443},
                "request": {
                    "allowed_methods": ["GET", "POST"],
                    "allowed_paths": ["/status", "/jobs/build"],
                },
                "inject": {"type": "bearer", "location": "authorization_header"},
                "approval": "required",
            },
            "report-job": {
                "type": "process_env",
                "credential_ref": "report-token",
                "program": "/usr/local/bin/report-cli",
                "argv": ["/usr/local/bin/report-cli"],
                "env_name": "REPORT_TOKEN",
                "timeout_seconds": 10,
                "max_stdout_bytes": 4096,
                "max_stderr_bytes": 4096,
                "approval": "required",
            },
        },
    }


def _identity_from_path(path: Path) -> dict[str, int]:
    st = path.lstat()
    return {
        "device": int(st.st_dev),
        "inode": int(st.st_ino),
        "size": int(st.st_size),
        "mtime_ns": int(st.st_mtime_ns),
    }


def _catalog_doc_for_config(cfg_path: Path, bindings: Optional[dict] = None) -> dict:
    if bindings is None:
        bindings = {
            "ci-api": {
                "type": "http",
                "credential_ref": "ci-token",
                "allowed_methods": ["GET", "POST"],
                "allowed_paths": ["/status", "/jobs/build"],
            },
            "report-job": {
                "type": "process_env",
                "credential_ref": "report-token",
            },
        }
    return {
        "version": 1,
        "source_identity": _identity_from_path(cfg_path),
        "bindings": bindings,
    }


def _write_store(
    hermes: Path,
    doc: dict[str, Any],
    *,
    write_catalog: bool = True,
    catalog: Optional[dict] = None,
) -> Path:
    store = hermes / "credential-guard"
    store.mkdir(parents=True, exist_ok=True)
    os.chmod(store, 0o700)
    cfg = store / CONFIG_FILENAME
    cfg.write_text(json.dumps(doc), encoding="utf-8")
    os.chmod(cfg, 0o600)
    if write_catalog:
        # Keep filename literal so knife-1 RED does not depend on the module yet.
        cat_path = store / "credential-guard.targets.json"
        body = catalog if catalog is not None else _catalog_doc_for_config(cfg)
        cat_path.write_text(json.dumps(body), encoding="utf-8")
        os.chmod(cat_path, 0o600)
    return store


@pytest.fixture(autouse=True)
def _reset():
    reset_runtime_for_tests()
    reset_execution_secret_resolve_count_for_tests()
    get_registry().clear()
    try:
        from credential_guard.target_catalog import reset_registration_catalog_for_tests

        reset_registration_catalog_for_tests()
    except ImportError:
        pass
    yield
    reset_runtime_for_tests()
    reset_execution_secret_resolve_count_for_tests()
    get_registry().clear()
    try:
        from credential_guard.target_catalog import reset_registration_catalog_for_tests

        reset_registration_catalog_for_tests()
    except ImportError:
        pass


# ---------------------------------------------------------------------------
# Knife 1: register must not read credential plaintext
# ---------------------------------------------------------------------------


def test_knife1_register_lists_bindings_without_reading_secrets(
    tmp_path, monkeypatch
):
    """Valid main config + sidecar: register lists bindings; never opens secrets."""
    from credential_guard import config as config_mod
    from credential_guard import runtime_config as rc_mod

    home = tmp_path / "home"
    hermes = tmp_path / "hermes_home"
    home.mkdir()
    hermes.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    _write_store(hermes, _v2_doc())

    def boom_open(*_a, **_k):
        raise AssertionError("_open_and_read must not run during register")

    def boom_load(*_a, **_k):
        raise AssertionError("CredentialGuardConfig.load must not run during register")

    def boom_publish(*_a, **_k):
        raise AssertionError("ensure_published_from_disk must not run during register")

    monkeypatch.setattr(config_mod, "_open_and_read", boom_open)
    monkeypatch.setattr(CredentialGuardConfig, "load", boom_load)
    monkeypatch.setattr(rc_mod, "ensure_published_from_disk", boom_publish)
    monkeypatch.setattr(
        credential_guard, "ensure_published_from_disk", boom_publish, raising=False
    )

    reset_runtime_for_tests()
    reset_execution_secret_resolve_count_for_tests()
    ctx = _RegisterCaptureCtx()
    register(ctx)
    descs = _tool_descs(ctx)

    assert "ci-api" in descs["http_credential_request"]
    assert "<CREDENTIAL:ci-token>" in descs["http_credential_request"]
    assert "report-job" not in descs["http_credential_request"]
    assert "report-job" in descs["credential_process_run"]
    assert "<CREDENTIAL:report-token>" in descs["credential_process_run"]
    assert "ci-api" not in descs["credential_process_run"]

    sensitive = (
        "ci.example.test",
        "443",
        "/usr/local/bin/report-cli",
        "REPORT_TOKEN",
        "decoy-ci-abc123",
        "decoy-report-xyz789",
    )
    joined = descs["http_credential_request"] + descs["credential_process_run"]
    for needle in sensitive:
        assert needle not in joined

    assert get_execution_secret_resolve_count() == 0
    with pytest.raises(RuntimeConfigError):
        get_runtime_view()


def test_knife1_register_without_ensure_published_import_path(tmp_path, monkeypatch):
    """register() must not call ensure_published_from_disk at all."""
    from credential_guard import runtime_config as rc_mod

    home = tmp_path / "home"
    hermes = tmp_path / "hermes_home"
    home.mkdir()
    hermes.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    _write_store(hermes, _v2_doc())

    calls: list[int] = []

    def _count(*_a, **_k):
        calls.append(1)
        raise AssertionError("ensure_published_from_disk must not be called")

    monkeypatch.setattr(rc_mod, "ensure_published_from_disk", _count)
    ctx = _RegisterCaptureCtx()
    register(ctx)
    assert calls == []
    descs = _tool_descs(ctx)
    assert "ci-api" in descs["http_credential_request"]
    assert not hasattr(credential_guard, "ensure_published_from_disk")


# ---------------------------------------------------------------------------
# Knife 2: strict sidecar + stale fallback
# ---------------------------------------------------------------------------


def _prepare_env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes_home"
    home.mkdir()
    hermes.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    return hermes


def test_knife2_missing_catalog_static_fallback(tmp_path, monkeypatch):
    hermes = _prepare_env(tmp_path, monkeypatch)
    _write_store(hermes, _v2_doc(), write_catalog=False)
    ctx = _RegisterCaptureCtx()
    register(ctx)
    descs = _tool_descs(ctx)
    assert descs["http_credential_request"] == HTTP_STATIC
    assert descs["credential_process_run"] == PROCESS_STATIC
    with pytest.raises(RuntimeConfigError):
        get_runtime_view()


def test_knife2_invalid_json_static_fallback(tmp_path, monkeypatch):
    hermes = _prepare_env(tmp_path, monkeypatch)
    store = _write_store(hermes, _v2_doc(), write_catalog=False)
    from credential_guard.target_catalog import TARGET_CATALOG_FILENAME

    bad = store / TARGET_CATALOG_FILENAME
    bad.write_text("{not-json", encoding="utf-8")
    os.chmod(bad, 0o600)
    ctx = _RegisterCaptureCtx()
    register(ctx)
    descs = _tool_descs(ctx)
    assert descs["http_credential_request"] == HTTP_STATIC


@pytest.mark.parametrize(
    "mutate",
    [
        "extra_top",
        "extra_binding",
        "mode_0644",
        "symlink",
        "parent_0755",
        "stale_identity",
        "forbidden_host",
        "too_large",
    ],
)
def test_knife2_insecure_or_stale_catalog_static_fallback(
    tmp_path, monkeypatch, mutate
):
    hermes = _prepare_env(tmp_path, monkeypatch)
    store = _write_store(hermes, _v2_doc())
    from credential_guard.target_catalog import TARGET_CATALOG_FILENAME

    cfg = store / CONFIG_FILENAME
    cat = store / TARGET_CATALOG_FILENAME
    if mutate == "extra_top":
        body = _catalog_doc_for_config(cfg)
        body["extra"] = 1
        cat.write_text(json.dumps(body), encoding="utf-8")
        os.chmod(cat, 0o600)
    elif mutate == "extra_binding":
        body = _catalog_doc_for_config(cfg)
        body["bindings"]["ci-api"]["host"] = "evil.test"
        cat.write_text(json.dumps(body), encoding="utf-8")
        os.chmod(cat, 0o600)
    elif mutate == "mode_0644":
        os.chmod(cat, 0o644)
    elif mutate == "symlink":
        real = store / "real-targets.json"
        real.write_text(cat.read_text(encoding="utf-8"), encoding="utf-8")
        os.chmod(real, 0o600)
        cat.unlink()
        cat.symlink_to(real)
    elif mutate == "parent_0755":
        os.chmod(store, 0o755)
    elif mutate == "stale_identity":
        body = _catalog_doc_for_config(cfg)
        body["source_identity"]["mtime_ns"] = int(
            body["source_identity"]["mtime_ns"]
        ) + 1
        cat.write_text(json.dumps(body), encoding="utf-8")
        os.chmod(cat, 0o600)
    elif mutate == "forbidden_host":
        body = _catalog_doc_for_config(cfg)
        body["bindings"]["ci-api"]["scheme"] = "https"
        cat.write_text(json.dumps(body), encoding="utf-8")
        os.chmod(cat, 0o600)
    elif mutate == "too_large":
        # Exceed catalog byte cap with padded whitespace-free JSON.
        from credential_guard.target_catalog import MAX_TARGET_CATALOG_BYTES

        pad = "x" * (MAX_TARGET_CATALOG_BYTES + 64)
        body = _catalog_doc_for_config(
            cfg,
            bindings={
                "ci-api": {
                    "type": "http",
                    "credential_ref": "ci-token",
                    "allowed_methods": ["GET"],
                    "allowed_paths": ["/" + pad[:200]],
                }
            },
        )
        # Force size by writing oversized raw bytes after a valid-looking prefix.
        raw = json.dumps(body).encode("utf-8") + (b" " * (MAX_TARGET_CATALOG_BYTES + 8))
        cat.write_bytes(raw)
        os.chmod(cat, 0o600)

    ctx = _RegisterCaptureCtx()
    register(ctx)  # must not raise
    descs = _tool_descs(ctx)
    assert descs["http_credential_request"] == HTTP_STATIC
    assert descs["credential_process_run"] == PROCESS_STATIC
    with pytest.raises(RuntimeConfigError):
        get_runtime_view()


def test_knife2_valid_catalog_dynamic_list_no_forbidden_fields(
    tmp_path, monkeypatch
):
    hermes = _prepare_env(tmp_path, monkeypatch)
    store = _write_store(hermes, _v2_doc())
    from credential_guard.target_catalog import TARGET_CATALOG_FILENAME

    cat_text = (store / TARGET_CATALOG_FILENAME).read_text(encoding="utf-8")
    forbidden = (
        "credentials",
        "decoy-ci-abc123",
        "ci.example.test",
        "program",
        "argv",
        "env_name",
        "header_name",
        "inject",
        "approval",
        "digest",
        "host",
        "port",
        "scheme",
    )
    for needle in forbidden:
        if needle in ("host", "port", "scheme", "program", "argv", "env_name"):
            # Keys must not appear as JSON field names in sidecar.
            assert f'"{needle}"' not in cat_text
        else:
            assert needle not in cat_text

    open_calls: list[str] = []
    real_open = open

    def tracking_open(path, *a, **k):
        p = str(path)
        if p.endswith(CONFIG_FILENAME):
            open_calls.append(p)
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", tracking_open)
    # Also track os.open for production path.
    real_os_open = os.open

    def tracking_os_open(path, *a, **k):
        p = str(path)
        if p.endswith(CONFIG_FILENAME) and not p.endswith(".targets.json"):
            # lstat-only contract: opening main config body is forbidden.
            flags = a[0] if a else k.get("flags", 0)
            # O_RDONLY opens still count as reading body.
            open_calls.append(p)
        return real_os_open(path, *a, **k)

    monkeypatch.setattr(os, "open", tracking_os_open)

    ctx = _RegisterCaptureCtx()
    register(ctx)
    descs = _tool_descs(ctx)
    assert "ci-api" in descs["http_credential_request"]
    assert "report-job" in descs["credential_process_run"]
    assert open_calls == []


@pytest.mark.parametrize(
    "mutate",
    [
        "version_true",
        "bad_method",
        "dup_method",
        "dup_path",
        "too_many_paths",
        "path_control",
        "path_query",
        "path_fragment",
        "path_dot_segment",
        "path_backslash",
        "path_too_long",
        "http_extra_field",
        "http_missing_field",
        "process_extra_field",
        "process_missing_field",
    ],
)
def test_knife2_sidecar_http_contract_static_fallback(tmp_path, monkeypatch, mutate):
    """Sidecar must match formal HTTP contract; otherwise static descriptions."""
    hermes = _prepare_env(tmp_path, monkeypatch)
    store = _write_store(hermes, _v2_doc())
    from credential_guard.target_catalog import TARGET_CATALOG_FILENAME

    cfg = store / CONFIG_FILENAME
    cat = store / TARGET_CATALOG_FILENAME
    body = _catalog_doc_for_config(cfg)
    http = body["bindings"]["ci-api"]
    proc = body["bindings"]["report-job"]

    if mutate == "version_true":
        body["version"] = True
    elif mutate == "bad_method":
        http["allowed_methods"] = ["GET", "TRACE"]
    elif mutate == "dup_method":
        http["allowed_methods"] = ["GET", "GET"]
    elif mutate == "dup_path":
        http["allowed_paths"] = ["/status", "/status"]
    elif mutate == "too_many_paths":
        http["allowed_paths"] = [f"/p{i}" for i in range(65)]
    elif mutate == "path_control":
        http["allowed_paths"] = ["/sta\ntus"]
    elif mutate == "path_query":
        http["allowed_paths"] = ["/status?x=1"]
    elif mutate == "path_fragment":
        http["allowed_paths"] = ["/status#frag"]
    elif mutate == "path_dot_segment":
        http["allowed_paths"] = ["/status/../admin"]
    elif mutate == "path_backslash":
        http["allowed_paths"] = ["/sta\\tus"]
    elif mutate == "path_too_long":
        http["allowed_paths"] = ["/" + ("a" * 512)]
    elif mutate == "http_extra_field":
        http["host"] = "evil.test"
    elif mutate == "http_missing_field":
        del http["allowed_paths"]
    elif mutate == "process_extra_field":
        proc["program"] = "/bin/evil"
    elif mutate == "process_missing_field":
        del proc["credential_ref"]
    else:
        raise AssertionError(mutate)

    cat.write_text(json.dumps(body), encoding="utf-8")
    os.chmod(cat, 0o600)

    ctx = _RegisterCaptureCtx()
    register(ctx)  # must not raise
    descs = _tool_descs(ctx)
    assert descs["http_credential_request"] == HTTP_STATIC
    assert descs["credential_process_run"] == PROCESS_STATIC
    joined = descs["http_credential_request"] + descs["credential_process_run"]
    assert "ci-api" not in joined
    assert "report-job" not in joined
    assert "TRACE" not in joined
    assert "evil" not in joined


def test_knife2_sidecar_methods_paths_are_immutable_tuples(tmp_path, monkeypatch):
    """Parsed sidecar HTTP methods/paths must be deep-frozen tuples."""
    from credential_guard.target_catalog import load_safe_bindings_from_sidecar

    hermes = _prepare_env(tmp_path, monkeypatch)
    store = _write_store(hermes, _v2_doc())
    bindings = load_safe_bindings_from_sidecar(store)
    assert bindings is not None
    http = bindings["ci-api"]
    assert isinstance(http["allowed_methods"], tuple)
    assert isinstance(http["allowed_paths"], tuple)
    with pytest.raises((TypeError, AttributeError)):
        http["allowed_methods"].append("TRACE")  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Knife 3: generate / refresh / migration
# ---------------------------------------------------------------------------


def test_knife3_refresh_targets_generates_strict_sidecar(tmp_path, monkeypatch, capsys):
    from credential_guard.cli import handle_command
    from credential_guard.target_catalog import TARGET_CATALOG_FILENAME

    hermes = _prepare_env(tmp_path, monkeypatch)
    store = _write_store(hermes, _v2_doc(), write_catalog=False)
    assert not (store / TARGET_CATALOG_FILENAME).exists()

    class Args:
        credential_guard_command = "refresh-targets"

    rc = handle_command(Args())
    assert rc == 0
    out = capsys.readouterr().out
    assert out.strip() == "credential-guard: refresh-targets ok"
    assert "decoy" not in out
    assert str(store) not in out
    assert "ci-api" not in out

    cat = store / TARGET_CATALOG_FILENAME
    assert cat.is_file()
    assert stat.S_IMODE(cat.stat().st_mode) == 0o600
    body = json.loads(cat.read_text(encoding="utf-8"))
    assert set(body.keys()) == {"version", "source_identity", "bindings"}
    assert body["version"] == 1
    assert body["source_identity"] == _identity_from_path(store / CONFIG_FILENAME)
    assert set(body["bindings"].keys()) == {"ci-api", "report-job"}
    assert body["bindings"]["ci-api"] == {
        "type": "http",
        "credential_ref": "ci-token",
        "allowed_methods": ["GET", "POST"],
        "allowed_paths": ["/status", "/jobs/build"],
    }
    assert body["bindings"]["report-job"] == {
        "type": "process_env",
        "credential_ref": "report-token",
    }
    blob = json.dumps(body)
    for needle in (
        "decoy-ci",
        "ci.example.test",
        "REPORT_TOKEN",
        "/usr/local/bin",
        "approval",
        "inject",
        "digest",
    ):
        assert needle not in blob


def test_knife3_refresh_rejects_name_secret_collision_keeps_old(
    tmp_path, monkeypatch, capsys
):
    from credential_guard.cli import handle_command
    from credential_guard.target_catalog import TARGET_CATALOG_FILENAME

    hermes = _prepare_env(tmp_path, monkeypatch)
    store = _write_store(hermes, _v2_doc())
    old = (store / TARGET_CATALOG_FILENAME).read_bytes()
    colliding = {
        "version": 2,
        "credentials": {
            "legit-token": {"type": "token", "value": _C5_COLLISION_SECRET},
            _C5_COLLISION_SECRET: {"type": "token", "value": _C5_OTHER_SECRET},
        },
        "bindings": {},
    }
    (store / CONFIG_FILENAME).write_text(json.dumps(colliding), encoding="utf-8")
    os.chmod(store / CONFIG_FILENAME, 0o600)

    class Args:
        credential_guard_command = "refresh-targets"

    rc = handle_command(Args())
    assert rc != 0
    err_out = capsys.readouterr()
    combined = err_out.out + err_out.err
    assert "refresh-targets" in combined
    assert _C5_COLLISION_SECRET not in combined
    assert _C5_OTHER_SECRET not in combined
    assert "Traceback" not in combined
    assert (store / TARGET_CATALOG_FILENAME).read_bytes() == old


def test_knife3_atomic_write_failure_leaves_no_temp(tmp_path, monkeypatch):
    from credential_guard.target_catalog import (
        TARGET_CATALOG_FILENAME,
        TargetCatalogError,
        generate_and_write_target_catalog,
    )

    hermes = _prepare_env(tmp_path, monkeypatch)
    store = _write_store(hermes, _v2_doc(), write_catalog=False)

    real_replace = os.replace

    def boom_replace(src, dst):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(os, "replace", boom_replace)
    with pytest.raises(TargetCatalogError):
        generate_and_write_target_catalog(store)
    leftovers = [
        p.name
        for p in store.iterdir()
        if p.name.startswith(".cg-targets") or p.name.endswith(".tmp")
    ]
    assert leftovers == []
    assert not (store / TARGET_CATALOG_FILENAME).exists()
    monkeypatch.setattr(os, "replace", real_replace)


def test_knife3_replace_config_and_refresh_targets_api(tmp_path, monkeypatch):
    from credential_guard.target_catalog import (
        TARGET_CATALOG_FILENAME,
        replace_config_and_refresh_targets,
    )

    hermes = _prepare_env(tmp_path, monkeypatch)
    store = hermes / "credential-guard"
    store.mkdir(parents=True)
    os.chmod(store, 0o700)
    # Seed an empty valid config so store is usable.
    empty = {"version": 2, "credentials": {}, "bindings": {}}
    (store / CONFIG_FILENAME).write_text(json.dumps(empty), encoding="utf-8")
    os.chmod(store / CONFIG_FILENAME, 0o600)

    new_text = json.dumps(_v2_doc(), ensure_ascii=False, sort_keys=True)
    replace_config_and_refresh_targets(store, new_text)
    loaded = json.loads((store / CONFIG_FILENAME).read_text(encoding="utf-8"))
    assert "ci-token" in loaded["credentials"]
    cat = json.loads((store / TARGET_CATALOG_FILENAME).read_text(encoding="utf-8"))
    assert "ci-api" in cat["bindings"]
    assert cat["source_identity"] == _identity_from_path(store / CONFIG_FILENAME)


def test_knife3_generate_cooperative_writer_no_mixed_identity(tmp_path, monkeypatch):
    """Generate must not emit old-body/new-identity sidecar under cooperative writers."""
    from credential_guard.config_lock import (
        _thread_state,
        exclusive_atomic_replace_config,
    )
    from credential_guard import target_catalog as tc
    from credential_guard.target_catalog import (
        TARGET_CATALOG_FILENAME,
        generate_and_write_target_catalog,
        load_safe_bindings_from_sidecar,
    )

    hermes = _prepare_env(tmp_path, monkeypatch)
    store = _write_store(hermes, _v2_doc(), write_catalog=False)

    doc_b = {
        "version": 2,
        "credentials": {
            "other-token": {"type": "token", "value": "decoy-other-xyz78901"},
        },
        "bindings": {
            "other-api": {
                "type": "http",
                "credential_ref": "other-token",
                "target": {
                    "scheme": "https",
                    "host": "other.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET"],
                    "allowed_paths": ["/health"],
                },
                "inject": {"type": "bearer", "location": "authorization_header"},
                "approval": "required",
            }
        },
    }
    b_text = json.dumps(doc_b, ensure_ascii=False, sort_keys=True)

    real_fi = tc._file_identity
    injected = {"done": False}

    def hooked_fi(path):
        # Deterministic cooperative TOCTOU: only possible when generate does not
        # hold the shared config lock across load→identity.
        if not injected["done"] and int(getattr(_thread_state, "depth", 0) or 0) == 0:
            injected["done"] = True
            exclusive_atomic_replace_config(store, b_text, timeout_seconds=5.0)
        return real_fi(path)

    monkeypatch.setattr(tc, "_file_identity", hooked_fi)
    generate_and_write_target_catalog(store)

    cfg_path = store / CONFIG_FILENAME
    current_doc = json.loads(cfg_path.read_text(encoding="utf-8"))
    current_names = set(current_doc["bindings"])
    cat = json.loads((store / TARGET_CATALOG_FILENAME).read_text(encoding="utf-8"))
    # Never accept a catalog whose identity matches the live config while its
    # binding set still reflects a different body.
    if cat["source_identity"] == _identity_from_path(cfg_path):
        assert set(cat["bindings"]) == current_names

    bindings = load_safe_bindings_from_sidecar(store)
    if bindings is not None:
        assert set(bindings) == current_names


def test_knife3_register_cooperative_writer_identity_recheck(tmp_path, monkeypatch):
    """Identity before≠after during sidecar read must force static fallback."""
    from contextlib import contextmanager

    from credential_guard.config_lock import exclusive_atomic_replace_config
    from credential_guard import target_catalog as tc

    hermes = _prepare_env(tmp_path, monkeypatch)
    store = _write_store(hermes, _v2_doc())

    doc_b = {
        "version": 2,
        "credentials": {
            "other-token": {"type": "token", "value": "decoy-other-xyz78901"},
        },
        "bindings": {},
    }
    b_text = json.dumps(doc_b, ensure_ascii=False, sort_keys=True)

    # Isolate the before/after recheck from the shared-lock critical section:
    # a cooperative writer still mutates under exclusive replace in the read gap.
    @contextmanager
    def _noop_shared_lock(_store_dir, **_kwargs):
        yield

    monkeypatch.setattr(tc, "shared_config_lock", _noop_shared_lock, raising=False)

    real_open = tc._open_and_read_catalog
    injected = {"done": False}

    def hooked_open(path):
        if not injected["done"]:
            injected["done"] = True
            exclusive_atomic_replace_config(store, b_text, timeout_seconds=5.0)
        return real_open(path)

    monkeypatch.setattr(tc, "_open_and_read_catalog", hooked_open)

    ctx = _RegisterCaptureCtx()
    register(ctx)
    descs = _tool_descs(ctx)
    assert descs["http_credential_request"] == HTTP_STATIC
    assert descs["credential_process_run"] == PROCESS_STATIC
    assert "ci-api" not in descs["http_credential_request"]


def test_knife3_shared_lock_concurrency_bounded_no_deadlock(tmp_path, monkeypatch):
    """Normal concurrent generate + load must complete within a bounded wait."""
    import threading

    from credential_guard.target_catalog import (
        generate_and_write_target_catalog,
        load_safe_bindings_from_sidecar,
    )

    hermes = _prepare_env(tmp_path, monkeypatch)
    store = _write_store(hermes, _v2_doc(), write_catalog=False)
    errors: list[BaseException] = []

    def gen():
        try:
            generate_and_write_target_catalog(store)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def load():
        try:
            load_safe_bindings_from_sidecar(store)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=gen) for _ in range(2)] + [
        threading.Thread(target=load) for _ in range(2)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)
        assert not t.is_alive()
    assert errors == [], errors
    assert load_safe_bindings_from_sidecar(store) is not None


# ---------------------------------------------------------------------------
# Knife 4: partial-commit semantics
# ---------------------------------------------------------------------------


def test_knife4_replace_precommit_failure_keeps_old_config(tmp_path, monkeypatch):
    """Parse/schema failure before replace must not commit and must not be partial."""
    from credential_guard.target_catalog import (
        TARGET_CATALOG_FILENAME,
        TargetCatalogPartialCommitError,
        replace_config_and_refresh_targets,
    )

    hermes = _prepare_env(tmp_path, monkeypatch)
    store = _write_store(hermes, _v2_doc())
    old_cfg = (store / CONFIG_FILENAME).read_bytes()
    old_cat = (store / TARGET_CATALOG_FILENAME).read_bytes()

    with pytest.raises(ConfigError) as ei:
        replace_config_and_refresh_targets(store, "{not-json")
    assert not isinstance(ei.value, TargetCatalogPartialCommitError)
    assert ei.value.code == "CONFIG_INVALID_JSON"
    assert (store / CONFIG_FILENAME).read_bytes() == old_cfg
    assert (store / TARGET_CATALOG_FILENAME).read_bytes() == old_cat


def test_knife4_replace_partial_commit_when_sidecar_fails(tmp_path, monkeypatch):
    """Config committed + catalog failure → fixed partial-commit error; stale fallback."""
    from credential_guard.target_catalog import (
        TARGET_CATALOG_FILENAME,
        TargetCatalogPartialCommitError,
        generate_and_write_target_catalog,
        load_safe_bindings_from_sidecar,
        replace_config_and_refresh_targets,
    )

    hermes = _prepare_env(tmp_path, monkeypatch)
    store = _write_store(hermes, {"version": 2, "credentials": {}, "bindings": {}})
    # Seed a catalog matching the empty config.
    generate_and_write_target_catalog(store)
    old_cat = (store / TARGET_CATALOG_FILENAME).read_bytes()

    def boom(_store):
        raise OSError("simulated catalog write failure")

    monkeypatch.setattr(
        "credential_guard.target_catalog.generate_and_write_target_catalog",
        boom,
    )

    new_text = json.dumps(_v2_doc(), ensure_ascii=False, sort_keys=True)
    with pytest.raises(TargetCatalogPartialCommitError) as ei:
        replace_config_and_refresh_targets(store, new_text)
    assert ei.value.code == "CONFIG_COMMITTED_TARGET_CATALOG_UNAVAILABLE"
    blob = f"{type(ei.value).__name__}:{ei.value!s}:{ei.value!r}"
    assert "simulated" not in blob
    assert str(store) not in blob
    assert "decoy" not in blob
    assert "ci-token" not in blob
    assert "/" not in str(ei.value)

    # Main config is the new committed body.
    loaded = json.loads((store / CONFIG_FILENAME).read_text(encoding="utf-8"))
    assert "ci-token" in loaded["credentials"]
    # Old sidecar bytes may remain but must be identity-stale.
    assert (store / TARGET_CATALOG_FILENAME).read_bytes() == old_cat
    assert load_safe_bindings_from_sidecar(store) is None


def test_knife4_dir_fsync_best_effort_safe_fallback_only(tmp_path, monkeypatch):
    """Directory fsync failure must not claim durability; catalog may still exist."""
    from credential_guard.target_catalog import (
        TARGET_CATALOG_FILENAME,
        generate_and_write_target_catalog,
    )

    hermes = _prepare_env(tmp_path, monkeypatch)
    store = _write_store(hermes, _v2_doc(), write_catalog=False)

    real_fsync = os.fsync
    calls = {"n": 0}

    def flaky_fsync(fd):
        calls["n"] += 1
        # Second fsync is the directory fd in atomic_write_catalog.
        if calls["n"] >= 2:
            raise OSError("simulated dir fsync failure")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", flaky_fsync)
    generate_and_write_target_catalog(store)  # must not raise
    assert (store / TARGET_CATALOG_FILENAME).is_file()


# ---------------------------------------------------------------------------
# Knife 5: consecutive register clears stale registration state
# ---------------------------------------------------------------------------


def test_knife5_consecutive_register_clears_stale_catalog(tmp_path, monkeypatch):
    """Publish runtime A → valid register → destroy sidecar → register → static.

    Presses the PREPARED_INVALID branch while a prior RuntimeView remains live
    (no runtime reset). Registration must not fall back to RuntimeView.
    """
    from credential_guard.runtime_config import load_and_publish_runtime
    from credential_guard.target_catalog import (
        TARGET_CATALOG_FILENAME,
        get_registration_bindings,
    )

    hermes = _prepare_env(tmp_path, monkeypatch)
    store = _write_store(hermes, _v2_doc())
    # Keep a published scrubbed RuntimeView with target A alive across registers.
    load_and_publish_runtime(store / CONFIG_FILENAME)
    view = get_runtime_view()
    assert "ci-api" in view.bindings
    assert "report-job" in view.bindings

    ctx1 = _RegisterCaptureCtx()
    register(ctx1)
    descs1 = _tool_descs(ctx1)
    assert "ci-api" in descs1["http_credential_request"]
    assert get_registration_bindings() is not None
    # Runtime must still be the same published view (register never resets it).
    assert "ci-api" in get_runtime_view().bindings

    # Production sequence: no reset_registration_catalog_for_tests() / no runtime reset.
    (store / TARGET_CATALOG_FILENAME).unlink()

    ctx2 = _RegisterCaptureCtx()
    register(ctx2)
    descs2 = _tool_descs(ctx2)
    assert descs2["http_credential_request"] == HTTP_STATIC
    assert descs2["credential_process_run"] == PROCESS_STATIC
    assert "ci-api" not in descs2["http_credential_request"]
    assert "report-job" not in descs2["credential_process_run"]
    assert "<CREDENTIAL:ci-token>" not in descs2["http_credential_request"]
    assert "<CREDENTIAL:report-token>" not in descs2["credential_process_run"]
    assert get_registration_bindings() is None
    # RuntimeView A remains published — proving static came from isolation, not absence.
    assert "ci-api" in get_runtime_view().bindings


# ---------------------------------------------------------------------------
# Registration state isolation from published RuntimeView
# ---------------------------------------------------------------------------


def _runtime_a_doc() -> dict[str, Any]:
    """Synthetic RuntimeView A: distinctive names, no Profile / real secrets."""
    return {
        "version": 2,
        "credentials": {
            "alpha-token": {"type": "token", "value": "decoy-alpha-tok-min8chars"},
            "beta-token": {"type": "token", "value": "decoy-beta-tok-min8charsx"},
        },
        "bindings": {
            "alpha-api": {
                "type": "http",
                "credential_ref": "alpha-token",
                "target": {
                    "scheme": "https",
                    "host": "alpha.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET"],
                    "allowed_paths": ["/alpha"],
                },
                "inject": {"type": "bearer", "location": "authorization_header"},
                "approval": "required",
            },
            "beta-job": {
                "type": "process_env",
                "credential_ref": "beta-token",
                "program": "/usr/local/bin/beta-cli",
                "argv": ["/usr/local/bin/beta-cli"],
                "env_name": "BETA_TOKEN",
                "timeout_seconds": 10,
                "max_stdout_bytes": 4096,
                "max_stderr_bytes": 4096,
                "approval": "required",
            },
        },
    }


@pytest.mark.parametrize("sidecar_mode", ["missing", "invalid_json", "stale_identity"])
def test_register_prepared_invalid_ignores_published_runtime_view(
    tmp_path, monkeypatch, sidecar_mode
):
    """After publish(Runtime A), bad sidecar + register must be pure static.

    PREPARED_INVALID must not fall back to get_runtime_view().bindings.
    """
    from credential_guard.runtime_config import load_and_publish_runtime
    from credential_guard.target_catalog import TARGET_CATALOG_FILENAME

    hermes = _prepare_env(tmp_path, monkeypatch)
    doc = _runtime_a_doc()
    store = _write_store(hermes, doc)
    load_and_publish_runtime(store / CONFIG_FILENAME)
    view = get_runtime_view()
    assert "alpha-api" in view.bindings
    assert "beta-job" in view.bindings

    cfg = store / CONFIG_FILENAME
    cat = store / TARGET_CATALOG_FILENAME
    if sidecar_mode == "missing":
        cat.unlink()
    elif sidecar_mode == "invalid_json":
        cat.write_text("{not-json", encoding="utf-8")
        os.chmod(cat, 0o600)
    elif sidecar_mode == "stale_identity":
        body = _catalog_doc_for_config(
            cfg,
            bindings={
                "alpha-api": {
                    "type": "http",
                    "credential_ref": "alpha-token",
                    "allowed_methods": ["GET"],
                    "allowed_paths": ["/alpha"],
                },
                "beta-job": {
                    "type": "process_env",
                    "credential_ref": "beta-token",
                },
            },
        )
        body["source_identity"]["mtime_ns"] = int(
            body["source_identity"]["mtime_ns"]
        ) + 1
        cat.write_text(json.dumps(body), encoding="utf-8")
        os.chmod(cat, 0o600)
    else:
        raise AssertionError(sidecar_mode)

    # No reset_runtime_for_tests — Runtime A stays published.
    ctx = _RegisterCaptureCtx()
    register(ctx)
    descs = _tool_descs(ctx)
    assert descs["http_credential_request"] == HTTP_STATIC
    assert descs["credential_process_run"] == PROCESS_STATIC
    joined = descs["http_credential_request"] + descs["credential_process_run"]
    for needle in (
        "alpha-api",
        "beta-job",
        "alpha-token",
        "beta-token",
        "<CREDENTIAL:alpha-token>",
        "<CREDENTIAL:beta-token>",
    ):
        assert needle not in joined
    # Runtime A still live — isolation, not "no runtime".
    assert "alpha-api" in get_runtime_view().bindings


def test_unprepared_schema_builders_may_use_published_runtime_view(
    tmp_path, monkeypatch
):
    """Without prepare_registration_catalog(), schema builders keep RuntimeView fallback."""
    from credential_guard.process_tools import credential_process_run_schema
    from credential_guard.reference_tools import http_credential_request_schema
    from credential_guard.runtime_config import load_and_publish_runtime
    from credential_guard.target_catalog import (
        get_registration_bindings,
        reset_registration_catalog_for_tests,
    )

    hermes = _prepare_env(tmp_path, monkeypatch)
    store = _write_store(hermes, _runtime_a_doc(), write_catalog=False)
    load_and_publish_runtime(store / CONFIG_FILENAME)
    reset_registration_catalog_for_tests()  # UNPREPARED
    assert get_registration_bindings() is None

    http_desc = http_credential_request_schema()["description"]
    proc_desc = credential_process_run_schema()["description"]
    assert "alpha-api" in http_desc
    assert "<CREDENTIAL:alpha-token>" in http_desc
    assert "beta-job" in proc_desc
    assert "<CREDENTIAL:beta-token>" in proc_desc
    assert http_desc != HTTP_STATIC
    assert proc_desc != PROCESS_STATIC


# ---------------------------------------------------------------------------
# Mutations on /tmp copy
# ---------------------------------------------------------------------------


def test_knife4_mutations_on_tmp_copy():
    """Copy tree mutations must flip load-bearing contracts to RED."""
    with tempfile.TemporaryDirectory(prefix="cg-c5-mut-") as td:
        root = Path(td) / "repo"
        shutil.copytree(
            REPO,
            root,
            ignore=shutil.ignore_patterns(
                ".venv",
                "__pycache__",
                ".git",
                "dist",
                ".pytest_cache",
                "*.pyc",
            ),
            symlinks=True,
        )
        env = {**os.environ, **ENV_BASE, "PYTHONPATH": str(root)}

        def run_tests(*nodes: str) -> subprocess.CompletedProcess:
            return subprocess.run(
                [PY, "-m", "pytest", "-q", "--tb=line", *nodes],
                cwd=str(root),
                env=env,
                capture_output=True,
                text=True,
            )

        # Baseline GREEN for the knife1 + name-collision + stale + schema tests.
        base = run_tests(
            "tests/test_c5_target_catalog.py::test_knife1_register_lists_bindings_without_reading_secrets",
            "tests/test_c5_target_catalog.py::test_knife2_insecure_or_stale_catalog_static_fallback",
            "tests/test_c5c7_usability.py::test_c5_config_rejects_credential_name_eq_other_token_value",
            "tests/test_c5_target_catalog.py::test_knife2_valid_catalog_dynamic_list_no_forbidden_fields",
        )
        assert base.returncode == 0, base.stdout + base.stderr

        init_py = root / "credential_guard" / "__init__.py"
        text = init_py.read_text(encoding="utf-8")
        # Mutation A: register again publishes from disk (reads secrets).
        mutated = text.replace(
            "from .target_catalog import prepare_registration_catalog",
            "from .runtime_config import ensure_published_from_disk\n"
            "from .target_catalog import prepare_registration_catalog",
        ).replace(
            "prepare_registration_catalog()",
            "ensure_published_from_disk()\n    prepare_registration_catalog()",
        )
        assert mutated != text
        init_py.write_text(mutated, encoding="utf-8")
        r_a = run_tests(
            "tests/test_c5_target_catalog.py::test_knife1_register_lists_bindings_without_reading_secrets",
        )
        assert r_a.returncode != 0, r_a.stdout + r_a.stderr
        init_py.write_text(text, encoding="utf-8")

        # Mutation B: drop source identity compare.
        cat_py = root / "credential_guard" / "target_catalog.py"
        cat_text = cat_py.read_text(encoding="utf-8")
        mut_b = cat_text.replace(
            "if parsed[\"source_identity\"] != before:",
            "if False and parsed[\"source_identity\"] != before:",
        )
        assert mut_b != cat_text
        cat_py.write_text(mut_b, encoding="utf-8")
        r_b = run_tests(
            "tests/test_c5_target_catalog.py::test_knife2_insecure_or_stale_catalog_static_fallback"
            "[stale_identity]",
        )
        assert r_b.returncode != 0, r_b.stdout + r_b.stderr
        cat_py.write_text(cat_text, encoding="utf-8")

        # Mutation C: allow extra fields in sidecar schema.
        mut_c = cat_text.replace(
            "if set(entry.keys()) - _HTTP_BINDING_FIELDS:",
            "if False and set(entry.keys()) - _HTTP_BINDING_FIELDS:",
        ).replace(
            "if set(entry.keys()) != _HTTP_BINDING_FIELDS:",
            "if False and set(entry.keys()) != _HTTP_BINDING_FIELDS:",
        )
        assert mut_c != cat_text
        cat_py.write_text(mut_c, encoding="utf-8")
        r_c = run_tests(
            "tests/test_c5_target_catalog.py::test_knife2_insecure_or_stale_catalog_static_fallback"
            "[extra_binding]",
        )
        assert r_c.returncode != 0, r_c.stdout + r_c.stderr
        cat_py.write_text(cat_text, encoding="utf-8")

        # Mutation D: drop name↔secret collision check.
        cfg_py = root / "credential_guard" / "config.py"
        cfg_text = cfg_py.read_text(encoding="utf-8")
        mut_d = cfg_text.replace(
            "if set(names) & set(seen_secrets.keys()):",
            "if False and set(names) & set(seen_secrets.keys()):",
        )
        assert mut_d != cfg_text
        cfg_py.write_text(mut_d, encoding="utf-8")
        r_d = run_tests(
            "tests/test_c5c7_usability.py::test_c5_config_rejects_credential_name_eq_other_token_value",
        )
        assert r_d.returncode != 0, r_d.stdout + r_d.stderr
        cfg_py.write_text(cfg_text, encoding="utf-8")

        # Mutation E: PREPARED_INVALID falls back to RuntimeView (isolation regress).
        ref_py = root / "credential_guard" / "reference_tools.py"
        proc_py = root / "credential_guard" / "process_tools.py"
        ref_text = ref_py.read_text(encoding="utf-8")
        proc_text = proc_py.read_text(encoding="utf-8")
        bad_block = (
            "        prepared, bindings = resolve_registration_catalog()\n"
            "        if prepared:\n"
            "            # READY (bindings mapping) or PREPARED_INVALID (None → static).\n"
            "            # Never fall through to RuntimeView after prepare().\n"
            "            return bindings"
        )
        restored_block = (
            "        prepared, bindings = resolve_registration_catalog()\n"
            "        if prepared and bindings is not None:\n"
            "            return bindings\n"
            "        # MUTATION: PREPARED_INVALID falls through to RuntimeView.\n"
            "        pass"
        )
        mut_ref = ref_text.replace(bad_block, restored_block)
        mut_proc = proc_text.replace(bad_block, restored_block)
        assert mut_ref != ref_text
        assert mut_proc != proc_text
        ref_py.write_text(mut_ref, encoding="utf-8")
        proc_py.write_text(mut_proc, encoding="utf-8")
        r_e = run_tests(
            "tests/test_c5_target_catalog.py::"
            "test_register_prepared_invalid_ignores_published_runtime_view[missing]",
            "tests/test_c5_target_catalog.py::"
            "test_knife5_consecutive_register_clears_stale_catalog",
        )
        assert r_e.returncode != 0, r_e.stdout + r_e.stderr
        ref_py.write_text(ref_text, encoding="utf-8")
        proc_py.write_text(proc_text, encoding="utf-8")
