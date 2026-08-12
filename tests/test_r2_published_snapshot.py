"""R2 published-snapshot reuse: no config open/read after R1B publish.

Proves the prior metadata-only loader is invalid: it still open/reads and
parses secret fields. Correct R2 path uses get_runtime_view() + lstat only.
"""

from __future__ import annotations

import builtins
import json
import os
import secrets
import types
from pathlib import Path
from typing import Any, Dict, List

import pytest

from credential_guard.approval import on_pre_tool_call
from credential_guard.config import CONFIG_FILENAME
from credential_guard.injection_plan import PlanState
from credential_guard.runtime_config import (
    HTTP_REFERENCE_TOOL,
    get_execution_secret_resolve_count,
    load_and_publish_runtime,
    reset_execution_secret_resolve_count_for_tests,
    reset_runtime_for_tests,
)
from credential_guard.tool_execution import RUNTIME_ADAPTER_NOT_READY, on_tool_execution
from credential_guard.reference_tools import handle_http_credential_request
from credential_guard.tool_request import (
    get_invalid_marker,
    get_plan_store,
    on_tool_request,
    reset_tool_request_state_for_tests,
)

REPO = Path(__file__).resolve().parents[1]
R2_PROD_MODULES = (
    REPO / "credential_guard" / "tool_request.py",
    REPO / "credential_guard" / "approval.py",
    REPO / "credential_guard" / "tool_execution.py",
)


def _write_cfg(store: Path, token: str) -> Path:
    doc = {
        "version": 2,
        "credentials": {"jenkins-token": {"type": "token", "value": token}},
        "bindings": {
            "jenkins-production": {
                "type": "http",
                "credential_ref": "jenkins-token",
                "target": {
                    "scheme": "https",
                    "host": "jenkins.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                    "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
                },
                "inject": {"type": "bearer", "location": "authorization_header"},
                "approval": "required",
            }
        },
    }
    store.mkdir(parents=True, exist_ok=True)
    os.chmod(store, 0o700)
    path = store / CONFIG_FILENAME
    path.write_text(json.dumps(doc), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _ref_args() -> Dict[str, Any]:
    return {
        "target": "jenkins-production",
        "method": "POST",
        "path": "/job/project-x/build",
        "credential": "<CREDENTIAL:jenkins-token>",
    }


@pytest.fixture
def published_env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    store = hermes / "credential-guard"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    reset_runtime_for_tests()
    reset_tool_request_state_for_tests()
    token = "CG_R2SNAP_" + secrets.token_hex(12)
    cfg_path = _write_cfg(store, token)

    hermes_cli = types.ModuleType("hermes_cli")
    cfg_mod = types.ModuleType("hermes_cli.config")
    cfg_mod.load_config_readonly = lambda: {
        "approvals": {"mode": "manual", "timeout": 300}
    }
    hermes_cli.config = cfg_mod
    tools_mod = types.ModuleType("tools")
    approval_mod = types.ModuleType("tools.approval")
    approval_mod.is_approval_bypass_active_for_session = lambda sid: False
    approval_mod._get_approval_timeout = lambda: 300
    tools_mod.approval = approval_mod
    import sys

    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.config", cfg_mod)
    monkeypatch.setitem(sys.modules, "tools", tools_mod)
    monkeypatch.setitem(sys.modules, "tools.approval", approval_mod)

    # Simulate R1B Provider egress publish before any tool_request.
    view = load_and_publish_runtime()
    reset_execution_secret_resolve_count_for_tests()
    from credential_guard.tool_execution import (
        reset_http_adapter_observe_for_tests,
        set_http_transport_override_for_tests,
    )

    reset_http_adapter_observe_for_tests()
    set_http_transport_override_for_tests(
        lambda req: {
            "status": 201,
            "headers": {"content-type": "application/json"},
            "body": b'{"queued":true}',
        }
    )
    yield {
        "store": store,
        "token": token,
        "cfg_path": cfg_path,
        "view": view,
    }
    set_http_transport_override_for_tests(None)
    reset_tool_request_state_for_tests()
    reset_runtime_for_tests()


def _install_exploding_config_reads(monkeypatch) -> List[str]:
    """After R1B publish, any config body open/read must explode.

    Catches config._open_and_read, already-bound runtime_metadata._open_and_read,
    os.open, builtins.open, Path.read_text/read_bytes, and load_runtime_metadata.
    """
    hits: List[str] = []

    def _boom(label: str):
        def _inner(*_a, **_k):
            hits.append(label)
            raise AssertionError(f"CONFIG_BODY_READ_DURING_R2:{label}")

        return _inner

    import credential_guard.config as config_mod

    monkeypatch.setattr(config_mod, "_open_and_read", _boom("_open_and_read"))

    try:
        import credential_guard.runtime_metadata as meta_mod

        monkeypatch.setattr(
            meta_mod, "_open_and_read", _boom("runtime_metadata._open_and_read")
        )
        monkeypatch.setattr(
            meta_mod, "load_runtime_metadata", _boom("load_runtime_metadata")
        )
    except ImportError:
        pass

    real_os_open = os.open

    def _guarded_os_open(path, flags, *args, **kwargs):
        path_s = str(path)
        if path_s.endswith(CONFIG_FILENAME) and not (flags & os.O_WRONLY):
            # O_RDONLY body open — lstat is separate and allowed.
            hits.append("os.open")
            raise AssertionError("CONFIG_BODY_READ_DURING_R2:os.open")
        return real_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", _guarded_os_open)

    real_open = builtins.open

    def _guarded_open(file, mode="r", *args, **kwargs):
        path_s = str(file)
        if path_s.endswith(CONFIG_FILENAME) and any(
            c in str(mode) for c in ("r", "a", "+")
        ):
            hits.append("builtins.open")
            raise AssertionError("CONFIG_BODY_READ_DURING_R2:builtins.open")
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _guarded_open)

    real_read_text = Path.read_text
    real_read_bytes = Path.read_bytes

    def _guarded_read_text(self, *a, **k):
        if self.name == CONFIG_FILENAME:
            hits.append("read_text")
            raise AssertionError("CONFIG_BODY_READ_DURING_R2:read_text")
        return real_read_text(self, *a, **k)

    def _guarded_read_bytes(self, *a, **k):
        if self.name == CONFIG_FILENAME:
            hits.append("read_bytes")
            raise AssertionError("CONFIG_BODY_READ_DURING_R2:read_bytes")
        return real_read_bytes(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", _guarded_read_text)
    monkeypatch.setattr(Path, "read_bytes", _guarded_read_bytes)
    return hits


def test_red_tool_request_must_not_open_config_after_publish(
    published_env, monkeypatch
):
    hits = _install_exploding_config_reads(monkeypatch)
    before = get_execution_secret_resolve_count()
    out = on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_ref_args(),
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-snap-req",
    )
    assert out["args"]["credential"] == "<CREDENTIAL:jenkins-token>"
    plan = get_plan_store().lookup("s1", "tc-snap-req")
    assert plan is not None
    assert plan.state is PlanState.ANALYZED
    assert hits == [], f"R2 tool_request read config body: {hits}"
    assert get_execution_secret_resolve_count() == before


def test_red_pre_tool_call_must_not_open_config_after_publish(
    published_env, monkeypatch
):
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_ref_args(),
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-snap-pre",
    )
    hits = _install_exploding_config_reads(monkeypatch)
    before = get_execution_secret_resolve_count()
    out = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_ref_args(),
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-snap-pre",
    )
    assert out is not None
    assert out["action"] == "approve"
    assert hits == [], f"R2 pre_tool_call read config body: {hits}"
    assert get_execution_secret_resolve_count() == before


def test_red_tool_execution_must_not_open_config_after_publish(
    published_env, monkeypatch
):
    args = _ref_args()
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-snap-exec",
    )
    assert (
        on_pre_tool_call(
            tool_name=HTTP_REFERENCE_TOOL,
            args=args,
            session_id="s1",
            turn_id="t1",
            tool_call_id="tc-snap-exec",
        )["action"]
        == "approve"
    )
    hits = _install_exploding_config_reads(monkeypatch)
    before = get_execution_secret_resolve_count()
    calls: List[Any] = []
    out = on_tool_execution(
        HTTP_REFERENCE_TOOL,
        args,
        lambda a: calls.append(a) or handle_http_credential_request(a),
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-snap-exec",
    )
    assert len(calls) <= 1
    data = json.loads(out)
    assert data.get("ok") is True
    assert hits == [], f"R2 tool_execution read config body: {hits}"
    assert get_execution_secret_resolve_count() == before
    assert get_plan_store().lookup("s1", "tc-snap-exec").state is PlanState.CONSUMED


def test_red_lstat_allowed_and_identity_mismatch_blocks(
    published_env, monkeypatch
):
    args = _ref_args()
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-snap-lstat",
    )
    assert (
        on_pre_tool_call(
            tool_name=HTTP_REFERENCE_TOOL,
            args=args,
            session_id="s1",
            turn_id="t1",
            tool_call_id="tc-snap-lstat",
        )["action"]
        == "approve"
    )
    # Rewrite config → new mtime/size/inode; R2 must see via lstat only.
    _write_cfg(published_env["store"], "Z" * len(published_env["token"]))
    hits = _install_exploding_config_reads(monkeypatch)
    lstat_calls = {"n": 0}
    real_lstat = Path.lstat

    def _counting_lstat(self):
        if self.name == CONFIG_FILENAME:
            lstat_calls["n"] += 1
        return real_lstat(self)

    monkeypatch.setattr(Path, "lstat", _counting_lstat)
    calls: List[Any] = []
    out = on_tool_execution(
        HTTP_REFERENCE_TOOL,
        args,
        lambda a: calls.append(a) or handle_http_credential_request(a),
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-snap-lstat",
    )
    assert len(calls) <= 1
    assert RUNTIME_ADAPTER_NOT_READY in out
    assert hits == []
    assert lstat_calls["n"] >= 1
    plan = get_plan_store().lookup("s1", "tc-snap-lstat")
    assert plan is not None
    assert plan.state is PlanState.INVALIDATED


def test_red_lstat_to_consume_race_must_invalidate(published_env, monkeypatch):
    """Deterministic race: mutate config after first identity read, before consume."""
    args = _ref_args()
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-snap-race",
    )
    assert (
        on_pre_tool_call(
            tool_name=HTTP_REFERENCE_TOOL,
            args=args,
            session_id="s1",
            turn_id="t1",
            tool_call_id="tc-snap-race",
        )["action"]
        == "approve"
    )

    from credential_guard import runtime_config as rc

    # Prefer public helper once GREEN; fall back to Path.lstat seam for RED.
    identity_fn_name = "get_current_config_file_identity"
    if hasattr(rc, identity_fn_name):
        real_ident = getattr(rc, identity_fn_name)
        calls = {"n": 0}

        def _race_ident(*a, **k):
            calls["n"] += 1
            ident = real_ident(*a, **k)
            if calls["n"] == 1:
                _write_cfg(published_env["store"], "R" * len(published_env["token"]))
            return ident

        monkeypatch.setattr(rc, identity_fn_name, _race_ident)
    else:
        # RED against metadata loader: mutate between metadata load and consume.
        real_consume = get_plan_store().consume
        mutated = {"done": False}

        def _race_consume(session_id, tool_call_id):
            if not mutated["done"]:
                mutated["done"] = True
                _write_cfg(published_env["store"], "R" * len(published_env["token"]))
            return real_consume(session_id, tool_call_id)

        monkeypatch.setattr(get_plan_store(), "consume", _race_consume)

    hits = _install_exploding_config_reads(monkeypatch)
    calls_out: List[Any] = []
    out = on_tool_execution(
        HTTP_REFERENCE_TOOL,
        args,
        lambda a: calls_out.append(a) or handle_http_credential_request(a),
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-snap-race",
    )
    assert len(calls_out) <= 1
    assert RUNTIME_ADAPTER_NOT_READY in out
    assert hits == []
    plan = get_plan_store().lookup("s1", "tc-snap-race")
    assert plan is not None
    assert plan.state is PlanState.INVALIDATED, (
        f"race must INVALIDATE, got {plan.state}"
    )


def test_red_unpublished_runtime_blocks_reference_without_loading(tmp_path, monkeypatch):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    store = hermes / "credential-guard"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    reset_runtime_for_tests()
    reset_tool_request_state_for_tests()
    token = "CG_R2UNPUB_" + secrets.token_hex(8)
    _write_cfg(store, token)
    # Deliberately do NOT publish.
    hits = _install_exploding_config_reads(monkeypatch)

    out = on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_ref_args(),
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-unpub",
    )
    assert get_plan_store().lookup("s1", "tc-unpub") is None
    assert get_invalid_marker("s1", "tc-unpub") is not None
    assert hits == [], f"unpublished path must not load config: {hits}"
    assert out["trace"]["reason"] in {"runtime_unavailable", "reference_rejected"}


def test_red_unpublished_plain_tool_still_passthrough(tmp_path, monkeypatch):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    reset_runtime_for_tests()
    reset_tool_request_state_for_tests()
    # No publish, no config file required for plain tools.
    hits = _install_exploding_config_reads(monkeypatch)
    args = {"path": "/tmp/plain.txt", "content": "hello"}
    out = on_tool_request(
        tool_name="write_file",
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-plain",
    )
    assert get_plan_store().lookup("s1", "tc-plain") is None
    assert get_invalid_marker("s1", "tc-plain") is None
    assert out["trace"]["reason"] in {"passthrough", "no_reference"}
    assert hits == []

    calls: List[Any] = []
    result = on_tool_execution(
        "write_file",
        args,
        lambda a: calls.append(a) or {"ok": True},
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-plain",
    )
    assert calls == [args]
    assert result == {"ok": True}


def test_red_missing_turn_id_blocks_reference(published_env):
    out = on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_ref_args(),
        session_id="s1",
        turn_id="",
        tool_call_id="tc-no-turn",
    )
    assert get_plan_store().lookup("s1", "tc-no-turn") is None
    assert get_invalid_marker("s1", "tc-no-turn") is not None
    assert out["trace"]["reason"] in {"missing_identity", "reference_rejected"}


def test_red_cross_turn_replay_blocked(published_env):
    args = _ref_args()
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-xturn",
    )
    assert (
        on_pre_tool_call(
            tool_name=HTTP_REFERENCE_TOOL,
            args=args,
            session_id="s1",
            turn_id="t1",
            tool_call_id="tc-xturn",
        )["action"]
        == "approve"
    )
    calls: List[Any] = []
    out = on_tool_execution(
        HTTP_REFERENCE_TOOL,
        args,
        lambda a: calls.append(a) or handle_http_credential_request(a),
        session_id="s1",
        turn_id="t2",  # different turn
        tool_call_id="tc-xturn",
    )
    assert len(calls) <= 1
    assert RUNTIME_ADAPTER_NOT_READY in out
    plan = get_plan_store().lookup("s1", "tc-xturn")
    assert plan is not None
    assert plan.state is PlanState.INVALIDATED


def test_red_ttl_must_derive_from_hermes_timeout_fail_closed(published_env, monkeypatch):
    """TTL must come from Hermes approval timeout; invalid/missing → fail closed."""
    from credential_guard import injection_plan as ip

    # Invalid timeout type must not silently fall back to 300.
    import tools.approval as approval_mod

    monkeypatch.setattr(approval_mod, "_get_approval_timeout", lambda: "nope")
    # Also poison public readonly path.
    import hermes_cli.config as cfg_mod

    monkeypatch.setattr(
        cfg_mod,
        "load_config_readonly",
        lambda: {"approvals": {"mode": "manual", "timeout": "nope"}},
    )

    if hasattr(ip, "resolve_plan_ttl_seconds"):
        with pytest.raises(Exception):
            ip.resolve_plan_ttl_seconds()

    out = on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_ref_args(),
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-ttl-bad",
    )
    assert get_plan_store().lookup("s1", "tc-ttl-bad") is None
    assert get_invalid_marker("s1", "tc-ttl-bad") is not None
    assert out["trace"]["reason"] in {
        "ttl_unavailable",
        "create_failed",
        "reference_rejected",
        "missing_identity",
    }


def test_structural_runtime_metadata_module_deleted():
    meta = REPO / "credential_guard" / "runtime_metadata.py"
    assert not meta.exists(), "runtime_metadata.py must be deleted (misleading dead code)"


def test_structural_r2_modules_do_not_import_runtime_metadata():
    for path in R2_PROD_MODULES:
        text = path.read_text(encoding="utf-8")
        assert "runtime_metadata" not in text, f"{path.name} still references runtime_metadata"
        assert "load_runtime_metadata" not in text
