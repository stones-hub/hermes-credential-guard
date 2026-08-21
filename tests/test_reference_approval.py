"""R2D: reference approval (pre_tool_call) and tool_execution gate."""

from __future__ import annotations

import json
import os
import secrets
import types
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from credential_guard.approval import on_pre_tool_call, reference_approval_posture_allows
from credential_guard.config import CONFIG_FILENAME
from credential_guard.injection_plan import PlanState
from credential_guard.runtime_config import (
    HTTP_REFERENCE_TOOL,
    load_and_publish_runtime,
    reset_runtime_for_tests,
)
from credential_guard.tool_execution import PLAN_NOT_PENDING, on_tool_execution
from credential_guard.reference_tools import handle_http_credential_request
from credential_guard.tool_request import (
    get_plan_store,
    on_tool_request,
    reset_tool_request_state_for_tests,
)

def _handler_next(args: Dict[str, Any]) -> str:
    """Simulate host next_call reaching the formal reference handler."""
    return handle_http_credential_request(args)


def _write_cfg(store: Path, token: str) -> None:
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


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    store = hermes / "credential-guard"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    reset_runtime_for_tests()
    reset_tool_request_state_for_tests()
    token = "CG_R2D_" + secrets.token_hex(12)
    _write_cfg(store, token)

    # Hermes posture APIs — default manual / no bypass.
    hermes_cli = types.ModuleType("hermes_cli")
    cfg_mod = types.ModuleType("hermes_cli.config")
    cfg_mod.load_config_readonly = lambda: {"approvals": {"mode": "manual", "timeout": 300}}
    hermes_cli.config = cfg_mod
    tools_mod = types.ModuleType("tools")
    approval_mod = types.ModuleType("tools.approval")
    approval_mod.is_approval_bypass_active_for_session = lambda sid: False
    approval_mod._get_approval_timeout = lambda: 300
    tools_mod.approval = approval_mod
    monkeypatch.setitem(__import__("sys").modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(__import__("sys").modules, "hermes_cli.config", cfg_mod)
    monkeypatch.setitem(__import__("sys").modules, "tools", tools_mod)
    monkeypatch.setitem(__import__("sys").modules, "tools.approval", approval_mod)

    load_and_publish_runtime()
    from credential_guard.tool_execution import (
        set_http_transport_override_for_tests,
        reset_http_adapter_observe_for_tests,
    )
    reset_http_adapter_observe_for_tests()
    set_http_transport_override_for_tests(
        lambda req: {
            "status": 201,
            "headers": {"content-type": "application/json"},
            "body": b'{"queued":true}',
        }
    )
    yield store, token, approval_mod, cfg_mod
    from credential_guard.tool_execution import set_http_transport_override_for_tests as _clr
    _clr(None)
    reset_tool_request_state_for_tests()
    reset_runtime_for_tests()


def _ref_args(**overrides: Any) -> Dict[str, Any]:
    base = {
        "target": "jenkins-production",
        "method": "POST",
        "path": "/job/project-x/build",
        "credential": "<CREDENTIAL:jenkins-token>",
    }
    base.update(overrides)
    return base


def _analyze(session="s1", turn="t1", tc="tc1", tool=HTTP_REFERENCE_TOOL, args=None):
    return on_tool_request(
        tool_name=tool,
        args=args or _ref_args(),
        session_id=session,
        turn_id=turn,
        tool_call_id=tc,
    )


def test_d1_sensitive_path_still_blocks(env):
    store, token, _, _ = env
    target = str(store / CONFIG_FILENAME)
    out = on_pre_tool_call(
        tool_name="read_file",
        args={"path": target},
        session_id="s",
        turn_id="t1",
        tool_call_id="t",
    )
    assert out is not None
    assert out["action"] == "block"


def test_d1_unregistered_tool_gets_no_dedicated_approve(env):
    """Any tool outside the two generic shells mints no approve directive.

    Stated without naming a deleted tool: the plugin only ever approves its
    own registered reference tools, so an arbitrary foreign name is ignored.
    """
    out = on_pre_tool_call(
        tool_name="some_unregistered_host_tool",
        args={"target": "t1", "action": "check_connection"},
        session_id="s",
        turn_id="t1",
        tool_call_id="t",
    )
    assert out is None


def test_d1_no_reference_no_approval(env):
    assert (
        on_pre_tool_call(
            tool_name="write_file",
            args={"path": "/tmp/x", "content": "hi"},
            session_id="s",
            turn_id="t1",
            tool_call_id="t",
        )
        is None
    )


def test_d1_missing_plan_blocks(env):
    out = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_ref_args(),
        session_id="s1",
        turn_id="t1",
        tool_call_id="missing",
    )
    assert out["action"] == "block"


def test_d1_bypass_or_non_manual_blocks(env):
    store, token, approval_mod, cfg_mod = env
    _analyze(tc="tc-yolo")
    approval_mod.is_approval_bypass_active_for_session = lambda sid: True
    out = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_ref_args(),
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-yolo",
    )
    assert out["action"] == "block"

    approval_mod.is_approval_bypass_active_for_session = lambda sid: False
    _analyze(tc="tc-smart")
    cfg_mod.load_config_readonly = lambda: {"approvals": {"mode": "smart"}}
    out2 = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_ref_args(),
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-smart",
    )
    assert out2["action"] == "block"


def test_d1_valid_plan_pending_and_approve(env):
    _analyze(tc="tc-ok")
    out = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_ref_args(),
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-ok",
    )
    assert out["action"] == "approve"
    assert "jenkins-production" in out["message"]
    assert "jenkins-token" in out["message"]
    assert "仅本次" in out["message"]
    assert "工具：http_credential_request" in out["message"]
    assert "操作：POST /job/project-x/build" in out["message"]
    assert "HTTPS Authorization Header" in out["message"]
    assert "https:bearer:authorization_header" not in out["message"]
    plan = get_plan_store().lookup("s1", "tc-ok")
    assert plan.state is PlanState.APPROVAL_PENDING
    assert "jenkins.example" not in out["message"]
    assert plan.nonce not in out["message"]
    assert plan.nonce not in out["rule_key"]
    assert plan.args_digest not in out["rule_key"]
    assert plan.args_digest not in out["message"]


def test_d1_approval_summary_blocks_when_args_mutated(env):
    """Args change after analysis must not generate a digest-mismatched summary."""
    _analyze(tc="tc-mut")
    mutated = _ref_args(path="/job/evil/build")
    out = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=mutated,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-mut",
    )
    assert out["action"] == "block"
    assert "POST /job/evil/build" not in (out.get("message") or "")
    assert "POST /job/project-x/build" not in (out.get("message") or "")


def test_d1_approval_allows_password_substring_in_path(env):
    args = _ref_args(path="/api/reset-password")
    _analyze(tc="tc-pw", args=args)
    out = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-pw",
    )
    assert out["action"] == "approve"
    assert "操作：POST /api/reset-password" in out["message"]
    assert out["message"].count("\n") == 6


def test_d1_approval_blocks_unicode_line_separator_path(env):
    args = _ref_args(path="/job/x\u2028注入方式：forged")
    # Even if somehow analyzed (should fail path validation at approval), block.
    from credential_guard.reference_tools import validate_http_path
    import pytest

    with pytest.raises(ValueError):
        validate_http_path(args["path"])
    _analyze(tc="tc-u2028", args=args)
    out = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-u2028",
    )
    assert out["action"] == "block"


def test_d1_rule_key_unique_per_call(env):
    keys = []
    for i in range(3):
        tc = f"tc-k{i}"
        _analyze(tc=tc)
        out = on_pre_tool_call(
            tool_name=HTTP_REFERENCE_TOOL,
            args=_ref_args(),
            session_id="s1",
                turn_id="t1",
            tool_call_id=tc,
        )
        keys.append(out["rule_key"])
    assert len(set(keys)) == 3


def test_d2_no_reference_next_call_once(env):
    calls: List[Dict[str, Any]] = []

    def nxt(a):
        calls.append(deepcopy(a))
        return {"ok": True, "echo": a}

    result = on_tool_execution(
        "write_file",
        {"path": "/tmp/a"},
        nxt,
        session_id="s1",
        turn_id="t1",
        tool_call_id="plain",
    )
    assert result == {"ok": True, "echo": {"path": "/tmp/a"}}
    assert len(calls) == 1


def test_d2_reference_consumes_and_adapter_not_ready(env):
    _, token, _, _ = env
    args = _ref_args()
    _analyze(tc="tc-exec")
    assert (
        on_pre_tool_call(
            tool_name=HTTP_REFERENCE_TOOL,
            args=args,
            session_id="s1",
            turn_id="t1",
            tool_call_id="tc-exec",
        )["action"]
        == "approve"
    )
    out = on_tool_execution(
        HTTP_REFERENCE_TOOL,
        args,
        _handler_next,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-exec",
    )
    data = json.loads(out)
    assert data.get("ok") is True
    assert data.get("status") == 201
    assert token not in out
    plan = get_plan_store().lookup("s1", "tc-exec")
    assert plan.state is PlanState.CONSUMED


def test_d2_second_call_blocked(env):
    args = _ref_args()
    _analyze(tc="tc-once")
    on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-once",
    )
    on_tool_execution(
        HTTP_REFERENCE_TOOL,
        args,
        _handler_next,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-once",
    )
    calls = []
    out = on_tool_execution(
        HTTP_REFERENCE_TOOL,
        args,
        lambda a: calls.append(a) or "x",
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-once",
    )
    assert json.loads(out)["error"] == PLAN_NOT_PENDING
    assert calls == []


def test_d2_analyzed_allows_next_call_then_invalidates_without_handler(env):
    """Main-agent order: ANALYZED must enter next_call (approval still ahead)."""
    _analyze(tc="tc-nopend")  # ANALYZED only
    calls = []
    out = on_tool_execution(
        HTTP_REFERENCE_TOOL,
        _ref_args(),
        lambda a: calls.append(1) or "no-handler",
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-nopend",
    )
    assert calls == [1]
    assert out == "no-handler"
    plan = get_plan_store().lookup("s1", "tc-nopend")
    assert plan is None or plan.state is PlanState.INVALIDATED


def test_p6_pre_tool_call_must_not_touch_credential_secrets(env, monkeypatch):
    """P6 RED: approval path must not rebuild egress secret registry."""
    from credential_guard import runtime_config as rc
    from credential_guard.config import CredentialGuardConfig

    secret_hits: List[str] = []
    real_build = rc.build_file_egress_registry

    def _counting_build(cfg: CredentialGuardConfig):
        for entry in cfg.credentials.values():
            if "value" in entry:
                secret_hits.append("value")
                _ = entry["value"]
            if "password" in entry:
                secret_hits.append("password")
                _ = entry["password"]
        return real_build(cfg)

    monkeypatch.setattr(rc, "build_file_egress_registry", _counting_build)
    _analyze(tc="tc-p6-appr")
    secret_hits.clear()
    out = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_ref_args(),
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-p6-appr",
    )
    assert out["action"] == "approve"
    assert secret_hits == [], f"approval-path secret field access: {secret_hits}"


def test_p6_tool_execution_must_not_touch_credential_secrets(env, monkeypatch):
    """P6 RED: R2 execution recheck must not read credential values."""
    from credential_guard import runtime_config as rc
    from credential_guard.config import CredentialGuardConfig

    secret_hits: List[str] = []
    real_build = rc.build_file_egress_registry

    def _counting_build(cfg: CredentialGuardConfig):
        for entry in cfg.credentials.values():
            if "value" in entry:
                secret_hits.append("value")
                _ = entry["value"]
            if "password" in entry:
                secret_hits.append("password")
                _ = entry["password"]
        return real_build(cfg)

    monkeypatch.setattr(rc, "build_file_egress_registry", _counting_build)
    args = _ref_args()
    _analyze(tc="tc-p6-exec")
    on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-p6-exec",
    )
    secret_hits.clear()
    out = on_tool_execution(
        HTTP_REFERENCE_TOOL,
        args,
        _handler_next,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-p6-exec",
    )
    assert json.loads(out)["ok"] is True
    assert secret_hits == [], f"execution-path secret field access: {secret_hits}"
