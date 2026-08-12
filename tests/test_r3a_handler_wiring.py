"""R3A Slice A4: formal handler wires resolve + HTTP adapter after consume."""

from __future__ import annotations

import json
import os
import secrets
import types
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List

import pytest

from credential_guard.approval import on_pre_tool_call
from credential_guard.config import CONFIG_FILENAME
from credential_guard.injection_plan import PlanState
from credential_guard.reference_tools import handle_http_credential_request
from credential_guard.runtime_config import (
    HTTP_REFERENCE_TOOL,
    load_and_publish_runtime,
    reset_runtime_for_tests,
)
from credential_guard import runtime_config as rc
from credential_guard.tool_execution import (
    RUNTIME_ADAPTER_NOT_READY,
    get_http_adapter_invoke_count,
    on_tool_execution,
    reset_http_adapter_observe_for_tests,
    set_http_transport_override_for_tests,
)
from credential_guard.tool_request import (
    get_plan_store,
    on_tool_request,
    reset_tool_request_state_for_tests,
)


def _decoy(n: int = 16) -> str:
    return "CG_SYNTHETIC_DECOY_" + secrets.token_hex(n)


def _doc(token: str) -> Dict[str, Any]:
    return {
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
                    "allowed_methods": ["POST"],
                    "allowed_paths": ["/job/project-x/build"],
                },
                "inject": {
                    "type": "bearer",
                    "location": "authorization_header",
                },
                "approval": "required",
            }
        },
    }


def _write(store: Path, doc: Dict[str, Any]) -> None:
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
    reset_http_adapter_observe_for_tests()
    set_http_transport_override_for_tests(None)

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

    token = _decoy()
    _write(store, _doc(token))
    load_and_publish_runtime()
    rc.reset_injection_secret_resolve_count_for_tests()
    yield {"store": store, "token": token}
    set_http_transport_override_for_tests(None)
    reset_http_adapter_observe_for_tests()
    reset_tool_request_state_for_tests()
    reset_runtime_for_tests()


def _args() -> Dict[str, Any]:
    return {
        "target": "jenkins-production",
        "method": "POST",
        "path": "/job/project-x/build",
        "credential": "<CREDENTIAL:jenkins-token>",
    }


def test_a4_approve_resolves_and_runs_adapter_once(env):
    token = env["token"]
    captured: List[Dict[str, Any]] = []

    def fake_transport(req: Dict[str, Any]) -> Dict[str, Any]:
        captured.append(req)
        return {
            "status": 201,
            "headers": {"content-type": "application/json"},
            "body": b'{"queued":true}',
        }

    set_http_transport_override_for_tests(fake_transport)
    args = _args()
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-a4",
    )
    assert (
        on_pre_tool_call(
            tool_name=HTTP_REFERENCE_TOOL,
            args=args,
            session_id="s1",
            turn_id="t1",
            tool_call_id="tc-a4",
        )["action"]
        == "approve"
    )

    def nxt(a):
        return handle_http_credential_request(a)

    out = on_tool_execution(
        HTTP_REFERENCE_TOOL,
        args,
        nxt,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-a4",
    )
    data = json.loads(out)
    assert data["ok"] is True
    assert data["status"] == 201
    assert RUNTIME_ADAPTER_NOT_READY not in out
    assert rc.get_injection_secret_resolve_count() == 1
    assert get_http_adapter_invoke_count() == 1
    assert len(captured) == 1
    assert captured[0]["headers"]["Authorization"] == f"Bearer {token}"
    assert token not in out
    assert get_plan_store().lookup("s1", "tc-a4").state is PlanState.CONSUMED

    # Replay
    before_r = rc.get_injection_secret_resolve_count()
    before_a = get_http_adapter_invoke_count()
    out2 = on_tool_execution(
        HTTP_REFERENCE_TOOL,
        args,
        nxt,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-a4",
    )
    data2 = json.loads(out2)
    assert data2["ok"] is False
    assert rc.get_injection_secret_resolve_count() == before_r
    assert get_http_adapter_invoke_count() == before_a
    assert token not in out2


def test_a4_deny_does_not_resolve_or_adapter(env):
    token = env["token"]
    calls: List[Any] = []

    def fake_transport(req):
        calls.append(req)
        return {"status": 200, "headers": {}, "body": b""}

    set_http_transport_override_for_tests(fake_transport)
    args = _args()
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-deny",
    )
    # Force block instead of approve by invalidating before execution.
    get_plan_store().invalidate("s1", "tc-deny")
    out = on_tool_execution(
        HTTP_REFERENCE_TOOL,
        args,
        lambda a: handle_http_credential_request(a),
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-deny",
    )
    assert rc.get_injection_secret_resolve_count() == 0
    assert get_http_adapter_invoke_count() == 0
    assert calls == []
    assert token not in out
