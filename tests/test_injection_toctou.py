"""R2D/D3: TOCTOU and replay matrix for InjectionPlan consumption."""

from __future__ import annotations

import json
import os
import secrets
import threading
import types
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List

import pytest

from credential_guard.approval import on_pre_tool_call
from credential_guard.config import CONFIG_FILENAME
from credential_guard.injection_plan import PlanState
from credential_guard.runtime_config import (
    HTTP_REFERENCE_TOOL,
    load_and_publish_runtime,
    reset_runtime_for_tests,
)
from credential_guard.tool_execution import (
    PLAN_NOT_FOUND,
    PLAN_NOT_PENDING,
    PLAN_RECHECK_FAILED,
    on_tool_execution,
    reset_http_adapter_observe_for_tests,
    set_http_transport_override_for_tests,
)
from credential_guard.reference_tools import handle_http_credential_request
from credential_guard.tool_request import (
    get_plan_store,
    on_tool_request,
    reset_tool_request_state_for_tests,
)


def _doc(token: str, **binding_over: Any) -> Dict[str, Any]:
    binding = {
        "type": "http",
        "credential_ref": "jenkins-token",
        "target": {"scheme": "https", "host": "jenkins.example.test", "port": 443},
        "request": {
            "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
        },
        "inject": {"type": "bearer", "location": "authorization_header"},
        "approval": "required",
    }
    binding.update(binding_over)
    return {
        "version": 2,
        "credentials": {"jenkins-token": {"type": "token", "value": token}},
        "bindings": {"jenkins-production": binding},
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
    token = "CG_TOCTOU_" + secrets.token_hex(16)
    _write(store, _doc(token))

    hermes_cli = types.ModuleType("hermes_cli")
    cfg_mod = types.ModuleType("hermes_cli.config")
    cfg_mod.load_config_readonly = lambda: {"approvals": {"mode": "manual", "timeout": 300}}
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

    load_and_publish_runtime()
    reset_http_adapter_observe_for_tests()

    def _fake_transport(req):
        return {
            "status": 201,
            "headers": {"content-type": "application/json"},
            "body": b'{"queued":true}',
        }

    set_http_transport_override_for_tests(_fake_transport)
    yield {"store": store, "token": token, "canary": token}
    set_http_transport_override_for_tests(None)
    reset_http_adapter_observe_for_tests()
    reset_tool_request_state_for_tests()
    reset_runtime_for_tests()


def _args(**over: Any) -> Dict[str, Any]:
    base = {
        "target": "jenkins-production",
        "method": "POST",
        "path": "/job/project-x/build",
        "credential": "<CREDENTIAL:jenkins-token>",
    }
    base.update(over)
    return base


def _ready(tc: str = "tc", args=None, session="s1", turn="t1"):
    a = args or _args()
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=a,
        session_id=session,
        turn_id=turn,
        tool_call_id=tc,
    )
    assert (
        on_pre_tool_call(
            tool_name=HTTP_REFERENCE_TOOL,
            args=a,
            session_id=session,
            turn_id=turn,
            tool_call_id=tc,
        )["action"]
        == "approve"
    )
    return a


def _exec(args, tc="tc", session="s1", turn="t1", tool=HTTP_REFERENCE_TOOL):
    calls: List[Any] = []

    def nxt(a):
        calls.append(deepcopy(a))
        return handle_http_credential_request(a)

    out = on_tool_execution(
        tool,
        args,
        nxt,
        session_id=session,
        turn_id=turn,
        tool_call_id=tc,
    )
    return out, calls


def _assert_blocked(
    out: str,
    calls: List[Any],
    canary: str,
    expected_error: str = PLAN_RECHECK_FAILED,
) -> None:
    # Host next_call may run once to reach the formal handler; no secret leak.
    assert len(calls) <= 1
    assert canary not in out
    data = json.loads(out)
    assert data.get("ok") is False
    assert data["error"] == expected_error


def _assert_adapter_ok(out: str, calls: List[Any], canary: str) -> None:
    assert len(calls) == 1
    assert canary not in out
    data = json.loads(out)
    assert data.get("ok") is True
    assert data.get("status") == 201


def test_toctou_change_credential_value(env):
    store, token = env["store"], env["token"]
    args = _ready("tc-cred")
    # Rotate credential value (same length).
    new_token = "Z" * len(token)
    _write(store, _doc(new_token))
    out, calls = _exec(args, tc="tc-cred")
    _assert_blocked(out, calls, token)
    _assert_blocked(out, calls, new_token)


def test_toctou_change_binding(env):
    store, token = env["store"], env["token"]
    args = _ready("tc-bind")
    doc = _doc(token)
    doc["bindings"]["jenkins-production"]["inject"] = {
        "type": "api_key_header",
        "header_name": "X-Api-Key",
    }
    _write(store, doc)
    out, calls = _exec(args, tc="tc-bind")
    _assert_blocked(out, calls, token)


def test_toctou_change_tool_name(env):
    token = env["token"]
    args = _ready("tc-tool")
    out, calls = _exec(args, tc="tc-tool", tool="terminal")
    _assert_blocked(out, calls, token)


def test_toctou_change_method_path(env):
    token = env["token"]
    args = _ready("tc-path")
    mutated = deepcopy(args)
    mutated["path"] = "/job/evil/build"
    out, calls = _exec(mutated, tc="tc-path")
    _assert_blocked(out, calls, token)


def test_toctou_change_reference_name(env):
    token = env["token"]
    args = _ready("tc-ref")
    mutated = deepcopy(args)
    mutated["credential"] = "<CREDENTIAL:jenkins-token> "
    out, calls = _exec(mutated, tc="tc-ref")
    _assert_blocked(out, calls, token)


def test_toctou_change_session_ids(env):
    token = env["token"]
    args = _ready("tc-sess", session="s1")
    out, calls = _exec(args, tc="tc-sess", session="s2")
    _assert_blocked(out, calls, token, PLAN_NOT_FOUND)


def test_toctou_binding_deleted(env):
    store, token = env["store"], env["token"]
    args = _ready("tc-del")
    _write(
        store,
        {"version": 2, "credentials": {"jenkins-token": {"type": "token", "value": token}}, "bindings": {}},
    )
    out, calls = _exec(args, tc="tc-del")
    _assert_blocked(out, calls, token)


def test_toctou_replay_consumed(env):
    token = env["token"]
    args = _ready("tc-replay")
    out1, calls1 = _exec(args, tc="tc-replay")
    _assert_adapter_ok(out1, calls1, token)
    out2, calls2 = _exec(args, tc="tc-replay")
    _assert_blocked(out2, calls2, token, PLAN_NOT_PENDING)
    assert get_plan_store().lookup("s1", "tc-replay").state is PlanState.CONSUMED


def test_toctou_concurrent_only_one_consumes(env):
    token = env["token"]
    args = _ready("tc-conc")
    barrier = threading.Barrier(2)
    results: List[str] = []
    lock = threading.Lock()

    def worker():
        barrier.wait(timeout=5)
        out, calls = _exec(args, tc="tc-conc")
        with lock:
            results.append(out)
            assert len(calls) <= 1

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
    assert len(results) == 2
    oks = [json.loads(out).get("ok") is True for out in results]
    assert sum(1 for x in oks if x) == 1
    assert sum(1 for x in oks if not x) == 1
    for out in results:
        assert token not in out
    assert get_plan_store().lookup("s1", "tc-conc").state is PlanState.CONSUMED


def test_toctou_inode_replace_same_size(env):
    store, token = env["store"], env["token"]
    args = _ready("tc-inode")
    path = store / CONFIG_FILENAME
    # Replace file via write (new inode typically).
    os.remove(path)
    _write(store, _doc(token))
    out, calls = _exec(args, tc="tc-inode")
    _assert_blocked(out, calls, token)


def test_p5_egress_generation_bump_is_not_r2_security_binding(env):
    """R1B republish may bump generation; R2 security uses file identity + digests."""
    from credential_guard.runtime_config import load_and_publish_runtime

    args = _ready("tc-gen")
    # Bump observational generation without changing the config file.
    v1 = load_and_publish_runtime()
    v2 = load_and_publish_runtime()
    assert v2.generation > v1.generation
    out, calls = _exec(args, tc="tc-gen")
    # Still reaches post-consume adapter path (not identity mismatch).
    _assert_adapter_ok(out, calls, env["token"])
    assert get_plan_store().lookup("s1", "tc-gen").state is PlanState.CONSUMED
