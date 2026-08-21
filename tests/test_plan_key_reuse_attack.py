"""R2 final: same-(session, tool_call) plan substitution attack.

Store-level insert-only + tombstone must prevent an in-flight approval for
call A from consuming a later plan B that reused the same key.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import types
from pathlib import Path
from typing import Any, Dict, List

import pytest

from credential_guard.approval import on_pre_tool_call
from credential_guard.config import CONFIG_FILENAME
from credential_guard.injection_plan import (
    InjectionPlan,
    InjectionPlanStore,
    PlanState,
    PlanStoreError,
    _plan_key,
    canonical_args_digest,
)
from credential_guard.runtime_config import (
    HTTP_REFERENCE_TOOL,
    load_and_publish_runtime,
    reset_runtime_for_tests,
)
from credential_guard.tool_execution import on_tool_execution
from credential_guard.reference_tools import handle_http_credential_request
from credential_guard.tool_request import (
    get_invalid_marker,
    get_plan_store,
    on_tool_request,
    reset_tool_request_state_for_tests,
)


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
    token = "CG_R2_KEY_" + secrets.token_hex(12)
    _write_cfg(store, token)

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
    yield store, token
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


def _recompute_rule_key(plan) -> str:
    material = "|".join(
        [
            plan.nonce,
            plan.tool_call_id,
            plan.tool_name,
            plan.args_digest,
            plan.config_digest,
            plan.binding_digest,
        ]
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"cg-ref:{plan.tool_name}:{digest}"


def test_attack_same_key_b_cannot_replace_a_during_approval(env):
    """A pending approval must not be substitutable by a same-key call B."""
    _args_a = _ref_args()
    out_a = on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_args_a,
        session_id="s-atk",
        turn_id="t1",
        tool_call_id="tc-shared",
    )
    assert out_a["trace"]["reason"] == "analyzed"
    plan_a = get_plan_store().lookup("s-atk", "tc-shared")
    assert plan_a is not None
    nonce_a = plan_a.nonce
    digest_a = plan_a.args_digest

    approval_a = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_args_a,
        session_id="s-atk",
        turn_id="t1",
        tool_call_id="tc-shared",
    )
    assert approval_a["action"] == "approve"
    rule_key_a = approval_a["rule_key"]
    message_a = approval_a["message"]
    assert get_plan_store().lookup("s-atk", "tc-shared").state is PlanState.APPROVAL_PENDING
    assert _recompute_rule_key(get_plan_store().lookup("s-atk", "tc-shared")) == rule_key_a

    # During A's approval wait: same session+turn+tool_call call B (same args).
    out_b = on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_args_a,
        session_id="s-atk",
        turn_id="t1",
        tool_call_id="tc-shared",
    )
    assert out_b["trace"]["reason"] == "create_failed"
    assert get_invalid_marker("s-atk", "tc-shared") is not None

    kept = get_plan_store().lookup("s-atk", "tc-shared")
    assert kept is not None
    assert kept.nonce == nonce_a
    assert kept.args_digest == digest_a
    assert kept.state is PlanState.APPROVAL_PENDING
    assert _recompute_rule_key(kept) == rule_key_a
    assert message_a  # approval text captured; never consumed as B

    downstream: List[Dict[str, Any]] = []

    def _next(args: Dict[str, Any]) -> str:
        downstream.append(dict(args))
        return handle_http_credential_request(args)

    # Execute original A args after approval returns.
    result = on_tool_execution(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_args_a,
        next_call=_next,
        session_id="s-atk",
        turn_id="t1",
        tool_call_id="tc-shared",
    )
    assert len(downstream) <= 1
    assert "injected" not in result
    data = json.loads(result)
    # Fail-closed against B's steal: either A's plan consumes (ok via fake transport)
    # or create_failed marker blocks. Never B's mutated args.
    plan_after = get_plan_store().lookup("s-atk", "tc-shared")
    assert plan_after is not None
    assert plan_after.nonce == nonce_a
    if plan_after.state is PlanState.CONSUMED:
        assert data.get("ok") is True
    else:
        assert data.get("ok") is False
        assert plan_after.state in (
            PlanState.APPROVAL_PENDING,
            PlanState.INVALIDATED,
        )


def test_attack_b_different_args_still_cannot_replace(env):
    args_a = _ref_args(path="/job/project-x/build")
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args_a,
        session_id="s-atk",
        turn_id="t1",
        tool_call_id="tc-diff",
    )
    approval_a = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args_a,
        session_id="s-atk",
        turn_id="t1",
        tool_call_id="tc-diff",
    )
    assert approval_a["action"] == "approve"
    nonce_a = get_plan_store().lookup("s-atk", "tc-diff").nonce

    args_b = _ref_args(path="/job/evil/build")
    out_b = on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args_b,
        session_id="s-atk",
        turn_id="t2",
        tool_call_id="tc-diff",
    )
    assert out_b["trace"]["reason"] == "create_failed"
    kept = get_plan_store().lookup("s-atk", "tc-diff")
    assert kept.nonce == nonce_a
    assert kept.args_digest != canonical_args_digest(args_b)

    downstream: List[Any] = []

    def _next(args: Dict[str, Any]) -> str:
        downstream.append(args)
        return "{}"

    result = on_tool_execution(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args_b,
        next_call=_next,
        session_id="s-atk",
        turn_id="t1",
        tool_call_id="tc-diff",
    )
    assert len(downstream) <= 1
    assert json.loads(result)["ok"] is False
    plan = get_plan_store().lookup("s-atk", "tc-diff")
    assert plan is not None
    assert plan.nonce == nonce_a
    assert plan.state in (PlanState.APPROVAL_PENDING, PlanState.INVALIDATED)


def test_attack_different_tool_call_ids_remain_independent(env):
    args = _ref_args()
    for tc in ("tc-x", "tc-y"):
        out = on_tool_request(
            tool_name=HTTP_REFERENCE_TOOL,
            args=args,
            session_id="s-atk",
            turn_id="t1",
            tool_call_id=tc,
        )
        assert out["trace"]["reason"] == "analyzed"
        appr = on_pre_tool_call(
            tool_name=HTTP_REFERENCE_TOOL,
            args=args,
            session_id="s-atk",
            turn_id="t1",
            tool_call_id=tc,
        )
        assert appr["action"] == "approve"
    px = get_plan_store().lookup("s-atk", "tc-x")
    py = get_plan_store().lookup("s-atk", "tc-y")
    assert px is not None and py is not None
    assert px.nonce != py.nonce
    assert px.state is PlanState.APPROVAL_PENDING
    assert py.state is PlanState.APPROVAL_PENDING


def test_mutation_old_overwrite_allows_substitution_attack(env, monkeypatch):
    """Restore unconditional put overwrite → same-key B replaces A; attack RED."""

    def _overwrite_put(self: InjectionPlanStore, plan: InjectionPlan) -> None:
        key = _plan_key(plan.session_id, plan.tool_call_id)
        with self._lock:
            # Intentionally skip PLAN_KEY_REUSED — historical overwrite bug.
            if key not in self._plans and len(self._plans) >= self._capacity:
                raise PlanStoreError("STORE_FULL")
            self._plans[key] = plan
            self._reuse_block_until.pop(key, None)

    monkeypatch.setattr(InjectionPlanStore, "put", _overwrite_put)
    # Global store was constructed before patch; rebuild so put is bound.
    reset_tool_request_state_for_tests()
    load_and_publish_runtime()

    args = _ref_args()
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s-mut",
        turn_id="t1",
        tool_call_id="tc-mut",
    )
    approval_a = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s-mut",
        turn_id="t1",
        tool_call_id="tc-mut",
    )
    assert approval_a["action"] == "approve"
    nonce_a = get_plan_store().lookup("s-mut", "tc-mut").nonce
    rule_key_a = approval_a["rule_key"]

    # Same turn_id as A: overwrite replaces pending plan; Hermes execution has no
    # approval-receipt nonce, so lookup-by-key can consume B after B is pending.
    out_b = on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s-mut",
        turn_id="t1",
        tool_call_id="tc-mut",
    )
    assert out_b["trace"]["reason"] == "analyzed"
    plan_b = get_plan_store().lookup("s-mut", "tc-mut")
    assert plan_b is not None
    assert plan_b.nonce != nonce_a
    assert plan_b.state is PlanState.ANALYZED
    assert _recompute_rule_key(plan_b) != rule_key_a

    approval_b = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s-mut",
        turn_id="t1",
        tool_call_id="tc-mut",
    )
    assert approval_b["action"] == "approve"
    assert approval_b["rule_key"] != rule_key_a
    assert get_plan_store().lookup("s-mut", "tc-mut").nonce != nonce_a

    downstream: List[Any] = []

    def _next(a: Dict[str, Any]) -> str:
        downstream.append(a)
        return handle_http_credential_request(a)

    # A's approval returns; execution identity matches B's plan key → consumes B.
    result = on_tool_execution(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        next_call=_next,
        session_id="s-mut",
        turn_id="t1",
        tool_call_id="tc-mut",
    )
    plan_final = get_plan_store().lookup("s-mut", "tc-mut")
    assert plan_final is not None
    assert plan_final.nonce != nonce_a
    assert plan_final.state is PlanState.CONSUMED
    assert len(downstream) <= 1
    assert json.loads(result).get("ok") is True
