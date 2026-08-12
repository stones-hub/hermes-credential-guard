"""R2C: tool_request analysis — logical refs + binding match → InjectionPlan."""

from __future__ import annotations

import json
import os
import secrets
import types
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict

import pytest

from credential_guard.config import CONFIG_FILENAME
from credential_guard.injection_plan import PlanState
from credential_guard.runtime_config import (
    load_and_publish_runtime,
    reset_runtime_for_tests,
)
from credential_guard.tool_request import (
    HTTP_REFERENCE_TOOL,
    get_invalid_marker,
    get_plan_store,
    on_tool_request,
    reset_tool_request_state_for_tests,
)


def _chmod700(path: Path) -> None:
    os.chmod(path, 0o700)


def _chmod600(path: Path) -> None:
    os.chmod(path, 0o600)


def _write_json(path: Path, doc: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _chmod700(path.parent)
    path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    _chmod600(path)


def _jenkins_doc(token: str) -> Dict[str, Any]:
    return {
        "version": 2,
        "credentials": {
            "jenkins-token": {"type": "token", "value": token},
        },
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


@pytest.fixture
def isolated_runtime(tmp_path, monkeypatch):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    store = hermes / "credential-guard"
    store.mkdir(mode=0o700)
    _chmod700(store)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    reset_runtime_for_tests()
    reset_tool_request_state_for_tests()

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

    token = "CG_R2C_" + secrets.token_hex(12)
    _write_json(store / CONFIG_FILENAME, _jenkins_doc(token))
    view = load_and_publish_runtime()
    yield hermes, store, view, token
    reset_tool_request_state_for_tests()
    reset_runtime_for_tests()


def test_01_runtime_exposes_logical_credential_names_not_secrets(isolated_runtime):
    _, _, view, token = isolated_runtime
    assert "jenkins-token" in view.credential_names
    blob = json.dumps(dict(view.bindings), default=str)
    assert token not in blob
    assert "password" not in blob.lower() or "password" not in str(view.bindings)
    for meta in view.bindings.values():
        assert "host" not in meta
        assert "url" not in meta
        assert "alias" not in meta
        assert "value" not in meta
        assert "username" not in meta


def test_02_safe_binding_metadata_has_match_fields(isolated_runtime):
    _, _, view, _ = isolated_runtime
    meta = view.bindings["jenkins-production"]
    assert meta["type"] == "http"
    assert meta["credential_ref"] == "jenkins-token"
    assert meta["approval"] == "required"
    assert meta["inject_type"] == "bearer"
    assert tuple(meta["reference_arg_path"]) == ("credential",)
    assert HTTP_REFERENCE_TOOL in meta["allowed_tools"]
    assert "host" not in meta
    assert "target" not in meta or "host" not in str(meta.get("target"))


def test_03_registers_tool_request_middleware():
    from credential_guard import register

    class Ctx:
        def __init__(self):
            self.middlewares = []
            self.hooks = []
            self.cli = []
            self.tools = []

        def register_middleware(self, kind, cb):
            self.middlewares.append((kind, cb))

        def register_hook(self, *a, **k):
            self.hooks.append((a, k))

        def register_cli_command(self, **k):
            self.cli.append(k)

        def register_tool(self, **k):
            self.tools.append(k)

    ctx = Ctx()
    register(ctx)
    kinds = {k for k, _ in ctx.middlewares}
    assert "tool_request" in kinds
    paired = {k: cb for k, cb in ctx.middlewares}
    assert paired["tool_request"] is on_tool_request


def test_04_no_reference_no_plan_args_equivalent(isolated_runtime):
    args = {"path": "/tmp/x", "content": "hello"}
    original = deepcopy(args)
    out = on_tool_request(
        tool_name="write_file",
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc1",
    )
    assert out["args"] == original
    assert out["args"] is not args
    assert get_plan_store().lookup("s1", "tc1") is None
    assert "trace" in out
    assert out["trace"]["source"] == "credential-guard"


def test_05_unique_match_creates_analyzed_plan(isolated_runtime):
    args = {
        "target": "jenkins-production",
        "method": "POST",
        "path": "/job/project-x/build",
        "credential": "<CREDENTIAL:jenkins-token>",
    }
    out = on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-ok",
    )
    assert out["args"]["credential"] == "<CREDENTIAL:jenkins-token>"
    plan = get_plan_store().lookup("s1", "tc-ok")
    assert plan is not None
    assert plan.state is PlanState.ANALYZED
    assert plan.target_name == "jenkins-production"
    assert plan.credential_name == "jenkins-token"
    assert plan.binding_name == "jenkins-production"
    assert plan.reference_arg_path == ("credential",)


def test_06_target_is_binding_business_name(isolated_runtime):
    args = {
        "target": "jenkins-production",
        "credential": "<CREDENTIAL:jenkins-token>",
    }
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-t",
    )
    plan = get_plan_store().lookup("s1", "tc-t")
    assert plan.binding_name == plan.target_name == "jenkins-production"


def test_07_credential_must_match_credential_ref(isolated_runtime):
    _, store, _, token = isolated_runtime
    # Add second credential/binding so name is registered but wrong for target.
    doc = _jenkins_doc(token)
    doc["credentials"]["other-token"] = {"type": "token", "value": token + "x"}
    doc["bindings"]["other-api"] = {
        "type": "http",
        "credential_ref": "other-token",
        "target": {"scheme": "https", "host": "other.example.test", "port": 443},
        "request": {
            "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
        },
        "inject": {"type": "bearer", "location": "authorization_header"},
        "approval": "required",
    }
    _write_json(store / CONFIG_FILENAME, doc)
    load_and_publish_runtime()
    args = {
        "target": "jenkins-production",
        "credential": "<CREDENTIAL:other-token>",
    }
    out = on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-mismatch",
    )
    assert get_plan_store().lookup("s1", "tc-mismatch") is None
    assert get_invalid_marker("s1", "tc-mismatch") is not None
    assert out["args"]["credential"] == "<CREDENTIAL:other-token>"


def test_08_tool_arg_path_type_approval_must_match(isolated_runtime):
    args = {
        "target": "jenkins-production",
        "credential": "<CREDENTIAL:jenkins-token>",
    }
    # Wrong tool
    on_tool_request(
        tool_name="terminal",
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-tool",
    )
    assert get_plan_store().lookup("s1", "tc-tool") is None
    assert get_invalid_marker("s1", "tc-tool") is not None

    # Wrong arg path (ref nested)
    nested = {
        "target": "jenkins-production",
        "auth": {"credential": "<CREDENTIAL:jenkins-token>"},
    }
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=nested,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-path",
    )
    assert get_plan_store().lookup("s1", "tc-path") is None
    assert get_invalid_marker("s1", "tc-path") is not None


def test_09_zero_or_multi_match_fail_closed(isolated_runtime):
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args={
            "target": "unknown-target",
            "credential": "<CREDENTIAL:jenkins-token>",
        },
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-zero",
    )
    assert get_invalid_marker("s1", "tc-zero") is not None


def test_10_unregistered_or_mismatch_fail_closed(isolated_runtime):
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args={
            "target": "jenkins-production",
            "credential": "<CREDENTIAL:not-there>",
        },
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-unreg",
    )
    assert get_plan_store().lookup("s1", "tc-unreg") is None
    assert get_invalid_marker("s1", "tc-unreg") is not None


def test_11_missing_session_or_tool_call_fail_closed(isolated_runtime):
    args = {
        "target": "jenkins-production",
        "credential": "<CREDENTIAL:jenkins-token>",
    }
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="",
        turn_id="t1",
        tool_call_id="tc",
    )
    assert get_invalid_marker("", "tc") is not None

    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="",
    )
    assert get_invalid_marker("s1", "") is not None

    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="",
        tool_call_id="tc-turn",
    )
    assert get_invalid_marker("s1", "tc-turn") is not None
    # Store must reject empty identity keys — no successful plan.
    assert get_plan_store().snapshot()["size"] == 0 or all(
        not k.endswith(":") and not k.startswith(":")
        for k in get_plan_store().snapshot()["keys"]
    )


def test_12_returned_args_still_logical_ref_secret_count_zero(isolated_runtime):
    _, _, _, token = isolated_runtime
    args = {
        "target": "jenkins-production",
        "credential": "<CREDENTIAL:jenkins-token>",
    }
    out = on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-sec",
    )
    blob = json.dumps(out)
    assert token not in blob
    assert "<CREDENTIAL:jenkins-token>" in blob


def test_13_trace_fixed_fields_only(isolated_runtime):
    out = on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args={
            "target": "jenkins-production",
            "credential": "<CREDENTIAL:jenkins-token>",
        },
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-tr",
    )
    trace = out["trace"]
    assert set(trace.keys()) <= {"source", "reason", "name"}
    assert trace["source"] == "credential-guard"
    assert "plan" not in json.dumps(trace)
    assert "digest" not in json.dumps(trace)
    assert "host" not in json.dumps(trace)
    assert "jenkins.example" not in json.dumps(trace)


def test_14_internal_exception_sets_invalid_marker(isolated_runtime, monkeypatch):
    import credential_guard.tool_request as tr

    def boom(*a, **k):
        raise RuntimeError("injected")

    monkeypatch.setattr(tr, "analyze_references", boom)
    out = on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args={
            "target": "jenkins-production",
            "credential": "<CREDENTIAL:jenkins-token>",
        },
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-ex",
    )
    assert out["args"]["credential"] == "<CREDENTIAL:jenkins-token>"
    assert get_invalid_marker("s1", "tc-ex") is not None
    assert get_plan_store().lookup("s1", "tc-ex") is None


def test_15_uses_r1b_single_file_runtime_not_dual(isolated_runtime):
    hermes, store, _, _ = isolated_runtime
    # Plant old dual files — must not be read by tool_request path.
    (store / "credentials.json").write_text("{}", encoding="utf-8")
    (store / "targets.json").write_text("{}", encoding="utf-8")
    out = on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args={
            "target": "jenkins-production",
            "credential": "<CREDENTIAL:jenkins-token>",
        },
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-r1b",
    )
    assert get_plan_store().lookup("s1", "tc-r1b") is not None
    assert out["args"]["credential"].startswith("<CREDENTIAL:")


def test_16_ordinary_tools_unaffected_structure(isolated_runtime):
    for tool in ("read_file", "terminal", "some_unregistered_host_tool"):
        args = {"path": "/tmp/a", "command": "echo hi"}
        out = on_tool_request(
            tool_name=tool,
            args=args,
            session_id="s1",
            turn_id="t1",
            tool_call_id=f"tc-{tool}",
        )
        assert out["args"] == args or out["args"]["path"] == "/tmp/a"
        assert get_plan_store().lookup("s1", f"tc-{tool}") is None


def test_p6_tool_request_must_not_touch_credential_value_or_password(
    isolated_runtime, monkeypatch
):
    """P6 RED: reference analysis must not materialize execution secrets."""
    from credential_guard import runtime_config as rc
    from credential_guard.config import CredentialGuardConfig

    secret_hits: list[str] = []
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

    args = {
        "target": "jenkins-production",
        "method": "POST",
        "path": "/job/project-x/build",
        "credential": "<CREDENTIAL:jenkins-token>",
    }
    out = on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-p6-meta",
    )
    assert out["args"]["credential"] == "<CREDENTIAL:jenkins-token>"
    plan = get_plan_store().lookup("s1", "tc-p6-meta")
    assert plan is not None
    assert plan.state is PlanState.ANALYZED
    assert secret_hits == [], f"pre-approval secret field access: {secret_hits}"


def test_p6_tool_request_survives_exploding_egress_rebuild(
    isolated_runtime, monkeypatch
):
    """Full egress rebuild must not be on the R2 analysis critical path."""
    from credential_guard import runtime_config as rc

    def _explode(cfg):
        raise AssertionError("FULL_EGRESS_REBUILD_DURING_PREAPPROVAL")

    monkeypatch.setattr(rc, "build_file_egress_registry", _explode)
    out = on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args={
            "target": "jenkins-production",
            "credential": "<CREDENTIAL:jenkins-token>",
        },
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-p6-explode",
    )
    assert out["args"]["credential"] == "<CREDENTIAL:jenkins-token>"
    plan = get_plan_store().lookup("s1", "tc-p6-explode")
    assert plan is not None
    assert plan.state is PlanState.ANALYZED
