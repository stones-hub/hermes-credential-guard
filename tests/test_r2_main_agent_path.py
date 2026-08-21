"""R2 round-7 T1: real Hermes main-agent tool path (tool_executor middleware).

Drives ``agent.tool_executor._run_agent_tool_execution_middleware`` with the
live PluginManager callbacks and registry handler. Observes production
callback/handler entry via ``sys.setprofile`` on code objects — does not
overlay mgr callback lists or re-register counted handlers.
"""

from __future__ import annotations

import json
import os
import subprocess
import textwrap
from pathlib import Path
from typing import Dict

import pytest

from credential_guard.tool_execution import PLAN_NOT_PENDING

REPO = Path(__file__).resolve().parents[1]
HERMES_AGENT_ROOT = Path(
    os.environ.get("HERMES_AGENT_ROOT", "/tmp/credential-guard-r2-hermes-source")
)
HERMES_SPIKE_PYTHON = Path(
    os.environ.get(
        "HERMES_SPIKE_PYTHON",
        "/tmp/credential-guard-r2-hermes-venv/bin/python",
    )
)

DECOY = "CG_MAIN_AGENT_" + "y" * 24

PROBE = textwrap.dedent(
    r"""
import json
import os
import sys
import types
from copy import deepcopy
from pathlib import Path
from unittest.mock import MagicMock, patch

scenario = os.environ["CG_SCENARIO"]
token = os.environ["CG_DECOY"]
repo = Path(os.environ["CG_REPO"])
hermes_home = Path(os.environ["HERMES_HOME"])
store = hermes_home / "credential-guard"

sys.path.insert(0, os.environ["HERMES_AGENT_ROOT"])
sys.path.insert(0, str(repo))

# The plugin derives its store from its install location and no longer reads
# HERMES_HOME. This probe runs from a source checkout, so pin the store
# explicitly to the scenario's temporary profile.
from credential_guard import store_location as _sl

_sl.use_store_dir(store)

for _name in ("requests", "httpx", "modal", "openai", "anthropic", "firecrawl"):
    if _name not in sys.modules:
        sys.modules[_name] = types.ModuleType(_name)

import credential_guard as cg_pkg
import credential_guard.tool_execution as te_mod
from credential_guard import register
from credential_guard.reference_tools import handle_http_credential_request
from credential_guard.tool_execution import (
    PLAN_NOT_PENDING,
    reset_http_adapter_observe_for_tests,
    set_http_transport_override_for_tests,
    get_http_adapter_invoke_count,
)
from credential_guard.runtime_config import (
    HTTP_REFERENCE_TOOL,
    get_execution_secret_resolve_count,
    get_injection_secret_resolve_count,
    load_and_publish_runtime,
    reset_execution_secret_resolve_count_for_tests,
    reset_injection_secret_resolve_count_for_tests,
    reset_runtime_for_tests,
)
from credential_guard.tool_request import get_plan_store, reset_tool_request_state_for_tests
from credential_guard.injection_plan import InjectionPlanStore
from credential_guard.injection import resolve_one_for_execution
from credential_guard.adapters.http import execute_http

# Product mutation: restore pre-round7 ANALYZED fail-closed *before* register,
# so PluginManager still holds the mutated callable as its registered identity
# (no post-register callback-list overlay).
if os.environ.get("CG_MUTATE_OLD_EXEC") == "1":
    from credential_guard.injection_plan import PlanState as _PS
    from credential_guard.tool_request import get_plan_store as _gps
    _real_exec = te_mod.on_tool_execution
    def _mutated_exec(*, args, next_call, **kw):
        sid = str(kw.get("session_id") or "")
        tc = str(kw.get("tool_call_id") or "")
        plan = _gps().lookup(sid, tc) if sid and tc else None
        if plan is not None and plan.state is _PS.ANALYZED:
            try:
                _gps().invalidate(sid, tc)
            except Exception:
                pass
            return te_mod._safe_error(te_mod.PLAN_NOT_PENDING)
        return _real_exec(args=args, next_call=next_call, **kw)
    te_mod.on_tool_execution = _mutated_exec
    cg_pkg.on_tool_execution = _mutated_exec

doc = {
    "version": 2,
    "credentials": {"jenkins-token": {"type": "token", "value": token}},
    "bindings": {
        "jenkins-production": {
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
    },
}
store.mkdir(parents=True, exist_ok=True)
os.chmod(store, 0o700)
cfg = store / "credential-guard.json"
cfg.write_text(json.dumps(doc), encoding="utf-8")
os.chmod(cfg, 0o600)
(hermes_home / "config.yaml").write_text(
    'model: unused\napprovals:\n  mode: "manual"\n  timeout: 300\nplugins:\n  enabled: []\n',
    encoding="utf-8",
)

reset_runtime_for_tests()
reset_tool_request_state_for_tests()
load_and_publish_runtime()
reset_execution_secret_resolve_count_for_tests()
reset_injection_secret_resolve_count_for_tests()
reset_http_adapter_observe_for_tests()

def _fake_transport(req):
    return {
        "status": 201,
        "headers": {"content-type": "application/json"},
        "body": b'{"queued":true}',
    }

set_http_transport_override_for_tests(_fake_transport)
secret_before = get_execution_secret_resolve_count()
inj_before = get_injection_secret_resolve_count()
adapter_before = get_http_adapter_invoke_count()

import hermes_cli.plugins as plugins_mod
from hermes_cli.plugins import PluginManager
from tools.registry import registry
from agent.tool_executor import _run_agent_tool_execution_middleware

plugins_mod._plugin_manager = None
mgr = PluginManager()
plugins_mod._plugin_manager = mgr

class Ctx:
    def __init__(self, manager):
        self._manager = manager
        self.manifest = types.SimpleNamespace(
            name="credential-guard", key="credential-guard", source="user"
        )
    def register_middleware(self, kind, callback):
        self._manager._middleware.setdefault(kind, []).append(callback)
    def register_hook(self, name, callback):
        self._manager._hooks.setdefault(name, []).append(callback)
    def register_cli_command(self, **kwargs):
        pass
    def register_tool(self, **kwargs):
        try:
            registry.deregister(kwargs["name"])
        except Exception:
            pass
        registry.register(
            name=kwargs["name"],
            toolset=kwargs["toolset"],
            schema=kwargs["schema"],
            handler=kwargs["handler"],
            check_fn=kwargs.get("check_fn"),
            description=kwargs.get("description") or "",
        )
        self._manager._plugin_tool_names.add(kwargs["name"])

register(Ctx(mgr))

# Optional invasive mutation: drop a registered callback after register to prove
# Framework E2E goes RED when production path pieces are missing.
_drop = os.environ.get("CG_DROP_CALLBACK", "").strip()
if _drop == "tool_request":
    mgr._middleware.get("tool_request", []).clear()
elif _drop == "tool_execution":
    mgr._middleware.get("tool_execution", []).clear()
elif _drop == "pre_tool_call":
    mgr._hooks.get("pre_tool_call", []).clear()
elif _drop == "handler":
    try:
        registry.deregister(HTTP_REFERENCE_TOOL)
    except Exception:
        pass
    mgr._plugin_tool_names.discard(HTTP_REFERENCE_TOOL)

# Optional seam mutation: bypass post-handler consume/resolve/adapter.
_drop_seam = os.environ.get("CG_DROP_SEAM", "").strip()
if _drop_seam == "consume":
    def _blocked_consume(self, session_id, tool_call_id):
        raise RuntimeError("mutated-consume-bypassed")
    InjectionPlanStore.consume = _blocked_consume
elif _drop_seam == "resolve":
    def _blocked_resolve(plan, view):
        raise RuntimeError("mutated-resolve-bypassed")
    import credential_guard.injection as _inj
    import credential_guard.tool_execution as _te
    _inj.resolve_one_for_execution = _blocked_resolve
    # tool_execution imports the symbol at call time from .injection — patch module attr.
elif _drop_seam == "adapter":
    def _blocked_adapter(**kwargs):
        raise RuntimeError("mutated-adapter-bypassed")
    import credential_guard.adapters.http as _http
    _http.execute_http = _blocked_adapter

assert HTTP_REFERENCE_TOOL in mgr._plugin_tool_names or _drop == "handler"
entry = registry.get_entry(HTTP_REFERENCE_TOOL) if _drop != "handler" else None
formal_tool_registered = HTTP_REFERENCE_TOOL in mgr._plugin_tool_names
handler_identity_ok = (
    entry is not None and entry.handler is handle_http_credential_request
)

# Snapshot production callback identities — lists must remain untouched for evidence.
prod_req = list(mgr._middleware.get("tool_request", []) or [])
prod_exec = list(mgr._middleware.get("tool_execution", []) or [])
prod_pre = list(mgr._hooks.get("pre_tool_call", []) or [])
prod_handler = entry.handler if entry is not None else None

order = []
counts = {
    "pre_tool_call": 0,
    "approval_gate": 0,
    "handler": 0,
    "tool_request": 0,
    "tool_execution": 0,
    "consume": 0,
    "resolve": 0,
    "adapter": 0,
    "network": 0,
}
evidence = {"approval_message": None}

code_labels = {}
for cb, label in (
    (prod_req[0] if prod_req else None, "tool_request"),
    (prod_exec[0] if prod_exec else None, "tool_execution"),
    (prod_pre[0] if prod_pre else None, "pre_tool_call"),
    (prod_handler, "handler"),
    (InjectionPlanStore.consume, "consume"),
    (resolve_one_for_execution, "resolve"),
    (execute_http, "adapter"),
):
    if cb is not None and hasattr(cb, "__code__"):
        code_labels[id(cb.__code__)] = label

def _profile(frame, event, arg):
    if event == "call":
        label = code_labels.get(id(frame.f_code))
        if label is not None:
            counts[label] += 1
            order.append(label)
    elif event == "return":
        label = code_labels.get(id(frame.f_code))
        if label == "pre_tool_call" and isinstance(arg, dict) and arg.get("message"):
            evidence["approval_message"] = arg["message"]
    return _profile

class Guardrails:
    def before_call(self, name, args):
        return types.SimpleNamespace(allows_execution=True, message=None)

def gate(tool_name, reason, **kwargs):
    counts["approval_gate"] += 1
    order.append("approval_gate")
    if scenario == "deny":
        return {"approved": False, "message": "DENIED: main-agent"}
    if scenario == "timeout":
        return {"approved": False, "message": "BLOCKED: approval timed out"}
    if scenario == "approval_error":
        raise RuntimeError("gate boom")
    return {"approved": True, "message": None}

sys.setprofile(_profile)
try:
    if scenario == "plain":
        plain_counts = {"handler": 0}
        def plain_execute(final_args):
            plain_counts["handler"] += 1
            return json.dumps({"ok": True, "echo": final_args}, sort_keys=True)
        agent2 = MagicMock()
        agent2.session_id = "sess-plain"
        agent2._current_turn_id = "turn-p"
        agent2._current_api_request_id = "api-p"
        agent2._tool_guardrails = Guardrails()
        with patch("tools.approval.request_tool_approval", side_effect=gate):
            managed_p = _run_agent_tool_execution_middleware(
                agent2,
                function_name="write_file",
                function_args={"path": "/tmp/ordinary.txt", "content": "x"},
                effective_task_id="task-p",
                tool_call_id="tc-plain",
                execute=plain_execute,
            )
        plain = {
            "result": managed_p.result if isinstance(managed_p.result, str) else json.dumps(managed_p.result),
            "handler": plain_counts["handler"],
            "secret_delta": get_execution_secret_resolve_count() - secret_before,
        }
        try:
            p = get_plan_store().lookup("sess-plain", "tc-plain")
            plain["plan_state"] = p.state.value if p else None
        except Exception:
            plain["plan_state"] = None
        print(json.dumps({
            "scenario": scenario,
            "order": list(order),
            "counts": counts,
            "stage_error": None,
            "plan_state": None,
            "blocked": False,
            "token_in_result": 0,
            "token_in_message": 0,
            "secret_resolve_delta": get_execution_secret_resolve_count() - secret_before,
            "result_preview": "",
            "result2_preview": "",
            "handler_identity_ok": "not_applicable",
            "formal_tool_registered": formal_tool_registered,
            "registry_dispatch": "not_applicable",
            "plain": plain,
        }, sort_keys=True))
        raise SystemExit(0)

    args = {
        "target": "jenkins-production",
        "method": "POST",
        "path": "/job/project-x/build",
        "credential": "<CREDENTIAL:jenkins-token>",
    }
    session_id = "sess-main-" + scenario
    turn_id = "turn-1"
    tool_call_id = "tc-main-" + scenario

    agent = MagicMock()
    agent.session_id = session_id
    agent._current_turn_id = turn_id
    agent._current_api_request_id = "api-1"
    agent._tool_guardrails = Guardrails()
    agent._turns_since_memory = 0
    agent._iters_since_skill = 0

    identity_change = scenario == "identity_change"
    session_mismatch = scenario == "session_mismatch"

    def execute(final_args):
        from tools.approval import (
            reset_current_observability_context,
            set_current_observability_context,
        )
        tokens = set_current_observability_context(
            turn_id=turn_id, tool_call_id=tool_call_id
        )
        try:
            if identity_change:
                import time
                cfg.write_text(cfg.read_text(encoding="utf-8") + "\n", encoding="utf-8")
                os.chmod(cfg, 0o600)
                time.sleep(0.02)
            dispatch_args = deepcopy(final_args)
            if scenario == "approve_then_mutate_args":
                dispatch_args = dict(dispatch_args)
                dispatch_args["path"] = "/job/mutated/build"
            return registry.dispatch(
                HTTP_REFERENCE_TOOL,
                dispatch_args,
                task_id="task-1",
                session_id=session_id if not session_mismatch else "other-session",
            )
        finally:
            reset_current_observability_context(tokens)

    with patch("tools.approval.request_tool_approval", side_effect=gate):
        managed = _run_agent_tool_execution_middleware(
            agent,
            function_name=HTTP_REFERENCE_TOOL,
            function_args=deepcopy(args),
            effective_task_id="task-1",
            tool_call_id=tool_call_id,
            execute=execute,
        )
        result = managed.result
        result2 = None
        if scenario == "replay":
            managed2 = _run_agent_tool_execution_middleware(
                agent,
                function_name=HTTP_REFERENCE_TOOL,
                function_args=deepcopy(args),
                effective_task_id="task-1",
                tool_call_id=tool_call_id,
                execute=execute,
            )
            result2 = managed2.result

    blob = result if isinstance(result, str) else json.dumps(result)
    plan = None
    try:
        plan = get_plan_store().lookup(session_id, tool_call_id)
    except Exception:
        plan = None
    adapter_ok = False
    try:
        parsed = json.loads(blob) if isinstance(result, str) else result
        adapter_ok = bool(isinstance(parsed, dict) and parsed.get("ok") is True and parsed.get("status") == 201)
    except Exception:
        adapter_ok = False

    print(json.dumps({
        "scenario": scenario,
        "order": list(order),
        "counts": counts,
        "stage_error": (
            json.loads(blob).get("error")
            if isinstance(result, str) and blob.lstrip().startswith("{")
            else None
        ),
        "adapter_ok": adapter_ok,
        "plan_state": plan.state.value if plan else None,
        "blocked": bool(getattr(managed, "blocked", False)),
        "token_in_result": int(token in blob),
        "token_in_message": int(token in (evidence["approval_message"] or "")),
        "secret_resolve_delta": get_execution_secret_resolve_count() - secret_before,
        "injection_resolve_delta": get_injection_secret_resolve_count() - inj_before,
        "adapter_invoke_delta": get_http_adapter_invoke_count() - adapter_before,
        "result_preview": blob[:240],
        "result2_preview": (result2 if isinstance(result2, str) else json.dumps(result2 or ""))[:240],
        "handler_identity_ok": bool(handler_identity_ok),
        "formal_tool_registered": bool(formal_tool_registered),
        "registry_dispatch": counts["handler"] > 0,
        "plain": None,
    }, sort_keys=True))
finally:
    sys.setprofile(None)
    set_http_transport_override_for_tests(None)
"""
)


def _base_env(home: Path, hermes: Path) -> Dict[str, str]:
    return {
        "HOME": str(home),
        "HERMES_HOME": str(hermes),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C",
        "LC_ALL": "C",
        "TMPDIR": str(home / "tmp"),
        "NO_PROXY": "*",
        "no_proxy": "*",
        "HERMES_AGENT_ROOT": str(HERMES_AGENT_ROOT),
        "PYTHONPATH": os.pathsep.join([str(HERMES_AGENT_ROOT), str(REPO)]),
        "OPENAI_API_KEY": "",
        "ANTHROPIC_API_KEY": "",
        "HERMES_API_KEY": "",
        "HERMES_YOLO_MODE": "",
    }


def _run(scenario: str, tmp_path: Path, **extra: str) -> dict:
    assert HERMES_AGENT_ROOT.is_dir(), f"missing hermes source: {HERMES_AGENT_ROOT}"
    assert HERMES_SPIKE_PYTHON.is_file(), f"missing spike python: {HERMES_SPIKE_PYTHON}"
    home = tmp_path / f"home-{scenario}"
    hermes = tmp_path / f"hermes-{scenario}"
    home.mkdir()
    hermes.mkdir()
    (home / "tmp").mkdir()
    env = _base_env(home, hermes)
    env["CG_SCENARIO"] = scenario
    env["CG_DECOY"] = DECOY
    env["CG_REPO"] = str(REPO)
    env.update(extra)
    proc = subprocess.run(
        [str(HERMES_SPIKE_PYTHON), "-c", PROBE],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout[-2000:] + "\n" + proc.stderr[-2000:]
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    return json.loads(lines[-1])


def test_main_agent_approve_reaches_handler_adapter_not_ready(tmp_path):
    data = _run("approve", tmp_path)
    assert data["counts"]["tool_request"] == 1
    assert data["counts"]["tool_execution"] == 1
    assert data["counts"]["pre_tool_call"] == 1
    assert data["counts"]["approval_gate"] == 1
    assert data["counts"]["handler"] == 1
    assert data["order"] == [
        "tool_request",
        "tool_execution",
        "pre_tool_call",
        "approval_gate",
        "handler",
        "consume",
        "resolve",
        "adapter",
    ]
    assert data["adapter_ok"] is True
    assert data["stage_error"] is None
    assert data["plan_state"] == "consumed"
    assert data["secret_resolve_delta"] == 0
    assert data["injection_resolve_delta"] == 1
    assert data["adapter_invoke_delta"] == 1
    assert data["counts"].get("consume") == 1
    assert data["counts"].get("resolve") == 1
    assert data["counts"].get("adapter") == 1
    assert data["token_in_result"] == 0
    assert data["token_in_message"] == 0
    assert data["formal_tool_registered"] is True
    assert data["handler_identity_ok"] is True
    assert data["registry_dispatch"] is True


def test_main_agent_deny_fail_closed(tmp_path):
    data = _run("deny", tmp_path)
    assert data["counts"]["pre_tool_call"] == 1
    assert data["counts"]["approval_gate"] == 1
    assert data["counts"]["handler"] == 0
    assert data["registry_dispatch"] is False
    assert data["plan_state"] in ("invalidated", None)
    assert data["secret_resolve_delta"] == 0
    assert data["token_in_result"] == 0


def test_main_agent_timeout_fail_closed(tmp_path):
    data = _run("timeout", tmp_path)
    assert data["counts"]["handler"] == 0
    assert data["plan_state"] in ("invalidated", None)
    assert data["secret_resolve_delta"] == 0


def test_main_agent_approval_error_fail_closed(tmp_path):
    data = _run("approval_error", tmp_path)
    assert data["counts"]["handler"] == 0
    assert data["plan_state"] in ("invalidated", None)
    assert data["secret_resolve_delta"] == 0


def test_main_agent_mutate_args_after_approve_fail_closed(tmp_path):
    data = _run("approve_then_mutate_args", tmp_path)
    assert data["counts"]["handler"] == 1
    assert data["stage_error"] == "PLAN_RECHECK_FAILED"
    assert data["plan_state"] == "invalidated"
    assert data["secret_resolve_delta"] == 0


def test_main_agent_identity_change_fail_closed(tmp_path):
    data = _run("identity_change", tmp_path)
    assert data["counts"]["handler"] >= 1
    assert data["plan_state"] == "invalidated"
    assert data["secret_resolve_delta"] == 0


def test_main_agent_session_mismatch_fail_closed(tmp_path):
    data = _run("session_mismatch", tmp_path)
    assert data["counts"]["handler"] == 1
    assert data["plan_state"] == "invalidated"
    assert data["secret_resolve_delta"] == 0


def test_main_agent_replay_no_second_consume(tmp_path):
    data = _run("replay", tmp_path)
    assert data["counts"]["handler"] >= 1
    assert data["plan_state"] in ("consumed", "invalidated", None)
    assert data["secret_resolve_delta"] == 0
    assert data["adapter_ok"] is True
    assert data["injection_resolve_delta"] == 1
    assert '"ok":false' in data["result2_preview"].replace(" ", "") or (
        PLAN_NOT_PENDING in data["result2_preview"]
    )


def test_main_agent_plain_tool_non_interference(tmp_path):
    data = _run("plain", tmp_path)
    plain = data["plain"]
    assert plain is not None
    assert plain["handler"] == 1
    assert plain["plan_state"] is None
    assert plain["secret_delta"] == 0
    compact = plain["result"].replace(" ", "")
    assert '"ok":true' in compact
    assert data["handler_identity_ok"] == "not_applicable"
    assert data["registry_dispatch"] == "not_applicable"
    assert data["formal_tool_registered"] is True


def test_mutation_old_analyzed_skip_next_call_breaks_main_agent_approve(tmp_path):
    """Restoring pre-round7 ANALYZED fail-closed without next_call must RED."""
    data = _run("approve", tmp_path, CG_MUTATE_OLD_EXEC="1")
    # Under mutation, approval/handler never run — proves the order fix is load-bearing.
    assert data["counts"]["pre_tool_call"] == 0
    assert data["counts"]["handler"] == 0
    assert data["order"] == ["tool_request", "tool_execution"]


@pytest.mark.parametrize("dropped", ["tool_request", "tool_execution", "pre_tool_call", "handler"])
def test_mutation_drop_registered_callback_breaks_approve(tmp_path, dropped):
    """Removing any production path piece must break Framework E2E approve."""
    home = tmp_path / f"home-drop-{dropped}"
    hermes = tmp_path / f"hermes-drop-{dropped}"
    home.mkdir()
    hermes.mkdir()
    (home / "tmp").mkdir()
    env = _base_env(home, hermes)
    env["CG_SCENARIO"] = "approve"
    env["CG_DECOY"] = DECOY
    env["CG_REPO"] = str(REPO)
    env["CG_DROP_CALLBACK"] = dropped
    proc = subprocess.run(
        [str(HERMES_SPIKE_PYTHON), "-c", PROBE],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    # Either probe fails hard, or approve evidence is incomplete.
    if proc.returncode != 0:
        return
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    assert lines, proc.stderr[-1500:]
    data = json.loads(lines[-1])
    healthy = (
        data.get("counts", {}).get("tool_request") == 1
        and data.get("counts", {}).get("tool_execution") == 1
        and data.get("counts", {}).get("pre_tool_call") == 1
        and data.get("counts", {}).get("handler") == 1
        and data.get("adapter_ok") is True
        and data.get("plan_state") == "consumed"
        and data.get("registry_dispatch") is True
    )
    assert healthy is False
