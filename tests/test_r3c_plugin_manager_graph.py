"""R3C C2: real PluginManager discovery/load identity + ordinary tool non-interference.

Candidate evidence only — does not claim R3/R3C PASS.
"""

from __future__ import annotations

import json
import os
import subprocess
import textwrap
from pathlib import Path

import pytest

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

DECOY = "CG_R3C_GRAPH_" + "g" * 24

PROBE = textwrap.dedent(
    r"""
import hashlib
import json
import os
import sys
import textwrap
import types
from copy import deepcopy
from pathlib import Path
from unittest.mock import MagicMock, patch

scenario = os.environ["CG_SCENARIO"]
token = os.environ["CG_DECOY"]
token_http = os.environ.get("CG_DECOY_HTTP", token + "_HTTP")
hermes_home = Path(os.environ["HERMES_HOME"])
helper_dir = Path(os.environ["CG_HELPER_DIR"])
plugin_src = Path(os.environ["CG_PLUGIN_SRC"])

sys.path.insert(0, os.environ["HERMES_AGENT_ROOT"])
for _name in ("modal", "anthropic", "firecrawl", "exa_py", "fal_client"):
    sys.modules.setdefault(_name, types.ModuleType(_name))

plug_root = hermes_home / "plugins" / "credential-guard"
if plug_root.exists():
    import shutil as _sh
    _sh.rmtree(plug_root)
plug_root.mkdir(parents=True)
for name in ("plugin.yaml", "__init__.py"):
    src = plugin_src / name
    if src.is_file():
        (plug_root / name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
import shutil as _sh
_sh.copytree(plugin_src / "credential_guard", plug_root / "credential_guard")
# Formal plugin.yaml must already declare credential_process_run — no temp patch.

helper = helper_dir / "cg-env-probe"
helper.write_text(textwrap.dedent('''\
#!/bin/sh
MARK="$1"
VAL="${CG_PROBE_ENV-}"
if [ -z "$VAL" ]; then
  printf 'absent' > "$MARK"
else
  printf '%s' "$VAL" | openssl dgst -sha256 -hex | awk '{last=""; for(i=1;i<=NF;i++) if($i~/^[0-9a-fA-F]{64}$/) last=$i; if(last!="") print last}' > "$MARK"
fi
printf 'ok\\n'
'''), encoding="utf-8")
os.chmod(helper, 0o700)
program = str(helper)
marker = str(helper_dir / "mark.env")
stdin_helper = helper_dir / "cg-stdin-probe"
stdin_helper.write_text(textwrap.dedent('''\
#!/bin/sh
MARK="$1"
VAL=$(cat)
if [ -z "$VAL" ]; then
  printf 'absent' > "$MARK"
else
  printf '%s' "$VAL" | openssl dgst -sha256 -hex | awk '{last=""; for(i=1;i<=NF;i++) if($i~/^[0-9a-fA-F]{64}$/) last=$i; if(last!="") print last}' > "$MARK"
fi
printf 'ok\\n'
'''), encoding="utf-8")
os.chmod(stdin_helper, 0o700)
stdin_program = str(stdin_helper)
stdin_marker = str(helper_dir / "mark.stdin")
token_stdin = token + "_STDIN_DISTINCT"

store = hermes_home / "credential-guard"
store.mkdir(parents=True, exist_ok=True)
os.chmod(store, 0o700)
doc = {
    "version": 2,
    "credentials": {
        "cli_token": {"type": "token", "value": token},
        "http_token": {"type": "token", "value": token_http},
        "stdin_token": {"type": "token", "value": token_stdin},
    },
    "bindings": {
        "cli-env": {
            "type": "process_env",
            "credential_ref": "cli_token",
            "program": program,
            "argv": [program, marker],
            "env_name": "CG_PROBE_ENV",
            "timeout_seconds": 10,
            "max_stdout_bytes": 4096,
            "max_stderr_bytes": 4096,
            "approval": "required",
        },
        "cli-stdin": {
            "type": "stdin",
            "credential_ref": "stdin_token",
            "program": stdin_program,
            "argv": [stdin_program, stdin_marker],
            "stdin_format": "raw",
            "timeout_seconds": 10,
            "max_stdout_bytes": 4096,
            "max_stderr_bytes": 4096,
            "approval": "required",
        },
        "http-svc": {
            "type": "http",
            "credential_ref": "http_token",
            "target": {"scheme": "https", "host": "svc.example.test", "port": 443},
            "request": {
                "allowed_methods": ["GET", "POST"],
                "allowed_paths": ["/v1/run"],
                "connect_timeout_seconds": 5,
                "total_timeout_seconds": 15,
                "max_response_body_bytes": 4096,
            },
            "inject": {"type": "bearer", "location": "authorization_header"},
            "approval": "required",
        },
    },
}
cfg = store / "credential-guard.json"
cfg.write_text(json.dumps(doc), encoding="utf-8")
os.chmod(cfg, 0o600)
(hermes_home / "config.yaml").write_text(
    'model: unused\napprovals:\n  mode: "manual"\n  timeout: 300\n'
    "plugins:\n  enabled:\n    - credential-guard\n",
    encoding="utf-8",
)

import hermes_cli.plugins as plugins_mod
from hermes_cli.plugins import discover_plugins
from tools.registry import registry
from agent.tool_executor import _run_agent_tool_execution_middleware

plugins_mod._plugin_manager = None
# Real discovery/load — NO hand-built Ctx, NO registry deregister/re-register.
discover_plugins(force=True)
mgr = plugins_mod.get_plugin_manager()
loaded = mgr._plugins.get("credential-guard")
assert loaded is not None and loaded.enabled

PROCESS_TOOL = "credential_process_run"
HTTP_TOOL = "http_credential_request"
if scenario == "http_approve":
    entry = registry.get_entry(HTTP_TOOL)
elif scenario in {"approve", "stdin_approve"}:
    entry = registry.get_entry(PROCESS_TOOL)
else:
    entry = registry.get_entry(PROCESS_TOOL)
assert entry is not None

prod_req = list(mgr._middleware.get("tool_request", []) or [])
prod_exec = list(mgr._middleware.get("tool_execution", []) or [])
prod_pre = list(mgr._hooks.get("pre_tool_call", []) or [])
prod_handler = entry.handler

before = {
    "tool_request_list": id(mgr._middleware.get("tool_request")),
    "tool_execution_list": id(mgr._middleware.get("tool_execution")),
    "pre_tool_call_list": id(mgr._hooks.get("pre_tool_call")),
    "tool_request": id(prod_req[0].__code__) if prod_req else None,
    "tool_execution": id(prod_exec[0].__code__) if prod_exec else None,
    "pre_tool_call": id(prod_pre[0].__code__) if prod_pre else None,
    "handler": id(prod_handler.__code__),
    "handler_module": getattr(prod_handler, "__module__", ""),
}

import hermes_plugins.credential_guard.credential_guard.runtime_config as rc
import hermes_plugins.credential_guard.credential_guard.tool_request as tr
import hermes_plugins.credential_guard.credential_guard.adapters.process as proc_mod
import hermes_plugins.credential_guard.credential_guard.tool_execution as te_mod
from hermes_plugins.credential_guard.credential_guard.injection_plan import InjectionPlanStore
from hermes_plugins.credential_guard.credential_guard.injection import resolve_one_for_execution
from hermes_plugins.credential_guard.credential_guard.adapters.process import execute_process
from hermes_plugins.credential_guard.credential_guard.adapters.http import execute_http
from hermes_plugins.credential_guard.credential_guard.tool_request import get_plan_store

rc.reset_runtime_for_tests()
tr.reset_tool_request_state_for_tests()
rc.load_and_publish_runtime()
rc.reset_execution_secret_resolve_count_for_tests()
rc.reset_injection_secret_resolve_count_for_tests()
proc_mod.reset_process_start_count_for_tests()
te_mod.reset_http_adapter_observe_for_tests()
te_mod.set_http_transport_override_for_tests(
    lambda req: {"status": 201, "headers": {"content-type": "application/json"}, "body": b'{"queued":true}'}
)

inj_before = rc.get_injection_secret_resolve_count()
start_before = proc_mod.process_start_count()
http_before = te_mod.get_http_adapter_invoke_count()

order = []
counts = {
    "pre_tool_call": 0, "approval_gate": 0, "handler": 0,
    "tool_request": 0, "tool_execution": 0, "consume": 0, "resolve": 0, "adapter": 0,
}
adapter_fn = execute_http if scenario == "http_approve" else execute_process
code_labels = {}
for cb, label in (
    (prod_req[0] if prod_req else None, "tool_request"),
    (prod_exec[0] if prod_exec else None, "tool_execution"),
    (prod_pre[0] if prod_pre else None, "pre_tool_call"),
    (prod_handler, "handler"),
    (InjectionPlanStore.consume, "consume"),
    (resolve_one_for_execution, "resolve"),
    (adapter_fn, "adapter"),
):
    if cb is not None and hasattr(cb, "__code__"):
        code_labels[id(cb.__code__)] = label

def _profile(frame, event, arg):
    if event == "call":
        label = code_labels.get(id(frame.f_code))
        if label is not None:
            counts[label] += 1
            order.append(label)
    return _profile

class Guardrails:
    def before_call(self, name, args):
        return types.SimpleNamespace(allows_execution=True, message=None)

def gate(tool_name, reason, **kwargs):
    counts["approval_gate"] += 1
    order.append("approval_gate")
    if scenario == "deny":
        return {"approved": False, "message": "DENIED: r3c-graph"}
    return {"approved": True, "message": None}

# --- plain ordinary tool path (no credential reference) ---
plain = None
if scenario == "plain":
    plain_counts = {"handler": 0}
    def plain_execute(final_args):
        plain_counts["handler"] += 1
        return json.dumps({"ok": True, "echo": final_args}, sort_keys=True)
    agent_p = MagicMock()
    agent_p.session_id = "sess-r3c-plain"
    agent_p._current_turn_id = "turn-1"
    agent_p._current_api_request_id = "api-1"
    agent_p._tool_guardrails = Guardrails()
    agent_p._turns_since_memory = 0
    agent_p._iters_since_skill = 0
    with patch("tools.approval.request_tool_approval", side_effect=gate):
        managed = _run_agent_tool_execution_middleware(
            agent_p,
            function_name="write_file",
            function_args={"path": "/tmp/ordinary-r3c.txt", "content": "x"},
            effective_task_id="task-plain",
            tool_call_id="tc-plain",
            execute=plain_execute,
        )
    entry_after_plain = registry.get_entry(PROCESS_TOOL)
    after_plain = {
        "tool_request_list": id(mgr._middleware.get("tool_request")),
        "tool_execution_list": id(mgr._middleware.get("tool_execution")),
        "pre_tool_call_list": id(mgr._hooks.get("pre_tool_call")),
        "tool_request": id(mgr._middleware.get("tool_request", [None])[0].__code__) if mgr._middleware.get("tool_request") else None,
        "tool_execution": id(mgr._middleware.get("tool_execution", [None])[0].__code__) if mgr._middleware.get("tool_execution") else None,
        "pre_tool_call": id(mgr._hooks.get("pre_tool_call", [None])[0].__code__) if mgr._hooks.get("pre_tool_call") else None,
        "handler": id(entry_after_plain.handler.__code__) if entry_after_plain else None,
    }
    id_keys_plain = ("tool_request_list", "tool_execution_list", "pre_tool_call_list",
                     "tool_request", "tool_execution", "pre_tool_call", "handler")
    identity_unchanged_plain = all(before.get(k) == after_plain.get(k) for k in id_keys_plain) and all(
        before.get(k) is not None for k in id_keys_plain
    )
    plain = {
        "handler": plain_counts["handler"],
        "result": managed.result if isinstance(managed.result, str) else json.dumps(managed.result),
        "approval_gate": counts["approval_gate"],
        "injection_resolve_delta": rc.get_injection_secret_resolve_count() - inj_before,
        "process_start_delta": proc_mod.process_start_count() - start_before,
        "http_adapter_delta": te_mod.get_http_adapter_invoke_count() - http_before,
        "ordinary_evidence_layer": "middleware",
    }
    try:
        p = get_plan_store().lookup("sess-r3c-plain", "tc-plain")
        plain["plan_state"] = p.state.value if p else None
    except Exception:
        plain["plan_state"] = None
    print(json.dumps({
        "scenario": scenario,
        "plain": plain,
        "identity_unchanged": bool(identity_unchanged_plain),
        "load_path": "discover_and_load",
        "handler_module": before["handler_module"],
        "ordinary_evidence_layer": "middleware",
    }, sort_keys=True))
    raise SystemExit(0)

sys.setprofile(_profile)
try:
    if scenario == "http_approve":
        args = {"target": "http-svc", "method": "POST", "path": "/v1/run", "credential": "<CREDENTIAL:http_token>"}
        fname = HTTP_TOOL
        secret_for_leak = token_http
        active_marker = None
    elif scenario == "stdin_approve":
        args = {"target": "cli-stdin", "credential": "<CREDENTIAL:stdin_token>"}
        fname = PROCESS_TOOL
        secret_for_leak = token_stdin
        active_marker = Path(stdin_marker)
    else:
        args = {"target": "cli-env", "credential": "<CREDENTIAL:cli_token>"}
        fname = PROCESS_TOOL
        secret_for_leak = token
        active_marker = Path(marker)
    session_id = "sess-r3c-graph-" + scenario
    turn_id = "turn-1"
    tool_call_id = "tc-r3c-graph-" + scenario
    agent = MagicMock()
    agent.session_id = session_id
    agent._current_turn_id = turn_id
    agent._current_api_request_id = "api-1"
    agent._tool_guardrails = Guardrails()
    agent._turns_since_memory = 0
    agent._iters_since_skill = 0

    def execute(final_args):
        from tools.approval import (
            reset_current_observability_context,
            set_current_observability_context,
        )
        tokens = set_current_observability_context(turn_id=turn_id, tool_call_id=tool_call_id)
        try:
            return registry.dispatch(fname, deepcopy(final_args), task_id="task-1", session_id=session_id)
        finally:
            reset_current_observability_context(tokens)

    with patch("tools.approval.request_tool_approval", side_effect=gate):
        managed = _run_agent_tool_execution_middleware(
            agent,
            function_name=fname,
            function_args=deepcopy(args),
            effective_task_id="task-1",
            tool_call_id=tool_call_id,
            execute=execute,
        )
        result = managed.result
finally:
    sys.setprofile(None)

entry_after = registry.get_entry(fname)
after = {
    "tool_request_list": id(mgr._middleware.get("tool_request")),
    "tool_execution_list": id(mgr._middleware.get("tool_execution")),
    "pre_tool_call_list": id(mgr._hooks.get("pre_tool_call")),
    "tool_request": id(mgr._middleware.get("tool_request", [None])[0].__code__) if mgr._middleware.get("tool_request") else None,
    "tool_execution": id(mgr._middleware.get("tool_execution", [None])[0].__code__) if mgr._middleware.get("tool_execution") else None,
    "pre_tool_call": id(mgr._hooks.get("pre_tool_call", [None])[0].__code__) if mgr._hooks.get("pre_tool_call") else None,
    "handler": id(entry_after.handler.__code__) if entry_after else None,
}
id_keys = ("tool_request_list", "tool_execution_list", "pre_tool_call_list",
           "tool_request", "tool_execution", "pre_tool_call", "handler")
identity_unchanged = all(before.get(k) == after.get(k) for k in id_keys) and all(
    before.get(k) is not None for k in id_keys
)
blob = result if isinstance(result, str) else json.dumps(result)
adapter_ok = False
marker_ok = False
try:
    parsed = json.loads(blob) if isinstance(result, str) else result
    adapter_ok = bool(isinstance(parsed, dict) and parsed.get("ok") is True)
    if active_marker is not None and active_marker.is_file():
        expected = hashlib.sha256(secret_for_leak.encode("utf-8")).hexdigest()
        marker_ok = active_marker.read_text(encoding="utf-8").strip() == expected
except Exception:
    pass

print(json.dumps({
    "scenario": scenario,
    "order": list(order),
    "counts": counts,
    "adapter_ok": adapter_ok,
    "marker_ok": marker_ok,
    "token_in_result": int(secret_for_leak in blob),
    "process_start_delta": proc_mod.process_start_count() - start_before,
    "http_adapter_delta": te_mod.get_http_adapter_invoke_count() - http_before,
    "injection_resolve_delta": rc.get_injection_secret_resolve_count() - inj_before,
    "identity_unchanged": bool(identity_unchanged),
    "load_path": "discover_and_load",
    "handler_module": before["handler_module"],
}, sort_keys=True))
"""
)


def _minimal_env(home: Path, hermes: Path, helper_dir: Path) -> dict:
    return {
        "PATH": os.environ.get("PATH") or "/usr/bin:/bin",
        "LANG": os.environ.get("LANG") or "C",
        "TMPDIR": str(home / "tmp"),
        "TMP": str(home / "tmp"),
        "TEMP": str(home / "tmp"),
        "HOME": str(home),
        "HERMES_HOME": str(hermes),
        "HERMES_AGENT_ROOT": str(HERMES_AGENT_ROOT),
        "CG_REPO": str(REPO),
        "CG_HELPER_DIR": str(helper_dir),
        "CG_PLUGIN_SRC": str(REPO),
        "CG_DECOY": DECOY,
        "CG_DECOY_HTTP": DECOY + "_HTTP_DISTINCT",
        "PYTHONPATH": str(HERMES_AGENT_ROOT),
    }


def _run(scenario: str, tmp_path: Path) -> dict:
    home = tmp_path / f"home-{scenario}"
    hermes = tmp_path / f"hermes-{scenario}"
    helper_dir = tmp_path / f"helper-{scenario}"
    home.mkdir()
    hermes.mkdir()
    helper_dir.mkdir(mode=0o700)
    (home / "tmp").mkdir()
    env = _minimal_env(home, hermes, helper_dir)
    env["CG_SCENARIO"] = scenario
    proc = subprocess.run(
        [str(HERMES_SPIKE_PYTHON), "-c", PROBE],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-3000:] + "\n" + proc.stdout[-2000:]
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip().startswith("{")]
    assert lines, proc.stderr[-2000:]
    return json.loads(lines[-1])


def test_r3c_plugin_manager_discover_load_env_identity(tmp_path: Path):
    data = _run("approve", tmp_path)
    assert data["load_path"] == "discover_and_load"
    assert data["identity_unchanged"] is True
    assert "hermes_plugins.credential_guard" in data["handler_module"]
    assert data["adapter_ok"] is True
    assert data["marker_ok"] is True
    assert data["process_start_delta"] == 1
    assert data["http_adapter_delta"] == 0
    assert data["injection_resolve_delta"] == 1
    assert data["token_in_result"] == 0
    assert "class Ctx" not in PROBE
    assert "registry.deregister" not in PROBE


def test_r3c_plugin_manager_discover_load_http_identity(tmp_path: Path):
    data = _run("http_approve", tmp_path)
    assert data["identity_unchanged"] is True
    assert "hermes_plugins.credential_guard" in data["handler_module"]
    assert data["http_adapter_delta"] == 1
    assert data["process_start_delta"] == 0
    assert data["injection_resolve_delta"] == 1
    assert data["token_in_result"] == 0


def test_r3c_plugin_manager_discover_load_stdin_identity(tmp_path: Path):
    data = _run("stdin_approve", tmp_path)
    assert data["identity_unchanged"] is True
    assert "hermes_plugins.credential_guard" in data["handler_module"]
    assert data["process_start_delta"] == 1
    assert data["http_adapter_delta"] == 0
    assert data["injection_resolve_delta"] == 1
    assert data["marker_ok"] is True
    assert data["token_in_result"] == 0


def test_r3c_plugin_manager_ordinary_tool_non_interference(tmp_path: Path):
    data = _run("plain", tmp_path)
    plain = data["plain"]
    assert data["identity_unchanged"] is True
    assert plain["ordinary_evidence_layer"] == "middleware"
    assert data["ordinary_evidence_layer"] == "middleware"
    assert plain["handler"] == 1
    assert plain["approval_gate"] == 0
    assert plain["injection_resolve_delta"] == 0
    assert plain["process_start_delta"] == 0
    assert plain["http_adapter_delta"] == 0
    assert plain["plan_state"] is None
    compact = plain["result"].replace(" ", "")
    assert '"ok":true' in compact
    assert "ordinary-r3c.txt" in plain["result"]


def test_r3c_plugin_manager_source_forbids_self_register():
    src = Path(__file__).read_text(encoding="utf-8")
    assert "discover_plugins(force=True)" in src
    assert "class Ctx" not in PROBE
    assert "registry.deregister" not in PROBE
    assert "os.environ.copy" not in PROBE
    assert "sys.setprofile" in PROBE
    # Forbid constant True assignment in PROBE JSON (split to avoid gate self-match).
    assert ("identity_unchanged" + '": True') not in PROBE
    assert "before.get(k) == after.get(k)" in PROBE
    assert "stdin_approve" in PROBE
    assert "ordinary_evidence_layer" in PROBE
