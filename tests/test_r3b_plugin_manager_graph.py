"""R3B Blocker C: real PluginManager discovery/load identity graph (no hand-rolled Ctx)."""

from __future__ import annotations

import json
import os
import shutil
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

DECOY = "CG_R3B_GRAPH_" + "y" * 24

# Embedded probe — authenticity gate scans this string for forbidden self-reg patterns.
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
repo = Path(os.environ["CG_REPO"])
hermes_home = Path(os.environ["HERMES_HOME"])
helper_dir = Path(os.environ["CG_HELPER_DIR"])
plugin_src = Path(os.environ["CG_PLUGIN_SRC"])

sys.path.insert(0, os.environ["HERMES_AGENT_ROOT"])
# Repo is only used as plugin *source copy*; runtime symbols come from hermes_plugins after discover.

for _name in ("modal", "anthropic", "firecrawl", "exa_py", "fal_client"):
    sys.modules.setdefault(_name, types.ModuleType(_name))

# --- install isolated user plugin copy (Hermes discover_and_load path) ---
plug_root = hermes_home / "plugins" / "credential-guard"
if plug_root.exists():
    import shutil as _sh
    _sh.rmtree(plug_root)
plug_root.mkdir(parents=True)
for name in ("plugin.yaml", "__init__.py"):
    src = plugin_src / name
    if src.is_file():
        (plug_root / name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
# copy package tree
import shutil as _sh
_sh.copytree(plugin_src / "credential_guard", plug_root / "credential_guard")

# refresh provides_tools list in copied manifest (informational)
manifest = (plug_root / "plugin.yaml").read_text(encoding="utf-8")
if "credential_process_run" not in manifest:
    (plug_root / "plugin.yaml").write_text(
        manifest.rstrip() + "\n  - credential_process_run\n", encoding="utf-8"
    )

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

store = hermes_home / "credential-guard"
store.mkdir(parents=True, exist_ok=True)
os.chmod(store, 0o700)
doc = {
    "version": 2,
    "credentials": {"cli_token": {"type": "token", "value": token}},
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
        }
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
from hermes_cli.plugins import PluginManager, discover_plugins
from tools.registry import registry
from agent.tool_executor import _run_agent_tool_execution_middleware

PROCESS_REFERENCE_TOOL = "credential_process_run"

plugins_mod._plugin_manager = None
# Real discovery/load — NO hand-built context object, NO registry deregister/re-register.
discover_plugins(force=True)
mgr = plugins_mod.get_plugin_manager()

loaded = mgr._plugins.get("credential-guard")
assert loaded is not None and loaded.enabled, "credential-guard not enabled via discover_and_load"

entry = registry.get_entry(PROCESS_REFERENCE_TOOL)
assert entry is not None, "credential_process_run missing after discover_and_load"

prod_req = list(mgr._middleware.get("tool_request", []) or [])
prod_exec = list(mgr._middleware.get("tool_execution", []) or [])
prod_pre = list(mgr._hooks.get("pre_tool_call", []) or [])
prod_handler = entry.handler

# Identity fingerprints BEFORE exercise
before = {
    "tool_request": id(prod_req[0].__code__) if prod_req else None,
    "tool_execution": id(prod_exec[0].__code__) if prod_exec else None,
    "pre_tool_call": id(prod_pre[0].__code__) if prod_pre else None,
    "handler": id(prod_handler.__code__),
    "handler_qualname": getattr(prod_handler, "__qualname__", ""),
    "handler_module": getattr(prod_handler, "__module__", ""),
}

# Publish runtime from the loaded plugin package
import hermes_plugins.credential_guard.credential_guard.runtime_config as rc
import hermes_plugins.credential_guard.credential_guard.tool_request as tr
import hermes_plugins.credential_guard.credential_guard.adapters.process as proc_mod
from hermes_plugins.credential_guard.credential_guard.injection_plan import InjectionPlanStore
from hermes_plugins.credential_guard.credential_guard.injection import resolve_one_for_execution
from hermes_plugins.credential_guard.credential_guard.adapters.process import execute_process

rc.reset_runtime_for_tests()
tr.reset_tool_request_state_for_tests()
rc.load_and_publish_runtime()
rc.reset_execution_secret_resolve_count_for_tests()
rc.reset_injection_secret_resolve_count_for_tests()
proc_mod.reset_process_start_count_for_tests()

secret_before = rc.get_execution_secret_resolve_count()
inj_before = rc.get_injection_secret_resolve_count()
start_before = proc_mod.process_start_count()

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
    (execute_process, "adapter"),
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
        return {"approved": False, "message": "DENIED: r3b-graph"}
    return {"approved": True, "message": None}

sys.setprofile(_profile)
try:
    args = {"target": "cli-env", "credential": "<CREDENTIAL:cli_token>"}
    session_id = "sess-r3b-graph-" + scenario
    turn_id = "turn-1"
    tool_call_id = "tc-r3b-graph-" + scenario
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
        tokens = set_current_observability_context(
            turn_id=turn_id, tool_call_id=tool_call_id
        )
        try:
            return registry.dispatch(
                PROCESS_REFERENCE_TOOL,
                deepcopy(final_args),
                task_id="task-1",
                session_id=session_id,
            )
        finally:
            reset_current_observability_context(tokens)

    with patch("tools.approval.request_tool_approval", side_effect=gate):
        managed = _run_agent_tool_execution_middleware(
            agent,
            function_name=PROCESS_REFERENCE_TOOL,
            function_args=deepcopy(args),
            effective_task_id="task-1",
            tool_call_id=tool_call_id,
            execute=execute,
        )
        result = managed.result
finally:
    sys.setprofile(None)

# Identity AFTER — must be unchanged (no re-register / wrapper swap)
entry_after = registry.get_entry(PROCESS_REFERENCE_TOOL)
after = {
    "tool_request": id(mgr._middleware.get("tool_request", [None])[0].__code__)
    if mgr._middleware.get("tool_request")
    else None,
    "tool_execution": id(mgr._middleware.get("tool_execution", [None])[0].__code__)
    if mgr._middleware.get("tool_execution")
    else None,
    "pre_tool_call": id(mgr._hooks.get("pre_tool_call", [None])[0].__code__)
    if mgr._hooks.get("pre_tool_call")
    else None,
    "handler": id(entry_after.handler.__code__) if entry_after else None,
}

blob = result if isinstance(result, str) else json.dumps(result)
adapter_ok = False
marker_ok = False
try:
    parsed = json.loads(blob) if isinstance(result, str) else result
    adapter_ok = bool(isinstance(parsed, dict) and parsed.get("ok") is True)
    if Path(marker).is_file():
        expected = hashlib.sha256(token.encode("utf-8")).hexdigest()
        marker_ok = Path(marker).read_text(encoding="utf-8").strip() == expected
except Exception:
    adapter_ok = False

id_keys = ("tool_request", "tool_execution", "pre_tool_call", "handler")
identity_unchanged = all(before.get(k) == after.get(k) for k in id_keys) and all(
    before.get(k) is not None for k in id_keys
)

print(json.dumps({
    "scenario": scenario,
    "order": list(order),
    "counts": counts,
    "adapter_ok": adapter_ok,
    "marker_ok": marker_ok,
    "token_in_result": int(token in blob),
    "process_start_delta": proc_mod.process_start_count() - start_before,
    "injection_resolve_delta": rc.get_injection_secret_resolve_count() - inj_before,
    "secret_resolve_delta": rc.get_execution_secret_resolve_count() - secret_before,
    "identity_before": {k: before[k] for k in id_keys},
    "identity_after": {k: after[k] for k in id_keys},
    "identity_unchanged": bool(identity_unchanged),
    "load_path": "discover_and_load",
    "handler_module": before["handler_module"],
}, sort_keys=True))
"""
)


def _minimal_env(home: Path, hermes: Path, helper_dir: Path) -> dict:
    """Whitelist only — never clone the full process environment mapping."""
    path = os.environ.get("PATH") or "/usr/bin:/bin"
    env = {
        "PATH": path,
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
        "PYTHONPATH": str(HERMES_AGENT_ROOT),
    }
    return env


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


def test_r3b_plugin_manager_discover_load_approve_identity(tmp_path: Path):
    data = _run("approve", tmp_path)
    assert data["load_path"] == "discover_and_load"
    assert data["identity_before"]["handler"] == data["identity_after"]["handler"]
    assert data["identity_before"]["tool_request"] == data["identity_after"]["tool_request"]
    assert data["identity_before"]["tool_execution"] == data["identity_after"]["tool_execution"]
    assert data["identity_before"]["pre_tool_call"] == data["identity_after"]["pre_tool_call"]
    assert data["identity_unchanged"] is True
    assert "hermes_plugins.credential_guard" in data["handler_module"]
    assert data["adapter_ok"] is True
    assert data["marker_ok"] is True
    assert data["process_start_delta"] == 1
    assert data["injection_resolve_delta"] == 1
    assert data["token_in_result"] == 0
    assert data["counts"].get("handler") == 1
    assert data["counts"].get("adapter") == 1


def test_r3b_plugin_manager_discover_load_deny_zero(tmp_path: Path):
    data = _run("deny", tmp_path)
    assert data["process_start_delta"] == 0
    assert data["injection_resolve_delta"] == 0
    assert data["counts"].get("adapter", 0) == 0
    assert data["identity_unchanged"] is True
