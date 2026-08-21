"""R2 round-3: formal http_credential_request tool registration + schema/handler."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List

import pytest

from credential_guard import register
from credential_guard.runtime_config import HTTP_REFERENCE_TOOL
from credential_guard.tool_execution import (
    PLAN_NOT_PENDING,
    set_http_transport_override_for_tests,
    reset_http_adapter_observe_for_tests,
)

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

DECOY = "CG_HTTP_REF_" + "x" * 24


class RecordingCtx:
    def __init__(self) -> None:
        self.middlewares: List[tuple] = []
        self.hooks: List[tuple] = []
        self.cli: List[dict] = []
        self.tools: List[dict] = []

    def register_middleware(self, kind, callback):
        self.middlewares.append((kind, callback))

    def register_hook(self, name, callback):
        self.hooks.append((name, callback))

    def register_cli_command(self, **kwargs):
        self.cli.append(kwargs)

    def register_tool(self, **kwargs):
        self.tools.append(kwargs)


def _ref_args(**overrides: Any) -> Dict[str, Any]:
    base = {
        "target": "jenkins-production",
        "method": "POST",
        "path": "/job/project-x/build",
        "credential": "<CREDENTIAL:jenkins-token>",
    }
    base.update(overrides)
    return base


def _write_cfg(store: Path, token: str = DECOY) -> None:
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
    path = store / "credential-guard.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    os.chmod(path, 0o600)


# ---------------------------------------------------------------------------
# A. Formal registry reachability
# ---------------------------------------------------------------------------


def test_a_register_includes_http_credential_request():
    from credential_guard.reference_tools import (
        check_http_credential_request_available,
        handle_http_credential_request,
        http_credential_request_schema,
    )

    ctx = RecordingCtx()
    register(ctx)
    names = {t["name"] for t in ctx.tools}
    assert HTTP_REFERENCE_TOOL in names
    assert "http_credential_request" in names
    tool = next(t for t in ctx.tools if t["name"] == HTTP_REFERENCE_TOOL)
    assert tool["handler"] is handle_http_credential_request
    assert tool["check_fn"] is check_http_credential_request_available
    assert tool["schema"] == http_credential_request_schema()
    assert tool["schema"]["parameters"]["additionalProperties"] is False
    assert set(tool["schema"]["parameters"]["required"]) == {
        "target",
        "method",
        "path",
        "credential",
    }
    desc = tool.get("description") or tool["schema"].get("description") or ""
    assert "逻辑引用" in desc or "logical reference" in desc.lower()
    assert "R3" in desc


def test_a_schema_shape_and_method_enum():
    from credential_guard.reference_tools import http_credential_request_schema

    schema = http_credential_request_schema()
    assert schema["name"] == "http_credential_request"
    props = schema["parameters"]["properties"]
    assert set(props) == {"target", "method", "path", "credential"}
    assert schema["parameters"]["additionalProperties"] is False
    assert set(schema["parameters"]["required"]) == {
        "target",
        "method",
        "path",
        "credential",
    }
    methods = set(props["method"]["enum"])
    assert "POST" in methods
    assert methods <= {
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
    }


def _run_hermes_probe(scenario: str, tmp_path: Path) -> dict:
    assert HERMES_AGENT_ROOT.is_dir()
    assert HERMES_SPIKE_PYTHON.is_file()
    home = tmp_path / f"home-{scenario}"
    hermes = tmp_path / f"hermes-{scenario}"
    home.mkdir()
    hermes.mkdir()
    (home / "tmp").mkdir()
    env = {
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
        "CG_HTTP_REF_SCENARIO": scenario,
    }
    probe = r"""
import json, os, secrets, types
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from credential_guard import register
from credential_guard.runtime_config import (
    HTTP_REFERENCE_TOOL,
    load_and_publish_runtime,
    reset_execution_secret_resolve_count_for_tests,
    reset_runtime_for_tests,
)
from credential_guard.tool_execution import (
    PLAN_NOT_PENDING,
    set_http_transport_override_for_tests,
    reset_http_adapter_observe_for_tests,
)
from credential_guard.tool_request import reset_tool_request_state_for_tests
from credential_guard.reference_tools import handle_http_credential_request
from credential_guard.approval import on_pre_tool_call
from credential_guard.tool_execution import on_tool_execution
from credential_guard.tool_request import on_tool_request, get_plan_store
from credential_guard.injection_plan import PlanState

scenario = os.environ["CG_HTTP_REF_SCENARIO"]
hermes_home = Path(os.environ["HERMES_HOME"])
store = hermes_home / "credential-guard"

# The plugin derives its store from its install location and no longer reads
# HERMES_HOME; this probe runs from a checkout, so pin the store explicitly.
from credential_guard import store_location as _sl

_sl.use_store_dir(store)
token = "CG_DISP_" + secrets.token_hex(12)
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
reset_http_adapter_observe_for_tests()
set_http_transport_override_for_tests(lambda req: {
    "status": 201,
    "headers": {"content-type": "application/json"},
    "body": b'{"queued":true}',
})

import hermes_cli.plugins as plugins_mod
from hermes_cli.plugins import PluginManager
from tools.registry import registry
from model_tools import handle_function_call

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
assert HTTP_REFERENCE_TOOL in mgr._plugin_tool_names
entry = registry.get_entry(HTTP_REFERENCE_TOOL)
assert entry is not None and entry.handler is handle_http_credential_request
mgr._hooks["transform_tool_result"] = []

order = []
evidence = {"downstream": 0, "approval_message": None, "order": order}

def wrap_req(**kw):
    order.append("tool_request")
    return on_tool_request(**kw)

def wrap_pre(**kw):
    order.append("pre_tool_call")
    out = on_pre_tool_call(**kw)
    if isinstance(out, dict) and out.get("message"):
        evidence["approval_message"] = out["message"]
    return out

def wrap_exec(*, args, next_call, **kw):
    order.append("tool_execution")
    def counted(a):
        evidence["downstream"] += 1
        return next_call(a)
    return on_tool_execution(args=args, next_call=counted, **kw)

mgr._middleware["tool_request"] = [wrap_req]
mgr._middleware["tool_execution"] = [wrap_exec]
mgr._hooks["pre_tool_call"] = [wrap_pre]

args = {
    "target": "jenkins-production",
    "method": "POST",
    "path": "/job/project-x/build",
    "credential": "<CREDENTIAL:jenkins-token>",
}

def gate(tool_name, reason, **kwargs):
    order.append("approval_gate")
    if scenario == "deny":
        return {"approved": False, "message": "DENIED: http-ref"}
    return {"approved": True, "message": None}

with patch("tools.approval.request_tool_approval", side_effect=gate):
    result = handle_function_call(
        HTTP_REFERENCE_TOOL,
        deepcopy(args),
        task_id="task-" + scenario,
        tool_call_id="tc-" + scenario,
        session_id="sess-" + scenario,
        turn_id="turn-1",
    )

blob = result if isinstance(result, str) else json.dumps(result)
plan = None
try:
    plan = get_plan_store().lookup("sess-" + scenario, "tc-" + scenario)
except Exception:
    plan = None

out = {
    "scenario": scenario,
    "order": list(order),
    "downstream": evidence["downstream"],
    "approval_message": evidence["approval_message"],
    "adapter_not_ready": PLAN_NOT_PENDING in blob,
    "adapter_ok": ('"ok":true' in blob.replace(" ", "") and '"status":201' in blob.replace(" ", "")),
    "plan_state": plan.state.value if plan else None,
    "token_in_result": int(token in blob),
    "token_in_message": int(token in (evidence["approval_message"] or "")),
    "host_in_message": int("jenkins.example" in (evidence["approval_message"] or "")),
    "has_method_path": int("POST /job/project-x/build" in (evidence["approval_message"] or "")),
    "tool_in_registry": True,
    "handler_identity_ok": entry.handler is handle_http_credential_request,
}
print(json.dumps(out, sort_keys=True))
"""
    proc = subprocess.run(
        [str(HERMES_SPIKE_PYTHON), "-c", probe],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout[-1500:] + "\n" + proc.stderr[-1500:]
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    return json.loads(lines[-1])


def test_a_hermes_plugin_manager_discovers_handler_identity(tmp_path):
    data = _run_hermes_probe("approve", tmp_path)
    assert data["tool_in_registry"] is True
    assert data["handler_identity_ok"] is True


def test_a_hermes_dispatch_deny_handler_downstream_zero(tmp_path):
    data = _run_hermes_probe("deny", tmp_path)
    assert data["order"][:3] == ["tool_request", "pre_tool_call", "approval_gate"]
    assert "tool_execution" not in data["order"]
    assert data["downstream"] == 0
    assert data["token_in_result"] == 0


def test_a_hermes_dispatch_approve_adapter_not_ready(tmp_path):
    data = _run_hermes_probe("approve", tmp_path)
    assert data["order"] == [
        "tool_request",
        "pre_tool_call",
        "approval_gate",
        "tool_execution",
    ]
    # Backup dispatcher: next_call reaches formal handler (counted as local
    # boundary, not R3 downstream inject).
    assert data["downstream"] == 1
    assert data["adapter_ok"] is True
    assert data["adapter_not_ready"] is False
    assert data["plan_state"] == "consumed"
    assert data["has_method_path"] == 1
    assert data["token_in_result"] == 0
    assert data["token_in_message"] == 0
    assert data["host_in_message"] == 0
    msg = data["approval_message"] or ""
    assert "http_credential_request" in msg
    assert "jenkins-production" in msg
    assert "jenkins-token" in msg


# ---------------------------------------------------------------------------
# B. Schema/handler defence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_args",
    [
        {},
        {"target": "t", "method": "POST", "path": "/x"},
        {
            "target": "t",
            "method": "POST",
            "path": "/x",
            "credential": "<CREDENTIAL:c>",
            "extra": "nope",
        },
        {
            "target": 1,
            "method": "POST",
            "path": "/x",
            "credential": "<CREDENTIAL:c>",
        },
        {
            "target": "t",
            "method": "TRACE",
            "path": "/x",
            "credential": "<CREDENTIAL:c>",
        },
        {
            "target": "t",
            "method": "POST",
            "path": "https://evil.test/x",
            "credential": "<CREDENTIAL:c>",
        },
        {
            "target": "t",
            "method": "POST",
            "path": "//evil.test/x",
            "credential": "<CREDENTIAL:c>",
        },
        {
            "target": "t",
            "method": "POST",
            "path": "/x@user:pass",
            "credential": "<CREDENTIAL:c>",
        },
        {
            "target": "t",
            "method": "POST",
            "path": "/x#frag",
            "credential": "<CREDENTIAL:c>",
        },
        {
            "target": "t",
            "method": "POST",
            "path": "/x\ny",
            "credential": "<CREDENTIAL:c>",
        },
        {
            "target": "t",
            "method": "POST",
            "path": "/x\\y",
            "credential": "<CREDENTIAL:c>",
        },
        {
            "target": "t",
            "method": "POST",
            "path": "relative",
            "credential": "<CREDENTIAL:c>",
        },
        {
            "target": "t",
            "method": "POST",
            "path": "/x\u2028y",
            "credential": "<CREDENTIAL:c>",
        },
        {
            "target": "t",
            "method": "POST",
            "path": "/x\u2029y",
            "credential": "<CREDENTIAL:c>",
        },
    ],
)
def test_b_schema_rejects_invalid_args(bad_args):
    from credential_guard.reference_tools import (
        handle_http_credential_request,
        validate_http_credential_request_args,
    )

    with pytest.raises(ValueError):
        validate_http_credential_request_args(bad_args)
    out = json.loads(handle_http_credential_request(bad_args))
    assert out["ok"] is False
    blob = json.dumps(out)
    assert DECOY not in blob
    assert "CG_HTTP_REF_" not in blob


def test_b_handler_direct_call_never_connects_or_resolves(monkeypatch):
    from credential_guard.reference_tools import handle_http_credential_request

    banned = []

    def boom(name):
        def _inner(*a, **k):
            banned.append(name)
            raise AssertionError(f"banned:{name}")

        return _inner

    import socket
    import subprocess as sp

    monkeypatch.setattr(socket, "socket", boom("socket"))
    monkeypatch.setattr(socket, "create_connection", boom("create_connection"))
    monkeypatch.setattr(sp, "Popen", boom("Popen"))
    monkeypatch.setattr(sp, "run", boom("run"))

    resolve_hits = []

    def fake_resolve(*a, **k):
        resolve_hits.append(1)
        raise AssertionError("must not resolve")

    out = json.loads(handle_http_credential_request(_ref_args()))
    assert out["ok"] is False
    assert out["error"] == "CALL_IDENTITY_REQUIRED"
    assert banned == []
    assert resolve_hits == []
    assert DECOY not in json.dumps(out)


def test_b_check_fn_does_not_read_secret_or_connect(tmp_path, monkeypatch):
    from credential_guard.reference_tools import check_http_credential_request_available

    hermes = tmp_path / "hermes"
    store = hermes / "credential-guard"
    store.mkdir(parents=True)
    os.chmod(store, 0o700)
    (store / "credential-guard.json").write_text(
        json.dumps({"version": 2, "credentials": {}, "bindings": {}}),
        encoding="utf-8",
    )
    os.chmod(store / "credential-guard.json", 0o600)
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()

    import socket
    import subprocess as sp

    hits = []

    def boom(*a, **k):
        hits.append(1)
        raise AssertionError("connect")

    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(sp, "run", boom)
    assert check_http_credential_request_available() is True
    assert hits == []
