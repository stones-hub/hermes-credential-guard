"""R3B Slice B4: credential_process_run formal tool + finalize dispatch."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import textwrap
import types
from pathlib import Path
from typing import Any, Dict, List

import pytest

from credential_guard import register
from credential_guard.approval import on_pre_tool_call
from credential_guard.bindings import PROCESS_REFERENCE_TOOL
from credential_guard.config import CONFIG_FILENAME
from credential_guard.injection_plan import PlanState
from credential_guard import runtime_config as rc
from credential_guard.runtime_config import load_and_publish_runtime, reset_runtime_for_tests
from credential_guard.tool_execution import (
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


class RecordingCtx:
    def __init__(self) -> None:
        self.tools: List[dict] = []

    def register_middleware(self, *a, **k):
        return None

    def register_hook(self, *a, **k):
        return None

    def register_cli_command(self, **k):
        return None

    def register_tool(self, **kwargs):
        self.tools.append(kwargs)


# LibreSSL bare 64-hex vs OpenSSL "ALG(stdin)= HEX"; never awk '{print $2}'.
_OPENSSL_HEX_MARK = (
    "printf '%s' \"$VAL\" | openssl dgst -sha256 -hex | "
    "awk '{last=\"\"; for(i=1;i<=NF;i++) if($i~/^[0-9a-fA-F]{64}$/) last=$i; "
    "if(last!=\"\") print last}' > \"$MARK\""
)


def _make_helper(tmp_path: Path) -> Path:
    path = tmp_path / "cg-env-probe"
    path.write_text(
        textwrap.dedent(
            f"""\
            #!/bin/sh
            MARK="$1"
            VAL="${{CG_PROBE_ENV-}}"
            if [ -z "$VAL" ]; then
              printf 'absent' > "$MARK"
            else
              {_OPENSSL_HEX_MARK}
            fi
            printf 'ok\\n'
            """
        ),
        encoding="utf-8",
    )
    os.chmod(path, 0o700)
    return path


def _doc(token: str, program: str, marker: str) -> Dict[str, Any]:
    return {
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

    helper = _make_helper(tmp_path)
    marker = str(tmp_path / "mark.env")
    token = _decoy()
    _write(store, _doc(token, str(helper), marker))
    load_and_publish_runtime()
    rc.reset_injection_secret_resolve_count_for_tests()
    from credential_guard.adapters import process as proc

    proc.reset_process_start_count_for_tests()
    yield {
        "store": store,
        "token": token,
        "program": str(helper),
        "marker": marker,
        "tmp_path": tmp_path,
    }
    set_http_transport_override_for_tests(None)
    reset_http_adapter_observe_for_tests()
    reset_tool_request_state_for_tests()
    reset_runtime_for_tests()


def test_b4_register_includes_credential_process_run():
    from credential_guard.process_tools import (
        credential_process_run_schema,
        handle_credential_process_run,
    )

    ctx = RecordingCtx()
    register(ctx)
    names = [t["name"] for t in ctx.tools]
    assert PROCESS_REFERENCE_TOOL in names
    tool = next(t for t in ctx.tools if t["name"] == PROCESS_REFERENCE_TOOL)
    schema = tool["schema"]
    assert schema["parameters"]["required"] == ["target", "credential"]
    assert schema["parameters"]["additionalProperties"] is False
    props = set(schema["parameters"]["properties"])
    assert props == {"target", "credential"}
    assert "command" not in props and "env" not in props and "argv" not in props
    assert tool["handler"] is handle_credential_process_run
    assert callable(tool["check_fn"])


def test_b4_approve_env_resolve_and_process_start_once(env):
    from credential_guard.adapters import process as proc
    from credential_guard.process_tools import handle_credential_process_run

    token = env["token"]
    args = {
        "target": "cli-env",
        "credential": "<CREDENTIAL:cli_token>",
    }
    on_tool_request(
        tool_name=PROCESS_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-b4",
    )
    decision = on_pre_tool_call(
        tool_name=PROCESS_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-b4",
    )
    assert decision["action"] == "approve"
    prompt = json.dumps(decision, default=str)
    assert env["program"] not in prompt
    assert "CG_PROBE_ENV" not in prompt
    assert token not in prompt
    assert "fixed local program" in prompt.lower() or "process" in prompt.lower()

    out = on_tool_execution(
        PROCESS_REFERENCE_TOOL,
        args,
        handle_credential_process_run,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-b4",
    )
    data = json.loads(out)
    assert data["ok"] is True
    assert rc.get_injection_secret_resolve_count() == 1
    assert proc.process_start_count() == 1
    assert get_http_adapter_invoke_count() == 0
    expected = hashlib.sha256(token.encode("utf-8")).hexdigest()
    assert Path(env["marker"]).read_text(encoding="utf-8").strip() == expected
    assert token not in out
    assert env["program"] not in out
    assert get_plan_store().lookup("s1", "tc-b4").state is PlanState.CONSUMED

    # Replay: no second resolve/start
    before_r = rc.get_injection_secret_resolve_count()
    before_s = proc.process_start_count()
    out2 = on_tool_execution(
        PROCESS_REFERENCE_TOOL,
        args,
        handle_credential_process_run,
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-b4",
    )
    assert json.loads(out2)["ok"] is False
    assert rc.get_injection_secret_resolve_count() == before_r
    assert proc.process_start_count() == before_s
