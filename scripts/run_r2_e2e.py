#!/usr/bin/env python3
"""R2E isolated runner — Credential Guard reference flow under temp HOME.

Uses HERMES_AGENT_ROOT sanitized checkout. Never reads /Users/yelei/.hermes.
Prints one JSON evidence object. Never prints decoy plaintext.

Observes production PluginManager callbacks/handler via sys.setprofile on
code objects. Does not overlay mgr callback lists or re-register handlers.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
SPIKE_PYTHON_HINT = Path("/tmp/credential-guard-r2-hermes-venv/bin/python")


def _ensure_paths() -> Path:
    root = Path(os.environ.get("HERMES_AGENT_ROOT") or "/tmp/credential-guard-r2-hermes-source")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    return root


def _write_config(hermes_home: Path, token: str) -> Path:
    store = hermes_home / "credential-guard"
    store.mkdir(parents=True, exist_ok=True)
    os.chmod(store, 0o700)
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
    path = store / "credential-guard.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    os.chmod(path, 0o600)
    (hermes_home / "config.yaml").write_text(
        'model: unused-r2e\napprovals:\n  mode: "manual"\n  timeout: 300\nplugins:\n  enabled: []\n',
        encoding="utf-8",
    )
    return path


def _ref_args() -> Dict[str, Any]:
    return {
        "target": "jenkins-production",
        "method": "POST",
        "path": "/job/project-x/build",
        "credential": "<CREDENTIAL:jenkins-token>",
    }


def _scan(blob: str, secret: str, min_frag: int = 8) -> int:
    if not secret or not blob:
        return 0
    if secret in blob:
        return 1
    if len(secret) < min_frag:
        return 1 if secret in blob else 0
    for i in range(len(secret) - min_frag + 1):
        if secret[i : i + min_frag] in blob:
            return 1
    return 0


def run_scenario(scenario: str) -> Dict[str, Any]:
    _ensure_paths()
    hermes_home = Path(os.environ["HERMES_HOME"])
    home = Path(os.environ["HOME"])
    (home / "tmp").mkdir(parents=True, exist_ok=True)

    token = "CG_R2E_" + secrets.token_urlsafe(24)
    _write_config(hermes_home, token)

    from credential_guard import register
    from credential_guard.reference_tools import handle_http_credential_request
    from credential_guard.runtime_config import (
        HTTP_REFERENCE_TOOL,
        get_execution_secret_resolve_count,
        get_injection_secret_resolve_count,
        load_and_publish_runtime,
        reset_execution_secret_resolve_count_for_tests,
        reset_injection_secret_resolve_count_for_tests,
        reset_runtime_for_tests,
    )
    from credential_guard.tool_execution import (
        RUNTIME_ADAPTER_NOT_READY,
        get_http_adapter_invoke_count,
        reset_http_adapter_observe_for_tests,
        set_http_transport_override_for_tests,
    )
    from credential_guard.tool_request import (
        get_plan_store,
        reset_tool_request_state_for_tests,
    )

    reset_runtime_for_tests()
    reset_tool_request_state_for_tests()
    # Simulate R1B Provider egress publish before any tool path (model request gate).
    load_and_publish_runtime()
    # Separate egress-protect resolves from R2-path new resolves.
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
    resolve_before_r2 = get_execution_secret_resolve_count()
    inj_before = get_injection_secret_resolve_count()
    adapter_before = get_http_adapter_invoke_count()

    import builtins
    import types
    from pathlib import Path as _Path

    import credential_guard.config as config_mod

    body_read_hits: List[str] = []
    lstat_hits = {"n": 0}
    cfg_name = "credential-guard.json"
    # Phase marker: R2 critical path vs post-handler R1B transform_tool_result.
    phase = {"name": "r2_critical"}
    resolve_at_r2_end = {"n": None}

    def _boom(label: str):
        def _inner(*_a, **_k):
            body_read_hits.append(f"{phase['name']}:{label}")
            if phase["name"] == "r2_critical":
                raise AssertionError(f"CONFIG_BODY_READ_DURING_R2:{label}")
            return real_open_and_read(*_a, **_k)

        return _inner

    real_open_and_read = config_mod._open_and_read
    config_mod._open_and_read = _boom("_open_and_read")  # type: ignore[assignment]

    real_os_open = os.open

    def _guarded_os_open2(path, flags, *args, **kwargs):
        path_s = str(path)
        write_bits = os.O_WRONLY | getattr(os, "O_RDWR", 0) | getattr(os, "O_APPEND", 0)
        if path_s.endswith(cfg_name) and (flags & write_bits) == 0:
            body_read_hits.append(f"{phase['name']}:os.open")
            if phase["name"] == "r2_critical":
                raise AssertionError("CONFIG_BODY_READ_DURING_R2:os.open")
        return real_os_open(path, flags, *args, **kwargs)

    os.open = _guarded_os_open2  # type: ignore[assignment]

    real_open = builtins.open

    def _guarded_open(file, mode="r", *a, **k):
        path_s = str(file)
        mode_s = str(mode)
        if path_s.endswith(cfg_name) and "w" not in mode_s and "a" not in mode_s and "x" not in mode_s:
            if "r" in mode_s or mode_s == "":
                body_read_hits.append(f"{phase['name']}:builtins.open")
                if phase["name"] == "r2_critical":
                    raise AssertionError("CONFIG_BODY_READ_DURING_R2:builtins.open")
        return real_open(file, mode, *a, **k)

    builtins.open = _guarded_open  # type: ignore[assignment]

    real_lstat = _Path.lstat

    def _counting_lstat(self):
        if self.name == cfg_name:
            lstat_hits["n"] += 1
        return real_lstat(self)

    _Path.lstat = _counting_lstat  # type: ignore[assignment]

    import hermes_cli.plugins as plugins_mod
    from hermes_cli.middleware import (
        apply_tool_request_middleware,
        run_tool_execution_middleware,
    )
    from hermes_cli.plugins import PluginManager, resolve_pre_tool_block
    from model_tools import handle_function_call
    from tools.registry import registry

    plugins_mod._plugin_manager = None
    mgr = PluginManager()
    plugins_mod._plugin_manager = mgr

    class _RegisterCtx:
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

    register(_RegisterCtx(mgr))
    formal_tool_registered = HTTP_REFERENCE_TOOL in mgr._plugin_tool_names
    entry = registry.get_entry(HTTP_REFERENCE_TOOL)
    handler_identity_ok = (
        entry is not None and entry.handler is handle_http_credential_request
    )
    # Keep transform_tool_result registered (R1B). Do not clear the hook list.
    # Body-read boom is phase-gated: after formal handler returns, allow R1B reads.

    prod_req = list(mgr._middleware.get("tool_request", []) or [])
    prod_exec = list(mgr._middleware.get("tool_execution", []) or [])
    prod_pre = list(mgr._hooks.get("pre_tool_call", []) or [])
    prod_transform = list(mgr._hooks.get("transform_tool_result", []) or [])
    if not (prod_req and prod_exec and prod_pre):
        raise RuntimeError("PluginManager missing registered R2 callbacks")
    if not prod_transform:
        raise RuntimeError("PluginManager missing registered transform_tool_result")

    evidence: Dict[str, Any] = {
        "scenario": scenario,
        "decoy_len": len(token),
        "secret_resolve_count": None,  # filled from live counter at end
        "secret_resolve_delta_during_r2": None,
        "config_body_read_hits": None,
        "r2_critical_body_read_hits": None,
        "lstat_count": None,
        "downstream_call_count": 0,  # R3/network inject only
        "next_call_count": 0,
        "handler_call_count": 0,
        "approval_gate_count": 0,
        "canary_in_result": 0,
        "tool_execution_entered": False,
        "approval_denied": False,
        "adapter_not_ready": False,
        "adapter_ok": False,
        "injection_resolve_delta": 0,
        "adapter_invoke_delta": 0,
        "call_order": [],
        "worker_fingerprint_skipped": True,
        "worker_fingerprint_skip_reason": "coding_agent_forbidden_from_real_hermes_home",
        "dual_file_fallback": False,
        # Compatibility path below; main-agent Framework E2E is a separate scenario.
        "fake_provider": False,
        "provider_wire_included": False,
        "provider_wire_deferred_to": "R1B",
        "r3_injection_implemented": True,
        "r1b_publish_before_r2": True,
        "formal_tool_registered": bool(formal_tool_registered),
        "handler_identity_ok": bool(handler_identity_ok),
        "registry_dispatch": False,
        "evidence_tier": "compatibility_registry_dispatcher",
        "approval_message": None,
        "approval_shows_method_path": False,
    }

    order: List[str] = []
    prod_handler = entry.handler if entry is not None else None

    code_labels: Dict[int, str] = {}
    for cb, label in (
        (prod_req[0], "tool_request"),
        (prod_exec[0], "tool_execution"),
        (prod_pre[0], "pre_tool_call"),
        (prod_handler, "handler"),
        (prod_transform[0] if prod_transform else None, "transform_tool_result"),
    ):
        if cb is not None and hasattr(cb, "__code__"):
            code_labels[id(cb.__code__)] = label

    def _profile(frame, event, arg):
        code = frame.f_code
        if event == "call":
            label = code_labels.get(id(code))
            if label is not None:
                order.append(label)
                if label == "tool_execution":
                    evidence["tool_execution_entered"] = True
                elif label == "handler":
                    evidence["handler_call_count"] += 1
                    # Formal handler done; subsequent config body reads are R1B transform.
                    if resolve_at_r2_end["n"] is None:
                        resolve_at_r2_end["n"] = get_execution_secret_resolve_count()
                    phase["name"] = "r1b_transform"
                elif label == "transform_tool_result":
                    if resolve_at_r2_end["n"] is None:
                        resolve_at_r2_end["n"] = get_execution_secret_resolve_count()
                    phase["name"] = "r1b_transform"
            elif code.co_name == "next_call" and "middleware" in (code.co_filename or ""):
                evidence["next_call_count"] += 1
                order.append("next_call")
        elif event == "return":
            label = code_labels.get(id(code))
            if label == "pre_tool_call" and isinstance(arg, dict) and arg.get("message"):
                evidence["approval_message"] = arg["message"]
                if "POST /job/project-x/build" in arg["message"]:
                    evidence["approval_shows_method_path"] = True
        return _profile

    mode = os.environ.get("R2E_APPROVAL_MODE", "manual")
    if scenario in {"yolo", "smart", "off"}:
        mode = {"yolo": "manual", "smart": "smart", "off": "off"}[scenario]
        (hermes_home / "config.yaml").write_text(
            f'model: unused\napprovals:\n  mode: "{mode}"\n  timeout: 300\n',
            encoding="utf-8",
        )

    yolo = scenario == "yolo"

    def _gate(tool_name, reason, **kwargs):
        order.append("approval_gate")
        evidence["approval_gate_count"] += 1
        if scenario == "deny":
            return {"approved": False, "message": "DENIED: r2e"}
        return {"approved": True, "message": None}

    session = "r2e-session"
    tc = f"tc-{scenario}"
    args = _ref_args()
    if scenario == "plain":
        args = {"path": "/tmp/plain.txt", "content": "hello"}
        tool = "write_file"
    else:
        tool = HTTP_REFERENCE_TOOL

    posture_patch = patch(
        "credential_guard.approval.reference_approval_posture_allows",
        side_effect=lambda sid: (mode == "manual" and not yolo),
    )

    def plain_execute(a):
        return {"ok": True, "echo": a}

    # Observe plain downstream via code object (non-invasive relative to mgr lists).
    code_labels[id(plain_execute.__code__)] = "plain_downstream"

    try:
        sys.setprofile(_profile)
        with posture_patch, patch("tools.approval.request_tool_approval", side_effect=_gate):
            if scenario in {"mutate_after_approve", "config_after_approve"}:
                req = apply_tool_request_middleware(
                    tool,
                    deepcopy(args),
                    session_id=session,
                    turn_id="turn-1",
                    tool_call_id=tc,
                    skip_relay=True,
                )
                if scenario == "mutate_after_approve":
                    blocked = resolve_pre_tool_block(
                        tool,
                        req.payload,
                        session_id=session,
                        turn_id="turn-1",
                        tool_call_id=tc,
                        middleware_trace=list(req.trace or []),
                    )
                    exec_args = deepcopy(req.payload)
                    exec_args["path"] = "/job/evil/build"
                else:
                    blocked = resolve_pre_tool_block(
                        tool,
                        req.payload,
                        session_id=session,
                        turn_id="turn-1",
                        tool_call_id=tc,
                        middleware_trace=list(req.trace or []),
                    )
                    new_token = "Y" * len(token)
                    _write_config(hermes_home, new_token)
                    exec_args = deepcopy(req.payload)
                if blocked:
                    evidence["approval_denied"] = True
                else:
                    result = run_tool_execution_middleware(
                        tool,
                        exec_args,
                        lambda a: {"ok": True, "echo": a},
                        session_id=session,
                        turn_id="turn-1",
                        tool_call_id=tc,
                        skip_relay=True,
                    )
                    result_s = result if isinstance(result, str) else json.dumps(result)
                    evidence["canary_in_result"] = _scan(result_s, token)
                    if RUNTIME_ADAPTER_NOT_READY in result_s:
                        evidence["adapter_not_ready"] = True
                    try:
                        parsed = json.loads(result_s)
                        adapter_ok = bool(
                            isinstance(parsed, dict)
                            and parsed.get("ok") is True
                            and parsed.get("status") == 201
                        )
                        evidence["adapter_ok"] = adapter_ok
                    except Exception:
                        pass
            else:
                if tool == HTTP_REFERENCE_TOOL:
                    result = handle_function_call(
                        tool,
                        deepcopy(args),
                        task_id="r2e-task",
                        tool_call_id=tc,
                        session_id=session,
                        turn_id="turn-1",
                    )
                    result_s = result if isinstance(result, str) else json.dumps(result)
                    evidence["canary_in_result"] = _scan(result_s, token)
                    if RUNTIME_ADAPTER_NOT_READY in result_s:
                        evidence["adapter_not_ready"] = True
                    try:
                        parsed = json.loads(result_s)
                        adapter_ok = bool(
                            isinstance(parsed, dict)
                            and parsed.get("ok") is True
                            and parsed.get("status") == 201
                        )
                        evidence["adapter_ok"] = adapter_ok
                    except Exception:
                        pass
                    if "tool_execution" not in order:
                        evidence["approval_denied"] = True
                    if scenario == "replay" and "tool_execution" in order:
                        result2 = run_tool_execution_middleware(
                            tool,
                            deepcopy(args),
                            lambda a: {"ok": True},
                            session_id=session,
                            turn_id="turn-1",
                            tool_call_id=tc,
                            skip_relay=True,
                        )
                        r2 = result2 if isinstance(result2, str) else json.dumps(result2)
                        evidence["replay_blocked"] = RUNTIME_ADAPTER_NOT_READY in r2
                        evidence["canary_in_result"] += _scan(r2, token)
                else:
                    req = apply_tool_request_middleware(
                        tool,
                        deepcopy(args),
                        session_id=session,
                        turn_id="turn-1",
                        tool_call_id=tc,
                        skip_relay=True,
                    )
                    blocked = resolve_pre_tool_block(
                        tool,
                        req.payload,
                        session_id=session,
                        turn_id="turn-1",
                        tool_call_id=tc,
                        middleware_trace=list(req.trace or []),
                    )
                    if blocked:
                        evidence["approval_denied"] = True
                    else:
                        result = run_tool_execution_middleware(
                            tool,
                            deepcopy(req.payload),
                            plain_execute,
                            session_id=session,
                            turn_id="turn-1",
                            tool_call_id=tc,
                            skip_relay=True,
                        )
                        result_s = result if isinstance(result, str) else json.dumps(result)
                        evidence["canary_in_result"] = _scan(result_s, token)
    finally:
        sys.setprofile(None)
        config_mod._open_and_read = real_open_and_read  # type: ignore[assignment]
        os.open = real_os_open  # type: ignore[assignment]
        builtins.open = real_open  # type: ignore[assignment]
        _Path.lstat = real_lstat  # type: ignore[method-assign]

    evidence["call_order"] = list(order)
    plan = None
    try:
        plan = get_plan_store().lookup(session, tc)
    except Exception:
        plan = None
    evidence["plan_state"] = plan.state.value if plan else None
    resolve_after = get_execution_secret_resolve_count()
    evidence["secret_resolve_count"] = resolve_after
    # R2 critical-path delta excludes R1B transform_tool_result re-publish resolves.
    r2_end = resolve_at_r2_end["n"]
    if r2_end is None:
        r2_end = resolve_after
    evidence["secret_resolve_delta_during_r2"] = int(r2_end) - resolve_before_r2
    evidence["injection_resolve_delta"] = (
        get_injection_secret_resolve_count() - inj_before
    )
    evidence["adapter_invoke_delta"] = get_http_adapter_invoke_count() - adapter_before
    evidence["config_body_read_hits"] = list(body_read_hits)
    evidence["r2_critical_body_read_hits"] = [
        h for h in body_read_hits if h.startswith("r2_critical:")
    ]
    evidence["lstat_count"] = int(lstat_hits["n"])
    if scenario == "plain":
        evidence["downstream_call_count"] = int(order.count("plain_downstream"))
        evidence["handler_identity_ok"] = "not_applicable"
        evidence["registry_dispatch"] = "not_applicable"
    else:
        evidence["registry_dispatch"] = evidence["handler_call_count"] > 0
    evidence["canary_in_evidence"] = _scan(json.dumps(evidence, default=str), token)
    evidence["credentials_json_present"] = (hermes_home / "credential-guard" / "credentials.json").exists()
    evidence["targets_json_present"] = (hermes_home / "credential-guard" / "targets.json").exists()
    set_http_transport_override_for_tests(None)
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True)
    args = parser.parse_args()
    if "HOME" not in os.environ or "HERMES_HOME" not in os.environ:
        raise SystemExit("HOME and HERMES_HOME required")
    print(json.dumps(run_scenario(args.scenario), sort_keys=True))


if __name__ == "__main__":
    main()
