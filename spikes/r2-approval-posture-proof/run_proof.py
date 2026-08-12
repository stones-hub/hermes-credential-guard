#!/usr/bin/env python3
"""R2A/A0 proof: Hermes approval posture via stable APIs only.

Requires HERMES_AGENT_ROOT (sanitized checkout) and temporary HOME/HERMES_HOME.
Never opens real ~/.hermes profiles. Prints one JSON evidence object on stdout.
"""

from __future__ import annotations

import argparse
import builtins
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch

# Explicit post-approval recheck budget for R2 InjectionPlan TTL.
# Source: A0 — must cover config re-read + binding digest compare + consume
# after Hermes approval wait returns; not an arbitrary 10-minute pad.
EXECUTION_REVIEW_MARGIN_SECONDS = 60
TTL_FORMULA = "plan_ttl = approval_timeout + execution_review_margin"
VALID_MODES = frozenset({"manual", "smart", "off"})
SESSION_ID = "r2-a0-session"


def _ensure_hermes_path() -> Path:
    raw = os.environ.get("HERMES_AGENT_ROOT") or "/tmp/credential-guard-r2-hermes-source"
    root = Path(raw)
    if not root.is_dir():
        raise SystemExit(f"HERMES_AGENT_ROOT missing: {root}")
    inserted = str(root)
    if inserted not in sys.path:
        sys.path.insert(0, inserted)
    return root


def _write_approvals_config(
    *,
    mode: str = "manual",
    timeout: int = 300,
) -> None:
    """Create temporary HERMES_HOME config fixture (test setup only)."""
    hermes_home = Path(os.environ["HERMES_HOME"])
    hermes_home.mkdir(parents=True, exist_ok=True)
    # Quote mode so YAML 1.1 does not turn bare `off` into boolean false.
    (hermes_home / "config.yaml").write_text(
        "model: unused-r2-a0\n"
        "approvals:\n"
        f"  mode: \"{mode}\"\n"
        f"  timeout: {int(timeout)}\n"
        "plugins:\n"
        "  enabled: []\n",
        encoding="utf-8",
    )


def _normalize_raw_mode(raw: Any) -> Tuple[Optional[str], str]:
    """Return (mode, reason_if_invalid). Does not trust Hermes unknown→manual."""
    if isinstance(raw, bool):
        # YAML 1.1: bare `off` → False. Treat as off; True is unknown.
        if raw is False:
            return "off", ""
        return None, "unknown_mode"
    if raw is None:
        return "manual", ""
    if isinstance(raw, str):
        mode = raw.strip().lower()
        if not mode:
            return "manual", ""
        if mode in VALID_MODES:
            return mode, ""
        return None, "unknown_mode"
    return None, "unknown_mode"


def evaluate_reference_approval_posture(
    session_id: str,
    *,
    open_counter: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Decide whether credential-reference calls are allowed under host posture.

    Uses only Hermes stable/public APIs for mode and bypass. Never opens
    config.yaml from this function — tracked via open_counter when provided.
    """
    if os.environ.get("R2_POSTURE_FORCE_IMPORT_ERROR") == "1":
        return {
            "reference_calls_allowed": False,
            "reason": "import_failed",
            "mode": None,
            "bypass_active": None,
            "bypass_source": None,
            "mode_via": None,
            "used_hermes_stable_apis": False,
            "direct_config_yaml_open_count": (
                int((open_counter or {}).get("config_yaml", 0))
            ),
        }

    try:
        from hermes_cli.config import load_config_readonly
        from tools.approval import (
            is_approval_bypass_active_for_session,
            is_session_yolo_enabled,
        )
        from tools import approval as approval_mod
    except Exception:
        return {
            "reference_calls_allowed": False,
            "reason": "import_failed",
            "mode": None,
            "bypass_active": None,
            "bypass_source": None,
            "mode_via": None,
            "used_hermes_stable_apis": False,
            "direct_config_yaml_open_count": (
                int((open_counter or {}).get("config_yaml", 0))
            ),
        }

    try:
        cfg = load_config_readonly()
        approvals = cfg.get("approvals") if isinstance(cfg, dict) else None
        if not isinstance(approvals, dict):
            approvals = {}
        raw_mode = approvals.get("mode", "manual")
        mode, mode_reason = _normalize_raw_mode(raw_mode)
        if mode is None:
            return {
                "reference_calls_allowed": False,
                "reason": mode_reason or "unknown_mode",
                "mode": None,
                "bypass_active": None,
                "bypass_source": None,
                "mode_via": "hermes_cli.config.load_config_readonly",
                "used_hermes_stable_apis": True,
                "direct_config_yaml_open_count": (
                    int((open_counter or {}).get("config_yaml", 0))
                ),
            }

        try:
            timeout_public = int(approvals.get("timeout", 300))
        except (TypeError, ValueError):
            timeout_public = 300

        timeout_private = None
        timeout_api_compatibility_risk = True
        timeout_source = "hermes_cli.config.load_config_readonly"
        try:
            timeout_private = int(approval_mod._get_approval_timeout())
            if timeout_private == timeout_public:
                timeout_source = "tools.approval._get_approval_timeout"
            # Prefer public readonly API for production; private is cross-check.
            timeout_api_compatibility_risk = True
        except Exception:
            timeout_private = None
            timeout_api_compatibility_risk = False
            timeout_source = "hermes_cli.config.load_config_readonly"

        bypass = bool(is_approval_bypass_active_for_session(session_id))
        bypass_source = None
        if bypass:
            if bool(getattr(approval_mod, "_YOLO_MODE_FROZEN", False)):
                bypass_source = "process_yolo"
            elif is_session_yolo_enabled(session_id):
                bypass_source = "session_yolo"
            elif mode == "off":
                bypass_source = "mode_off"
            else:
                bypass_source = "unknown_bypass"

        if mode != "manual":
            return {
                "reference_calls_allowed": False,
                "reason": "mode_not_manual",
                "mode": mode,
                "bypass_active": bypass,
                "bypass_source": bypass_source,
                "mode_via": "hermes_cli.config.load_config_readonly",
                "used_hermes_stable_apis": True,
                "direct_config_yaml_open_count": (
                    int((open_counter or {}).get("config_yaml", 0))
                ),
                "approval_timeout_seconds": timeout_public,
                "approval_timeout_private": timeout_private,
                "approval_timeout_source": timeout_source,
                "timeout_api_compatibility_risk": timeout_api_compatibility_risk,
                "execution_review_margin_seconds": EXECUTION_REVIEW_MARGIN_SECONDS,
                "plan_ttl_seconds": timeout_public + EXECUTION_REVIEW_MARGIN_SECONDS,
                "ttl_formula": TTL_FORMULA,
            }

        if bypass:
            return {
                "reference_calls_allowed": False,
                "reason": "bypass_active",
                "mode": mode,
                "bypass_active": True,
                "bypass_source": bypass_source,
                "mode_via": "hermes_cli.config.load_config_readonly",
                "used_hermes_stable_apis": True,
                "direct_config_yaml_open_count": (
                    int((open_counter or {}).get("config_yaml", 0))
                ),
                "approval_timeout_seconds": timeout_public,
                "approval_timeout_private": timeout_private,
                "approval_timeout_source": timeout_source,
                "timeout_api_compatibility_risk": timeout_api_compatibility_risk,
                "execution_review_margin_seconds": EXECUTION_REVIEW_MARGIN_SECONDS,
                "plan_ttl_seconds": timeout_public + EXECUTION_REVIEW_MARGIN_SECONDS,
                "ttl_formula": TTL_FORMULA,
            }

        return {
            "reference_calls_allowed": True,
            "reason": "manual_no_bypass",
            "mode": mode,
            "bypass_active": False,
            "bypass_source": None,
            "mode_via": "hermes_cli.config.load_config_readonly",
            "used_hermes_stable_apis": True,
            "direct_config_yaml_open_count": (
                int((open_counter or {}).get("config_yaml", 0))
            ),
            "approval_timeout_seconds": timeout_public,
            "approval_timeout_private": timeout_private,
            "approval_timeout_source": timeout_source,
            "timeout_api_compatibility_risk": timeout_api_compatibility_risk,
            "execution_review_margin_seconds": EXECUTION_REVIEW_MARGIN_SECONDS,
            "plan_ttl_seconds": timeout_public + EXECUTION_REVIEW_MARGIN_SECONDS,
            "ttl_formula": TTL_FORMULA,
        }
    except Exception:
        return {
            "reference_calls_allowed": False,
            "reason": "call_exception",
            "mode": None,
            "bypass_active": None,
            "bypass_source": None,
            "mode_via": "hermes_cli.config.load_config_readonly",
            "used_hermes_stable_apis": True,
            "direct_config_yaml_open_count": (
                int((open_counter or {}).get("config_yaml", 0))
            ),
        }


def _track_opens(counter: Dict[str, int]):
    real_open = builtins.open

    def guarded_open(file, *args, **kwargs):
        try:
            path = os.fspath(file)
        except TypeError:
            path = str(file)
        # Count only config.yaml reads that originate outside hermes_cli.config
        # by checking the caller module name via a simple path suffix match
        # after evaluate starts — evaluate itself must never open it.
        if str(path).endswith("config.yaml"):
            # Inspect stack: if caller is evaluate_reference_approval_posture
            # frame's code, count as direct. Hermes load_config_readonly is OK.
            import inspect

            for frame in inspect.stack()[1:8]:
                mod = frame.frame.f_globals.get("__name__", "")
                func = frame.function
                if func == "evaluate_reference_approval_posture" or (
                    mod == "__main__" and "evaluate_reference" in func
                ):
                    counter["config_yaml"] = int(counter.get("config_yaml", 0)) + 1
                    break
                if mod.startswith("hermes_cli.config") or mod.startswith("tools.approval"):
                    break
        return real_open(file, *args, **kwargs)

    return guarded_open


def _run_posture(mode: str = "manual", timeout: Optional[int] = None) -> Dict[str, Any]:
    to = timeout
    if to is None:
        to = int(os.environ.get("R2_APPROVAL_TIMEOUT", "300"))
    _write_approvals_config(mode=mode, timeout=to)
    _ensure_hermes_path()
    counter: Dict[str, int] = {"config_yaml": 0}
    with patch("builtins.open", _track_opens(counter)):
        return evaluate_reference_approval_posture(SESSION_ID, open_counter=counter)


def _run_session_yolo() -> Dict[str, Any]:
    _write_approvals_config(mode="manual", timeout=300)
    _ensure_hermes_path()
    from tools.approval import enable_session_yolo, disable_session_yolo

    enable_session_yolo(SESSION_ID)
    try:
        counter: Dict[str, int] = {"config_yaml": 0}
        with patch("builtins.open", _track_opens(counter)):
            return evaluate_reference_approval_posture(SESSION_ID, open_counter=counter)
    finally:
        disable_session_yolo(SESSION_ID)


def _install_order_callbacks(mgr: Any, order: List[str], approval: str) -> None:
    def tool_request(**kwargs: Any) -> Dict[str, Any]:
        order.append("tool_request")
        return {"args": dict(kwargs.get("args") or {})}

    def pre_tool_call(**kwargs: Any) -> Dict[str, Any]:
        order.append("pre_tool_call")
        return {
            "action": "approve",
            "message": "r2-a0 posture order proof",
            "rule_key": "r2-a0-once",
        }

    def tool_execution(*, args: Dict[str, Any], next_call, **kwargs: Any) -> Any:
        order.append("tool_execution")
        return next_call(args)

    mgr._hooks.setdefault("pre_tool_call", []).append(pre_tool_call)
    mgr._middleware.setdefault("tool_request", []).append(tool_request)
    mgr._middleware.setdefault("tool_execution", []).append(tool_execution)


def _run_order(approval: str) -> Dict[str, Any]:
    _write_approvals_config(mode="manual", timeout=300)
    _ensure_hermes_path()

    import hermes_cli.plugins as plugins_mod
    from hermes_cli.middleware import (
        apply_tool_request_middleware,
        run_tool_execution_middleware,
    )
    from hermes_cli.plugins import PluginManager, resolve_pre_tool_block

    plugins_mod._plugin_manager = None
    mgr = PluginManager()
    # Do not discover installed platform plugins — register only proof callbacks.
    plugins_mod._plugin_manager = mgr

    order: List[str] = []
    _install_order_callbacks(mgr, order, approval)
    tool_execution_entered = False
    approval_denied = False

    req = apply_tool_request_middleware(
        "r2_a0_probe",
        {"credential": "<CREDENTIAL:demo>"},
        session_id=SESSION_ID,
        tool_call_id="tc-a0",
        skip_relay=True,
    )

    def _gate(tool_name, reason, **kwargs):
        order.append("approval_gate")
        approved = approval == "approve"
        return {
            "approved": approved,
            "message": None if approved else "DENIED: r2-a0 deny path",
        }

    with patch("tools.approval.request_tool_approval", side_effect=_gate):
        blocked = resolve_pre_tool_block(
            "r2_a0_probe",
            req.payload,
            session_id=SESSION_ID,
            tool_call_id="tc-a0",
            middleware_trace=list(req.trace or []),
        )

    if blocked:
        approval_denied = True
    else:

        def _downstream(args: Dict[str, Any]) -> str:
            return "ok"

        run_tool_execution_middleware(
            "r2_a0_probe",
            req.payload,
            _downstream,
            session_id=SESSION_ID,
            tool_call_id="tc-a0",
            skip_relay=True,
        )
        tool_execution_entered = "tool_execution" in order

    return {
        "call_order": list(order),
        "tool_execution_entered": bool(tool_execution_entered),
        "approval_denied": bool(approval_denied),
        "request_changed": bool(req.changed),
    }


def run_scenario(scenario: str) -> Dict[str, Any]:
    if "HOME" not in os.environ or "HERMES_HOME" not in os.environ:
        raise SystemExit("HOME and HERMES_HOME required")

    if scenario == "manual_ok":
        return _run_posture(mode="manual")
    if scenario == "process_yolo":
        return _run_posture(mode="manual")
    if scenario == "session_yolo":
        return _run_session_yolo()
    if scenario == "mode_off":
        return _run_posture(mode="off")
    if scenario == "mode_smart":
        return _run_posture(mode="smart")
    if scenario == "mode_unknown":
        return _run_posture(mode="auto")
    if scenario == "import_failure":
        return _run_posture(mode="manual")
    if scenario == "order_approve":
        return _run_order("approve")
    if scenario == "order_deny":
        return _run_order("deny")
    if scenario == "timeout_ttl":
        return _run_posture(mode="manual")
    raise SystemExit(f"unknown scenario: {scenario}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True)
    args = parser.parse_args()
    evidence = run_scenario(args.scenario)
    print(json.dumps(evidence, sort_keys=True))


if __name__ == "__main__":
    main()
