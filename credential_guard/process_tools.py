"""Formal credential_process_run shell (R3B) — fixed local program env/stdin."""

from __future__ import annotations

import json
from typing import Any, Dict

from .bindings import PROCESS_REFERENCE_ARG_PATH, PROCESS_REFERENCE_TOOL
from .tool_execution import finalize_reference_execution
from .constants import TOOLSET_NAME

TOOL_DESCRIPTION = (
    "逻辑引用本地程序外壳：提交业务目标与 <CREDENTIAL:name> 引用；"
    "须经人工审批；批准后仅在本机对配置登记的固定程序做单次 env/stdin 注入，"
    "模型不得提交 command/argv/env/cwd，也拿不到真值。"
)


def credential_process_run_schema() -> Dict[str, Any]:
    return {
        "name": PROCESS_REFERENCE_TOOL,
        "description": TOOL_DESCRIPTION,
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Logical process target name from credential-guard.json",
                },
                "credential": {
                    "type": "string",
                    "description": "Logical credential reference, e.g. <CREDENTIAL:name>",
                },
            },
            "required": ["target", "credential"],
            "additionalProperties": False,
        },
    }


def check_credential_process_run_available() -> bool:
    try:
        schema = credential_process_run_schema()
        return (
            schema.get("name") == PROCESS_REFERENCE_TOOL
            and callable(handle_credential_process_run)
        )
    except Exception:
        return False


def validate_credential_process_run_args(args: Any) -> Dict[str, str]:
    if not isinstance(args, dict):
        raise ValueError("invalid_args")
    if set(args) - {"target", "credential"}:
        raise ValueError("invalid_args")
    target = args.get("target")
    credential = args.get("credential")
    if not isinstance(target, str) or not target:
        raise ValueError("invalid_args")
    if not isinstance(credential, str) or not credential:
        raise ValueError("invalid_args")
    return {"target": target, "credential": credential}


def handle_credential_process_run(args: Dict[str, Any], **context: Any) -> str:
    """Post-approval local boundary: recheck + consume + process adapter."""
    try:
        validate_credential_process_run_args(args)
    except ValueError:
        return json.dumps(
            {
                "ok": False,
                "error": "INVALID_REFERENCE_ARGS",
                "source": "credential-guard",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    return finalize_reference_execution(
        PROCESS_REFERENCE_TOOL,
        args if isinstance(args, dict) else {},
        session_id=str(context.get("session_id") or ""),
        turn_id=str(context.get("turn_id") or ""),
        tool_call_id=str(context.get("tool_call_id") or ""),
    )


__all__ = [
    "PROCESS_REFERENCE_ARG_PATH",
    "PROCESS_REFERENCE_TOOL",
    "TOOLSET_NAME",
    "TOOL_DESCRIPTION",
    "check_credential_process_run_available",
    "credential_process_run_schema",
    "handle_credential_process_run",
    "validate_credential_process_run_args",
]
