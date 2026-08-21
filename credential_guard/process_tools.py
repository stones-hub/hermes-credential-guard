"""Formal credential_process_run shell — fixed local program env/stdin."""

from __future__ import annotations

import json
from typing import Any, Dict, Mapping

from .bindings import PROCESS_REFERENCE_ARG_PATH, PROCESS_REFERENCE_TOOL
from .credential_code import (
    credential_code_not_usable_error,
    is_redacted_credential_code,
)
from .reference_tools import compose_binding_tool_description
from .runtime_config import get_runtime_view
from .tool_execution import finalize_reference_execution
from .constants import TOOLSET_NAME

_PROCESS_TYPES = frozenset({"process_env", "stdin"})

_PROCESS_INTRO = (
    "逻辑引用本地程序外壳：使用本机配置的凭证运行已登记的固定本地程序。"
    "模型不能指定 command、argv、env 或 cwd。"
)
_PROCESS_OUTRO = (
    "须经人工审批；批准后仅在本机短暂注入，模型拿不到真值。"
    "配置更新后需重启 Hermes 才会刷新此清单。"
)

TOOL_DESCRIPTION = f"{_PROCESS_INTRO}\n{_PROCESS_OUTRO}"


def _safe_runtime_bindings():
    """READY → sidecar; PREPARED_INVALID → static; UNPREPARED → RuntimeView."""
    try:
        from .target_catalog import resolve_registration_catalog

        prepared, bindings = resolve_registration_catalog()
        if prepared:
            # READY (bindings mapping) or PREPARED_INVALID (None → static).
            # Never fall through to RuntimeView after prepare().
            return bindings
    except Exception:
        # Prepared-path errors must static-fallback; do not read RuntimeView.
        return None
    try:
        return get_runtime_view().bindings
    except Exception:
        return None


def _format_process_binding_line(name: str, meta: Mapping[str, Any]) -> str:
    cred = str(meta.get("credential_ref") or "")
    return f"- {name}：fixed local program；credential=<CREDENTIAL:{cred}>"


def _process_binding_entry_lines(bindings: Mapping[str, Any]) -> list[str]:
    lines: list[str] = []
    for name in sorted(bindings):
        meta = bindings[name]
        if not isinstance(meta, Mapping):
            continue
        if meta.get("type") not in _PROCESS_TYPES:
            continue
        lines.append(_format_process_binding_line(name, meta))
    return lines


def build_process_tool_description() -> str:
    bindings = _safe_runtime_bindings()
    if bindings is None:
        return TOOL_DESCRIPTION
    return compose_binding_tool_description(
        intro=_PROCESS_INTRO,
        outro=_PROCESS_OUTRO,
        entry_lines=_process_binding_entry_lines(bindings),
    )


def credential_process_run_schema() -> Dict[str, Any]:
    return {
        "name": PROCESS_REFERENCE_TOOL,
        "description": build_process_tool_description(),
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
    raw_args = args if isinstance(args, dict) else {}
    if is_redacted_credential_code(raw_args.get("credential")):
        return credential_code_not_usable_error()
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
        raw_args,
        session_id=str(context.get("session_id") or ""),
        turn_id=str(context.get("turn_id") or ""),
        tool_call_id=str(context.get("tool_call_id") or ""),
    )


__all__ = [
    "PROCESS_REFERENCE_ARG_PATH",
    "PROCESS_REFERENCE_TOOL",
    "TOOLSET_NAME",
    "TOOL_DESCRIPTION",
    "build_process_tool_description",
    "check_credential_process_run_available",
    "credential_process_run_schema",
    "handle_credential_process_run",
    "validate_credential_process_run_args",
]
