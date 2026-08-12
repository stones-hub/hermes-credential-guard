from __future__ import annotations

import json
import logging
from typing import Any

from . import result_guard as result_guard_mod
from .sensitive_paths import (
    args_target_protected,
    python_code_reads_protected,
    terminal_command_reads_protected,
)
from .state import get_egress_registry_snapshot

logger = logging.getLogger("credential_guard")

# Protected-path / terminal pre-block (not R4 result-guard product semantics).
_SAFE_TOOL_RESULT = json.dumps(
    {"error": "tool result blocked by credential-guard"},
    ensure_ascii=False,
)

_TERMINAL_TOOLS = frozenset({"terminal", "execute_code", "run_terminal_command"})


def on_transform_tool_result(**kwargs: Any) -> str:
    try:
        result = kwargs.get("result", "")
        tool_name = kwargs.get("tool_name", "") or kwargs.get("name", "")
        args = kwargs.get("args") or kwargs.get("arguments") or {}
        if not isinstance(result, str):
            result = str(result)

        # Secondary protection: protected-path tool results never reach the model.
        if isinstance(tool_name, str) and isinstance(args, dict):
            if args_target_protected(tool_name, args):
                return _SAFE_TOOL_RESULT
            name = tool_name.strip()
            if name == "execute_code":
                code = args.get("code")
                if isinstance(code, str) and code:
                    if python_code_reads_protected(code) or terminal_command_reads_protected(
                        code
                    ):
                        return _SAFE_TOOL_RESULT
            elif name in _TERMINAL_TOOLS:
                command = ""
                if isinstance(args.get("command"), str):
                    command = args["command"]
                elif isinstance(args.get("code"), str):
                    command = args["code"]
                if command and terminal_command_reads_protected(command):
                    return _SAFE_TOOL_RESULT

        registry = get_egress_registry_snapshot()
        return result_guard_mod.guard_tool_result(result, registry)
    except Exception:
        # Never log exception objects — they may embed decoy/secret text.
        logger.warning(
            "credential-guard failed closed at transform_tool_result reason=%s",
            result_guard_mod.RESULT_GUARD_FAIL_REASON,
        )
        return result_guard_mod.RESULT_GUARD_FAIL_TEXT
