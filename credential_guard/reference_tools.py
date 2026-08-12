"""Formal http_credential_request shell (R2) — no R3 network/injection."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Mapping, Optional

from .runtime_config import HTTP_REFERENCE_TOOL
from .tool_execution import finalize_reference_execution
from .constants import TOOLSET_NAME

ALLOWED_HTTP_METHODS = (
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
)

# Relative origin path: leading slash; ban scheme/host/userinfo/fragment/query,
# ASCII + C1 controls, Unicode line/paragraph separators, and backslash.
_UNSAFE_PATH_CHARS = re.compile(
    r"[\x00-\x1f\x7f-\x9f\\\u0085\u2028\u2029]"
)

TOOL_DESCRIPTION = (
    "逻辑引用请求外壳：提交业务目标、HTTP method/path 与 <CREDENTIAL:name> 引用；"
    "须经人工审批；R3A 批准后仅在本机结构化 HTTP 适配器中短暂注入，模型拿不到真值。"
)


def http_credential_request_schema() -> Dict[str, Any]:
    return {
        "name": HTTP_REFERENCE_TOOL,
        "description": TOOL_DESCRIPTION,
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Logical business target name from credential-guard.json",
                },
                "method": {
                    "type": "string",
                    "enum": list(ALLOWED_HTTP_METHODS),
                    "description": "HTTP method for the logical request",
                },
                "path": {
                    "type": "string",
                    "description": (
                        "Relative origin path starting with /; "
                        "no scheme, host, userinfo, fragment, or backslash"
                    ),
                },
                "credential": {
                    "type": "string",
                    "description": "Logical credential reference, e.g. <CREDENTIAL:name>",
                },
            },
            "required": ["target", "method", "path", "credential"],
            "additionalProperties": False,
        },
    }


def check_http_credential_request_available() -> bool:
    """Plugin capability only — never reads secrets or connects to targets."""
    try:
        schema = http_credential_request_schema()
        return (
            schema.get("name") == HTTP_REFERENCE_TOOL
            and callable(handle_http_credential_request)
        )
    except Exception:
        return False


def validate_http_path(path: Any) -> str:
    if not isinstance(path, str) or not path:
        raise ValueError("invalid_path")
    if not path.startswith("/"):
        raise ValueError("invalid_path")
    if path.startswith("//"):
        raise ValueError("invalid_path")
    if "://" in path:
        raise ValueError("invalid_path")
    if "@" in path:
        raise ValueError("invalid_path")
    if "#" in path:
        raise ValueError("invalid_path")
    if "?" in path:
        raise ValueError("invalid_path")
    if _UNSAFE_PATH_CHARS.search(path):
        raise ValueError("invalid_path")
    # Reject authority-like first segment with embedded host hints after scheme-less //.
    # Already blocked //; also reject backslash-normalized surprises.
    return path


def validate_http_method(method: Any) -> str:
    if not isinstance(method, str) or method not in ALLOWED_HTTP_METHODS:
        raise ValueError("invalid_method")
    return method


def validate_http_credential_request_args(args: Any) -> Dict[str, str]:
    if not isinstance(args, dict):
        raise ValueError("invalid_args")
    allowed = {"target", "method", "path", "credential"}
    extra = set(args.keys()) - allowed
    if extra:
        raise ValueError("additional_properties")
    missing = allowed - set(args.keys())
    if missing:
        raise ValueError("missing_fields")
    target = args.get("target")
    credential = args.get("credential")
    if not isinstance(target, str) or not target:
        raise ValueError("invalid_target")
    if not isinstance(credential, str) or not credential:
        raise ValueError("invalid_credential")
    method = validate_http_method(args.get("method"))
    path = validate_http_path(args.get("path"))
    return {
        "target": target,
        "method": method,
        "path": path,
        "credential": credential,
    }


def safe_operation_summary(
    method: Any = None, path: Any = None, *, binding_type: str = ""
) -> str:
    """Display-safe operation summary; process bindings never show program paths."""
    btype = str(binding_type or "")
    if btype in {"process_env", "stdin"}:
        return "fixed local program"
    method_s = validate_http_method(method)
    path_s = validate_http_path(path)
    return f"{method_s} {path_s}"


def safe_inject_summary(meta: Optional[Mapping[str, Any]], binding_type: str = "") -> str:
    """Human-safe inject description — no host, header values, or secrets."""
    btype = ""
    inj = None
    if isinstance(meta, Mapping):
        btype = str(meta.get("type") or binding_type or "")
        inj = meta.get("inject_type")
    else:
        btype = str(binding_type or "")
    if btype == "http":
        if inj == "bearer":
            return "HTTPS Authorization Header"
        if inj == "api_key_header":
            return "HTTPS API Key Header"
        return "HTTPS Header"
    if btype == "process_env":
        return "fixed local program (env)"
    if btype == "stdin":
        return "fixed local program (stdin)"
    if btype:
        return btype
    return "configured-inject"


def handle_http_credential_request(args: Dict[str, Any], **context: Any) -> str:
    """Formal post-approval local boundary: recheck + consume + R3A HTTP inject.

    Requires a live APPROVAL_PENDING plan bound to this call identity. On success
    resolves one credential and runs the HTTP adapter once (fake transport in tests).
    """
    try:
        validate_http_credential_request_args(args)
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
        HTTP_REFERENCE_TOOL,
        args if isinstance(args, dict) else {},
        session_id=str(context.get("session_id") or ""),
        turn_id=str(context.get("turn_id") or ""),
        tool_call_id=str(context.get("tool_call_id") or ""),
    )


__all__ = [
    "ALLOWED_HTTP_METHODS",
    "HTTP_REFERENCE_TOOL",
    "TOOLSET_NAME",
    "TOOL_DESCRIPTION",
    "check_http_credential_request_available",
    "handle_http_credential_request",
    "http_credential_request_schema",
    "safe_inject_summary",
    "safe_operation_summary",
    "validate_http_credential_request_args",
    "validate_http_method",
    "validate_http_path",
]
