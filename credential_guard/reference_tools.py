"""Formal http_credential_request shell (R2) — no R3 network/injection."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Mapping, Optional, Sequence

from .credential_code import (
    credential_code_not_usable_error,
    is_redacted_credential_code,
)
from .runtime_config import HTTP_REFERENCE_TOOL, get_runtime_view
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

DESCRIPTION_CHAR_LIMIT = 12000
_OMISSION_LINE = "另有 {n} 个目标未展示，请查看本机配置"

_HTTP_INTRO = (
    "逻辑引用请求外壳：使用本机配置的凭证访问已登记 HTTP 目标。"
    "凭证不能从对话传入。"
)
# Keep bare "R3" for historical registration wording tests; never R3A/R3B.
_HTTP_OUTRO = (
    "须经人工审批；R3 边界下批准后仅在本机短暂注入，模型拿不到真值。"
    "配置更新后需重启 Hermes 才会刷新此清单。"
)

TOOL_DESCRIPTION = f"{_HTTP_INTRO}\n{_HTTP_OUTRO}"


def compose_binding_tool_description(
    *,
    intro: str,
    outro: str,
    entry_lines: Sequence[str],
    limit: int = DESCRIPTION_CHAR_LIMIT,
) -> str:
    """Assemble intro + sorted entries + outro; truncate by whole entries only."""
    if not entry_lines:
        text = f"{intro}\n{outro}"
        return text if len(text) <= limit else text[:limit]

    header = f"{intro}\n当前可用目标：\n"
    full_body = "\n".join(entry_lines)
    full = f"{header}{full_body}\n{outro}"
    if len(full) <= limit:
        return full

    kept: list[str] = []
    total = len(entry_lines)
    for line in entry_lines:
        trial = kept + [line]
        omitted = total - len(trial)
        pieces = [header + "\n".join(trial)]
        if omitted:
            pieces.append(_OMISSION_LINE.format(n=omitted))
        pieces.append(outro)
        candidate = "\n".join(pieces)
        if len(candidate) <= limit:
            kept = trial
        else:
            break

    if not kept:
        omitted_all = _OMISSION_LINE.format(n=total)
        fallback = f"{intro}\n{omitted_all}\n{outro}"
        if len(fallback) <= limit:
            return fallback
        return f"{intro}\n{outro}"[:limit]

    omitted = total - len(kept)
    return (
        f"{header}{chr(10).join(kept)}\n"
        f"{_OMISSION_LINE.format(n=omitted)}\n"
        f"{outro}"
    )


def _safe_runtime_bindings() -> Optional[Mapping[str, Any]]:
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


def _format_http_binding_line(name: str, meta: Mapping[str, Any]) -> str:
    methods = [str(m) for m in (meta.get("allowed_methods") or ()) if m is not None]
    paths = [str(p) for p in (meta.get("allowed_paths") or ()) if p is not None]
    cred = str(meta.get("credential_ref") or "")
    methods_s = "、".join(methods)
    paths_s = "、".join(paths)
    ops = "；".join(part for part in (methods_s, paths_s) if part)
    if ops:
        return f"- {name}：{ops}；credential=<CREDENTIAL:{cred}>"
    return f"- {name}：credential=<CREDENTIAL:{cred}>"


def _http_binding_entry_lines(bindings: Mapping[str, Any]) -> list[str]:
    lines: list[str] = []
    for name in sorted(bindings):
        meta = bindings[name]
        if not isinstance(meta, Mapping):
            continue
        if meta.get("type") != "http":
            continue
        lines.append(_format_http_binding_line(name, meta))
    return lines


def build_http_tool_description() -> str:
    bindings = _safe_runtime_bindings()
    if bindings is None:
        return TOOL_DESCRIPTION
    return compose_binding_tool_description(
        intro=_HTTP_INTRO,
        outro=_HTTP_OUTRO,
        entry_lines=_http_binding_entry_lines(bindings),
    )


def http_credential_request_schema() -> Dict[str, Any]:
    return {
        "name": HTTP_REFERENCE_TOOL,
        "description": build_http_tool_description(),
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
    scheme = ""
    if isinstance(meta, Mapping):
        btype = str(meta.get("type") or binding_type or "")
        inj = meta.get("inject_type")
        raw_scheme = meta.get("scheme")
        if isinstance(raw_scheme, str) and raw_scheme in {"http", "https"}:
            scheme = raw_scheme
    else:
        btype = str(binding_type or "")
    if btype == "http":
        label = "HTTPS" if scheme != "http" else "HTTP"
        if inj == "bearer":
            return f"{label} Authorization Header"
        if inj == "api_key_header":
            return f"{label} API Key Header"
        return f"{label} Header"
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
    raw_args = args if isinstance(args, dict) else {}
    if is_redacted_credential_code(raw_args.get("credential")):
        return credential_code_not_usable_error()
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
        raw_args,
        session_id=str(context.get("session_id") or ""),
        turn_id=str(context.get("turn_id") or ""),
        tool_call_id=str(context.get("tool_call_id") or ""),
    )


__all__ = [
    "ALLOWED_HTTP_METHODS",
    "DESCRIPTION_CHAR_LIMIT",
    "HTTP_REFERENCE_TOOL",
    "TOOLSET_NAME",
    "TOOL_DESCRIPTION",
    "build_http_tool_description",
    "check_http_credential_request_available",
    "compose_binding_tool_description",
    "handle_http_credential_request",
    "http_credential_request_schema",
    "safe_inject_summary",
    "safe_operation_summary",
    "validate_http_credential_request_args",
    "validate_http_method",
    "validate_http_path",
]
