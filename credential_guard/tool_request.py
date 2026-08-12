"""tool_request middleware: analyze logical refs and bind InjectionPlan (R2C).

Never resolves credential values. Uses R1B published runtime snapshot only —
never re-reads credential-guard.json. Fail-closed markers survive for
pre/tool_execution via bounded InvalidMarkerStore.
"""

from __future__ import annotations

import copy
import threading
from typing import Any, Dict, Mapping, Optional, Tuple

from .injection_plan import InjectionPlanStore, PlanStoreError, resolve_plan_ttl_seconds
from .invalid_marker_store import InvalidMarkerStore
from .references import ReferenceError, analyze_references
from . import runtime_config as runtime_config
from .runtime_config import HTTP_REFERENCE_TOOL, RuntimeConfigError

_LOCK = threading.RLock()
_STORE = InjectionPlanStore()
_INVALID_STORE = InvalidMarkerStore()

TRACE_SOURCE = "credential-guard"


def reset_tool_request_state_for_tests() -> None:
    global _STORE, _INVALID_STORE
    with _LOCK:
        _STORE = InjectionPlanStore()
        _INVALID_STORE = InvalidMarkerStore()


def get_plan_store() -> InjectionPlanStore:
    return _STORE


def get_invalid_marker_store() -> InvalidMarkerStore:
    return _INVALID_STORE


def get_invalid_marker(session_id: str, tool_call_id: str) -> Optional[Dict[str, str]]:
    return _INVALID_STORE.get(session_id, tool_call_id)


def consume_invalid_marker(
    session_id: str, tool_call_id: str
) -> Optional[Dict[str, str]]:
    return _INVALID_STORE.consume(session_id, tool_call_id)


def reference_path_blocked(session_id: str, tool_call_id: str) -> bool:
    return _INVALID_STORE.reference_path_blocked(session_id, tool_call_id)


def _set_invalid(session_id: str, tool_call_id: str, reason: str) -> None:
    _INVALID_STORE.set(session_id, tool_call_id, reason)


def _clear_invalid(session_id: str, tool_call_id: str) -> None:
    _INVALID_STORE.clear(session_id, tool_call_id)


def _trace(reason: str, name: str = "tool_request") -> Dict[str, str]:
    return {"source": TRACE_SOURCE, "reason": reason, "name": name}


def _match_bindings(
    *,
    tool_name: str,
    target_name: str,
    credential_name: str,
    arg_path: Tuple[object, ...],
    view,
) -> Tuple[Optional[str], Optional[Mapping[str, Any]], str]:
    matches = []
    for name, meta in view.bindings.items():
        if name != target_name:
            continue
        if meta.get("credential_ref") != credential_name:
            continue
        if meta.get("approval") != "required":
            continue
        allowed = tuple(meta.get("allowed_tools") or ())
        if tool_name not in allowed:
            continue
        expected_path = tuple(meta.get("reference_arg_path") or ())
        if tuple(arg_path) != expected_path:
            continue
        matches.append((name, meta))
    if not matches:
        return None, None, "NO_MATCH"
    if len(matches) > 1:
        return None, None, "MULTI_MATCH"
    return matches[0][0], matches[0][1], "OK"


def on_tool_request(
    tool_name: str,
    args: Dict[str, Any],
    **context: Any,
) -> Dict[str, Any]:
    """Hermes tool_request middleware entry.

    Returns ``{"args": ..., "trace": {...}}``. Never raises to Hermes.
    """
    session_id = str(context.get("session_id") or "")
    turn_id = str(context.get("turn_id") or "")
    tool_call_id = str(context.get("tool_call_id") or "")
    # Bind the effective args Hermes handed us (post prior middleware).
    effective = copy.deepcopy(args) if isinstance(args, dict) else {}

    try:
        if not isinstance(args, dict):
            _set_invalid(session_id, tool_call_id, "ARGS_NOT_OBJECT")
            return {"args": effective, "trace": _trace("args_not_object")}

        # R2: published snapshot only — never re-open credential-guard.json.
        try:
            view = runtime_config.get_runtime_view()
        except RuntimeConfigError:
            analysis_probe = None
            try:
                analysis_probe = analyze_references(effective, frozenset())
            except ReferenceError:
                _set_invalid(session_id, tool_call_id, "RUNTIME_UNAVAILABLE")
                return {"args": effective, "trace": _trace("runtime_unavailable")}
            if analysis_probe is not None and analysis_probe.has_reference:
                _set_invalid(session_id, tool_call_id, "RUNTIME_UNAVAILABLE")
                return {"args": effective, "trace": _trace("runtime_unavailable")}
            return {"args": effective, "trace": _trace("passthrough")}

        registered = frozenset(view.credential_names)
        try:
            analysis = analyze_references(effective, registered)
        except ReferenceError as exc:
            code = getattr(exc, "code", "REFERENCE_INVALID")
            _set_invalid(session_id, tool_call_id, code)
            return {"args": effective, "trace": _trace("reference_rejected")}

        if not analysis.has_reference:
            _clear_invalid(session_id, tool_call_id)
            return {
                "args": analysis.args,
                "trace": _trace("no_reference"),
            }

        if not session_id or not turn_id or not tool_call_id:
            _set_invalid(session_id, tool_call_id, "MISSING_IDENTITY")
            return {"args": analysis.args, "trace": _trace("missing_identity")}

        ref = analysis.references[0]
        target_name = analysis.args.get("target")
        if not isinstance(target_name, str) or not target_name:
            _set_invalid(session_id, tool_call_id, "MISSING_TARGET")
            return {"args": analysis.args, "trace": _trace("missing_target")}

        binding_name, meta, match_code = _match_bindings(
            tool_name=tool_name,
            target_name=target_name,
            credential_name=ref.credential_name,
            arg_path=ref.arg_path,
            view=view,
        )
        if match_code != "OK" or binding_name is None or meta is None:
            _set_invalid(session_id, tool_call_id, match_code)
            return {"args": analysis.args, "trace": _trace("binding_mismatch")}

        try:
            ttl = resolve_plan_ttl_seconds()
        except PlanStoreError:
            _set_invalid(session_id, tool_call_id, "TTL_UNAVAILABLE")
            return {"args": analysis.args, "trace": _trace("ttl_unavailable")}

        # Capture published identity; optional lstat confirms file still matches.
        try:
            published_identity = dict(view.config_file_identity)
            current_identity = dict(runtime_config.get_current_config_file_identity())
            if current_identity != published_identity:
                _set_invalid(session_id, tool_call_id, "CONFIG_IDENTITY_MISMATCH")
                return {"args": analysis.args, "trace": _trace("identity_mismatch")}
        except RuntimeConfigError:
            _set_invalid(session_id, tool_call_id, "RUNTIME_UNAVAILABLE")
            return {"args": analysis.args, "trace": _trace("runtime_unavailable")}

        program_identity: Dict[str, Any] = {}
        btype = str(meta.get("type") or "")
        if btype in {"process_env", "stdin"}:
            try:
                from .process_identity import (
                    ProgramIdentityError,
                    capture_program_identity,
                )

                canonical = view.to_canonical_dict()
                raw_bindings = canonical.get("bindings") or {}
                raw = raw_bindings.get(binding_name) if isinstance(raw_bindings, dict) else None
                if not isinstance(raw, dict):
                    _set_invalid(session_id, tool_call_id, "PROGRAM_IDENTITY_REJECTED")
                    return {"args": analysis.args, "trace": _trace("program_identity")}
                program = raw.get("program")
                if not isinstance(program, str) or not program:
                    _set_invalid(session_id, tool_call_id, "PROGRAM_IDENTITY_REJECTED")
                    return {"args": analysis.args, "trace": _trace("program_identity")}
                ident = capture_program_identity(program)
                program_identity = {
                    "device": ident.device,
                    "inode": ident.inode,
                    "mode": ident.mode,
                    "uid": ident.uid,
                    "size": ident.size,
                    "mtime_ns": ident.mtime_ns,
                    "content_sha256": ident.content_sha256,
                }
            except ProgramIdentityError:
                _set_invalid(session_id, tool_call_id, "PROGRAM_IDENTITY_REJECTED")
                return {"args": analysis.args, "trace": _trace("program_identity")}
            except Exception:
                _set_invalid(session_id, tool_call_id, "PROGRAM_IDENTITY_REJECTED")
                return {"args": analysis.args, "trace": _trace("program_identity")}

        try:
            _STORE.create_analyzed_plan(
                session_id=session_id,
                turn_id=turn_id,
                tool_call_id=tool_call_id,
                tool_name=tool_name,
                args=analysis.args,
                reference_arg_path=tuple(ref.arg_path),
                credential_name=ref.credential_name,
                target_name=target_name,
                binding_name=binding_name,
                binding_type=btype,
                config_digest=view.config_digest,
                binding_digest=str(meta.get("binding_digest") or ""),
                target_digest=str(meta.get("target_digest") or ""),
                config_file_identity=published_identity,
                ttl_seconds=ttl,
                program_identity=program_identity,
            )
        except (PlanStoreError, Exception):
            _set_invalid(session_id, tool_call_id, "PLAN_CREATE_FAILED")
            return {"args": analysis.args, "trace": _trace("create_failed")}

        _clear_invalid(session_id, tool_call_id)
        return {
            "args": analysis.args,
            "trace": _trace("analyzed"),
        }
    except Exception:
        _set_invalid(session_id, tool_call_id, "INTERNAL_ERROR")
        return {"args": effective, "trace": _trace("internal_error")}


__all__ = [
    "HTTP_REFERENCE_TOOL",
    "consume_invalid_marker",
    "get_invalid_marker",
    "get_invalid_marker_store",
    "get_plan_store",
    "on_tool_request",
    "reference_path_blocked",
    "reset_tool_request_state_for_tests",
]
