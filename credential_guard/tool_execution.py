"""tool_execution middleware: gate reference plans into host next_call (R2/R3).

Hermes main-agent order is:
  tool_request → tool_execution → next_call(pre_tool_call/approval → handler)

Backup registry dispatcher may approve before tool_execution. Both paths share
semantics: this middleware must not consume or invalidate a live ANALYZED /
APPROVAL_PENDING plan before the host next_call; the formal reference handler
performs final lstat → identity/digest/args recheck → one-shot consume →
resolve_one → HTTP/process adapter under the cross-process shared config lock.
"""

from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any, Callable, Dict, Iterator, Optional

from .config_lock import ConfigLockError, shared_config_lock
from .injection_plan import PlanState, PlanStoreError, canonical_args_digest
from .references import ReferenceError, analyze_references
from . import runtime_config as runtime_config
from .runtime_config import RuntimeConfigError, default_config_path, execution_recheck_lock
from .tool_request import (
    consume_invalid_marker,
    get_invalid_marker,
    get_plan_store,
    reference_path_blocked,
)

# Stage-accurate fixed codes. Never claim adapters are unimplemented.
REFERENCE_PATH_BLOCKED = "REFERENCE_PATH_BLOCKED"
CALL_IDENTITY_REQUIRED = "CALL_IDENTITY_REQUIRED"
PLAN_NOT_FOUND = "PLAN_NOT_FOUND"
PLAN_NOT_PENDING = "PLAN_NOT_PENDING"
PLAN_RECHECK_FAILED = "PLAN_RECHECK_FAILED"
PLAN_ARGS_INVALID = "PLAN_ARGS_INVALID"
PLAN_CONSUME_FAILED = "PLAN_CONSUME_FAILED"
RUNTIME_CONFIG_UNAVAILABLE = "RUNTIME_CONFIG_UNAVAILABLE"
CONFIG_LOCK_UNAVAILABLE = "CONFIG_LOCK_UNAVAILABLE"
EXECUTION_FAILED = "EXECUTION_FAILED"
ADAPTER_FAILED = "ADAPTER_FAILED"
HTTP_ADAPTER_FAILED = "HTTP_ADAPTER_FAILED"
PROCESS_ADAPTER_FAILED = "PROCESS_ADAPTER_FAILED"

# Bound by on_tool_execution around next_call so the formal handler can recover
# session/turn/tool_call identity even when registry.dispatch omits them.
_bound_execution: ContextVar[Optional[Dict[str, str]]] = ContextVar(
    "cg_bound_execution", default=None
)

# Test-injectable HTTP transport (fake). Production leaves this None.
_http_transport_override: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None
_http_adapter_invoke_count = 0
_http_observe_lock = threading.Lock()


def set_http_transport_override_for_tests(
    transport: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]],
) -> None:
    global _http_transport_override
    with _http_observe_lock:
        _http_transport_override = transport


def get_http_adapter_invoke_count() -> int:
    with _http_observe_lock:
        return int(_http_adapter_invoke_count)


def reset_http_adapter_observe_for_tests() -> None:
    global _http_adapter_invoke_count, _http_transport_override
    with _http_observe_lock:
        _http_adapter_invoke_count = 0
        _http_transport_override = None


def _note_http_adapter_invoke() -> None:
    global _http_adapter_invoke_count
    with _http_observe_lock:
        _http_adapter_invoke_count += 1


@contextmanager
def _shared_config_lock_for_execution() -> Iterator[None]:
    """Shared config lock for the reference-path final recheck+consume window.

    Test mutation controls may replace this seam with a nullcontext.
    """
    store = default_config_path().parent
    with shared_config_lock(store):
        yield


def _safe_error(code: str) -> str:
    """Fixed error payload. ``code`` is required — no lying default."""
    return json.dumps(
        {"ok": False, "error": code, "source": "credential-guard"},
        separators=(",", ":"),
        sort_keys=True,
    )


def _plan_store_code(exc: BaseException, fallback: str) -> str:
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code and code.isascii() and " " not in code:
        return code
    return fallback


def _config_lock_code(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code and code.isascii() and " " not in code:
        return code
    return CONFIG_LOCK_UNAVAILABLE


def _has_reference(args: Dict[str, Any], registered) -> bool:
    try:
        analysis = analyze_references(args, registered)
        return bool(analysis.has_reference)
    except ReferenceError:
        return True


def _identities_aligned(plan, view, current: Dict[str, Any]) -> bool:
    plan_id = dict(plan.config_file_identity)
    published_id = dict(view.config_file_identity)
    return (
        current == plan_id
        and current == published_id
        and plan_id == published_id
    )


def bind_execution_context(
    *,
    tool_name: str,
    session_id: str,
    turn_id: str,
    tool_call_id: str,
) -> Token:
    return _bound_execution.set(
        {
            "tool_name": str(tool_name or ""),
            "session_id": str(session_id or ""),
            "turn_id": str(turn_id or ""),
            "tool_call_id": str(tool_call_id or ""),
        }
    )


def reset_execution_context(token: Token) -> None:
    _bound_execution.reset(token)


def get_bound_execution_context() -> Optional[Dict[str, str]]:
    bound = _bound_execution.get()
    return dict(bound) if bound else None


def finalize_reference_execution(
    tool_name: str,
    args: Dict[str, Any],
    *,
    session_id: str = "",
    turn_id: str = "",
    tool_call_id: str = "",
) -> str:
    """Post-approval local boundary: lstat → compare → consume → resolve → HTTP.

    Store key prefers the middleware-bound call identity; conflicting explicit
    kwargs ids fail closed without losing the live plan key. Resolve/adapter
    failures leave the plan consumed (no replay of the old approval).
    """
    bound = get_bound_execution_context() or {}
    bound_session = str(bound.get("session_id") or "")
    bound_turn = str(bound.get("turn_id") or "")
    bound_tc = str(bound.get("tool_call_id") or "")
    bound_tool = str(bound.get("tool_name") or "")
    arg_session = str(session_id or "")
    arg_turn = str(turn_id or "")
    arg_tc = str(tool_call_id or "")
    arg_tool = str(tool_name or "")

    # Authoritative store key: bound context from tool_execution next_call window.
    session_id = bound_session or arg_session
    turn_id = bound_turn or arg_turn
    tool_call_id = bound_tc or arg_tc
    tool_name = bound_tool or arg_tool
    payload = args if isinstance(args, dict) else {}

    try:
        if get_invalid_marker(session_id, tool_call_id) or reference_path_blocked(
            session_id, tool_call_id
        ):
            return _safe_error(REFERENCE_PATH_BLOCKED)

        if not session_id or not turn_id or not tool_call_id or not tool_name:
            return _safe_error(CALL_IDENTITY_REQUIRED)

        store = get_plan_store()
        try:
            plan = store.lookup(session_id, tool_call_id)
        except PlanStoreError as exc:
            return _safe_error(_plan_store_code(exc, PLAN_NOT_FOUND))

        if plan is None or plan.state is not PlanState.APPROVAL_PENDING:
            if plan is not None and plan.state not in (
                PlanState.CONSUMED,
                PlanState.INVALIDATED,
            ):
                try:
                    store.invalidate(session_id, tool_call_id)
                except PlanStoreError:
                    pass
            return _safe_error(PLAN_NOT_PENDING)

        # Explicit kwargs that disagree with the bound call identity are theft.
        id_conflicts = [
            bool(arg_session) and arg_session != session_id,
            bool(arg_turn) and arg_turn != turn_id,
            bool(arg_tc) and arg_tc != tool_call_id,
            bool(arg_tool) and arg_tool != tool_name,
        ]

        try:
            with _shared_config_lock_for_execution():
                with execution_recheck_lock():
                    try:
                        view = runtime_config.get_runtime_view()
                    except RuntimeConfigError:
                        try:
                            store.invalidate(session_id, tool_call_id)
                        except PlanStoreError:
                            pass
                        return _safe_error(RUNTIME_CONFIG_UNAVAILABLE)

                    try:
                        id1 = dict(runtime_config.get_current_config_file_identity())
                    except RuntimeConfigError:
                        try:
                            store.invalidate(session_id, tool_call_id)
                        except PlanStoreError:
                            pass
                        return _safe_error(RUNTIME_CONFIG_UNAVAILABLE)

                    try:
                        args_digest = canonical_args_digest(payload)
                    except Exception:
                        try:
                            store.invalidate(session_id, tool_call_id)
                        except PlanStoreError:
                            pass
                        return _safe_error(PLAN_ARGS_INVALID)

                    mismatches = [
                        *id_conflicts,
                        plan.session_id != session_id,
                        plan.turn_id != turn_id,
                        plan.tool_call_id != tool_call_id,
                        plan.tool_name != tool_name,
                        plan.args_digest != args_digest,
                        not _identities_aligned(plan, view, id1),
                        plan.config_digest != view.config_digest,
                    ]
                    meta = view.bindings.get(plan.binding_name)
                    if meta is None:
                        mismatches.append(True)
                    else:
                        mismatches.extend(
                            [
                                meta.get("credential_ref") != plan.credential_name,
                                str(meta.get("binding_digest") or "")
                                != plan.binding_digest,
                                str(meta.get("target_digest") or "")
                                != plan.target_digest,
                                tuple(meta.get("reference_arg_path") or ())
                                != tuple(plan.reference_arg_path),
                            ]
                        )

                    if plan.target_name != (
                        payload.get("target")
                        if isinstance(payload.get("target"), str)
                        else ""
                    ):
                        mismatches.append(True)

                    if any(mismatches):
                        try:
                            store.invalidate(session_id, tool_call_id)
                        except PlanStoreError:
                            pass
                        return _safe_error(PLAN_RECHECK_FAILED)

                    try:
                        id2 = dict(runtime_config.get_current_config_file_identity())
                    except RuntimeConfigError:
                        try:
                            store.invalidate(session_id, tool_call_id)
                        except PlanStoreError:
                            pass
                        return _safe_error(RUNTIME_CONFIG_UNAVAILABLE)

                    if id2 != id1 or not _identities_aligned(plan, view, id2):
                        try:
                            store.invalidate(session_id, tool_call_id)
                        except PlanStoreError:
                            pass
                        return _safe_error(PLAN_RECHECK_FAILED)

                    try:
                        store.consume(session_id, tool_call_id)
                    except PlanStoreError as exc:
                        return _safe_error(_plan_store_code(exc, PLAN_CONSUME_FAILED))

                    try:
                        consumed = store.lookup(session_id, tool_call_id)
                    except PlanStoreError as exc:
                        return _safe_error(_plan_store_code(exc, PLAN_CONSUME_FAILED))
                    if consumed is None or consumed.state is not PlanState.CONSUMED:
                        return _safe_error(PLAN_CONSUME_FAILED)

                    # R3: resolve_one → adapter dispatch by verified binding type.
                    return _resolve_and_execute(consumed, view, payload)
        except ConfigLockError as exc:
            try:
                store.invalidate(session_id, tool_call_id)
            except PlanStoreError:
                pass
            return _safe_error(_config_lock_code(exc))
    except Exception:
        try:
            if session_id and tool_call_id:
                get_plan_store().invalidate(session_id, tool_call_id)
        except Exception:
            pass
        return _safe_error(EXECUTION_FAILED)


def _resolve_and_execute(consumed, view, payload: Dict[str, Any]) -> str:
    """Post-consume resolve + one adapter call. Plan stays consumed on failure."""
    canonical = view.to_canonical_dict()
    bindings = canonical.get("bindings")
    if not isinstance(bindings, dict):
        return _safe_error(ADAPTER_FAILED)
    binding = bindings.get(consumed.binding_name)
    if not isinstance(binding, dict):
        return _safe_error(ADAPTER_FAILED)
    btype = binding.get("type")
    if btype == "http":
        return _resolve_and_execute_http(consumed, view, payload, binding)
    if btype in {"process_env", "stdin"}:
        return _resolve_and_execute_process(consumed, view, payload, binding)
    return _safe_error(ADAPTER_FAILED)


def _resolve_and_execute_http(consumed, view, payload: Dict[str, Any], binding: Dict[str, Any]) -> str:
    """Post-consume resolve + one HTTP adapter call. Plan stays consumed on failure."""
    from .adapters.http import execute_http
    from .injection import InjectionError, resolve_one_for_execution

    lease = None
    try:
        lease = resolve_one_for_execution(consumed, view)
        method = payload.get("method")
        path = payload.get("path")
        if not isinstance(method, str) or not isinstance(path, str):
            return _safe_error(HTTP_ADAPTER_FAILED)
        with _http_observe_lock:
            transport = _http_transport_override
        _note_http_adapter_invoke()
        result = execute_http(
            binding=binding,
            method=method,
            path=path,
            lease=lease,
            transport=transport,
        )
        if not isinstance(result, dict):
            return _safe_error(HTTP_ADAPTER_FAILED)
        return json.dumps(result, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    except InjectionError:
        return _safe_error(HTTP_ADAPTER_FAILED)
    except Exception:
        return _safe_error(HTTP_ADAPTER_FAILED)
    finally:
        if lease is not None:
            try:
                lease.close()
            except Exception:
                pass


def _resolve_and_execute_process(
    consumed, view, payload: Dict[str, Any], binding: Dict[str, Any]
) -> str:
    """Post-consume resolve + process adapter. Plan stays consumed on failure."""
    import tempfile

    from .adapters.process import execute_process
    from .injection import InjectionError, resolve_one_for_execution
    from .process_identity import (
        ProgramIdentity,
        ProgramIdentityError,
        cleanup_verified_executable,
        prepare_verified_executable,
        verify_same_identity,
    )

    lease = None
    verified = None
    try:
        expected_raw = dict(consumed.program_identity or {})
        if not expected_raw:
            return _safe_error(PROCESS_ADAPTER_FAILED)
        try:
            expected = ProgramIdentity(
                device=int(expected_raw["device"]),
                inode=int(expected_raw["inode"]),
                mode=int(expected_raw["mode"]),
                uid=int(expected_raw["uid"]),
                size=int(expected_raw["size"]),
                mtime_ns=int(expected_raw["mtime_ns"]),
                content_sha256=str(expected_raw["content_sha256"]),
            )
        except Exception:
            return _safe_error(PROCESS_ADAPTER_FAILED)

        program = binding.get("program")
        if not isinstance(program, str) or not program:
            return _safe_error(PROCESS_ADAPTER_FAILED)

        # Recheck inside the already-held config + execution locks.
        verify_same_identity(program, expected)
        work = tempfile.mkdtemp(prefix="cg-r3b-")
        os.chmod(work, 0o700)
        verified = prepare_verified_executable(program, expected, work_dir=work)

        lease = resolve_one_for_execution(consumed, view)
        result = execute_process(binding=binding, lease=lease, verified=verified)
        if not isinstance(result, dict):
            return _safe_error(PROCESS_ADAPTER_FAILED)
        return json.dumps(result, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    except ProgramIdentityError:
        return _safe_error(PROCESS_ADAPTER_FAILED)
    except InjectionError:
        return _safe_error(PROCESS_ADAPTER_FAILED)
    except Exception:
        return _safe_error(PROCESS_ADAPTER_FAILED)
    finally:
        if lease is not None:
            try:
                lease.close()
            except Exception:
                pass
        if verified is not None:
            try:
                cleanup_verified_executable(verified)
            except Exception:
                pass


def _invalidate_if_live(session_id: str, tool_call_id: str) -> None:
    if not session_id or not tool_call_id:
        return
    store = get_plan_store()
    try:
        plan = store.lookup(session_id, tool_call_id)
    except PlanStoreError:
        return
    if plan is None:
        return
    if plan.state in (PlanState.CONSUMED, PlanState.INVALIDATED):
        return
    try:
        store.invalidate(session_id, tool_call_id)
    except PlanStoreError:
        pass


def on_tool_execution(
    tool_name: str,
    args: Dict[str, Any],
    next_call: Callable[[Dict[str, Any]], Any],
    **context: Any,
) -> Any:
    session_id = str(context.get("session_id") or "")
    turn_id = str(context.get("turn_id") or "")
    tool_call_id = str(context.get("tool_call_id") or "")
    payload = args if isinstance(args, dict) else {}

    try:
        try:
            view = runtime_config.get_runtime_view()
            registered = frozenset(view.credential_names)
        except RuntimeConfigError:
            view = None
            registered = frozenset()

        referenced = _has_reference(payload, registered)
        store = get_plan_store()
        plan = None
        try:
            if session_id and tool_call_id:
                plan = store.lookup(session_id, tool_call_id)
        except PlanStoreError:
            plan = None

        # Plain tools must remain non-interfering even under marker overflow.
        if not referenced and plan is None:
            return next_call(payload)

        # Reference / plan path — markers, overflow, and empty-identity circuit.
        if reference_path_blocked(session_id, tool_call_id) or get_invalid_marker(
            session_id, tool_call_id
        ):
            consume_invalid_marker(session_id, tool_call_id)
            return _safe_error(REFERENCE_PATH_BLOCKED)

        # Reference / plan path — require full call identity.
        if not session_id or not turn_id or not tool_call_id:
            _invalidate_if_live(session_id, tool_call_id)
            return _safe_error(CALL_IDENTITY_REQUIRED)

        if plan is None:
            return _safe_error(PLAN_NOT_FOUND)

        # Live plans must reach host next_call (approval and/or formal handler).
        # Never consume here; never invalidate ANALYZED/PENDING before next_call.
        if plan.state not in (PlanState.ANALYZED, PlanState.APPROVAL_PENDING):
            return _safe_error(PLAN_NOT_PENDING)

        token = bind_execution_context(
            tool_name=tool_name,
            session_id=session_id,
            turn_id=turn_id,
            tool_call_id=tool_call_id,
        )
        try:
            result = next_call(payload)
        except Exception:
            _invalidate_if_live(session_id, tool_call_id)
            return _safe_error(EXECUTION_FAILED)
        finally:
            reset_execution_context(token)

        # If the formal handler never consumed, fail-close the plan.
        try:
            after = store.lookup(session_id, tool_call_id)
        except PlanStoreError:
            after = None
        if after is not None and after.state is not PlanState.CONSUMED:
            _invalidate_if_live(session_id, tool_call_id)
        return result
    except Exception:
        try:
            if session_id and tool_call_id:
                get_plan_store().invalidate(session_id, tool_call_id)
        except Exception:
            pass
        return _safe_error(EXECUTION_FAILED)


__all__ = [
    "ADAPTER_FAILED",
    "CALL_IDENTITY_REQUIRED",
    "CONFIG_LOCK_UNAVAILABLE",
    "EXECUTION_FAILED",
    "HTTP_ADAPTER_FAILED",
    "PLAN_ARGS_INVALID",
    "PLAN_CONSUME_FAILED",
    "PLAN_NOT_FOUND",
    "PLAN_NOT_PENDING",
    "PLAN_RECHECK_FAILED",
    "PROCESS_ADAPTER_FAILED",
    "REFERENCE_PATH_BLOCKED",
    "RUNTIME_CONFIG_UNAVAILABLE",
    "bind_execution_context",
    "finalize_reference_execution",
    "get_bound_execution_context",
    "get_http_adapter_invoke_count",
    "on_tool_execution",
    "reset_execution_context",
    "reset_http_adapter_observe_for_tests",
    "set_http_transport_override_for_tests",
]
