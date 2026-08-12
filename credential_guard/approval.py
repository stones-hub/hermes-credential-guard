"""pre_tool_call: sensitive paths and R2 reference approval."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

from .injection_plan import CanonicalError, PlanState, PlanStoreError, canonical_args_digest
from .references import ReferenceError, analyze_references
from . import runtime_config as runtime_config
from .runtime_config import RuntimeConfigError
from .reference_tools import safe_inject_summary, safe_operation_summary
from .sensitive_paths import (
    args_target_protected,
    python_code_reads_protected,
    terminal_command_reads_protected,
)
from .tool_request import (
    consume_invalid_marker,
    get_invalid_marker,
    get_plan_store,
    reference_path_blocked,
)

_VALID_MODES = frozenset({"manual", "smart", "off"})

_SAFE_BLOCK = {
    "action": "block",
    "message": "credential-guard blocked access to a protected local path",
}
_REF_BLOCK = {
    "action": "block",
    "message": "credential-guard blocked credential reference call",
}


def _reference_rule_key(
    *,
    nonce: str,
    tool_call_id: str,
    tool_name: str,
    args_digest: str,
    config_digest: str,
    binding_digest: str,
) -> str:
    """Bind approval grain without embedding raw nonce or full digests."""
    material = "|".join(
        [
            nonce,
            tool_call_id,
            tool_name,
            args_digest,
            config_digest,
            binding_digest,
        ]
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"cg-ref:{tool_name}:{digest}"


def _block_sensitive_path(tool_name: str, args: Dict[str, Any]) -> Optional[Dict[str, str]]:
    name = (tool_name or "").strip()
    if name in ("read_file", "search_files"):
        if args_target_protected(name, args):
            return dict(_SAFE_BLOCK)
        return None
    if name == "execute_code":
        code = args.get("code")
        if isinstance(code, str) and code:
            if python_code_reads_protected(code) or terminal_command_reads_protected(code):
                return dict(_SAFE_BLOCK)
        return None
    if name in ("terminal", "run_terminal_command"):
        command = ""
        if isinstance(args.get("command"), str):
            command = args["command"]
        elif isinstance(args.get("code"), str):
            command = args["code"]
        if command and terminal_command_reads_protected(command):
            return dict(_SAFE_BLOCK)
        return None
    return None


def _normalize_mode(raw: Any) -> Optional[str]:
    if isinstance(raw, bool):
        return "off" if raw is False else None
    if raw is None:
        return "manual"
    if isinstance(raw, str):
        mode = raw.strip().lower()
        if not mode:
            return "manual"
        if mode in _VALID_MODES:
            return mode
        return None
    return None


def reference_approval_posture_allows(session_id: str) -> bool:
    """True only for approvals.mode=manual with no YOLO/off bypass."""
    try:
        from hermes_cli.config import load_config_readonly
        from tools.approval import is_approval_bypass_active_for_session
    except Exception:
        return False
    try:
        cfg = load_config_readonly()
        approvals = cfg.get("approvals") if isinstance(cfg, dict) else {}
        if not isinstance(approvals, dict):
            approvals = {}
        mode = _normalize_mode(approvals.get("mode", "manual"))
        if mode != "manual":
            return False
        if is_approval_bypass_active_for_session(session_id):
            return False
        return True
    except Exception:
        return False


def _reference_approval_message(
    plan,
    meta: Optional[Dict[str, Any]],
    *,
    payload: Dict[str, Any],
) -> str:
    """Build digest-aligned approval text. Raises ValueError on unsafe/mismatch."""
    try:
        if canonical_args_digest(payload) != plan.args_digest:
            raise ValueError("args_digest_mismatch")
    except CanonicalError as exc:
        raise ValueError(getattr(exc, "code", "CANONICAL_INVALID")) from exc
    try:
        op = safe_operation_summary(
            payload.get("method"),
            payload.get("path"),
            binding_type=getattr(plan, "binding_type", "") or "",
        )
    except ValueError as exc:
        raise ValueError("unsafe_operation") from exc
    inject = safe_inject_summary(meta, getattr(plan, "binding_type", "") or "")
    return (
        "Credential Guard 请求使用本机凭证\n"
        f"工具：{plan.tool_name}\n"
        f"业务目标：{plan.target_name}\n"
        f"逻辑凭证：{plan.credential_name}\n"
        f"操作：{op}\n"
        f"注入方式：{inject}\n"
        "审批范围：仅本次调用"
    )


def _handle_reference_approval(
    *,
    tool_name: str,
    payload: Dict[str, Any],
    session_id: str,
    turn_id: str,
    tool_call_id: str,
) -> Optional[Dict[str, str]]:
    try:
        view = runtime_config.get_runtime_view()
        registered = frozenset(view.credential_names)
    except RuntimeConfigError:
        view = None
        registered = frozenset()

    try:
        analysis = analyze_references(payload, registered)
    except ReferenceError:
        if get_invalid_marker(session_id, tool_call_id) or reference_path_blocked(
            session_id, tool_call_id
        ):
            consume_invalid_marker(session_id, tool_call_id)
        return dict(_REF_BLOCK)

    if not analysis.has_reference:
        return None

    # Reference path: per-key marker, overflow circuit, or empty-identity circuit.
    if get_invalid_marker(session_id, tool_call_id) or reference_path_blocked(
        session_id, tool_call_id
    ):
        consume_invalid_marker(session_id, tool_call_id)
        return dict(_REF_BLOCK)

    if not session_id or not turn_id or not tool_call_id:
        return dict(_REF_BLOCK)

    store = get_plan_store()
    try:
        plan = store.lookup(session_id, tool_call_id)
    except PlanStoreError:
        return dict(_REF_BLOCK)

    if plan is None or plan.state is not PlanState.ANALYZED:
        return dict(_REF_BLOCK)

    if plan.tool_name != tool_name or plan.tool_call_id != tool_call_id:
        return dict(_REF_BLOCK)
    if plan.session_id != session_id or plan.turn_id != turn_id:
        return dict(_REF_BLOCK)

    if not reference_approval_posture_allows(session_id):
        return dict(_REF_BLOCK)

    # Published snapshot + current lstat only — never re-open config body.
    try:
        if view is None:
            view = runtime_config.get_runtime_view()
        current_identity = dict(runtime_config.get_current_config_file_identity())
        published_identity = dict(view.config_file_identity)
        plan_identity = dict(plan.config_file_identity)
        if (
            current_identity != plan_identity
            or current_identity != published_identity
            or plan_identity != published_identity
        ):
            store.invalidate(session_id, tool_call_id)
            return dict(_REF_BLOCK)
        if view.config_digest != plan.config_digest:
            store.invalidate(session_id, tool_call_id)
            return dict(_REF_BLOCK)
    except Exception:
        return dict(_REF_BLOCK)

    try:
        pending = store.mark_approval_pending(session_id, tool_call_id)
    except PlanStoreError:
        return dict(_REF_BLOCK)

    meta = None
    try:
        meta = dict(view.bindings.get(pending.binding_name) or {})
    except Exception:
        meta = None

    try:
        message = _reference_approval_message(pending, meta, payload=payload)
    except ValueError:
        try:
            store.invalidate(session_id, tool_call_id)
        except PlanStoreError:
            pass
        return dict(_REF_BLOCK)
    rule_key = _reference_rule_key(
        nonce=pending.nonce,
        tool_call_id=pending.tool_call_id,
        tool_name=pending.tool_name,
        args_digest=pending.args_digest,
        config_digest=pending.config_digest,
        binding_digest=pending.binding_digest,
    )
    # Scrub accidental secret-ish / structured leakage. Do not treat ordinary
    # path substrings like "/reset-password" as secrets.
    lowered = message.lower()
    if any(
        x in lowered
        for x in ("traceback", "authorization: ", "bearer ", "password=", "password:")
    ):
        try:
            store.invalidate(session_id, tool_call_id)
        except PlanStoreError:
            pass
        return dict(_REF_BLOCK)
    # Fixed template is exactly 7 lines; extra breaks mean path smuggled structure.
    if message.count("\n") != 6:
        try:
            store.invalidate(session_id, tool_call_id)
        except PlanStoreError:
            pass
        return dict(_REF_BLOCK)
    return {
        "action": "approve",
        "message": message,
        "rule_key": rule_key,
    }


def on_pre_tool_call(
    tool_name: str = "",
    args: Optional[Dict[str, Any]] = None,
    tool_call_id: str = "",
    session_id: str = "",
    turn_id: str = "",
    **_kwargs: Any,
) -> Optional[Dict[str, str]]:
    """Sensitive-path block or reference approval; no legacy fixed-action branch."""
    try:
        payload = args if isinstance(args, dict) else {}
        blocked = _block_sensitive_path(tool_name, payload)
        if blocked is not None:
            return blocked

        # Prefer explicit turn_id; Hermes may also pass via kwargs.
        effective_turn = str(turn_id or _kwargs.get("turn_id") or "")
        ref_directive = _handle_reference_approval(
            tool_name=tool_name,
            payload=payload,
            session_id=str(session_id or ""),
            turn_id=effective_turn,
            tool_call_id=str(tool_call_id or ""),
        )
        if ref_directive is not None:
            return ref_directive

        return None
    except Exception:
        # Reference / unknown path: fail closed block, never raise.
        try:
            analysis = analyze_references(
                args if isinstance(args, dict) else {},
                frozenset(),
            )
            if analysis.has_reference:
                return dict(_REF_BLOCK)
        except Exception:
            return dict(_REF_BLOCK)
        return dict(_SAFE_BLOCK)
