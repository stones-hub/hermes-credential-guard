"""R0 spike plugin: approve-before-inject proof (no production credential_guard)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from copy import deepcopy
from typing import Any, Dict, List, Optional

REF_PATTERN = re.compile(r"<CREDENTIAL:([A-Za-z0-9_-]+)>")
TOOL_NAME = "tip_probe_tool"
TOOLSET = "tip_probe"

# Process-local proof counters. Decoy plaintext lives only in resolver_store
# and is never written into traces/approval payloads/shared proof dumps.
_lock = threading.RLock()
_state: Dict[str, Any] = {}
_tls = threading.local()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def reset_state(
    *,
    decoy_plain: str = "",
    fault: str = "",
    resolver_store: Optional[Dict[str, str]] = None,
) -> None:
    with _lock:
        store: Dict[str, str] = dict(resolver_store or {})
        if decoy_plain and "decoy" not in store:
            store["decoy"] = decoy_plain
        primary = decoy_plain or (next(iter(store.values())) if store else "")
        _state.clear()
        _state.update(
            {
                "decoy_plain": primary,
                "resolver_store": store,
                "fault": fault or os.environ.get("TIP_FAULT", ""),
                "call_order": [],
                "tool_request_saw_ref": False,
                "pre_tool_call_saw_ref": False,
                "approval_payload_plain_count": 0,
                "middleware_trace_plain_count": 0,
                "before_execution_plain_count": 0,
                "tool_received_plain_count": 0,
                "downstream_call_count": 0,
                "secret_resolve_count": 0,
                "next_call_count": 0,
                "real_exception_count": 0,
                "fail_closed": False,
                "fail_closed_reason": "",
                "original_args_snapshot": None,
                "last_injected_args": None,
                "trace_blobs": [],
                "approval_blobs": [],
                "plans": {},
                "received_values": [],
                "host_bypass_note": "",
                "fault_via_real_raise": False,
            }
        )


def snapshot_counts() -> Dict[str, Any]:
    with _lock:
        decoy = str(_state.get("decoy_plain") or "")
        store = _state.get("resolver_store") or {}
        decoy_len = len(decoy) if decoy else max((len(v) for v in store.values()), default=0)
        return {
            "ref": "<CREDENTIAL:decoy>",
            "decoy_len": decoy_len,
            "fault": _state.get("fault") or "",
            "call_order": list(_state.get("call_order") or []),
            "tool_request_saw_ref": bool(_state.get("tool_request_saw_ref")),
            "pre_tool_call_saw_ref": bool(_state.get("pre_tool_call_saw_ref")),
            "approval_payload_plain_count": int(
                _state.get("approval_payload_plain_count") or 0
            ),
            "middleware_trace_plain_count": int(
                _state.get("middleware_trace_plain_count") or 0
            ),
            "before_execution_plain_count": int(
                _state.get("before_execution_plain_count") or 0
            ),
            "tool_received_plain_count": int(
                _state.get("tool_received_plain_count") or 0
            ),
            "downstream_call_count": int(_state.get("downstream_call_count") or 0),
            "secret_resolve_count": int(_state.get("secret_resolve_count") or 0),
            "next_call_count": int(_state.get("next_call_count") or 0),
            "real_exception_count": int(_state.get("real_exception_count") or 0),
            "fail_closed": bool(_state.get("fail_closed")),
            "fail_closed_reason": str(_state.get("fail_closed_reason") or ""),
            "host_bypass_note": str(_state.get("host_bypass_note") or ""),
            "fault_via_real_raise": bool(_state.get("fault_via_real_raise")),
            "resolver_store_empty": not bool(_state.get("resolver_store")),
        }


def _plain() -> str:
    return str(_state.get("decoy_plain") or "")


def _all_secrets() -> List[str]:
    store = _state.get("resolver_store") or {}
    vals = [str(v) for v in store.values() if v]
    primary = _plain()
    if primary and primary not in vals:
        vals.append(primary)
    return vals


def _count_plain(obj: Any) -> int:
    secrets = _all_secrets()
    if not secrets:
        return 0
    try:
        blob = json.dumps(obj, default=str)
    except Exception:
        blob = str(obj)
    return sum(blob.count(s) for s in secrets)


def _contains_ref(args: Any) -> bool:
    try:
        blob = json.dumps(args, default=str)
    except Exception:
        blob = str(args)
    return "<CREDENTIAL:" in blob


def _mark_fail_closed(reason: str) -> None:
    _state["fail_closed"] = True
    _state["fail_closed_reason"] = reason


def _note(step: str) -> None:
    order = _state.setdefault("call_order", [])
    if not order or order[-1] != step:
        order.append(step)


def _bump_real_exception() -> None:
    _state["real_exception_count"] = int(_state.get("real_exception_count") or 0) + 1
    _state["fault_via_real_raise"] = True


def _analyze_request(args: Any) -> Dict[str, Any]:
    """Identify refs only — never resolve or inject plaintext."""
    if _state.get("fault") == "tool_request":
        raise RuntimeError("injected fault: analyze_request")

    if _contains_ref(args):
        _state["tool_request_saw_ref"] = True
    _state["before_execution_plain_count"] = int(
        _state.get("before_execution_plain_count") or 0
    ) + _count_plain(args)
    return {
        "args": deepcopy(args),
        "source": "tool-injection-proof",
        "reason": "ref-detected" if _contains_ref(args) else "passthrough",
    }


def _build_approval(args: Dict[str, Any], trace: Any) -> Optional[Dict[str, Any]]:
    if _state.get("fault") == "pre_tool_call":
        raise RuntimeError("injected fault: build_approval")

    if any(
        isinstance(t, dict) and "fail-closed" in str(t.get("reason") or "")
        for t in (trace or [])
    ):
        _mark_fail_closed("pre_tool_call_after_request_fault")
        return {
            "action": "block",
            "message": "TIP fail-closed: prior tool_request fault",
        }

    if _contains_ref(args):
        _state["pre_tool_call_saw_ref"] = True

    plain_in_args = _count_plain(args)
    _state["before_execution_plain_count"] = int(
        _state.get("before_execution_plain_count") or 0
    ) + plain_in_args
    _state["middleware_trace_plain_count"] = int(
        _state.get("middleware_trace_plain_count") or 0
    ) + _count_plain(trace)

    if not _contains_ref(args):
        return None

    message = (
        "TIP proof: approve tool with credential reference only "
        "(no plaintext in this message)"
    )
    directive = {
        "action": "approve",
        "message": message,
        "rule_key": f"tip_probe:{TOOL_NAME}:ref",
    }
    _state["approval_payload_plain_count"] = int(
        _state.get("approval_payload_plain_count") or 0
    ) + _count_plain(directive)
    _state.setdefault("approval_blobs", []).append(
        {"keys": sorted(directive.keys()), "plain": _count_plain(directive)}
    )
    return directive


def _resolve_ref(token: str) -> str:
    """Synthetic resolver — only called from tool_execution after approval."""
    _state["secret_resolve_count"] = int(_state.get("secret_resolve_count") or 0) + 1
    if _state.get("fault") == "tool_execution_resolver":
        raise RuntimeError("injected fault: resolve_ref")
    store = _state.get("resolver_store") or {}
    if token not in store:
        raise KeyError(f"unknown credential ref: {token}")
    return str(store[token])


def _inject_args(args: Dict[str, Any]) -> Dict[str, Any]:
    if _state.get("fault") == "tool_execution_inject":
        raise RuntimeError("injected fault: inject_args")

    out = deepcopy(args)

    def walk(node: Any) -> Any:
        if isinstance(node, str):
            def repl(m: re.Match[str]) -> str:
                return _resolve_ref(m.group(1))

            return REF_PATTERN.sub(repl, node)
        if isinstance(node, list):
            return [walk(x) for x in node]
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        return node

    return walk(out)


def on_tool_request(**kwargs: Any) -> Optional[Dict[str, Any]]:
    """Identify refs only — never resolve or inject plaintext."""
    try:
        _note("tool_request")
        return _analyze_request(kwargs.get("args") or {})
    except Exception as exc:
        _bump_real_exception()
        _mark_fail_closed(f"tool_request_exception:{type(exc).__name__}")
        _state["host_bypass_note"] = (
            "hermes invoke_middleware swallows bare tool_request raises and "
            "continues; plugin catches internal analyze exceptions and returns "
            "fail-closed marker (bare raise bypass is NOT plugin fail-closed)"
        )
        return {
            "args": deepcopy(kwargs.get("args") or {}),
            "source": "tool-injection-proof",
            "reason": "fail-closed:tool_request_exception",
            "tip_fail_closed": True,
        }


def on_pre_tool_call(**kwargs: Any) -> Optional[Dict[str, Any]]:
    try:
        args = kwargs.get("args") if isinstance(kwargs.get("args"), dict) else {}
        trace = kwargs.get("middleware_trace") or []
        _note("pre_tool_call")
        return _build_approval(args, trace)
    except Exception as exc:
        _bump_real_exception()
        _mark_fail_closed(f"pre_tool_call_exception:{type(exc).__name__}")
        _state["host_bypass_note"] = (
            "hermes invoke_hook swallows bare pre_tool_call raises and "
            "continues; plugin catches internal build_approval exceptions and "
            "returns action=block (bare raise bypass is NOT plugin fail-closed)"
        )
        return {
            "action": "block",
            "message": f"TIP fail-closed: pre_tool_call exception ({type(exc).__name__})",
        }


def on_tool_execution(**kwargs: Any) -> Any:
    """Resolve + inject only after approval; single next_call with a deep copy."""
    next_call = kwargs["next_call"]
    args = kwargs.get("args") if isinstance(kwargs.get("args"), dict) else {}
    original_args = kwargs.get("original_args")
    if isinstance(original_args, dict):
        _state["original_args_snapshot"] = deepcopy(original_args)

    try:
        _note("tool_execution")
        entry_plain = _count_plain(args)
        _state["before_execution_plain_count"] = int(
            _state.get("before_execution_plain_count") or 0
        ) + entry_plain

        if not _contains_ref(args):
            _state["next_call_count"] = int(_state.get("next_call_count") or 0) + 1
            return next_call(args)

        plan_id = str(kwargs.get("tool_call_id") or threading.get_ident())
        injected = _inject_args(args)
        token_val = str(injected.get("token") or "")
        _state.setdefault("plans", {})[plan_id] = {
            "token_digest": _digest(token_val) if token_val and not _contains_ref(injected) else "",
            "has_ref": _contains_ref(injected),
            "next_call_once": True,
        }
        _state["last_injected_args"] = {
            "plain_count": _count_plain(injected),
            "has_ref": _contains_ref(injected),
        }

        _tls.plan_id = plan_id
        _state["next_call_count"] = int(_state.get("next_call_count") or 0) + 1
        return next_call(injected)
    except Exception as exc:
        _bump_real_exception()
        _mark_fail_closed(f"tool_execution_exception:{type(exc).__name__}")
        _state["host_bypass_note"] = (
            "hermes run_tool_execution_middleware bypasses to downstream on bare "
            "raise before next_call; plugin catches resolve/inject exceptions and "
            "returns fixed error without next_call (bare raise bypass is NOT "
            "plugin fail-closed)"
        )
        return json.dumps(
            {
                "error": f"TIP fail-closed: tool_execution ({type(exc).__name__})",
                "ok": False,
            }
        )


def handle_tip_probe_tool(args: Dict[str, Any], **_kwargs: Any) -> str:
    with _lock:
        _note("downstream_tool")
        _state["downstream_call_count"] = int(_state.get("downstream_call_count") or 0) + 1
        plain_n = _count_plain(args)
        _state["tool_received_plain_count"] = (
            int(_state.get("tool_received_plain_count") or 0) + (1 if plain_n else 0)
        )
        token_val = str(args.get("token") or "")
        plan_id = getattr(_tls, "plan_id", None)
        expected = ""
        if plan_id and isinstance(_state.get("plans"), dict):
            expected = str((_state["plans"].get(plan_id) or {}).get("token_digest") or "")
        recv_digest = _digest(token_val) if token_val else ""
        _state.setdefault("received_values", []).append(
            {
                "plan_id": plan_id,
                "digest": recv_digest,
                "digest_match": bool(expected) and recv_digest == expected,
                "plain_count": plain_n,
                "has_ref": _contains_ref(args),
            }
        )
    return json.dumps(
        {
            "ok": True,
            "received_plain": bool(plain_n),
            "received_ref": _contains_ref(args),
            "downstream_call_count": int(_state.get("downstream_call_count") or 0),
        }
    )


def tip_probe_schema() -> Dict[str, Any]:
    return {
        "name": TOOL_NAME,
        "description": "R0 isolated fake tool — returns counts only, no network",
        "parameters": {
            "type": "object",
            "properties": {
                "token": {"type": "string"},
                "note": {"type": "string"},
            },
            "required": ["token"],
        },
    }


def register(ctx) -> None:
    ctx.register_middleware("tool_request", on_tool_request)
    ctx.register_middleware("tool_execution", on_tool_execution)
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_tool(
        name=TOOL_NAME,
        toolset=TOOLSET,
        schema=tip_probe_schema(),
        handler=handle_tip_probe_tool,
        check_fn=lambda: True,
        description=tip_probe_schema()["description"],
    )
