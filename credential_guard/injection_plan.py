"""Immutable InjectionPlan and bounded in-process store (R2B).

TTL and capacity are derived from Hermes host facts discovered in A0:
- approval timeout default 300s (Hermes approvals.timeout / _get_approval_timeout)
- execution review margin 60s (A0 spike)
- max concurrent tool workers 8 (agent.tool_executor / run_agent _MAX_TOOL_WORKERS)
- store capacity = 8 workers × 4 approval-backlog multiplier = 32
"""

from __future__ import annotations

import hashlib
import json
import math
import secrets
import threading
import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

# A0 facts — do not invent unrelated 600s/1024 defaults.
HERMES_DEFAULT_APPROVAL_TIMEOUT_SECONDS = 300
EXECUTION_REVIEW_MARGIN_SECONDS = 60
PLAN_TTL_SECONDS = (
    HERMES_DEFAULT_APPROVAL_TIMEOUT_SECONDS + EXECUTION_REVIEW_MARGIN_SECONDS
)
# Hermes config_defaults / _get_approval_timeout define default 300 with no schema
# max; reject non-finite and values above this explicit safety ceiling so a
# malicious approvals.timeout cannot create unbounded InjectionPlan lifetime.
MAX_APPROVAL_TIMEOUT_SECONDS = 86400
HERMES_MAX_TOOL_WORKERS = 8
PLAN_STORE_CAPACITY_MULTIPLIER = 4
PLAN_STORE_CAPACITY = HERMES_MAX_TOOL_WORKERS * PLAN_STORE_CAPACITY_MULTIPLIER


class PlanState(Enum):
    ANALYZED = "analyzed"
    APPROVAL_PENDING = "approval_pending"
    CONSUMED = "consumed"
    INVALIDATED = "invalidated"


class CanonicalError(Exception):
    """Args cannot be stably canonicalized."""

    __slots__ = ("code",)

    def __init__(self, code: str = "CANONICAL_INVALID") -> None:
        object.__setattr__(self, "code", code)
        super().__init__(code)


class PlanStoreError(Exception):
    """Fail-closed plan store error. Message is a stable code only."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        object.__setattr__(self, "code", code)
        super().__init__(code)


def default_plan_ttl_seconds() -> int:
    """Documented default when Hermes timeout is 300s. Prefer resolve_plan_ttl_seconds()."""
    return PLAN_TTL_SECONDS


def resolve_plan_ttl_seconds() -> int:
    """Derive plan TTL from Hermes approval timeout + review margin.

    Prefer ``tools.approval._get_approval_timeout``; fall back to
    ``load_config_readonly().approvals.timeout``. Fail closed on missing,
    non-numeric, bool, non-positive, non-finite, or oversize values — never
    silent-fallback to 300. Fractional timeouts use ``ceil`` so plan TTL is
    never shorter than the host approval window via truncating ``int()``.
    """
    timeout: Any = None
    try:
        from tools.approval import _get_approval_timeout

        timeout = _get_approval_timeout()
    except Exception:
        timeout = None
    if timeout is None:
        try:
            from hermes_cli.config import load_config_readonly

            cfg = load_config_readonly()
            approvals = cfg.get("approvals") if isinstance(cfg, dict) else {}
            if isinstance(approvals, dict):
                timeout = approvals.get("timeout")
        except Exception:
            timeout = None
    # Reject bool (subclass of int) and non-numeric types.
    if type(timeout) not in (int, float):
        raise PlanStoreError("TTL_UNAVAILABLE")
    timeout_f = float(timeout)
    if not math.isfinite(timeout_f) or timeout_f <= 0:
        raise PlanStoreError("TTL_UNAVAILABLE")
    if timeout_f > float(MAX_APPROVAL_TIMEOUT_SECONDS):
        raise PlanStoreError("TTL_UNAVAILABLE")
    return int(math.ceil(timeout_f)) + EXECUTION_REVIEW_MARGIN_SECONDS


def _canonical_value(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise CanonicalError("NON_FINITE_NUMBER")
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        out = {}
        for key in sorted(value.keys(), key=lambda k: (str(type(k)), str(k))):
            if not isinstance(key, str):
                raise CanonicalError("NON_STRING_KEY")
            out[key] = _canonical_value(value[key])
        return out
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    if isinstance(value, (bytes, bytearray, set, tuple)):
        raise CanonicalError("UNSUPPORTED_TYPE")
    raise CanonicalError("UNSUPPORTED_TYPE")


def canonical_args_digest(args: Mapping[str, Any]) -> str:
    if not isinstance(args, dict):
        raise CanonicalError("ARGS_NOT_OBJECT")
    canonical = _canonical_value(args)
    payload = json.dumps(
        canonical,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class InjectionPlan:
    session_id: str
    turn_id: str
    tool_call_id: str
    tool_name: str
    args_digest: str
    reference_arg_path: Tuple[object, ...]
    credential_name: str
    target_name: str
    binding_name: str
    binding_type: str
    config_digest: str
    binding_digest: str
    target_digest: str
    config_file_identity: Mapping[str, Any]
    nonce: str
    created_monotonic: float
    expires_monotonic: float
    state: PlanState
    # R3B: bound at plan build for process_env/stdin; empty for HTTP/other.
    program_identity: Mapping[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            "InjectionPlan("
            f"session_id={self.session_id!r}, "
            f"tool_call_id={self.tool_call_id!r}, "
            f"tool_name={self.tool_name!r}, "
            f"state={self.state.value!r}, "
            f"credential_name={self.credential_name!r}, "
            f"target_name={self.target_name!r})"
        )


def _plan_key(session_id: str, tool_call_id: str) -> Tuple[str, str]:
    if not session_id or not tool_call_id:
        raise PlanStoreError("MISSING_IDENTITY")
    return (session_id, tool_call_id)


class InjectionPlanStore:
    def __init__(
        self,
        *,
        clock: Optional[Callable[[], float]] = None,
        nonce_source: Optional[Callable[[], str]] = None,
        capacity: int = PLAN_STORE_CAPACITY,
        ttl_seconds: int = PLAN_TTL_SECONDS,
    ) -> None:
        self._clock = clock or time.monotonic
        self._nonce_source = nonce_source or self._default_nonce
        self._capacity = int(capacity)
        self._ttl_seconds = int(ttl_seconds)
        self._lock = threading.RLock()
        self._plans: Dict[Tuple[str, str], InjectionPlan] = {}
        # Insert-only lifecycle: terminal/expired keys stay blocked until
        # expires_monotonic + EXECUTION_REVIEW_MARGIN_SECONDS.
        self._reuse_block_until: Dict[Tuple[str, str], float] = {}

    @staticmethod
    def _default_nonce() -> str:
        # 128-bit secure random as 32 hex chars.
        return secrets.token_hex(16)

    def _new_nonce(self) -> str:
        nonce = self._nonce_source()
        raw = bytes.fromhex(nonce) if all(c in "0123456789abcdef" for c in nonce.lower()) else nonce.encode("utf-8")
        if len(raw) < 16:
            raise PlanStoreError("WEAK_NONCE")
        return nonce

    def reset_for_tests(self) -> None:
        """Clear plans and tombstones. Test-only; no production single-key delete API."""
        with self._lock:
            self._plans.clear()
            self._reuse_block_until.clear()

    def create_analyzed_plan(
        self,
        *,
        session_id: str,
        turn_id: str,
        tool_call_id: str,
        tool_name: str,
        args: Mapping[str, Any],
        reference_arg_path: Tuple[object, ...],
        credential_name: str,
        target_name: str,
        binding_name: str,
        binding_type: str,
        config_digest: str,
        binding_digest: str,
        target_digest: str,
        config_file_identity: Mapping[str, Any],
        ttl_seconds: Optional[int] = None,
        program_identity: Optional[Mapping[str, Any]] = None,
    ) -> InjectionPlan:
        now = float(self._clock())
        ttl = self._ttl_seconds if ttl_seconds is None else int(ttl_seconds)
        if ttl <= 0:
            raise PlanStoreError("TTL_UNAVAILABLE")
        plan = InjectionPlan(
            session_id=session_id,
            turn_id=turn_id,
            tool_call_id=tool_call_id,
            tool_name=tool_name,
            args_digest=canonical_args_digest(dict(args)),
            reference_arg_path=tuple(reference_arg_path),
            credential_name=credential_name,
            target_name=target_name,
            binding_name=binding_name,
            binding_type=binding_type,
            config_digest=config_digest,
            binding_digest=binding_digest,
            target_digest=target_digest,
            config_file_identity=dict(config_file_identity),
            nonce=self._new_nonce(),
            created_monotonic=now,
            expires_monotonic=now + float(ttl),
            state=PlanState.ANALYZED,
            program_identity=dict(program_identity or {}),
        )
        # put() raises on reuse — must not return or leave a partial entry.
        self.put(plan)
        return plan

    def put(self, plan: InjectionPlan) -> None:
        key = _plan_key(plan.session_id, plan.tool_call_id)
        with self._lock:
            self.cleanup()
            if key in self._plans or key in self._reuse_block_until:
                raise PlanStoreError("PLAN_KEY_REUSED")
            # Unique-key occupancy: a terminal tombstone lives in both maps.
            occupied = len(set(self._plans) | set(self._reuse_block_until))
            if occupied >= self._capacity:
                raise PlanStoreError("STORE_FULL")
            self._plans[key] = plan

    def lookup(self, session_id: str, tool_call_id: str) -> Optional[InjectionPlan]:
        key = _plan_key(session_id, tool_call_id)
        with self._lock:
            plan = self._plans.get(key)
            if plan is None:
                return None
            if self._is_expired(plan):
                self._mark_terminal(key, replace(plan, state=PlanState.INVALIDATED))
                return self._plans[key]
            return plan

    def mark_approval_pending(self, session_id: str, tool_call_id: str) -> InjectionPlan:
        key = _plan_key(session_id, tool_call_id)
        with self._lock:
            plan = self._require(key)
            if self._is_expired(plan):
                self._mark_terminal(key, replace(plan, state=PlanState.INVALIDATED))
                raise PlanStoreError("PLAN_EXPIRED")
            if plan.state is not PlanState.ANALYZED:
                raise PlanStoreError("INVALID_STATE")
            updated = replace(plan, state=PlanState.APPROVAL_PENDING)
            self._plans[key] = updated
            return updated

    def consume(self, session_id: str, tool_call_id: str) -> InjectionPlan:
        key = _plan_key(session_id, tool_call_id)
        with self._lock:
            plan = self._require(key)
            if self._is_expired(plan):
                self._mark_terminal(key, replace(plan, state=PlanState.INVALIDATED))
                raise PlanStoreError("PLAN_EXPIRED")
            if plan.state is not PlanState.APPROVAL_PENDING:
                raise PlanStoreError("INVALID_STATE")
            updated = replace(plan, state=PlanState.CONSUMED)
            self._mark_terminal(key, updated)
            return updated

    def invalidate(self, session_id: str, tool_call_id: str) -> InjectionPlan:
        key = _plan_key(session_id, tool_call_id)
        with self._lock:
            plan = self._require(key)
            if plan.state in (PlanState.CONSUMED, PlanState.INVALIDATED):
                raise PlanStoreError("INVALID_STATE")
            updated = replace(plan, state=PlanState.INVALIDATED)
            self._mark_terminal(key, updated)
            return updated

    def cleanup(self) -> int:
        with self._lock:
            now = float(self._clock())
            # Establish tombstones for terminal / expired keys; never evict early.
            for key, plan in list(self._plans.items()):
                if key in self._reuse_block_until:
                    continue
                if plan.state in (PlanState.CONSUMED, PlanState.INVALIDATED):
                    self._reuse_block_until[key] = self._tombstone_deadline(plan)
                elif plan.expires_monotonic <= now:
                    self._mark_terminal(
                        key, replace(plan, state=PlanState.INVALIDATED)
                    )
            remove_keys = []
            for key, deadline in self._reuse_block_until.items():
                if now >= float(deadline):
                    remove_keys.append(key)
            for key in remove_keys:
                self._plans.pop(key, None)
                del self._reuse_block_until[key]
            return len(remove_keys)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "size": len(self._plans),
                "capacity": self._capacity,
                "keys": sorted(
                    f"{s}:{t}" for (s, t) in self._plans.keys()
                ),
                "states": {
                    f"{s}:{t}": plan.state.value
                    for (s, t), plan in self._plans.items()
                },
            }

    def __repr__(self) -> str:
        with self._lock:
            return (
                f"InjectionPlanStore(size={len(self._plans)}, "
                f"capacity={self._capacity})"
            )

    def _tombstone_deadline(self, plan: InjectionPlan) -> float:
        return float(plan.expires_monotonic) + float(EXECUTION_REVIEW_MARGIN_SECONDS)

    def _mark_terminal(self, key: Tuple[str, str], plan: InjectionPlan) -> None:
        self._plans[key] = plan
        self._reuse_block_until[key] = self._tombstone_deadline(plan)

    def _require(self, key: Tuple[str, str]) -> InjectionPlan:
        plan = self._plans.get(key)
        if plan is None:
            raise PlanStoreError("PLAN_NOT_FOUND")
        return plan

    def _is_expired(self, plan: InjectionPlan) -> bool:
        return float(self._clock()) >= float(plan.expires_monotonic)



__all__ = [
    "EXECUTION_REVIEW_MARGIN_SECONDS",
    "HERMES_MAX_TOOL_WORKERS",
    "MAX_APPROVAL_TIMEOUT_SECONDS",
    "PLAN_STORE_CAPACITY",
    "PLAN_STORE_CAPACITY_MULTIPLIER",
    "PLAN_TTL_SECONDS",
    "CanonicalError",
    "InjectionPlan",
    "InjectionPlanStore",
    "PlanState",
    "PlanStoreError",
    "canonical_args_digest",
    "default_plan_ttl_seconds",
    "resolve_plan_ttl_seconds",
]
