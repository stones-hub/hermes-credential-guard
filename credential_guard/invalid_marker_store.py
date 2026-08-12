"""Bounded invalid-marker store for cross-dispatcher fail-closed (R2 Round8).

Untrusted models can mint unique (session_id, tool_call_id) malformed references.
Markers are capacity-bounded, TTL-bound (monotonic), lazily reclaimed, and on
saturation trip a TTL'd overflow circuit so reference paths stay fail-closed
without silently dropping markers or evicting in-flight keys.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple

from .injection_plan import (
    PLAN_STORE_CAPACITY,
    PLAN_TTL_SECONDS,
    PlanStoreError,
    resolve_plan_ttl_seconds,
)

TRACE_SOURCE = "credential-guard"

Key = Tuple[str, str]


def _resolve_marker_ttl_seconds() -> int:
    """TTL from Hermes approval timeout + review margin; bounded fallback."""
    try:
        return int(resolve_plan_ttl_seconds())
    except PlanStoreError:
        return int(PLAN_TTL_SECONDS)


class InvalidMarkerStore:
    """Thread-safe bounded store for per-call invalid markers + overflow circuit."""

    def __init__(
        self,
        *,
        capacity: int = PLAN_STORE_CAPACITY,
        ttl_seconds: Optional[int] = None,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self._capacity = max(1, int(capacity))
        self._ttl_seconds = (
            int(ttl_seconds) if ttl_seconds is not None else _resolve_marker_ttl_seconds()
        )
        if self._ttl_seconds <= 0:
            self._ttl_seconds = int(PLAN_TTL_SECONDS)
        self._clock = clock or time.monotonic
        self._lock = threading.RLock()
        self._entries: Dict[Key, Dict[str, Any]] = {}
        self._overflow_until: Optional[float] = None
        self._empty_identity_until: Optional[float] = None

    def reset(self) -> None:
        with self._lock:
            self._entries.clear()
            self._overflow_until = None
            self._empty_identity_until = None

    def _now(self) -> float:
        return float(self._clock())

    def _deadline(self, now: Optional[float] = None) -> float:
        return float(now if now is not None else self._now()) + float(self._ttl_seconds)

    def _cleanup_locked(self) -> int:
        now = self._now()
        removed = 0
        expired = [
            key
            for key, entry in self._entries.items()
            if float(entry["deadline"]) <= now
        ]
        for key in expired:
            del self._entries[key]
            removed += 1
        if self._overflow_until is not None and now >= float(self._overflow_until):
            self._overflow_until = None
        if self._empty_identity_until is not None and now >= float(
            self._empty_identity_until
        ):
            self._empty_identity_until = None
        return removed

    def _trip_overflow_locked(self) -> None:
        self._overflow_until = self._deadline()

    def _trip_empty_identity_locked(self) -> None:
        self._empty_identity_until = self._deadline()

    def set(self, session_id: str, tool_call_id: str, reason: str) -> None:
        sid = str(session_id or "")
        tid = str(tool_call_id or "")
        safe_reason = str(reason or "INVALID")
        with self._lock:
            self._cleanup_locked()
            if not sid or not tid:
                # No shared empty key — trip a TTL'd empty-identity circuit.
                self._trip_empty_identity_locked()
                return
            key: Key = (sid, tid)
            if key in self._entries:
                self._entries[key] = {
                    "reason": safe_reason,
                    "source": TRACE_SOURCE,
                    "deadline": self._deadline(),
                }
                return
            if len(self._entries) >= self._capacity:
                # Do not evict in-flight markers; fail-closed via overflow.
                self._trip_overflow_locked()
                return
            self._entries[key] = {
                "reason": safe_reason,
                "source": TRACE_SOURCE,
                "deadline": self._deadline(),
            }

    def get(self, session_id: str, tool_call_id: str) -> Optional[Dict[str, str]]:
        sid = str(session_id or "")
        tid = str(tool_call_id or "")
        with self._lock:
            self._cleanup_locked()
            if not sid or not tid:
                if self._empty_identity_until is not None:
                    return {
                        "reason": "MISSING_IDENTITY",
                        "source": TRACE_SOURCE,
                    }
                return None
            entry = self._entries.get((sid, tid))
            if entry is None:
                return None
            return {
                "reason": str(entry["reason"]),
                "source": str(entry["source"]),
            }

    def consume(self, session_id: str, tool_call_id: str) -> Optional[Dict[str, str]]:
        """Read-and-reclaim one marker (terminal fail-closed paths)."""
        sid = str(session_id or "")
        tid = str(tool_call_id or "")
        with self._lock:
            self._cleanup_locked()
            if not sid or not tid:
                if self._empty_identity_until is not None:
                    return {
                        "reason": "MISSING_IDENTITY",
                        "source": TRACE_SOURCE,
                    }
                return None
            key: Key = (sid, tid)
            entry = self._entries.pop(key, None)
            if entry is None:
                return None
            return {
                "reason": str(entry["reason"]),
                "source": str(entry["source"]),
            }

    def clear(self, session_id: str, tool_call_id: str) -> None:
        sid = str(session_id or "")
        tid = str(tool_call_id or "")
        if not sid or not tid:
            return
        with self._lock:
            self._entries.pop((sid, tid), None)

    def is_overflow_active(self) -> bool:
        with self._lock:
            self._cleanup_locked()
            return self._overflow_until is not None

    def is_empty_identity_blocked(self) -> bool:
        with self._lock:
            self._cleanup_locked()
            return self._empty_identity_until is not None

    def reference_path_blocked(self, session_id: str, tool_call_id: str) -> bool:
        """Fail-closed for reference/protected paths (markers, overflow, empty id)."""
        sid = str(session_id or "")
        tid = str(tool_call_id or "")
        with self._lock:
            self._cleanup_locked()
            if self._overflow_until is not None:
                return True
            if not sid or not tid:
                return self._empty_identity_until is not None
            return (sid, tid) in self._entries

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            self._cleanup_locked()
            return {
                "size": len(self._entries),
                "capacity": self._capacity,
                "keys": sorted(f"{s}:{t}" for (s, t) in self._entries.keys()),
                "overflow": self._overflow_until is not None,
                "empty_identity_blocked": self._empty_identity_until is not None,
            }

    def __repr__(self) -> str:
        with self._lock:
            return (
                f"InvalidMarkerStore(size={len(self._entries)}, "
                f"capacity={self._capacity}, overflow={self._overflow_until is not None})"
            )


__all__ = [
    "TRACE_SOURCE",
    "InvalidMarkerStore",
    "_resolve_marker_ttl_seconds",
]
