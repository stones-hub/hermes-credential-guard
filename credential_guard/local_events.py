"""Bounded async local fail-closed events (stderr / logging.lastResort safe).

Hot-path callers only enqueue fixed short event keys. A single daemon worker
performs logging I/O. Queue full, startup failure, or worker exceptions drop
the event — never change the fail-closed return value.

Leaf module: must not import middleware / hooks / result_guard (cycle risk).
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Optional

logger = logging.getLogger("credential_guard")

# Fixed reason code only — duplicated here to keep this module a leaf.
_RESULT_GUARD_FAIL_REASON = "RESULT_GUARD_FAIL"

_FAIL_CLOSED_STAGES = frozenset(
    {
        "llm_request",
        "llm_execution",
        "llm_execution_prior_block",
        "llm_execution_missing_next",
    }
)
_FAIL_CLOSED_CODES = frozenset(
    {
        "CG-CONFIG-UNAVAILABLE",
        "CG-REDACTION-COLLISION",
        "CG-RESIDUAL-SECRET",
        "CG-SCANNER-ERROR",
    }
)

_EVENT_PREFIX = "fail-closed:"
_EVENT_DEFAULT = "fail-closed:DEFAULT"
_EVENT_TRANSFORM = "fail-closed:transform_tool_result"
_EVENT_RESULT_GUARD = "fail-closed:result_guard"

_FAIL_CLOSED_FIXED_EVENTS: frozenset[str] = frozenset(
    {_EVENT_DEFAULT, _EVENT_TRANSFORM, _EVENT_RESULT_GUARD}
    | {f"{_EVENT_PREFIX}{stage}" for stage in _FAIL_CLOSED_STAGES}
    | {
        f"{_EVENT_PREFIX}{stage}:{code}"
        for stage in _FAIL_CLOSED_STAGES
        for code in _FAIL_CLOSED_CODES
    }
)

_QUEUE_MAX = 16
_QUEUE: "queue.Queue[str]" = queue.Queue(maxsize=_QUEUE_MAX)
_WORKER_LOCK = threading.Lock()
_WORKER_STARTED = False
_WORKER_THREAD: Optional[threading.Thread] = None
_IDLE_LOCK = threading.Lock()
_EMITS_SUBMITTED = 0
_EMITS_COMPLETED = 0
_WRITE_IN_FLIGHT = 0


def wait_fail_closed_idle_for_tests(timeout: float = 2.0) -> bool:
    """Bounded wait until queued fail-closed events finish. Tests only.

    Does not join a possibly blocked stderr / lastResort worker.
    """
    deadline = time.monotonic() + max(0.0, timeout)
    while time.monotonic() < deadline:
        with _IDLE_LOCK:
            submitted = _EMITS_SUBMITTED
            completed = _EMITS_COMPLETED
            in_flight = _WRITE_IN_FLIGHT
        if submitted == completed and in_flight == 0 and _QUEUE.empty():
            return True
        time.sleep(0.005)
    return False


def _normalize_middleware_event(stage: str, code: str = "") -> str:
    """Map stage/code to a finite fixed event. Never retains arbitrary strings."""
    if not isinstance(stage, str) or stage not in _FAIL_CLOSED_STAGES:
        return _EVENT_DEFAULT
    if not code:
        return f"{_EVENT_PREFIX}{stage}"
    if not isinstance(code, str) or code not in _FAIL_CLOSED_CODES:
        return _EVENT_DEFAULT
    return f"{_EVENT_PREFIX}{stage}:{code}"


def _normalize_event(event: str) -> str:
    if event in _FAIL_CLOSED_FIXED_EVENTS:
        return event
    return _EVENT_DEFAULT


def _log_fixed_event(event: str) -> None:
    """Emit the historical fixed warning text (worker thread only)."""
    fixed = _normalize_event(event)
    if fixed == _EVENT_TRANSFORM:
        logger.warning(
            "credential-guard failed closed at transform_tool_result reason=%s",
            _RESULT_GUARD_FAIL_REASON,
        )
        return
    if fixed == _EVENT_RESULT_GUARD:
        logger.warning(
            "credential-guard result_guard failed closed reason=%s",
            _RESULT_GUARD_FAIL_REASON,
        )
        return
    if fixed == _EVENT_DEFAULT:
        logger.warning("credential-guard failed closed at %s", "DEFAULT")
        return
    rest = fixed[len(_EVENT_PREFIX) :]
    if ":" in rest:
        stage, code = rest.split(":", 1)
        logger.warning(
            "credential-guard failed closed at %s code=%s", stage, code
        )
        return
    logger.warning("credential-guard failed closed at %s", rest)


def _ensure_worker() -> None:
    """Start at most one daemon worker; never recreates if stuck."""
    global _WORKER_STARTED, _WORKER_THREAD
    if _WORKER_STARTED:
        return
    with _WORKER_LOCK:
        if _WORKER_STARTED:
            return
        thread = threading.Thread(
            target=_worker_loop,
            name="cg-fail-closed-events",
            daemon=True,
        )
        _WORKER_THREAD = thread
        _WORKER_STARTED = True
        thread.start()


def _worker_loop() -> None:
    global _EMITS_COMPLETED, _WRITE_IN_FLIGHT
    while True:
        try:
            event = _QUEUE.get()
        except Exception:
            return
        with _IDLE_LOCK:
            _WRITE_IN_FLIGHT += 1
        try:
            try:
                _log_fixed_event(str(event))
            except Exception:
                pass
        finally:
            with _IDLE_LOCK:
                _WRITE_IN_FLIGHT = max(0, _WRITE_IN_FLIGHT - 1)
                _EMITS_COMPLETED += 1


def _enqueue(event: str) -> None:
    """Non-blocking submit. Drop when full or startup fails."""
    global _EMITS_SUBMITTED
    try:
        _ensure_worker()
        with _IDLE_LOCK:
            _QUEUE.put_nowait(event)
            _EMITS_SUBMITTED += 1
    except queue.Full:
        return
    except Exception:
        return


def submit_fail_closed(stage: str, code: str = "") -> None:
    """Middleware fail-closed: enqueue fixed stage(+code) event only."""
    _enqueue(_normalize_middleware_event(stage, code))


def submit_transform_fail_closed() -> None:
    """hooks.on_transform_tool_result outer catch — fixed event only."""
    _enqueue(_EVENT_TRANSFORM)


def submit_result_guard_fail_closed() -> None:
    """result_guard.guard_tool_result internal catch — fixed event only."""
    _enqueue(_EVENT_RESULT_GUARD)


__all__ = [
    "submit_fail_closed",
    "submit_transform_fail_closed",
    "submit_result_guard_fail_closed",
    "wait_fail_closed_idle_for_tests",
]
