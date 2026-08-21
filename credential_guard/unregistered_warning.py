"""C7: best-effort local warning for high-signal unregistered credential shapes.

Not a security backstop: never blocks, redacts, or mutates the Provider request.
Never returns hit values, fragments, lengths, positions, hashes, or field paths.
"""

from __future__ import annotations

import queue
import re
import sys
import threading
import time
from collections import OrderedDict
from typing import Any, FrozenSet, Optional, Set

UNREGISTERED_WARNING_TEXT = (
    "Credential Guard 风险提醒：检测到疑似未登记的凭证；它不受本插件保护，"
    "当前请求内容未被修改。请将需要保护的凭证加入本机配置。"
    "检测可能遗漏或误报。"
)

FAMILY_OPENAI = "openai"
FAMILY_GITHUB = "github"
FAMILY_AWS = "aws"
FAMILY_SLACK = "slack"

KNOWN_FAMILIES: FrozenSet[str] = frozenset(
    {FAMILY_OPENAI, FAMILY_GITHUB, FAMILY_AWS, FAMILY_SLACK}
)

_MAX_NODES = 10_000
_MAX_STRING_CHARS = 1_000_000
_MAX_DEPTH = 64
_MAX_SESSIONS = 1024
# Hard cap on session_id characters retained as LRU keys. Oversized / non-str /
# empty ids collapse to the process-level (empty) dedupe bucket — never truncated.
MAX_SESSION_ID_CHARS = 256

# Fixed emit events only — never family/session/hit/path/length/hash payloads.
_WARN_QUEUE_MAX = 16
_WARN_EVENT = object()

# Linear patterns with explicit boundaries; no nested quantifiers / backtracking traps.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        FAMILY_OPENAI,
        re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,200}(?![A-Za-z0-9_-])"),
    ),
    (
        FAMILY_GITHUB,
        re.compile(
            r"(?<![A-Za-z0-9_])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}(?![A-Za-z0-9])"
        ),
    ),
    (
        FAMILY_AWS,
        re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    ),
    (
        FAMILY_SLACK,
        re.compile(
            r"(?<![A-Za-z0-9_-])(?:xoxb|xoxp|xoxa|xoxr)-[A-Za-z0-9-]{10,200}(?![A-Za-z0-9-])"
        ),
    ),
)

_LOCK = threading.Lock()
# session_id -> set of families already warned (at most len(KNOWN_FAMILIES)).
_SESSION_FAMILIES: "OrderedDict[str, Set[str]]" = OrderedDict()
# Empty session_id: process-level family set (at most len(KNOWN_FAMILIES)); not LRU.
_PROCESS_FAMILIES: Set[str] = set()

_WARN_QUEUE: "queue.Queue[object]" = queue.Queue(maxsize=_WARN_QUEUE_MAX)
_WORKER_LOCK = threading.Lock()
_WORKER_STARTED = False
_WORKER_THREAD: Optional[threading.Thread] = None
_EMIT_IDLE_LOCK = threading.Lock()
_EMITS_SUBMITTED = 0
_EMITS_COMPLETED = 0
_WRITE_IN_FLIGHT = 0


def reset_unregistered_warning_state_for_tests() -> None:
    """Clear per-process / per-session warning ledger. Tests only.

    Does not join a possibly blocked stderr worker.
    """
    with _LOCK:
        _SESSION_FAMILIES.clear()
        _PROCESS_FAMILIES.clear()


def scan_unregistered_credential_families(payload: Any) -> Set[str]:
    """Return the set of matched family labels; never returns hit material.

    Recurses only JSON-shaped dict/list/tuple/str/scalars. Other objects are
    skipped without calling ``str()`` / ``repr()``. Hitting any scan budget
    stops detection and returns whatever was found so far (silent, non-fatal).
    """
    found: Set[str] = set()
    nodes = 0
    chars = 0

    def _walk(node: Any, depth: int) -> bool:
        """Return False when a budget is exhausted and scanning must stop."""
        nonlocal nodes, chars
        if depth > _MAX_DEPTH:
            return False
        nodes += 1
        if nodes > _MAX_NODES:
            return False

        if isinstance(node, str):
            chars += len(node)
            if chars > _MAX_STRING_CHARS:
                return False
            for family, pattern in _PATTERNS:
                if family in found:
                    continue
                if pattern.search(node) is not None:
                    found.add(family)
            return True

        if isinstance(node, dict):
            for key, value in node.items():
                # Keys may be strings; scan them as string leaves too.
                if isinstance(key, str):
                    if not _walk(key, depth + 1):
                        return False
                elif not _is_json_scalar(key):
                    # Non-JSON-shaped key: skip without coercing.
                    pass
                if not _walk(value, depth + 1):
                    return False
            return True

        if isinstance(node, (list, tuple)):
            for item in node:
                if not _walk(item, depth + 1):
                    return False
            return True

        if _is_json_scalar(node):
            return True

        # Non-JSON-shaped object: skip; do not call str()/repr().
        return True

    _walk(payload, 0)
    return found


def _is_json_scalar(node: Any) -> bool:
    return node is None or isinstance(node, (bool, int, float))


def _normalize_session_key(session_id: Any) -> str:
    """Return LRU key or ``\"\"`` for process-level policy.

    Non-str, empty, or ``len(session_id) > MAX_SESSION_ID_CHARS`` → empty.
    Never truncates, hashes, or retains oversized material.
    """
    if not isinstance(session_id, str) or not session_id:
        return ""
    if len(session_id) > MAX_SESSION_ID_CHARS:
        return ""
    return session_id


def _should_emit_locked(session_id: str, family: str) -> bool:
    """Record and return whether this session+family should emit once.

    Must be called while holding ``_LOCK``. Family set is fixed; session map
    is LRU-capped at ``_MAX_SESSIONS``. Empty ``session_id`` (including
    oversized / non-str normalized to empty) uses a separate process-level
    set that is not subject to session LRU eviction.
    """
    if family not in KNOWN_FAMILIES:
        return False
    key = _normalize_session_key(session_id)
    if key == "":
        if family in _PROCESS_FAMILIES:
            return False
        _PROCESS_FAMILIES.add(family)
        return True
    if key in _SESSION_FAMILIES:
        _SESSION_FAMILIES.move_to_end(key)
        seen = _SESSION_FAMILIES[key]
        if family in seen:
            return False
        seen.add(family)
        return True
    while len(_SESSION_FAMILIES) >= _MAX_SESSIONS:
        _SESSION_FAMILIES.popitem(last=False)
    _SESSION_FAMILIES[key] = {family}
    return True


def note_families_and_select_emits(session_id: str, families: Set[str]) -> Set[str]:
    """Return the subset of families that should emit for this session (once)."""
    to_emit: Set[str] = set()
    with _LOCK:
        for family in sorted(families):
            if _should_emit_locked(session_id, family):
                to_emit.add(family)
    return to_emit


def session_state_size_for_tests() -> int:
    """Number of tracked sessions. Tests only."""
    with _LOCK:
        return len(_SESSION_FAMILIES)


def session_keys_snapshot_for_tests() -> tuple[str, ...]:
    """Ordered snapshot of resident session keys only. Tests only."""
    with _LOCK:
        return tuple(_SESSION_FAMILIES.keys())


def session_resident_key_chars_for_tests() -> int:
    """Total characters across resident LRU session keys. Tests only."""
    with _LOCK:
        return sum(len(k) for k in _SESSION_FAMILIES)


def wait_unregistered_warning_idle_for_tests(timeout: float = 2.0) -> bool:
    """Bounded wait until queued emits finish (normal stderr). Tests only."""
    deadline = time.monotonic() + max(0.0, timeout)
    while time.monotonic() < deadline:
        with _EMIT_IDLE_LOCK:
            submitted = _EMITS_SUBMITTED
            completed = _EMITS_COMPLETED
            in_flight = _WRITE_IN_FLIGHT
        if submitted == completed and in_flight == 0 and _WARN_QUEUE.empty():
            return True
        time.sleep(0.005)
    return False


def _ensure_warn_worker() -> None:
    """Start at most one daemon worker; thread-safe; never recreates if stuck."""
    global _WORKER_STARTED, _WORKER_THREAD
    if _WORKER_STARTED:
        return
    with _WORKER_LOCK:
        if _WORKER_STARTED:
            return
        thread = threading.Thread(
            target=_warn_worker_loop,
            name="cg-unregistered-warn",
            daemon=True,
        )
        _WORKER_THREAD = thread
        _WORKER_STARTED = True
        thread.start()


def _warn_worker_loop() -> None:
    """Consume fixed emit events and write the constant warning to stderr."""
    global _EMITS_COMPLETED, _WRITE_IN_FLIGHT
    while True:
        try:
            _WARN_QUEUE.get()
        except Exception:
            return
        with _EMIT_IDLE_LOCK:
            _WRITE_IN_FLIGHT += 1
        try:
            try:
                sys.stderr.write(UNREGISTERED_WARNING_TEXT + "\n")
                sys.stderr.flush()
            except Exception:
                pass
        finally:
            with _EMIT_IDLE_LOCK:
                _WRITE_IN_FLIGHT = max(0, _WRITE_IN_FLIGHT - 1)
                _EMITS_COMPLETED += 1


def _enqueue_warn_event() -> None:
    """Non-blocking Provider-hot-path submit. Drop when the queue is full."""
    global _EMITS_SUBMITTED
    try:
        _ensure_warn_worker()
        with _EMIT_IDLE_LOCK:
            # Count before put so wait_idle cannot observe completed > submitted.
            _WARN_QUEUE.put_nowait(_WARN_EVENT)
            _EMITS_SUBMITTED += 1
    except queue.Full:
        return
    except Exception:
        return


def best_effort_warn_unregistered(payload: Any, session_id: str = "") -> None:
    """Scan + dedupe + async stderr warn. Swallow every failure; never raise.

    Provider hot path never performs synchronous stderr I/O.
    """
    try:
        families = scan_unregistered_credential_families(payload)
    except Exception:
        return
    if not families:
        return
    try:
        to_emit = note_families_and_select_emits(session_id, families)
    except Exception:
        return
    for _family in sorted(to_emit):
        try:
            _enqueue_warn_event()
        except Exception:
            return
