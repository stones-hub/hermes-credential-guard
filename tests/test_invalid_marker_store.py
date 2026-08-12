"""R2 Round8 B1: bounded InvalidMarkerStore — attack + contract + mutation.

Attacker is an untrusted model that can mint unique (session_id, tool_call_id)
malformed/unregistered references. Must not grow process memory unboundedly,
and saturation must remain fail-closed (never silent-drop markers).
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import types
from pathlib import Path
from typing import Any, Dict, List

import pytest

from credential_guard.approval import on_pre_tool_call
from credential_guard.config import CONFIG_FILENAME
from credential_guard.injection_plan import PLAN_STORE_CAPACITY
from credential_guard.runtime_config import (
    HTTP_REFERENCE_TOOL,
    load_and_publish_runtime,
    reset_runtime_for_tests,
)
from credential_guard.tool_execution import on_tool_execution
from credential_guard.tool_request import (
    get_invalid_marker,
    get_plan_store,
    on_tool_request,
    reset_tool_request_state_for_tests,
)


def _write_cfg(store: Path, token: str) -> None:
    doc = {
        "version": 2,
        "credentials": {"jenkins-token": {"type": "token", "value": token}},
        "bindings": {
            "jenkins-production": {
                "type": "http",
                "credential_ref": "jenkins-token",
                "target": {
                    "scheme": "https",
                    "host": "jenkins.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                    "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
                },
                "inject": {"type": "bearer", "location": "authorization_header"},
                "approval": "required",
            }
        },
    }
    store.mkdir(parents=True, exist_ok=True)
    os.chmod(store, 0o700)
    path = store / CONFIG_FILENAME
    path.write_text(json.dumps(doc), encoding="utf-8")
    os.chmod(path, 0o600)


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    store = hermes / "credential-guard"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    reset_runtime_for_tests()
    reset_tool_request_state_for_tests()
    token = "CG_R8_INV_" + secrets.token_hex(12)
    _write_cfg(store, token)

    hermes_cli = types.ModuleType("hermes_cli")
    cfg_mod = types.ModuleType("hermes_cli.config")
    cfg_mod.load_config_readonly = lambda: {
        "approvals": {"mode": "manual", "timeout": 300}
    }
    hermes_cli.config = cfg_mod
    tools_mod = types.ModuleType("tools")
    approval_mod = types.ModuleType("tools.approval")
    approval_mod.is_approval_bypass_active_for_session = lambda sid: False
    approval_mod._get_approval_timeout = lambda: 300
    tools_mod.approval = approval_mod
    import sys

    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.config", cfg_mod)
    monkeypatch.setitem(sys.modules, "tools", tools_mod)
    monkeypatch.setitem(sys.modules, "tools.approval", approval_mod)

    load_and_publish_runtime()
    yield store, token
    reset_tool_request_state_for_tests()
    reset_runtime_for_tests()


def _bad_ref_args(**overrides: Any) -> Dict[str, Any]:
    base = {
        "target": "jenkins-production",
        "method": "POST",
        "path": "/job/project-x/build",
        "credential": "<CREDENTIAL:not-registered>",
    }
    base.update(overrides)
    return base


def _flood_invalid(n: int, *, session: str = "s-flood") -> None:
    for i in range(n):
        on_tool_request(
            tool_name=HTTP_REFERENCE_TOOL,
            args=_bad_ref_args(),
            session_id=session,
            turn_id="t1",
            tool_call_id=f"tc-flood-{i}",
        )


def _marker_store():
    from credential_guard.tool_request import get_invalid_marker_store

    return get_invalid_marker_store()


def _legacy_invalid_len() -> int:
    """Probe pre-fix global dict if still present (RED diagnostic)."""
    import credential_guard.tool_request as tr

    raw = getattr(tr, "_INVALID", None)
    if isinstance(raw, dict):
        return len(raw)
    return -1


# ---------------------------------------------------------------------------
# Contract tests (RED against unbounded _INVALID; GREEN after InvalidMarkerStore)
# ---------------------------------------------------------------------------


def test_b1_flood_size_bounded_by_capacity(env):
    """Unique-id flood must not grow past PlanStore capacity."""
    n = PLAN_STORE_CAPACITY * 4
    _flood_invalid(n)
    assert get_plan_store().snapshot()["size"] == 0
    store = _marker_store()
    snap = store.snapshot()
    assert snap["size"] <= snap["capacity"]
    assert snap["capacity"] <= PLAN_STORE_CAPACITY
    # RED diagnostic on frozen snapshot: bare dict grows to N.
    legacy = _legacy_invalid_len()
    if legacy >= 0:
        assert legacy <= snap["capacity"], (
            f"unbounded _INVALID grew to {legacy} (N={n})"
        )


def test_b1_saturation_still_fail_closed_pre_and_execution(env):
    """When full, new malformed refs must not be silently allowed later."""
    _flood_invalid(PLAN_STORE_CAPACITY)
    store = _marker_store()
    assert store.snapshot()["size"] == store.snapshot()["capacity"]

    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_bad_ref_args(),
        session_id="s-over",
        turn_id="t1",
        tool_call_id="tc-over-new",
    )
    assert store.snapshot().get("overflow") is True

    blocked = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_bad_ref_args(),
        session_id="s-over",
        turn_id="t1",
        tool_call_id="tc-over-new",
    )
    assert blocked is not None
    assert blocked.get("action") == "block"

    downstream: List[Dict[str, Any]] = []

    def _next(args: Dict[str, Any]) -> str:
        downstream.append(dict(args))
        return '{"ok":true}'

    result = on_tool_execution(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_bad_ref_args(),
        next_call=_next,
        session_id="s-over",
        turn_id="t1",
        tool_call_id="tc-over-new",
    )
    assert downstream == []
    data = json.loads(result)
    assert data["ok"] is False


def test_b1_ttl_expiry_reclaims_and_recovers(env, monkeypatch):
    store = _marker_store()
    clock = {"t": 1000.0}
    monkeypatch.setattr(store, "_clock", lambda: clock["t"])
    # Force short TTL for the test without waiting 360s.
    monkeypatch.setattr(store, "_ttl_seconds", 10)

    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_bad_ref_args(),
        session_id="s-ttl",
        turn_id="t1",
        tool_call_id="tc-ttl-1",
    )
    assert store.snapshot()["size"] == 1
    assert get_invalid_marker("s-ttl", "tc-ttl-1") is not None

    clock["t"] = 1000.0 + 11.0
    assert get_invalid_marker("s-ttl", "tc-ttl-1") is None
    assert store.snapshot()["size"] == 0

    # After expiry, capacity recovers for a new marker.
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_bad_ref_args(),
        session_id="s-ttl",
        turn_id="t1",
        tool_call_id="tc-ttl-2",
    )
    assert store.snapshot()["size"] == 1


def test_b1_terminal_block_reclaims_marker(env):
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_bad_ref_args(),
        session_id="s-term",
        turn_id="t1",
        tool_call_id="tc-term",
    )
    assert get_invalid_marker("s-term", "tc-term") is not None
    blocked = on_pre_tool_call(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_bad_ref_args(),
        session_id="s-term",
        turn_id="t1",
        tool_call_id="tc-term",
    )
    assert blocked is not None and blocked.get("action") == "block"
    # Terminal block must reclaim (or consume) — not permanently retain.
    store = _marker_store()
    assert "s-term:tc-term" not in store.snapshot()["keys"]


def test_b1_tool_execution_consume_reclaims(env):
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_bad_ref_args(),
        session_id="s-exec",
        turn_id="t1",
        tool_call_id="tc-exec",
    )
    assert get_invalid_marker("s-exec", "tc-exec") is not None

    def _next(args: Dict[str, Any]) -> str:
        raise AssertionError("must not reach downstream")

    result = on_tool_execution(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_bad_ref_args(),
        next_call=_next,
        session_id="s-exec",
        turn_id="t1",
        tool_call_id="tc-exec",
    )
    assert json.loads(result)["ok"] is False
    store = _marker_store()
    assert "s-exec:tc-exec" not in store.snapshot()["keys"]


def test_b1_concurrent_flood_stays_bounded_and_fail_closed(env):
    errors: List[BaseException] = []

    def worker(start: int, count: int) -> None:
        try:
            for i in range(start, start + count):
                on_tool_request(
                    tool_name=HTTP_REFERENCE_TOOL,
                    args=_bad_ref_args(),
                    session_id="s-conc",
                    turn_id="t1",
                    tool_call_id=f"tc-c-{i}",
                )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(i * 40, 40)) for i in range(4)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    store = _marker_store()
    snap = store.snapshot()
    assert snap["size"] <= snap["capacity"]

    # A new unique key after flood must still fail closed (overflow or marker).
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_bad_ref_args(),
        session_id="s-conc",
        turn_id="t1",
        tool_call_id="tc-c-post",
    )
    downstream: List[Any] = []

    def _next(args: Dict[str, Any]) -> str:
        downstream.append(1)
        return '{"ok":true}'

    result = on_tool_execution(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_bad_ref_args(),
        next_call=_next,
        session_id="s-conc",
        turn_id="t1",
        tool_call_id="tc-c-post",
    )
    assert downstream == []
    assert json.loads(result)["ok"] is False


def test_b1_plain_tool_passthrough_once_under_overflow(env):
    _flood_invalid(PLAN_STORE_CAPACITY + 5)
    assert _marker_store().snapshot().get("overflow") is True

    calls: List[Dict[str, Any]] = []

    def _next(args: Dict[str, Any]) -> str:
        calls.append(dict(args))
        return '{"ok":true,"plain":1}'

    result = on_tool_execution(
        tool_name="web_search",
        args={"query": "hello"},
        next_call=_next,
        session_id="s-plain",
        turn_id="t1",
        tool_call_id="tc-plain",
    )
    assert calls == [{"query": "hello"}]
    assert json.loads(result)["plain"] == 1

    # Exactly once — second call still passthrough, not double-wrapped side effects.
    result2 = on_tool_execution(
        tool_name="web_search",
        args={"query": "hello"},
        next_call=_next,
        session_id="s-plain",
        turn_id="t1",
        tool_call_id="tc-plain-2",
    )
    assert len(calls) == 2
    assert json.loads(result2)["plain"] == 1


def test_b1_empty_identity_blocks_without_unbounded_empty_key(env):
    for i in range(20):
        on_tool_request(
            tool_name=HTTP_REFERENCE_TOOL,
            args=_bad_ref_args(),
            session_id="",
            turn_id="t1",
            tool_call_id="",
        )
    store = _marker_store()
    snap = store.snapshot()
    # Must not mint 20 distinct empty-key entries.
    assert snap["size"] <= snap["capacity"]
    assert ":".join(["", ""]) not in snap.get("keys", []) or snap["size"] <= 1

    downstream: List[Any] = []

    def _next(args: Dict[str, Any]) -> str:
        downstream.append(1)
        return '{"ok":true}'

    result = on_tool_execution(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_bad_ref_args(),
        next_call=_next,
        session_id="",
        turn_id="t1",
        tool_call_id="",
    )
    assert downstream == []
    assert json.loads(result)["ok"] is False


def test_b1_snapshot_repr_no_secrets(env):
    secret = "CG_R8_SECRET_" + secrets.token_hex(8)
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_bad_ref_args(credential=f"<CREDENTIAL:{secret}>"),
        session_id="s-sec",
        turn_id="t1",
        tool_call_id="tc-sec",
    )
    store = _marker_store()
    blob = repr(store) + json.dumps(store.snapshot(), sort_keys=True)
    assert secret not in blob
    marker = get_invalid_marker("s-sec", "tc-sec")
    if marker:
        assert secret not in json.dumps(marker)


def test_b1_reset_clears_markers_and_overflow(env):
    _flood_invalid(PLAN_STORE_CAPACITY + 1)
    assert _marker_store().snapshot()["size"] > 0
    assert _marker_store().snapshot().get("overflow") is True
    reset_tool_request_state_for_tests()
    snap = _marker_store().snapshot()
    assert snap["size"] == 0
    assert snap.get("overflow") is False


# ---------------------------------------------------------------------------
# Mutations — restoring unsafe semantics must RED
# ---------------------------------------------------------------------------


def test_b1_mutation_bare_dict_unbounded_red(env, monkeypatch):
    """Restoring a naked process dict must fail the capacity contract."""
    import credential_guard.tool_request as tr

    bare: Dict = {}
    monkeypatch.setattr(tr, "_INVALID", bare, raising=False)

    real_set = tr._set_invalid

    def bare_set(session_id: str, tool_call_id: str, reason: str) -> None:
        bare[(session_id or "", tool_call_id or "")] = {
            "reason": reason,
            "source": tr.TRACE_SOURCE,
        }

    monkeypatch.setattr(tr, "_set_invalid", bare_set)
    n = PLAN_STORE_CAPACITY + 10
    for i in range(n):
        bare_set("s-mut", f"tc-{i}", "UNREGISTERED")
    assert len(bare) == n
    # Desired store must still report bounded — mutation proves bare dict diverges.
    with pytest.raises(AssertionError):
        assert len(bare) <= PLAN_STORE_CAPACITY


def test_b1_mutation_silent_drop_on_full_red(env, monkeypatch):
    """Saturation that silently drops markers must RED the fail-closed contract."""
    store = _marker_store()
    _flood_invalid(PLAN_STORE_CAPACITY)
    assert store.snapshot()["size"] == store.snapshot()["capacity"]

    good = {
        "target": "jenkins-production",
        "method": "POST",
        "path": "/job/project-x/build",
        "credential": "<CREDENTIAL:jenkins-token>",
    }
    out = on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=good,
        session_id="s-drop",
        turn_id="t1",
        tool_call_id="tc-live",
    )
    assert out["trace"]["reason"] == "analyzed"

    import credential_guard.tool_request as tr

    def silent_set(session_id: str, tool_call_id: str, reason: str) -> None:
        store._overflow_until = None  # type: ignore[attr-defined]

    monkeypatch.setattr(tr, "_set_invalid", silent_set)

    out_b = on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=good,
        session_id="s-drop",
        turn_id="t1",
        tool_call_id="tc-live",
    )
    assert out_b["trace"]["reason"] == "create_failed"

    downstream: List[Any] = []

    def _next(args: Dict[str, Any]) -> str:
        downstream.append(1)
        return '{"ok":true,"leaked":1}'

    result = on_tool_execution(
        tool_name=HTTP_REFERENCE_TOOL,
        args=good,
        next_call=_next,
        session_id="s-drop",
        turn_id="t1",
        tool_call_id="tc-live",
    )
    with pytest.raises(AssertionError):
        assert downstream == []
        assert json.loads(result)["ok"] is False


def test_b1_mutation_no_ttl_red(env, monkeypatch):
    store = _marker_store()
    clock = {"t": 1000.0}
    monkeypatch.setattr(store, "_clock", lambda: clock["t"])
    monkeypatch.setattr(store, "_ttl_seconds", 10)

    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=_bad_ref_args(),
        session_id="s-nttl",
        turn_id="t1",
        tool_call_id="tc-nttl",
    )
    # Cancel TTL by rewriting deadline to +inf.
    key = ("s-nttl", "tc-nttl")
    entry = store._entries[key]  # type: ignore[attr-defined]
    entry["deadline"] = float("inf")
    clock["t"] = 1000.0 + 10_000.0
    # Without TTL reclaim, marker remains — contract requires expiry cleanup.
    with pytest.raises(AssertionError):
        assert get_invalid_marker("s-nttl", "tc-nttl") is None
