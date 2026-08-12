"""R2B: immutable InjectionPlan and bounded store."""

from __future__ import annotations

import math
import threading
from typing import Any, Dict, List

import pytest

from credential_guard.injection_plan import (
    EXECUTION_REVIEW_MARGIN_SECONDS,
    HERMES_MAX_TOOL_WORKERS,
    PLAN_STORE_CAPACITY,
    PLAN_STORE_CAPACITY_MULTIPLIER,
    PLAN_TTL_SECONDS,
    CanonicalError,
    InjectionPlan,
    InjectionPlanStore,
    PlanState,
    PlanStoreError,
    canonical_args_digest,
    default_plan_ttl_seconds,
)


def _plan_kwargs(**overrides: Any) -> Dict[str, Any]:
    base = {
        "session_id": "sess-1",
        "turn_id": "turn-1",
        "tool_call_id": "tc-1",
        "tool_name": "http_credential_request",
        "args_digest": "a" * 64,
        "reference_arg_path": ("credential",),
        "credential_name": "jenkins-token",
        "target_name": "jenkins-production",
        "binding_name": "jenkins-production",
        "binding_type": "http_bearer",
        "config_digest": "b" * 64,
        "binding_digest": "c" * 64,
        "target_digest": "d" * 64,
        "config_file_identity": {
            "mtime_ns": 1,
            "size": 2,
            "inode": 3,
            "device": 4,
        },
        "nonce": "n" * 32,
        "created_monotonic": 100.0,
        "expires_monotonic": 460.0,
        "state": PlanState.ANALYZED,
    }
    base.update(overrides)
    return base


def test_01_canonical_digest_sorts_keys_preserves_array_order():
    a = {"z": 1, "a": [3, 1, 2], "m": {"b": 1, "a": 2}}
    b = {"a": [3, 1, 2], "m": {"a": 2, "b": 1}, "z": 1}
    assert canonical_args_digest(a) == canonical_args_digest(b)
    # Array order preserved: different order ⇒ different digest
    assert canonical_args_digest({"a": [1, 2]}) != canonical_args_digest({"a": [2, 1]})


def test_02_canonical_rejects_nan_inf_bytes_set_custom():
    class Obj:
        pass

    for bad in (
        {"x": math.nan},
        {"x": math.inf},
        {"x": -math.inf},
        {"x": b"abc"},
        {"x": {1, 2}},
        {"x": Obj()},
    ):
        with pytest.raises(CanonicalError):
            canonical_args_digest(bad)


def test_03_plan_frozen_complete_no_full_args():
    plan = InjectionPlan(**_plan_kwargs())
    assert plan.state is PlanState.ANALYZED
    with pytest.raises(Exception):
        plan.state = PlanState.CONSUMED  # type: ignore[misc]
    assert not hasattr(plan, "args")
    assert "args" not in plan.__dataclass_fields__


def test_04_digests_not_secret_derived():
    # Digest helpers must hash logical metadata only — no secret material API.
    plan = InjectionPlan(**_plan_kwargs(credential_name="jenkins-token"))
    assert "password" not in repr(plan).lower()
    assert "token" not in plan.config_digest
    assert len(plan.args_digest) == 64


def test_05_nonce_at_least_128_bit():
    store = InjectionPlanStore(
        clock=lambda: 0.0,
        nonce_source=lambda: "ab" * 16,  # 32 hex chars = 128 bit
    )
    nonce = store._new_nonce()
    assert len(bytes.fromhex(nonce)) >= 16


def test_06_key_requires_session_and_tool_call_id():
    store = InjectionPlanStore(clock=lambda: 0.0)
    plan = InjectionPlan(**_plan_kwargs(session_id="", tool_call_id="tc"))
    with pytest.raises(PlanStoreError) as exc:
        store.put(plan)
    assert exc.value.code == "MISSING_IDENTITY"

    plan2 = InjectionPlan(**_plan_kwargs(session_id="s", tool_call_id=""))
    with pytest.raises(PlanStoreError) as exc2:
        store.put(plan2)
    assert exc2.value.code == "MISSING_IDENTITY"


def test_07_state_machine_happy_path():
    clock = {"t": 0.0}
    store = InjectionPlanStore(clock=lambda: clock["t"])
    plan = InjectionPlan(**_plan_kwargs(created_monotonic=0.0, expires_monotonic=360.0))
    store.put(plan)
    pending = store.mark_approval_pending("sess-1", "tc-1")
    assert pending.state is PlanState.APPROVAL_PENDING
    consumed = store.consume("sess-1", "tc-1")
    assert consumed.state is PlanState.CONSUMED


def test_08_terminal_states_irreversible():
    store = InjectionPlanStore(clock=lambda: 0.0)
    store.put(InjectionPlan(**_plan_kwargs(expires_monotonic=360.0)))
    store.invalidate("sess-1", "tc-1")
    with pytest.raises(PlanStoreError):
        store.mark_approval_pending("sess-1", "tc-1")
    with pytest.raises(PlanStoreError):
        store.consume("sess-1", "tc-1")

    store2 = InjectionPlanStore(clock=lambda: 0.0)
    store2.put(
        InjectionPlan(
            **_plan_kwargs(tool_call_id="tc-2", expires_monotonic=360.0)
        )
    )
    store2.mark_approval_pending("sess-1", "tc-2")
    store2.consume("sess-1", "tc-2")
    with pytest.raises(PlanStoreError):
        store2.mark_approval_pending("sess-1", "tc-2")


def test_09_lookup_does_not_consume():
    store = InjectionPlanStore(clock=lambda: 0.0)
    store.put(InjectionPlan(**_plan_kwargs(expires_monotonic=360.0)))
    store.mark_approval_pending("sess-1", "tc-1")
    looked = store.lookup("sess-1", "tc-1")
    assert looked is not None
    assert looked.state is PlanState.APPROVAL_PENDING
    again = store.lookup("sess-1", "tc-1")
    assert again is not None
    assert again.state is PlanState.APPROVAL_PENDING


def test_10_session_and_tool_call_isolation():
    store = InjectionPlanStore(clock=lambda: 0.0)
    store.put(
        InjectionPlan(
            **_plan_kwargs(
                session_id="s1",
                tool_call_id="tc",
                nonce="1" * 32,
                expires_monotonic=360.0,
            )
        )
    )
    store.put(
        InjectionPlan(
            **_plan_kwargs(
                session_id="s2",
                tool_call_id="tc",
                nonce="2" * 32,
                expires_monotonic=360.0,
            )
        )
    )
    store.put(
        InjectionPlan(
            **_plan_kwargs(
                session_id="s1",
                tool_call_id="tc-other",
                nonce="3" * 32,
                expires_monotonic=360.0,
            )
        )
    )
    assert store.lookup("s1", "tc").nonce == "1" * 32
    assert store.lookup("s2", "tc").nonce == "2" * 32
    assert store.lookup("s1", "tc-other").nonce == "3" * 32


def test_11_concurrent_consume_only_one_wins():
    store = InjectionPlanStore(clock=lambda: 0.0)
    store.put(InjectionPlan(**_plan_kwargs(expires_monotonic=360.0)))
    store.mark_approval_pending("sess-1", "tc-1")
    barrier = threading.Barrier(8)
    winners: List[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait(timeout=5)
        try:
            store.consume("sess-1", "tc-1")
            with lock:
                winners.append(True)
        except PlanStoreError:
            with lock:
                winners.append(False)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
    assert winners.count(True) == 1
    assert winners.count(False) == 7


def test_12_monotonic_ttl_expire_cannot_consume():
    clock = {"t": 0.0}
    store = InjectionPlanStore(clock=lambda: clock["t"])
    store.put(InjectionPlan(**_plan_kwargs(created_monotonic=0.0, expires_monotonic=10.0)))
    store.mark_approval_pending("sess-1", "tc-1")
    clock["t"] = 11.0
    with pytest.raises(PlanStoreError) as exc:
        store.consume("sess-1", "tc-1")
    assert exc.value.code == "PLAN_EXPIRED"
    looked = store.lookup("sess-1", "tc-1")
    assert looked is None or looked.state is PlanState.INVALIDATED


def test_13_capacity_fail_closed_no_silent_eviction():
    assert PLAN_STORE_CAPACITY == HERMES_MAX_TOOL_WORKERS * PLAN_STORE_CAPACITY_MULTIPLIER
    assert HERMES_MAX_TOOL_WORKERS == 8
    assert PLAN_STORE_CAPACITY_MULTIPLIER == 4
    store = InjectionPlanStore(clock=lambda: 0.0, capacity=2)
    store.put(
        InjectionPlan(
            **_plan_kwargs(tool_call_id="tc-1", expires_monotonic=360.0)
        )
    )
    store.put(
        InjectionPlan(
            **_plan_kwargs(tool_call_id="tc-2", nonce="2" * 32, expires_monotonic=360.0)
        )
    )
    with pytest.raises(PlanStoreError) as exc:
        store.put(
            InjectionPlan(
                **_plan_kwargs(
                    tool_call_id="tc-3",
                    nonce="3" * 32,
                    expires_monotonic=360.0,
                )
            )
        )
    assert exc.value.code == "STORE_FULL"
    assert store.lookup("sess-1", "tc-1") is not None
    assert store.lookup("sess-1", "tc-2") is not None


def test_14_cleanup_only_after_tombstone_deadline():
    """Terminal/expired keys become tombstones; cleanup frees only after deadline."""
    clock = {"t": 0.0}
    store = InjectionPlanStore(clock=lambda: clock["t"], capacity=10)
    store.put(
        InjectionPlan(
            **_plan_kwargs(tool_call_id="alive", expires_monotonic=1000.0)
        )
    )
    store.put(
        InjectionPlan(
            **_plan_kwargs(
                tool_call_id="old",
                nonce="2" * 32,
                created_monotonic=0.0,
                expires_monotonic=5.0,
            )
        )
    )
    store.put(
        InjectionPlan(
            **_plan_kwargs(
                tool_call_id="done",
                nonce="3" * 32,
                expires_monotonic=100.0,
            )
        )
    )
    store.mark_approval_pending("sess-1", "done")
    store.consume("sess-1", "done")
    clock["t"] = 6.0
    # Before tombstone deadline: keep keys (capacity / anti-reuse), do not free.
    assert store.cleanup() == 0
    assert store.lookup("sess-1", "alive") is not None
    old = store.lookup("sess-1", "old")
    assert old is not None and old.state is PlanState.INVALIDATED
    done = store.lookup("sess-1", "done")
    assert done is not None and done.state is PlanState.CONSUMED
    # After old's deadline (expires 5 + margin 60 = 65): only "old" frees.
    clock["t"] = 5.0 + EXECUTION_REVIEW_MARGIN_SECONDS
    removed = store.cleanup()
    assert removed == 1
    assert store.lookup("sess-1", "old") is None
    assert store.lookup("sess-1", "alive") is not None
    assert store.lookup("sess-1", "done") is not None
    # After done's deadline: consumed tombstone frees.
    clock["t"] = 100.0 + EXECUTION_REVIEW_MARGIN_SECONDS
    removed2 = store.cleanup()
    assert removed2 == 1
    assert store.lookup("sess-1", "done") is None
    assert store.lookup("sess-1", "alive") is not None


def test_15_injectable_clock_and_nonce_no_sleep():
    stamps = iter([1.0, 1.0, 1.0])
    nonces = iter(["aa" * 16, "bb" * 16])
    store = InjectionPlanStore(
        clock=lambda: next(stamps),
        nonce_source=lambda: next(nonces),
    )
    p1 = store.create_analyzed_plan(
        session_id="s",
        turn_id="t",
        tool_call_id="c1",
        tool_name="http_credential_request",
        args={"credential": "<CREDENTIAL:jenkins-token>"},
        reference_arg_path=("credential",),
        credential_name="jenkins-token",
        target_name="jenkins-production",
        binding_name="jenkins-production",
        binding_type="http_bearer",
        config_digest="b" * 64,
        binding_digest="c" * 64,
        target_digest="d" * 64,
        config_file_identity={"mtime_ns": 1, "size": 1, "inode": 1, "device": 1},
    )
    assert p1.nonce == "aa" * 16
    assert p1.created_monotonic == 1.0
    assert p1.expires_monotonic == 1.0 + default_plan_ttl_seconds()


def test_16_repr_exception_snapshot_have_no_args_or_secrets():
    store = InjectionPlanStore(clock=lambda: 0.0)
    secret = "SUPER_SECRET_CANARY_VALUE_XYZ"
    store.put(
        InjectionPlan(
            **_plan_kwargs(
                args_digest=canonical_args_digest(
                    {"credential": "<CREDENTIAL:jenkins-token>"}
                ),
                expires_monotonic=360.0,
            )
        )
    )
    snap = store.snapshot()
    blob = repr(store) + repr(snap) + str(PlanStoreError("STORE_FULL"))
    assert secret not in blob
    assert "SUPER_SECRET" not in blob
    assert "<CREDENTIAL:" not in str(snap)


def test_p5_plan_omits_runtime_generation_security_binding():
    """P5: generation is observational on RuntimeView only — not a plan security field."""
    assert "runtime_generation" not in InjectionPlan.__dataclass_fields__
    import inspect

    sig = inspect.signature(InjectionPlanStore.create_analyzed_plan)
    assert "runtime_generation" not in sig.parameters


def test_ttl_constants_from_a0():
    assert EXECUTION_REVIEW_MARGIN_SECONDS == 60
    assert PLAN_TTL_SECONDS == 300 + 60
    assert default_plan_ttl_seconds() == PLAN_TTL_SECONDS


def test_resolve_plan_ttl_from_hermes_fail_closed(monkeypatch):
    from credential_guard.injection_plan import resolve_plan_ttl_seconds

    import types
    import sys

    tools_mod = types.ModuleType("tools")
    approval_mod = types.ModuleType("tools.approval")
    approval_mod._get_approval_timeout = lambda: 120
    tools_mod.approval = approval_mod
    monkeypatch.setitem(sys.modules, "tools", tools_mod)
    monkeypatch.setitem(sys.modules, "tools.approval", approval_mod)
    assert resolve_plan_ttl_seconds() == 120 + 60

    approval_mod._get_approval_timeout = lambda: -1
    with pytest.raises(PlanStoreError) as exc:
        resolve_plan_ttl_seconds()
    assert exc.value.code == "TTL_UNAVAILABLE"

    approval_mod._get_approval_timeout = lambda: "300"
    with pytest.raises(PlanStoreError):
        resolve_plan_ttl_seconds()

    approval_mod._get_approval_timeout = lambda: True
    with pytest.raises(PlanStoreError):
        resolve_plan_ttl_seconds()


def test_resolve_plan_ttl_ceils_fractional_timeout(monkeypatch):
    """Fractional host timeout must not truncate below the approval window."""
    import math
    import sys
    import types

    from credential_guard.injection_plan import (
        EXECUTION_REVIEW_MARGIN_SECONDS,
        resolve_plan_ttl_seconds,
    )

    tools_mod = types.ModuleType("tools")
    approval_mod = types.ModuleType("tools.approval")
    approval_mod._get_approval_timeout = lambda: 300.1
    tools_mod.approval = approval_mod
    monkeypatch.setitem(sys.modules, "tools", tools_mod)
    monkeypatch.setitem(sys.modules, "tools.approval", approval_mod)
    assert resolve_plan_ttl_seconds() == math.ceil(300.1) + EXECUTION_REVIEW_MARGIN_SECONDS
    assert resolve_plan_ttl_seconds() >= 301 + EXECUTION_REVIEW_MARGIN_SECONDS


def test_resolve_plan_ttl_rejects_non_finite_and_oversize(monkeypatch):
    import math
    import sys
    import types

    from credential_guard.injection_plan import (
        MAX_APPROVAL_TIMEOUT_SECONDS,
        resolve_plan_ttl_seconds,
    )

    tools_mod = types.ModuleType("tools")
    approval_mod = types.ModuleType("tools.approval")
    tools_mod.approval = approval_mod
    monkeypatch.setitem(sys.modules, "tools", tools_mod)
    monkeypatch.setitem(sys.modules, "tools.approval", approval_mod)

    for bad in (float("nan"), float("inf"), float("-inf"), MAX_APPROVAL_TIMEOUT_SECONDS + 1):
        approval_mod._get_approval_timeout = (lambda v=bad: v)
        with pytest.raises(PlanStoreError) as exc:
            resolve_plan_ttl_seconds()
        assert exc.value.code == "TTL_UNAVAILABLE"

    approval_mod._get_approval_timeout = lambda: MAX_APPROVAL_TIMEOUT_SECONDS
    assert resolve_plan_ttl_seconds() == MAX_APPROVAL_TIMEOUT_SECONDS + 60
    # sanity: documented safety cap is finite
    assert math.isfinite(MAX_APPROVAL_TIMEOUT_SECONDS)
    assert MAX_APPROVAL_TIMEOUT_SECONDS > 0


# --- R2 final: insert-only same-key + bounded tombstone ---


def _create_kwargs(**overrides: Any) -> Dict[str, Any]:
    base = {
        "session_id": "sess-1",
        "turn_id": "turn-1",
        "tool_call_id": "tc-1",
        "tool_name": "http_credential_request",
        "args": {"credential": "<CREDENTIAL:jenkins-token>", "target": "jenkins-production"},
        "reference_arg_path": ("credential",),
        "credential_name": "jenkins-token",
        "target_name": "jenkins-production",
        "binding_name": "jenkins-production",
        "binding_type": "http_bearer",
        "config_digest": "b" * 64,
        "binding_digest": "c" * 64,
        "target_digest": "d" * 64,
        "config_file_identity": {
            "mtime_ns": 1,
            "size": 2,
            "inode": 3,
            "device": 4,
        },
    }
    base.update(overrides)
    return base


def test_r2_put_rejects_reuse_analyzed_preserves_old():
    store = InjectionPlanStore(clock=lambda: 0.0)
    old = InjectionPlan(
        **_plan_kwargs(nonce="a" * 32, args_digest="1" * 64, expires_monotonic=360.0)
    )
    store.put(old)
    with pytest.raises(PlanStoreError) as exc:
        store.put(
            InjectionPlan(
                **_plan_kwargs(
                    nonce="b" * 32,
                    args_digest="2" * 64,
                    expires_monotonic=360.0,
                )
            )
        )
    assert exc.value.code == "PLAN_KEY_REUSED"
    kept = store.lookup("sess-1", "tc-1")
    assert kept is not None
    assert kept.nonce == "a" * 32
    assert kept.args_digest == "1" * 64
    assert kept.state is PlanState.ANALYZED


def test_r2_put_rejects_reuse_approval_pending_preserves_old():
    store = InjectionPlanStore(clock=lambda: 0.0)
    store.put(
        InjectionPlan(**_plan_kwargs(nonce="a" * 32, expires_monotonic=360.0))
    )
    store.mark_approval_pending("sess-1", "tc-1")
    with pytest.raises(PlanStoreError) as exc:
        store.put(
            InjectionPlan(**_plan_kwargs(nonce="b" * 32, expires_monotonic=360.0))
        )
    assert exc.value.code == "PLAN_KEY_REUSED"
    kept = store.lookup("sess-1", "tc-1")
    assert kept is not None
    assert kept.nonce == "a" * 32
    assert kept.state is PlanState.APPROVAL_PENDING


def test_r2_put_rejects_reuse_consumed_and_invalidated():
    store = InjectionPlanStore(clock=lambda: 0.0)
    store.put(
        InjectionPlan(**_plan_kwargs(nonce="a" * 32, expires_monotonic=360.0))
    )
    store.mark_approval_pending("sess-1", "tc-1")
    store.consume("sess-1", "tc-1")
    with pytest.raises(PlanStoreError) as exc:
        store.put(
            InjectionPlan(**_plan_kwargs(nonce="b" * 32, expires_monotonic=360.0))
        )
    assert exc.value.code == "PLAN_KEY_REUSED"
    kept = store.lookup("sess-1", "tc-1")
    assert kept is not None
    assert kept.nonce == "a" * 32
    assert kept.state is PlanState.CONSUMED

    store2 = InjectionPlanStore(clock=lambda: 0.0)
    store2.put(
        InjectionPlan(**_plan_kwargs(nonce="c" * 32, expires_monotonic=360.0))
    )
    store2.invalidate("sess-1", "tc-1")
    with pytest.raises(PlanStoreError) as exc2:
        store2.put(
            InjectionPlan(**_plan_kwargs(nonce="d" * 32, expires_monotonic=360.0))
        )
    assert exc2.value.code == "PLAN_KEY_REUSED"
    kept2 = store2.lookup("sess-1", "tc-1")
    assert kept2 is not None
    assert kept2.nonce == "c" * 32
    assert kept2.state is PlanState.INVALIDATED


def test_r2_create_analyzed_plan_reuse_raises_without_return_or_pollute():
    nonces = iter(["aa" * 16, "bb" * 16, "cc" * 16])
    store = InjectionPlanStore(
        clock=lambda: 0.0,
        nonce_source=lambda: next(nonces),
    )
    first = store.create_analyzed_plan(**_create_kwargs())
    assert first.nonce == "aa" * 16
    with pytest.raises(PlanStoreError) as exc:
        store.create_analyzed_plan(**_create_kwargs(args={"credential": "<CREDENTIAL:jenkins-token>", "target": "other"}))
    assert exc.value.code == "PLAN_KEY_REUSED"
    kept = store.lookup("sess-1", "tc-1")
    assert kept is not None
    assert kept.nonce == first.nonce
    assert kept.args_digest == first.args_digest
    assert kept.state is PlanState.ANALYZED


def test_r2_expired_lookup_tombstone_blocks_reuse_until_deadline():
    clock = {"t": 0.0}
    store = InjectionPlanStore(clock=lambda: clock["t"], ttl_seconds=10)
    plan = store.create_analyzed_plan(**_create_kwargs(ttl_seconds=10))
    assert plan.expires_monotonic == 10.0
    clock["t"] = 10.0
    looked = store.lookup("sess-1", "tc-1")
    assert looked is not None
    assert looked.state is PlanState.INVALIDATED
    assert looked.nonce == plan.nonce
    # Immediate cleanup must not free the key for reuse.
    assert store.cleanup() == 0
    with pytest.raises(PlanStoreError) as exc:
        store.create_analyzed_plan(**_create_kwargs(ttl_seconds=10))
    assert exc.value.code == "PLAN_KEY_REUSED"
    # Tombstone lasts through expires + execution review margin.
    deadline = plan.expires_monotonic + EXECUTION_REVIEW_MARGIN_SECONDS
    clock["t"] = deadline - 0.001
    assert store.cleanup() == 0
    with pytest.raises(PlanStoreError):
        store.create_analyzed_plan(**_create_kwargs(ttl_seconds=10))
    clock["t"] = deadline
    removed = store.cleanup()
    assert removed == 1
    assert store.lookup("sess-1", "tc-1") is None
    reused = store.create_analyzed_plan(**_create_kwargs(ttl_seconds=10))
    assert reused.nonce != plan.nonce


def test_r2_concurrent_same_key_put_exactly_one_wins():
    store = InjectionPlanStore(clock=lambda: 0.0)
    barrier = threading.Barrier(2)
    results: List[str] = []
    lock = threading.Lock()

    def worker(nonce: str) -> None:
        barrier.wait(timeout=5)
        try:
            store.put(
                InjectionPlan(
                    **_plan_kwargs(nonce=nonce, expires_monotonic=360.0)
                )
            )
            with lock:
                results.append("ok:" + nonce)
        except PlanStoreError as exc:
            with lock:
                results.append("err:" + exc.code)

    t1 = threading.Thread(target=worker, args=("1" * 32,))
    t2 = threading.Thread(target=worker, args=("2" * 32,))
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)
    oks = [r for r in results if r.startswith("ok:")]
    errs = [r for r in results if r.startswith("err:")]
    assert len(oks) == 1
    assert len(errs) == 1
    assert errs[0] == "err:PLAN_KEY_REUSED"
    kept = store.lookup("sess-1", "tc-1")
    assert kept is not None
    assert kept.nonce == oks[0].split(":", 1)[1]


def test_r2_capacity_counts_tombstones_fail_closed():
    clock = {"t": 0.0}
    store = InjectionPlanStore(clock=lambda: clock["t"], capacity=2)
    store.put(
        InjectionPlan(
            **_plan_kwargs(tool_call_id="tc-1", nonce="1" * 32, expires_monotonic=100.0)
        )
    )
    store.put(
        InjectionPlan(
            **_plan_kwargs(tool_call_id="tc-2", nonce="2" * 32, expires_monotonic=100.0)
        )
    )
    store.invalidate("sess-1", "tc-1")
    store.mark_approval_pending("sess-1", "tc-2")
    store.consume("sess-1", "tc-2")
    # Terminal tombstones still occupy capacity; cleanup before deadline frees nothing.
    assert store.cleanup() == 0
    with pytest.raises(PlanStoreError) as exc:
        store.put(
            InjectionPlan(
                **_plan_kwargs(tool_call_id="tc-3", nonce="3" * 32, expires_monotonic=100.0)
            )
        )
    assert exc.value.code == "STORE_FULL"
    assert store.snapshot()["size"] == 2


def test_r2_capacity_unique_key_tombstone_plus_new_succeeds():
    """One tombstone must not double-count; capacity=2 allows tombstone + new key."""
    clock = {"t": 0.0}
    store = InjectionPlanStore(clock=lambda: clock["t"], capacity=2)
    store.put(
        InjectionPlan(
            **_plan_kwargs(tool_call_id="tc-old", nonce="1" * 32, expires_monotonic=100.0)
        )
    )
    store.invalidate("sess-1", "tc-old")
    assert store.cleanup() == 0
    # Unique occupancy is 1; a distinct key must succeed under capacity=2.
    store.put(
        InjectionPlan(
            **_plan_kwargs(tool_call_id="tc-new", nonce="2" * 32, expires_monotonic=100.0)
        )
    )
    assert store.lookup("sess-1", "tc-new") is not None
    # Original key still blocked by tombstone.
    with pytest.raises(PlanStoreError) as exc:
        store.put(
            InjectionPlan(
                **_plan_kwargs(tool_call_id="tc-old", nonce="3" * 32, expires_monotonic=100.0)
            )
        )
    assert exc.value.code == "PLAN_KEY_REUSED"
    # After tombstone deadline, old key may be reused under existing rules.
    clock["t"] = 100.0 + EXECUTION_REVIEW_MARGIN_SECONDS
    assert store.cleanup() >= 1
    store.put(
        InjectionPlan(
            **_plan_kwargs(tool_call_id="tc-old", nonce="4" * 32, expires_monotonic=clock["t"] + 100.0)
        )
    )
    assert store.lookup("sess-1", "tc-old").nonce == "4" * 32


def test_r2_capacity_double_count_mutation_red():
    """Restoring len(plans)+len(tombstones) occupancy must RED the unique-key case."""
    clock = {"t": 0.0}
    store = InjectionPlanStore(clock=lambda: clock["t"], capacity=2)
    real_put = store.put

    def double_count_put(plan):
        key = (plan.session_id, plan.tool_call_id)
        with store._lock:
            store.cleanup()
            if key in store._plans or key in store._reuse_block_until:
                raise PlanStoreError("PLAN_KEY_REUSED")
            occupied = len(store._plans) + len(store._reuse_block_until)
            if occupied >= store._capacity:
                raise PlanStoreError("STORE_FULL")
            store._plans[key] = plan

    store.put(
        InjectionPlan(
            **_plan_kwargs(tool_call_id="tc-old", nonce="1" * 32, expires_monotonic=100.0)
        )
    )
    store.invalidate("sess-1", "tc-old")
    store.put = double_count_put  # type: ignore[method-assign]
    with pytest.raises(PlanStoreError) as exc:
        store.put(
            InjectionPlan(
                **_plan_kwargs(tool_call_id="tc-new", nonce="2" * 32, expires_monotonic=100.0)
            )
        )
    assert exc.value.code == "STORE_FULL"


def test_r2_reset_for_tests_clears_tombstones():
    store = InjectionPlanStore(clock=lambda: 0.0, capacity=2)
    store.put(InjectionPlan(**_plan_kwargs(expires_monotonic=360.0)))
    store.invalidate("sess-1", "tc-1")
    store.reset_for_tests()
    assert store.snapshot()["size"] == 0
    store.put(
        InjectionPlan(**_plan_kwargs(nonce="z" * 32, expires_monotonic=360.0))
    )
    assert store.lookup("sess-1", "tc-1").nonce == "z" * 32


def test_r2_different_tool_call_ids_still_independent():
    store = InjectionPlanStore(clock=lambda: 0.0)
    a = store.create_analyzed_plan(**_create_kwargs(tool_call_id="tc-a"))
    b = store.create_analyzed_plan(**_create_kwargs(tool_call_id="tc-b"))
    assert a.nonce != b.nonce
    store.mark_approval_pending("sess-1", "tc-a")
    store.mark_approval_pending("sess-1", "tc-b")
    assert store.lookup("sess-1", "tc-a").state is PlanState.APPROVAL_PENDING
    assert store.lookup("sess-1", "tc-b").state is PlanState.APPROVAL_PENDING
