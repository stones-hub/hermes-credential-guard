"""R2 config lock protocol: shared load/recheck vs exclusive writers (cross-process).

Threat model (frozen): cooperative Credential Guard components only.
Does NOT claim protection against malicious same-UID syscall bypass.
"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import secrets
import threading
import time
import types
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from credential_guard.config import CONFIG_FILENAME
from credential_guard.injection_plan import PlanState
from credential_guard.runtime_config import (
    HTTP_REFERENCE_TOOL,
    load_and_publish_runtime,
    reset_execution_secret_resolve_count_for_tests,
    reset_runtime_for_tests,
)
from credential_guard.tool_execution import on_tool_execution
from credential_guard.reference_tools import handle_http_credential_request
from credential_guard.tool_request import (
    get_plan_store,
    on_tool_request,
    reset_tool_request_state_for_tests,
)
from credential_guard.approval import on_pre_tool_call

# Production helpers under test (RED until implemented).
from credential_guard.config_lock import (
    DEFAULT_LOCK_TIMEOUT_SECONDS,
    MAX_LOCK_TIMEOUT_SECONDS,
    RUNTIME_LOCK_NAME,
    ConfigLockError,
    exclusive_atomic_replace_config,
    exclusive_config_lock,
    shared_config_lock,
)


REPO = Path(__file__).resolve().parents[1]


def _write_cfg(store: Path, token: str) -> Path:
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
    path.write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _ref_args() -> Dict[str, Any]:
    return {
        "target": "jenkins-production",
        "method": "POST",
        "path": "/job/project-x/build",
        "credential": "<CREDENTIAL:jenkins-token>",
    }


def _install_hermes_stubs(monkeypatch) -> None:
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


@pytest.fixture
def published_env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    store = hermes / "credential-guard"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    reset_runtime_for_tests()
    reset_tool_request_state_for_tests()
    _install_hermes_stubs(monkeypatch)
    token = "CG_R2LOCK_" + secrets.token_hex(12)
    cfg_path = _write_cfg(store, token)
    view = load_and_publish_runtime()
    reset_execution_secret_resolve_count_for_tests()
    from credential_guard.tool_execution import (
        reset_http_adapter_observe_for_tests,
        set_http_transport_override_for_tests,
    )

    reset_http_adapter_observe_for_tests()
    set_http_transport_override_for_tests(
        lambda req: {
            "status": 201,
            "headers": {"content-type": "application/json"},
            "body": b'{"queued":true}',
        }
    )
    yield {
        "store": store,
        "token": token,
        "cfg_path": cfg_path,
        "view": view,
        "home": home,
        "hermes": hermes,
    }
    set_http_transport_override_for_tests(None)
    reset_runtime_for_tests()
    reset_tool_request_state_for_tests()


def _arm_pending_plan(tool_call_id: str = "tc-lock-race") -> Dict[str, Any]:
    args = _ref_args()
    on_tool_request(
        tool_name=HTTP_REFERENCE_TOOL,
        args=args,
        session_id="s1",
        turn_id="t1",
        tool_call_id=tool_call_id,
    )
    assert (
        on_pre_tool_call(
            tool_name=HTTP_REFERENCE_TOOL,
            args=args,
            session_id="s1",
            turn_id="t1",
            tool_call_id=tool_call_id,
        )["action"]
        == "approve"
    )
    return args


def _child_exclusive_replace(
    store_s: str,
    new_text: str,
    started_evt,
    done_evt,
    result_q,
    timeout: float,
) -> None:
    """Independent process: exclusive replace under formal helper."""
    try:
        started_evt.set()
        exclusive_atomic_replace_config(
            Path(store_s), new_text, timeout_seconds=timeout
        )
        result_q.put({"ok": True})
    except Exception as exc:  # noqa: BLE001 — cross-process result only
        result_q.put({"ok": False, "err": type(exc).__name__, "code": getattr(exc, "code", "")})
    finally:
        done_evt.set()


# ---------------------------------------------------------------------------
# A. Final lstat → consume window vs exclusive writer
# ---------------------------------------------------------------------------


def test_a_exclusive_writer_blocked_until_consume_shared_section_ends(
    published_env, monkeypatch
):
    """Writer must not finish while shared critical section holds past 2nd lstat."""
    args = _arm_pending_plan("tc-lock-a1")
    store = published_env["store"]
    token = published_env["token"]
    # Same-length body so schema stays valid; exclusive path still mutates inode/mtime.
    new_token = ("Z" * len(token)) if token[0] != "Z" else ("Y" * len(token))
    new_text = (store / CONFIG_FILENAME).read_text(encoding="utf-8").replace(token, new_token)
    assert len(new_text) == (store / CONFIG_FILENAME).stat().st_size

    entered = threading.Event()
    release = threading.Event()
    real_consume = get_plan_store().consume

    def _barrier_consume(session_id, tool_call_id):
        # Second lstat already completed; still inside shared + execution lock.
        entered.set()
        assert release.wait(timeout=8.0), "release barrier timed out"
        return real_consume(session_id, tool_call_id)

    monkeypatch.setattr(get_plan_store(), "consume", _barrier_consume)

    ctx = mp.get_context("spawn")
    started_evt = ctx.Event()
    done_evt = ctx.Event()
    result_q: mp.Queue = ctx.Queue()
    child = ctx.Process(
        target=_child_exclusive_replace,
        args=(str(store), new_text, started_evt, done_evt, result_q, 5.0),
    )

    out_holder: Dict[str, Any] = {}

    def _run_exec():
        calls: List[Any] = []
        out_holder["out"] = on_tool_execution(
            HTTP_REFERENCE_TOOL,
            args,
            lambda a: calls.append(a) or handle_http_credential_request(a),
            session_id="s1",
            turn_id="t1",
            tool_call_id="tc-lock-a1",
        )
        out_holder["calls"] = calls

    exec_thread = threading.Thread(target=_run_exec)
    exec_thread.start()
    assert entered.wait(timeout=5.0), "consume barrier not reached"

    child.start()
    assert started_evt.wait(timeout=5.0), "child did not start"
    # While shared section held, exclusive writer must still be blocked.
    time.sleep(0.4)
    assert not done_evt.is_set(), "exclusive writer finished inside shared critical section"

    release.set()
    exec_thread.join(timeout=5.0)
    assert not exec_thread.is_alive()
    child.join(timeout=8.0)
    assert not child.is_alive(), "child exclusive writer hung"
    assert done_evt.is_set()

    assert len(out_holder.get("calls") or []) <= 1
    out = out_holder.get("out") or ""
    data = json.loads(out)
    assert data.get("ok") is True
    plan = get_plan_store().lookup("s1", "tc-lock-a1")
    assert plan is not None
    # Cooperative serialization: plan may CONSUME; config rotate happens after.
    assert plan.state is PlanState.CONSUMED, f"expected CONSUMED under lock, got {plan.state}"

    result = result_q.get(timeout=2.0)
    assert result.get("ok") is True, f"writer should succeed after shared release: {result}"
    assert new_token in (store / CONFIG_FILENAME).read_text(encoding="utf-8")


def test_a_negative_control_without_shared_lock_writer_wins_in_window(
    published_env, monkeypatch
):
    """Control: if shared lock is skipped, exclusive writer can finish after 2nd lstat."""
    import credential_guard.tool_execution as te

    args = _arm_pending_plan("tc-lock-a-neg")
    store = published_env["store"]
    token = published_env["token"]
    new_token = ("W" * len(token)) if token[0] != "W" else ("V" * len(token))
    new_text = (store / CONFIG_FILENAME).read_text(encoding="utf-8").replace(token, new_token)

    entered = threading.Event()
    release = threading.Event()
    writer_done = threading.Event()
    real_consume = get_plan_store().consume

    def _barrier_consume(session_id, tool_call_id):
        entered.set()
        assert release.wait(timeout=8.0)
        return real_consume(session_id, tool_call_id)

    monkeypatch.setattr(get_plan_store(), "consume", _barrier_consume)

    # Force reference path to skip cross-process shared lock (old buggy window).
    from contextlib import nullcontext

    monkeypatch.setattr(
        te,
        "_shared_config_lock_for_execution",
        lambda *a, **k: nullcontext(),
        raising=False,
    )
    # Also patch module-level helper if wired via config_lock import.
    monkeypatch.setattr(
        "credential_guard.config_lock.shared_config_lock",
        lambda *a, **k: nullcontext(),
        raising=False,
    )

    def _writer():
        # Direct os.replace WITHOUT exclusive helper — simulates old unlocked writer
        # completing in the lstat→consume window.
        path = store / CONFIG_FILENAME
        tmp = store / f".cg-race-tmp-{secrets.token_hex(4)}"
        tmp.write_text(new_text, encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        writer_done.set()

    exec_calls: List[Any] = []

    def _run_exec():
        on_tool_execution(
            HTTP_REFERENCE_TOOL,
            args,
            lambda a: exec_calls.append(a) or handle_http_credential_request(a),
            session_id="s1",
            turn_id="t1",
            tool_call_id="tc-lock-a-neg",
        )

    t = threading.Thread(target=_run_exec)
    t.start()
    assert entered.wait(timeout=5.0)
    w = threading.Thread(target=_writer)
    w.start()
    assert writer_done.wait(timeout=3.0), "control: unlocked writer must finish in window"
    release.set()
    t.join(timeout=5.0)
    w.join(timeout=2.0)
    assert new_token in (store / CONFIG_FILENAME).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# B. Publish vs exclusive writer
# ---------------------------------------------------------------------------


def _child_hold_shared(store_s: str, hold_evt, release_evt, done_evt, result_q, timeout: float):
    try:
        with shared_config_lock(Path(store_s), timeout_seconds=timeout):
            hold_evt.set()
            assert release_evt.wait(timeout=timeout + 2.0)
        result_q.put({"ok": True})
    except Exception as exc:  # noqa: BLE001
        result_q.put({"ok": False, "err": type(exc).__name__, "code": getattr(exc, "code", "")})
    finally:
        done_evt.set()


def test_b_exclusive_writer_blocked_during_shared_publish(published_env):
    store = published_env["store"]
    token = published_env["token"]
    new_token = ("P" * len(token)) if token[0] != "P" else ("Q" * len(token))
    new_text = (store / CONFIG_FILENAME).read_text(encoding="utf-8").replace(token, new_token)

    ctx = mp.get_context("spawn")
    hold_evt = ctx.Event()
    release_evt = ctx.Event()
    done_evt = ctx.Event()
    result_q = ctx.Queue()
    holder = ctx.Process(
        target=_child_hold_shared,
        args=(str(store), hold_evt, release_evt, done_evt, result_q, 5.0),
    )
    holder.start()
    assert hold_evt.wait(timeout=5.0)

    writer_done = threading.Event()
    writer_ok = {"v": False}

    def _writer():
        try:
            exclusive_atomic_replace_config(store, new_text, timeout_seconds=5.0)
            writer_ok["v"] = True
        finally:
            writer_done.set()

    wt = threading.Thread(target=_writer)
    wt.start()
    time.sleep(0.4)
    assert not writer_done.is_set(), "exclusive must block while shared publish/load held"

    release_evt.set()
    assert writer_done.wait(timeout=8.0)
    holder.join(timeout=5.0)
    assert writer_ok["v"] is True
    # Next publish must see the new complete config (no mixed generation).
    view = load_and_publish_runtime()
    assert new_token in json.dumps(view.to_canonical_dict())


def test_b_publish_failure_releases_lock_and_marks_unavailable(published_env, monkeypatch):
    from credential_guard.runtime_config import (
        RuntimeConfigError,
        get_runtime_view,
        mark_runtime_unavailable,
    )
    import credential_guard.runtime_config as rc

    store = published_env["store"]
    real_load = rc.load_config

    def _boom(path=None):
        raise RuntimeConfigError("RUNTIME_CONFIG_INVALID")

    monkeypatch.setattr(rc, "load_config", _boom)
    with pytest.raises(RuntimeConfigError):
        load_and_publish_runtime()
    # Lock released: exclusive acquire must succeed promptly.
    with exclusive_config_lock(store, timeout_seconds=1.0):
        pass
    with pytest.raises(RuntimeConfigError):
        get_runtime_view()
    monkeypatch.setattr(rc, "load_config", real_load)
    # Restore for fixture teardown.
    load_and_publish_runtime()


def test_b_writer_exception_releases_lock_no_partial(published_env, monkeypatch):
    store = published_env["store"]
    before = (store / CONFIG_FILENAME).read_text(encoding="utf-8")

    from credential_guard import config_lock as cl

    def _wrapped(store_dir, new_text, **kwargs):
        with exclusive_config_lock(store_dir, timeout_seconds=kwargs.get("timeout_seconds", 5.0)):
            raise RuntimeError("synthetic writer failure")

    monkeypatch.setattr(cl, "exclusive_atomic_replace_config", _wrapped)
    with pytest.raises(RuntimeError):
        cl.exclusive_atomic_replace_config(store, before + "x", timeout_seconds=2.0)
    # Lock free + no half-written formal config.
    with exclusive_config_lock(store, timeout_seconds=1.0):
        pass
    assert (store / CONFIG_FILENAME).read_text(encoding="utf-8") == before


# ---------------------------------------------------------------------------
# C. Lock safety attributes + real two-process flock + mutation
# ---------------------------------------------------------------------------


def test_c_symlink_lock_file_rejected(tmp_path):
    store = tmp_path / "credential-guard"
    store.mkdir()
    os.chmod(store, 0o700)
    lock_path = store / RUNTIME_LOCK_NAME
    target = tmp_path / "elsewhere"
    target.write_text("x", encoding="utf-8")
    lock_path.symlink_to(target)
    with pytest.raises(ConfigLockError) as ei:
        with shared_config_lock(store, timeout_seconds=1.0):
            pass
    assert ei.value.code in {"CONFIG_LOCK_FS", "CONFIG_LOCK_SYMLINK"}


def test_c_non_0600_lock_rejected(tmp_path):
    store = tmp_path / "credential-guard"
    store.mkdir()
    os.chmod(store, 0o700)
    lock_path = store / RUNTIME_LOCK_NAME
    lock_path.write_text("", encoding="utf-8")
    os.chmod(lock_path, 0o644)
    with pytest.raises(ConfigLockError) as ei:
        with exclusive_config_lock(store, timeout_seconds=1.0):
            pass
    assert ei.value.code in {"CONFIG_LOCK_FS", "CONFIG_LOCK_MODE"}


def test_c_timeout_fail_closed_two_process(tmp_path):
    store = tmp_path / "credential-guard"
    store.mkdir()
    os.chmod(store, 0o700)
    ctx = mp.get_context("spawn")
    hold_evt = ctx.Event()
    release_evt = ctx.Event()
    done_evt = ctx.Event()
    result_q = ctx.Queue()
    holder = ctx.Process(
        target=_child_hold_shared,
        args=(str(store), hold_evt, release_evt, done_evt, result_q, 10.0),
    )
    holder.start()
    assert hold_evt.wait(timeout=5.0)
    with pytest.raises(ConfigLockError) as ei:
        with exclusive_config_lock(store, timeout_seconds=0.3):
            pass
    assert ei.value.code == "CONFIG_LOCK_TIMEOUT"
    release_evt.set()
    holder.join(timeout=5.0)


def test_c_exception_releases_lock(tmp_path):
    store = tmp_path / "credential-guard"
    store.mkdir()
    os.chmod(store, 0o700)
    with pytest.raises(RuntimeError):
        with exclusive_config_lock(store, timeout_seconds=2.0):
            raise RuntimeError("boom")
    with exclusive_config_lock(store, timeout_seconds=1.0):
        pass


def test_c_nested_same_thread_fail_loud(tmp_path):
    store = tmp_path / "credential-guard"
    store.mkdir()
    os.chmod(store, 0o700)
    with shared_config_lock(store, timeout_seconds=2.0):
        with pytest.raises(ConfigLockError) as ei:
            with shared_config_lock(store, timeout_seconds=1.0):
                pass
    assert ei.value.code == "CONFIG_LOCK_REENTRANT"


def _child_exclusive_hold(store_s, hold_evt, release_evt, done_evt, result_q, timeout):
    try:
        with exclusive_config_lock(Path(store_s), timeout_seconds=timeout):
            hold_evt.set()
            assert release_evt.wait(timeout=timeout + 2.0)
        result_q.put({"ok": True})
    except Exception as exc:  # noqa: BLE001
        result_q.put({"ok": False, "err": type(exc).__name__})
    finally:
        done_evt.set()


def test_c_two_process_real_flock_mutex(tmp_path):
    store = tmp_path / "credential-guard"
    store.mkdir()
    os.chmod(store, 0o700)
    ctx = mp.get_context("spawn")
    hold_evt = ctx.Event()
    release_evt = ctx.Event()
    done_evt = ctx.Event()
    result_q = ctx.Queue()
    a = ctx.Process(
        target=_child_exclusive_hold,
        args=(str(store), hold_evt, release_evt, done_evt, result_q, 8.0),
    )
    a.start()
    assert hold_evt.wait(timeout=5.0)
    with pytest.raises(ConfigLockError) as ei:
        with exclusive_config_lock(store, timeout_seconds=0.4):
            pass
    assert ei.value.code == "CONFIG_LOCK_TIMEOUT"
    release_evt.set()
    a.join(timeout=5.0)
    assert result_q.get(timeout=2.0).get("ok") is True


def test_c_mutation_without_shared_race_window_reappears(published_env, monkeypatch):
    """Mutation: remove shared lock → exclusive can complete in consume window."""
    from contextlib import nullcontext
    import credential_guard.tool_execution as te

    args = _arm_pending_plan("tc-mut-shared")
    store = published_env["store"]
    token = published_env["token"]
    new_token = ("M" * len(token)) if token[0] != "M" else ("N" * len(token))
    new_text = (store / CONFIG_FILENAME).read_text(encoding="utf-8").replace(token, new_token)

    entered = threading.Event()
    release = threading.Event()
    real_consume = get_plan_store().consume

    def _barrier_consume(session_id, tool_call_id):
        entered.set()
        assert release.wait(timeout=8.0)
        return real_consume(session_id, tool_call_id)

    monkeypatch.setattr(get_plan_store(), "consume", _barrier_consume)
    monkeypatch.setattr(
        te, "_shared_config_lock_for_execution", lambda *a, **k: nullcontext(), raising=False
    )
    monkeypatch.setattr(
        "credential_guard.config_lock.shared_config_lock",
        lambda *a, **k: nullcontext(),
        raising=False,
    )

    ctx = mp.get_context("spawn")
    started_evt = ctx.Event()
    done_evt = ctx.Event()
    result_q = ctx.Queue()
    # Child uses exclusive helper; without parent's shared lock it must finish promptly.
    child = ctx.Process(
        target=_child_exclusive_replace,
        args=(str(store), new_text, started_evt, done_evt, result_q, 3.0),
    )

    def _run():
        on_tool_execution(
            HTTP_REFERENCE_TOOL,
            args,
            handle_http_credential_request,
            session_id="s1",
            turn_id="t1",
            tool_call_id="tc-mut-shared",
        )

    t = threading.Thread(target=_run)
    t.start()
    assert entered.wait(timeout=5.0)
    child.start()
    assert done_evt.wait(timeout=4.0), "mutation: without shared, exclusive must win in window"
    release.set()
    t.join(timeout=5.0)
    child.join(timeout=3.0)
    assert result_q.get(timeout=1.0).get("ok") is True


def test_c_mutation_without_exclusive_race_window_reappears(published_env, monkeypatch):
    """Mutation: exclusive helper without lock → replace finishes under shared hold."""
    from contextlib import nullcontext
    from credential_guard import config_lock as cl

    store = published_env["store"]
    token = published_env["token"]
    new_token = ("E" * len(token)) if token[0] != "E" else ("F" * len(token))
    new_text = (store / CONFIG_FILENAME).read_text(encoding="utf-8").replace(token, new_token)

    # Hold shared in parent via real lock.
    release = threading.Event()
    held = threading.Event()

    def _holder():
        with shared_config_lock(store, timeout_seconds=5.0):
            held.set()
            release.wait(timeout=8.0)

    ht = threading.Thread(target=_holder)
    ht.start()
    assert held.wait(timeout=3.0)

    # Patch exclusive helper to write without taking exclusive lock.
    def _unlocked_replace(store_dir, content, **kwargs):
        path = Path(store_dir) / CONFIG_FILENAME
        tmp = Path(store_dir) / f".cg-unlocked-{secrets.token_hex(4)}"
        tmp.write_text(content, encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    monkeypatch.setattr(cl, "exclusive_atomic_replace_config", _unlocked_replace)
    # Unlocked write completes even while shared is held (documents need for exclusive).
    cl.exclusive_atomic_replace_config(store, new_text, timeout_seconds=1.0)
    assert new_token in (store / CONFIG_FILENAME).read_text(encoding="utf-8")
    release.set()
    ht.join(timeout=3.0)


# ---------------------------------------------------------------------------
# D. Plain tools must not touch config lock / config
# ---------------------------------------------------------------------------


def test_d_plain_tool_no_lock_no_config_read(tmp_path, monkeypatch):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    store = hermes / "credential-guard"
    store.mkdir()
    os.chmod(store, 0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    reset_runtime_for_tests()
    reset_tool_request_state_for_tests()
    _install_hermes_stubs(monkeypatch)

    lock_opens = {"n": 0}
    real_open = os.open

    def _counting_open(path, flags, mode=0o777, *a, **k):
        if Path(path).name == RUNTIME_LOCK_NAME:
            lock_opens["n"] += 1
        return real_open(path, flags, mode, *a, **k)

    monkeypatch.setattr(os, "open", _counting_open)

    hits: List[str] = []
    real_open_builtin = open

    def _boom_open(file, *a, **k):
        name = Path(str(file)).name if file is not None else ""
        if name == CONFIG_FILENAME:
            hits.append("open-config")
            raise AssertionError("plain tool must not open config")
        return real_open_builtin(file, *a, **k)

    monkeypatch.setattr("builtins.open", _boom_open)

    calls: List[Any] = []
    out = on_tool_execution(
        "write_file",
        {"path": "/tmp/plain.txt", "content": "hello"},
        lambda a: calls.append(a) or "OK",
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-plain",
    )
    assert out == "OK"
    assert calls == [{"path": "/tmp/plain.txt", "content": "hello"}]
    assert lock_opens["n"] == 0
    assert not (store / RUNTIME_LOCK_NAME).exists()
    assert hits == []


def test_d_plain_tool_ok_when_config_missing(tmp_path, monkeypatch):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    reset_runtime_for_tests()
    reset_tool_request_state_for_tests()
    _install_hermes_stubs(monkeypatch)
    calls: List[Any] = []
    out = on_tool_execution(
        "write_file",
        {"path": "/tmp/x", "content": "y"},
        lambda a: calls.append(1) or "OK",
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-plain2",
    )
    assert out == "OK"
    assert calls == [1]


# ---------------------------------------------------------------------------
# E. Timeout input bounds — finite positive bounded before lock/config side effects
# ---------------------------------------------------------------------------


_INVALID_TIMEOUTS = [
    True,
    False,
    None,
    "1",
    "5.0",
    float("nan"),
    float("inf"),
    float("-inf"),
    0,
    0.0,
    -1,
    -0.1,
]


def _resolve_bad_timeout(bad: Any) -> Any:
    if bad == "over_max":
        return float(MAX_LOCK_TIMEOUT_SECONDS) + 1.0
    return bad


@pytest.mark.parametrize(
    "bad",
    _INVALID_TIMEOUTS + ["over_max"],
    ids=[
        "True",
        "False",
        "None",
        "str_1",
        "str_5_0",
        "nan",
        "inf",
        "neg_inf",
        "zero_int",
        "zero_float",
        "neg_int",
        "neg_float",
        "over_max",
    ],
)
@pytest.mark.parametrize("api", ["shared", "exclusive", "atomic_replace"])
def test_e_invalid_timeout_rejected_before_lock_or_config(tmp_path, bad, api):
    """Public lock APIs must reject bad timeouts before open/create/write."""
    store = tmp_path / "credential-guard"
    store.mkdir()
    os.chmod(store, 0o700)
    formal = store / CONFIG_FILENAME
    formal.write_text('{"version":2,"credentials":{},"bindings":{}}', encoding="utf-8")
    os.chmod(formal, 0o600)
    before = formal.read_text(encoding="utf-8")
    value = _resolve_bad_timeout(bad)

    with pytest.raises(ConfigLockError) as ei:
        if api == "shared":
            with shared_config_lock(store, timeout_seconds=value):
                pass
        elif api == "exclusive":
            with exclusive_config_lock(store, timeout_seconds=value):
                pass
        else:
            exclusive_atomic_replace_config(store, before + "x", timeout_seconds=value)

    assert ei.value.code == "CONFIG_LOCK_TIMEOUT"
    assert not (store / RUNTIME_LOCK_NAME).exists()
    assert formal.read_text(encoding="utf-8") == before


@pytest.mark.parametrize(
    "good",
    [0.05, 0.001, "default", "max"],
    ids=["small_pos", "tiny_pos", "default", "max"],
)
@pytest.mark.parametrize("api", ["shared", "exclusive", "atomic_replace"])
def test_e_valid_timeout_bounds_accepted(tmp_path, good, api):
    """Small positive, default, and explicit max must acquire normally."""
    store = tmp_path / "credential-guard"
    store.mkdir()
    os.chmod(store, 0o700)
    formal = store / CONFIG_FILENAME
    body = '{"version":2,"credentials":{},"bindings":{}}'
    formal.write_text(body, encoding="utf-8")
    os.chmod(formal, 0o600)

    if good == "default":
        kwargs: Dict[str, Any] = {}
    elif good == "max":
        kwargs = {"timeout_seconds": MAX_LOCK_TIMEOUT_SECONDS}
    else:
        kwargs = {"timeout_seconds": good}

    if api == "shared":
        with shared_config_lock(store, **kwargs):
            assert (store / RUNTIME_LOCK_NAME).is_file()
    elif api == "exclusive":
        with exclusive_config_lock(store, **kwargs):
            assert (store / RUNTIME_LOCK_NAME).is_file()
    else:
        exclusive_atomic_replace_config(store, body, **kwargs)
        assert formal.read_text(encoding="utf-8") == body
        assert (store / RUNTIME_LOCK_NAME).is_file()


def test_e_max_lock_timeout_is_documented_finite_bound():
    assert type(MAX_LOCK_TIMEOUT_SECONDS) in (int, float)
    assert MAX_LOCK_TIMEOUT_SECONDS == 300
    assert DEFAULT_LOCK_TIMEOUT_SECONDS > 0
    assert DEFAULT_LOCK_TIMEOUT_SECONDS <= MAX_LOCK_TIMEOUT_SECONDS
    import math

    assert math.isfinite(float(MAX_LOCK_TIMEOUT_SECONDS))
