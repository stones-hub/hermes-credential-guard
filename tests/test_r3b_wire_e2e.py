"""R3B Blocker D: public AIAgent + loopback provider wire E2E (env/stdin approve+deny)."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
WIRE_SCRIPT = REPO / "scripts" / "run_r3b_wire_e2e.py"
HERMES_SPIKE_PYTHON = Path(
    os.environ.get(
        "HERMES_SPIKE_PYTHON",
        "/tmp/credential-guard-r2-hermes-venv/bin/python",
    )
)


@pytest.fixture(scope="module")
def wire_results():
    """Run the wire harness once; assert structural contract in dedicated tests."""
    assert WIRE_SCRIPT.is_file()
    import importlib.util

    spec = importlib.util.spec_from_file_location("run_r3b_wire_e2e", WIRE_SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    work = Path(tempfile.mkdtemp(prefix="r3b-wire-test-"))
    try:
        results = mod.run_all(work)
        yield results
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_r3b_wire_env_approve_zero_secret(wire_results):
    r = wire_results["env_approve"]
    assert r["marker_ok"] is True
    assert r["process_start_delta"] == 1
    assert r["injection_resolve_delta"] == 1
    assert r["provider_raw_request_count"] >= 2
    assert r["provider_logical_turns"] >= 2
    assert r["approval_raw_count"] >= 1
    assert r["approval_raw_has_reason"] is True
    assert r["wire_secret_count"] == 0
    assert r["token_in_provider_raw"] == 0
    assert r["token_in_approval_raw"] == 0
    assert r["token_in_result"] == 0
    assert r["used_environ_copy"] is False
    assert r["loopback_only"] is True
    assert r["raw_http_has_request_line"] >= 1
    assert r["raw_http_has_headers"] >= 1
    assert r["raw_http_has_body"] >= 1
    assert r["net_attempts"] > 0
    assert r["non_loopback_original_calls"] == 0
    assert r["net_violations"] == 0


def test_r3b_wire_stdin_approve_zero_secret(wire_results):
    r = wire_results["stdin_approve"]
    assert r["marker_ok"] is True
    assert r["process_start_delta"] == 1
    assert r["injection_resolve_delta"] == 1
    assert r["provider_logical_turns"] >= 2
    assert r["approval_raw_count"] >= 1
    assert r["wire_secret_count"] == 0
    assert r["used_environ_copy"] is False
    assert r["raw_http_has_request_line"] >= 1
    assert r["raw_http_has_body"] >= 1


def test_r3b_wire_env_deny_zero_start(wire_results):
    r = wire_results["env_deny"]
    assert r["process_start_delta"] == 0
    assert r["injection_resolve_delta"] == 0
    assert r["wire_secret_count"] == 0
    assert r["approval_raw_count"] >= 1


def test_r3b_wire_stdin_deny_zero_start(wire_results):
    r = wire_results["stdin_deny"]
    assert r["process_start_delta"] == 0
    assert r["injection_resolve_delta"] == 0
    assert r["wire_secret_count"] == 0


def test_r3b_wire_test_net_blocked_before_original(wire_results):
    r = wire_results["net_probe"]
    assert r["test_net_blocked_before_original"] is True
    assert r["net_violations"] >= 1
    assert r["non_loopback_original_calls"] == 0
    assert "test_net" in r.get("blocked_categories", [])
    assert r.get("guard_enabled", True) is True
    assert r["loopback_only"] is True


def test_r3b_wire_script_cli_entrypoint():
    """Public script entry — exit 0 when env+stdin approve/deny contracts hold."""
    proc = subprocess.run(
        [str(HERMES_SPIKE_PYTHON), str(WIRE_SCRIPT)],
        cwd=str(REPO),
        env={
            "PATH": os.environ.get("PATH") or "/usr/bin:/bin",
            "LANG": "C",
            "HOME": tempfile.mkdtemp(prefix="r3b-wire-cli-home-"),
            "TMPDIR": tempfile.mkdtemp(prefix="r3b-wire-cli-tmp-"),
            "HERMES_AGENT_ROOT": os.environ.get(
                "HERMES_AGENT_ROOT", "/tmp/credential-guard-r2-hermes-source"
            ),
            "HERMES_SPIKE_PYTHON": str(HERMES_SPIKE_PYTHON),
            "PYTHONPATH": str(REPO),
        },
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-3000:] + proc.stdout[-2000:]
    assert "wire_secret_count" in WIRE_SCRIPT.read_text(encoding="utf-8")


def test_r3b_wire_mutation_guard_disabled_hits_bomb_runtime():
    """Runtime mutation: same net_probe helper with guard_enabled=False must hit bomb.

    Policy guard bypassed → TEST-NET reaches independent original bomb/spy,
    non_loopback_original_calls > 0, loopback_only False — without real syscall.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("run_r3b_wire_e2e", WIRE_SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    work = Path(tempfile.mkdtemp(prefix="r3b-wire-mut-guard-"))
    try:
        healthy = mod.run_net_probe(work, guard_enabled=True)
        assert healthy["non_loopback_original_calls"] == 0
        assert healthy["net_violations"] >= 1
        assert healthy["loopback_only"] is True
        assert healthy["test_net_blocked_before_original"] is True

        mutated = mod.run_net_probe(work, guard_enabled=False)
        # RED contract under guard-disabled mutation (same runtime path):
        assert mutated["guard_enabled"] is False
        assert mutated["non_loopback_original_calls"] > 0
        assert mutated["loopback_only"] is False
        assert mutated["test_net_blocked_before_original"] is False
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_r3b_wire_mutation_remove_net_guard_is_red():
    """Source mutation: delete guard install assignments → install gate must RED."""
    src = WIRE_SCRIPT.read_text(encoding="utf-8")
    mutated = src
    for old, new in (
        ("socket.socket.connect = _guard_connect", "pass  # mutated-drop-guard-connect"),
        ("socket.socket.connect_ex = _guard_connect_ex", "pass  # mutated-drop-guard-connect_ex"),
        (
            "socket.create_connection = _guard_create_connection",
            "pass  # mutated-drop-guard-create",
        ),
    ):
        mutated = mutated.replace(old, new)
    assert "socket.socket.connect = _guard_connect" not in mutated
    install_hits = len(
        re.findall(
            r"socket\.(?:socket\.connect|create_connection)\s*=\s*_guard_", mutated
        )
    )
    healthy_guarded = install_hits >= 2 and "203.0.113.1" in mutated
    assert healthy_guarded is False
    # Bomb layer must still be present in source (independent of policy guard).
    assert "_bomb_connect" in src
    assert "non_loopback_original_calls" in src
    # Forbid the Round5 tautology as a live predicate (comment mentions OK).
    live_lines = [
        ln
        for ln in src.splitlines()
        if not ln.lstrip().startswith("#")
    ]
    assert not any(
        re.search(r"\[['\"]violations['\"]\]\s*>=\s*0", ln) for ln in live_lines
    )


def test_r3b_wire_raw_http_mechanical_shape_required():
    """Source must mechanically assert request-line/header/body presence — not body-only."""
    src = WIRE_SCRIPT.read_text(encoding="utf-8")
    assert "raw_http_has_request_line" in src
    assert "raw_http_has_headers" in src
    assert "raw_http_has_body" in src
    assert 'b"POST "' in src or "startswith(b\"POST \")" in src
    assert "header_blob" in src
    assert "raw_requests.append(body)" not in src
