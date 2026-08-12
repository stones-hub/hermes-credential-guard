"""R2E: isolated Credential Guard reference E2E (no real ~/.hermes)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RUNNER = REPO / "scripts" / "run_r2_e2e.py"
HERMES_AGENT_ROOT = Path(
    os.environ.get("HERMES_AGENT_ROOT", "/tmp/credential-guard-r2-hermes-source")
)
HERMES_SPIKE_PYTHON = Path(
    os.environ.get(
        "HERMES_SPIKE_PYTHON",
        "/tmp/credential-guard-r2-hermes-venv/bin/python",
    )
)


def _env(home: Path, hermes_home: Path) -> dict:
    return {
        "HOME": str(home),
        "HERMES_HOME": str(hermes_home),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C",
        "LC_ALL": "C",
        "TMPDIR": str(home / "tmp"),
        "NO_PROXY": "*",
        "no_proxy": "*",
        "HERMES_AGENT_ROOT": str(HERMES_AGENT_ROOT),
        "PYTHONPATH": os.pathsep.join([str(HERMES_AGENT_ROOT), str(REPO)]),
        "OPENAI_API_KEY": "",
        "ANTHROPIC_API_KEY": "",
        "HERMES_API_KEY": "",
        "HERMES_YOLO_MODE": "",
    }


def _run(scenario: str, tmp_path: Path, **extra: str) -> dict:
    assert RUNNER.is_file()
    assert HERMES_SPIKE_PYTHON.is_file()
    home = tmp_path / f"home-{scenario}"
    hermes = tmp_path / f"hermes-{scenario}"
    home.mkdir()
    hermes.mkdir()
    (home / "tmp").mkdir()
    env = _env(home, hermes)
    env.update(extra)
    proc = subprocess.run(
        [str(HERMES_SPIKE_PYTHON), str(RUNNER), "--scenario", scenario],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout[-1500:] + "\n" + proc.stderr[-1500:]
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    data = json.loads(lines[-1])
    assert "decoy_plain" not in data
    assert data.get("canary_in_evidence", 0) == 0
    return data


def test_e2e_deny_no_execution(tmp_path):
    data = _run("deny", tmp_path)
    assert data["secret_resolve_delta_during_r2"] == 0
    assert data["r2_critical_body_read_hits"] == []
    assert data["downstream_call_count"] == 0
    assert data["tool_execution_entered"] is False
    assert data["approval_denied"] is True
    assert data["handler_call_count"] == 0
    assert data["registry_dispatch"] is False


def test_e2e_approve_adapter_not_ready(tmp_path):
    data = _run("approve", tmp_path)
    assert data["tool_execution_entered"] is True
    assert data["adapter_ok"] is True
    assert data["adapter_not_ready"] is False
    assert data["secret_resolve_delta_during_r2"] == 0
    assert data["injection_resolve_delta"] == 1
    assert data["adapter_invoke_delta"] == 1
    assert data["r2_critical_body_read_hits"] == []
    assert data["lstat_count"] >= 1
    assert data["downstream_call_count"] == 0  # no second network hop / R3B
    assert data["next_call_count"] == 1
    assert data["handler_call_count"] == 1
    assert data["approval_gate_count"] == 1
    assert data["plan_state"] == "consumed"
    assert data["canary_in_result"] == 0
    assert data["r3_injection_implemented"] is True
    assert data["r1b_publish_before_r2"] is True
    assert data["formal_tool_registered"] is True
    assert data["handler_identity_ok"] is True
    assert data["registry_dispatch"] is True
    assert data["evidence_tier"] == "compatibility_registry_dispatcher"
    assert data["approval_shows_method_path"] is True
    assert "POST /job/project-x/build" in (data.get("approval_message") or "")
    # transform_tool_result stays registered; R1B may re-publish after handler.
    assert "transform_tool_result" in data["call_order"]


def test_e2e_main_agent_framework_path(tmp_path):
    """Framework E2E: real tool_executor main-agent order (not backup dispatcher)."""
    from tests.test_r2_main_agent_path import _run as _main_run

    data = _main_run("approve", tmp_path)
    assert data["order"] == [
        "tool_request",
        "tool_execution",
        "pre_tool_call",
        "approval_gate",
        "handler",
        "consume",
        "resolve",
        "adapter",
    ]
    assert data["counts"]["handler"] == 1
    assert data["adapter_ok"] is True
    assert data["plan_state"] == "consumed"
    assert data["formal_tool_registered"] is True
    assert data["injection_resolve_delta"] == 1
    assert data["adapter_invoke_delta"] == 1


def test_e2e_mutation_hardcoded_formal_tool_must_fail():
    text = RUNNER.read_text(encoding="utf-8")
    assert 'evidence["formal_tool_registered"] = True' not in text
    assert 'evidence["registry_dispatch"] = True' not in text
    assert "code_labels" in text and "setprofile" in text
    assert "compatibility_registry_dispatcher" in text
    assert "handle_http_credential_request" in text
    assert 'mgr._hooks["transform_tool_result"] = []' not in text
    assert "def wrap_tool_request" not in text
    assert "def wrap_exec" not in text
    assert "counted_handler" not in text


def test_e2e_config_change_after_approve(tmp_path):
    data = _run("config_after_approve", tmp_path)
    assert data["downstream_call_count"] == 0
    assert data["secret_resolve_delta_during_r2"] == 0
    assert data["r2_critical_body_read_hits"] == []
    assert data["lstat_count"] >= 1
    assert data["canary_in_result"] == 0
    assert data["plan_state"] in {"invalidated", None} or data["adapter_not_ready"]


def test_e2e_param_change_after_approve(tmp_path):
    data = _run("mutate_after_approve", tmp_path)
    assert data["downstream_call_count"] == 0
    assert data["secret_resolve_delta_during_r2"] == 0
    assert data["r2_critical_body_read_hits"] == []


def test_e2e_replay_blocked(tmp_path):
    data = _run("replay", tmp_path)
    assert data.get("replay_blocked") is True
    assert data["downstream_call_count"] == 0
    assert data["secret_resolve_delta_during_r2"] == 0
    assert data["r2_critical_body_read_hits"] == []


def test_e2e_non_manual_blocks(tmp_path):
    for scenario in ("smart", "off", "yolo"):
        data = _run(scenario, tmp_path)
        assert data["downstream_call_count"] == 0
        assert data["secret_resolve_delta_during_r2"] == 0
        assert data["r2_critical_body_read_hits"] == []
        assert data["tool_execution_entered"] is False or data["approval_denied"]


def test_e2e_plain_tool_reaches_downstream(tmp_path):
    data = _run("plain", tmp_path)
    assert data["downstream_call_count"] == 1
    assert data["secret_resolve_delta_during_r2"] == 0
    assert data["r2_critical_body_read_hits"] == []
    assert data["handler_identity_ok"] == "not_applicable"
    assert data["registry_dispatch"] == "not_applicable"


def test_e2e_no_dual_file_runtime(tmp_path):
    data = _run("approve", tmp_path)
    assert data["credentials_json_present"] is False
    assert data["targets_json_present"] is False
    assert data["dual_file_fallback"] is False


def test_e2e_distinguishes_surfaces(tmp_path):
    data = _run("approve", tmp_path)
    assert data["fake_provider"] is False
    assert data.get("provider_wire_included") is False
    assert data.get("provider_wire_deferred_to") == "R1B"
    assert data["worker_fingerprint_skipped"] is True
    assert data["r3_injection_implemented"] is True


def test_e2e_secret_resolve_count_is_live_not_hardcoded(tmp_path, monkeypatch):
    """Mutation: if a resolve seam fires, evidence must not still claim 0 via constant."""
    # Patch the runner module path used inside the subprocess... not available.
    # Instead verify the runner source no longer assigns a literal 0 at the end,
    # and that a local in-process measurement catches a forced resolve.
    text = RUNNER.read_text(encoding="utf-8")
    assert 'evidence["secret_resolve_count"] = 0' not in text
    assert "get_execution_secret_resolve_count" in text
    assert "load_and_publish_runtime" in text
    assert "secret_resolve_delta_during_r2" in text

    from credential_guard.runtime_config import (
        get_execution_secret_resolve_count,
        note_execution_secret_resolve,
        reset_execution_secret_resolve_count_for_tests,
    )

    reset_execution_secret_resolve_count_for_tests()
    assert get_execution_secret_resolve_count() == 0
    note_execution_secret_resolve()
    assert get_execution_secret_resolve_count() == 1
    reset_execution_secret_resolve_count_for_tests()
