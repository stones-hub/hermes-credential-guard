"""R2A/A0: Hermes approval posture interfaces via sanitized checkout.

Uses temporary HOME/HERMES_HOME only. Never reads /Users/yelei/.hermes.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SPIKE = REPO / "spikes" / "r2-approval-posture-proof"
RUN_PROOF = SPIKE / "run_proof.py"
HERMES_AGENT_ROOT = Path(
    os.environ.get("HERMES_AGENT_ROOT", "/tmp/credential-guard-r2-hermes-source")
)
HERMES_SPIKE_PYTHON = Path(
    os.environ.get(
        "HERMES_SPIKE_PYTHON",
        "/tmp/credential-guard-r2-hermes-venv/bin/python",
    )
)


def _whitelist_env(home: Path, hermes_home: Path) -> dict[str, str]:
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
        "PYTHONPATH": str(HERMES_AGENT_ROOT),
        "OPENAI_API_KEY": "",
        "ANTHROPIC_API_KEY": "",
        "HERMES_API_KEY": "",
        # Never inherit process YOLO into child unless scenario sets it.
        "HERMES_YOLO_MODE": "",
    }


def _run_proof(scenario: str, tmp_path: Path, **extra_env: str) -> dict:
    assert HERMES_AGENT_ROOT.is_dir(), f"missing HERMES_AGENT_ROOT={HERMES_AGENT_ROOT}"
    assert HERMES_SPIKE_PYTHON.is_file(), (
        f"missing HERMES_SPIKE_PYTHON={HERMES_SPIKE_PYTHON}"
    )
    if not RUN_PROOF.is_file():
        pytest.fail(
            "RED: spikes/r2-approval-posture-proof/run_proof.py missing — "
            "A0 host posture cannot be proven yet"
        )

    home = tmp_path / f"home-{scenario}"
    hermes_home = tmp_path / f"hermes-{scenario}"
    home.mkdir(parents=True, exist_ok=True)
    hermes_home.mkdir(parents=True, exist_ok=True)
    (home / "tmp").mkdir(parents=True, exist_ok=True)

    env = _whitelist_env(home, hermes_home)
    env.update({k: str(v) for k, v in extra_env.items()})

    proc = subprocess.run(
        [str(HERMES_SPIKE_PYTHON), str(RUN_PROOF), "--scenario", scenario],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, (
        f"scenario={scenario}\nstdout={proc.stdout[-2000:]}\nstderr={proc.stderr[-2000:]}"
    )
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    assert lines, f"no stdout from run_proof\nstderr={proc.stderr[-1000:]}"
    data = json.loads(lines[-1])
    assert "config_yaml_body" not in data
    assert "config_path" not in data
    return data


def test_a0_spike_present_or_red(tmp_path: Path):
    """Baseline RED gate: spike runner must exist before posture claims."""
    if not RUN_PROOF.is_file():
        pytest.fail("RED: A0 spike run_proof.py missing")
    data = _run_proof("manual_ok", tmp_path)
    assert data["reference_calls_allowed"] is True
    assert data["mode"] == "manual"
    assert data["bypass_active"] is False


def test_a0_bypass_process_yolo(tmp_path: Path):
    data = _run_proof("process_yolo", tmp_path, HERMES_YOLO_MODE="1")
    assert data["bypass_active"] is True
    assert data["bypass_source"] == "process_yolo"
    assert data["reference_calls_allowed"] is False


def test_a0_bypass_session_yolo(tmp_path: Path):
    data = _run_proof("session_yolo", tmp_path)
    assert data["bypass_active"] is True
    assert data["bypass_source"] == "session_yolo"
    assert data["reference_calls_allowed"] is False


def test_a0_bypass_mode_off(tmp_path: Path):
    data = _run_proof("mode_off", tmp_path)
    assert data["mode"] == "off"
    assert data["bypass_active"] is True
    assert data["reference_calls_allowed"] is False


def test_a0_smart_mode_not_manual(tmp_path: Path):
    data = _run_proof("mode_smart", tmp_path)
    assert data["mode"] == "smart"
    assert data["bypass_active"] is False
    assert data["reference_calls_allowed"] is False
    assert data["reason"] == "mode_not_manual"
    assert data["mode_via"] == "hermes_cli.config.load_config_readonly"


def test_a0_unknown_mode_fail_closed(tmp_path: Path):
    data = _run_proof("mode_unknown", tmp_path)
    assert data["reference_calls_allowed"] is False
    assert data["reason"] == "unknown_mode"


def test_a0_import_failure_fail_closed(tmp_path: Path):
    data = _run_proof(
        "import_failure",
        tmp_path,
        R2_POSTURE_FORCE_IMPORT_ERROR="1",
    )
    assert data["reference_calls_allowed"] is False
    assert data["reason"] == "import_failed"


def test_a0_no_direct_config_yaml_read(tmp_path: Path):
    data = _run_proof("manual_ok", tmp_path)
    assert data["direct_config_yaml_open_count"] == 0
    assert data["used_hermes_stable_apis"] is True


def test_a0_callback_order_approve_and_deny(tmp_path: Path):
    approve = _run_proof("order_approve", tmp_path)
    assert approve["call_order"] == [
        "tool_request",
        "pre_tool_call",
        "approval_gate",
        "tool_execution",
    ]
    assert approve["tool_execution_entered"] is True

    deny = _run_proof("order_deny", tmp_path)
    assert deny["call_order"] == [
        "tool_request",
        "pre_tool_call",
        "approval_gate",
    ]
    assert deny["tool_execution_entered"] is False
    assert deny["approval_denied"] is True


def test_a0_approval_timeout_and_ttl_formula(tmp_path: Path):
    data = _run_proof("timeout_ttl", tmp_path, R2_APPROVAL_TIMEOUT="300")
    assert data["approval_timeout_seconds"] == 300
    assert data["approval_timeout_source"] in (
        "tools.approval._get_approval_timeout",
        "hermes_cli.config.load_config_readonly",
    )
    assert data["execution_review_margin_seconds"] > 0
    assert data["plan_ttl_seconds"] == (
        data["approval_timeout_seconds"] + data["execution_review_margin_seconds"]
    )
    assert data["plan_ttl_seconds"] > data["approval_timeout_seconds"]
    assert data["ttl_formula"] == (
        "plan_ttl = approval_timeout + execution_review_margin"
    )
    # Private timeout helper is usable but must be flagged for R2B.
    assert "timeout_api_compatibility_risk" in data
