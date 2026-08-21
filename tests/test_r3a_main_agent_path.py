"""R3A main-agent path: reuse R2 Framework probe with adapter_ok evidence."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from tests.test_r2_main_agent_path import (
    DECOY,
    HERMES_SPIKE_PYTHON,
    PROBE,
    REPO,
    _base_env,
    _run,
)

_FULL_APPROVE_ORDER = [
    "tool_request",
    "tool_execution",
    "pre_tool_call",
    "approval_gate",
    "handler",
    "consume",
    "resolve",
    "adapter",
]


def test_r3a_main_agent_approve_resolve_adapter(tmp_path: Path):
    data = _run("approve", tmp_path)
    assert data["order"] == _FULL_APPROVE_ORDER
    assert data["counts"].get("consume") == 1
    assert data["counts"].get("resolve") == 1
    assert data["counts"].get("adapter") == 1
    assert data["adapter_ok"] is True
    assert data["injection_resolve_delta"] == 1
    assert data["adapter_invoke_delta"] == 1
    assert data["secret_resolve_delta"] == 0
    assert data["token_in_result"] == 0
    assert data["plan_state"] == "consumed"


def test_r3a_main_agent_deny_zero_resolve(tmp_path: Path):
    data = _run("deny", tmp_path)
    assert data["counts"]["handler"] == 0
    assert data["counts"].get("consume", 0) == 0
    assert data["counts"].get("resolve", 0) == 0
    assert data["counts"].get("adapter", 0) == 0
    assert data["injection_resolve_delta"] == 0
    assert data["adapter_invoke_delta"] == 0
    assert data["token_in_result"] == 0


def test_r3a_main_agent_timeout_zero_resolve(tmp_path: Path):
    data = _run("timeout", tmp_path)
    assert data["counts"].get("resolve", 0) == 0
    assert data["counts"].get("adapter", 0) == 0
    assert data["injection_resolve_delta"] == 0
    assert data["adapter_invoke_delta"] == 0


def test_r3a_main_agent_replay_second_adapter_zero(tmp_path: Path):
    data = _run("replay", tmp_path)
    assert data["adapter_ok"] is True
    assert data["injection_resolve_delta"] == 1
    assert data["adapter_invoke_delta"] == 1
    # First approve consumed once; second run must not re-enter resolve/adapter.
    assert data["counts"].get("consume") == 1
    assert data["counts"].get("resolve") == 1
    assert data["counts"].get("adapter") == 1
    preview2 = data["result2_preview"]
    assert '"ok":false' in preview2.replace(" ", "") or "PLAN_NOT_PENDING" in preview2


@pytest.mark.parametrize("seam", ["consume", "resolve", "adapter"])
def test_r3a_mutation_drop_consume_resolve_adapter_breaks_approve(tmp_path: Path, seam: str):
    """Load-bearing: bypassing consume/resolve/adapter must break healthy approve evidence."""
    home = tmp_path / f"home-drop-{seam}"
    hermes = tmp_path / f"hermes-drop-{seam}"
    home.mkdir()
    hermes.mkdir()
    (home / "tmp").mkdir()
    env = _base_env(home, hermes)
    env["CG_SCENARIO"] = "approve"
    env["CG_DECOY"] = DECOY
    env["CG_REPO"] = str(REPO)
    env["CG_DROP_SEAM"] = seam
    proc = subprocess.run(
        [str(HERMES_SPIKE_PYTHON), "-c", PROBE],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if proc.returncode != 0:
        return
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    assert lines, proc.stderr[-1500:]
    data = json.loads(lines[-1])
    healthy = (
        data.get("order") == _FULL_APPROVE_ORDER
        and data.get("adapter_ok") is True
        and data.get("plan_state") == "consumed"
        and data.get("counts", {}).get("consume") == 1
        and data.get("counts", {}).get("resolve") == 1
        and data.get("counts", {}).get("adapter") == 1
    )
    assert healthy is False
