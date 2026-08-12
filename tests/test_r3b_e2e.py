"""R3B E2E thin suite — main-agent process path evidence."""

from __future__ import annotations

from pathlib import Path

from tests.test_r3b_main_agent_path import _run


def test_r3b_e2e_main_agent_approve(tmp_path: Path):
    data = _run("approve", tmp_path)
    assert data["adapter_ok"] is True
    assert data["marker_ok"] is True
    assert data["injection_resolve_delta"] == 1
    assert data["process_start_delta"] == 1
    assert data["formal_tool_registered"] is True
    assert data["handler_identity_ok"] is True
    assert data["token_in_result"] == 0


def test_r3b_e2e_main_agent_deny(tmp_path: Path):
    data = _run("deny", tmp_path)
    assert data["process_start_delta"] == 0
    assert data["injection_resolve_delta"] == 0
