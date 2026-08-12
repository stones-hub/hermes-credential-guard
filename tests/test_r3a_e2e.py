"""R3A E2E thin suite — Framework + compatibility adapter_ok evidence."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.test_r2_e2e import _run as _compat_run
from tests.test_r2_main_agent_path import _run as _main_run


def test_r3a_e2e_compat_approve(tmp_path: Path):
    data = _compat_run("approve", tmp_path)
    assert data["adapter_ok"] is True
    assert data["injection_resolve_delta"] == 1
    assert data["adapter_invoke_delta"] == 1
    assert data["canary_in_result"] == 0
    assert data["r3_injection_implemented"] is True


def test_r3a_e2e_main_agent_approve(tmp_path: Path):
    data = _main_run("approve", tmp_path)
    assert data["adapter_ok"] is True
    assert data["injection_resolve_delta"] == 1
    assert data["adapter_invoke_delta"] == 1
    assert data["formal_tool_registered"] is True
    assert data["handler_identity_ok"] is True
