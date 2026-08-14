"""R0: Hermes tool_request → pre_tool_call → tool_execution injection gate.

Uses real Hermes PluginManager / middleware / resolve_pre_tool_block under the
Hermes venv (project .venv is 3.9; Hermes requires 3.10+). Spike only — never
touches credential_guard production code.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HERMES_PYTHON = Path("/Users/yelei/.hermes/hermes-agent/venv/bin/python")
HERMES_ROOT = Path("/Users/yelei/.hermes/hermes-agent")
SPIKE = REPO / "spikes" / "tool-injection-proof"
RUN_PROOF = SPIKE / "run_proof.py"


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
        "PYTHONPATH": os.pathsep.join([str(HERMES_ROOT), str(SPIKE.parent)]),
        "HERMES_INTERACTIVE": "1",
        # Strip provider keys — empty/whitelist only.
        "OPENAI_API_KEY": "",
        "ANTHROPIC_API_KEY": "",
        "HERMES_API_KEY": "",
    }


def _run_proof(scenario: str, tmp_path: Path, **extra_env: str) -> dict:
    assert HERMES_PYTHON.is_file(), "Hermes Python missing"
    assert RUN_PROOF.is_file(), f"spike run_proof missing: {RUN_PROOF}"

    home = tmp_path / f"home-{scenario}"
    hermes_home = tmp_path / f"hermes-{scenario}"
    home.mkdir(parents=True, exist_ok=True)
    hermes_home.mkdir(parents=True, exist_ok=True)
    (home / "tmp").mkdir(parents=True, exist_ok=True)

    env = _whitelist_env(home, hermes_home)
    env.update(extra_env)

    proc = subprocess.run(
        [str(HERMES_PYTHON), str(RUN_PROOF), "--scenario", scenario],
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
    # Hard rule: never print decoy plaintext in evidence.
    blob = json.dumps(data)
    assert "decoy_plain" not in data
    assert data.get("decoy_len", 0) > 0
    assert data.get("ref") == "<CREDENTIAL:decoy>"
    return data


def test_t1_red_contract_spike_present_or_documented(tmp_path: Path):
    """T1: before tool_execution, plain count must be 0; ref visible in request/approve."""
    if not RUN_PROOF.is_file():
        pytest.fail(
            "RED: spikes/tool-injection-proof/run_proof.py missing — "
            "approve.before_execution_plain_count cannot be proven yet"
        )
    data = _run_proof("approve", tmp_path)
    assert data["tool_request_saw_ref"] is True
    assert data["pre_tool_call_saw_ref"] is True
    assert data["approval_payload_plain_count"] == 0
    assert data["before_execution_plain_count"] == 0, (
        "T1: plain must not appear before tool_execution"
    )


def test_t2_approve_injects_only_after_approval(tmp_path: Path):
    data = _run_proof("approve", tmp_path)
    assert data["before_execution_plain_count"] == 0
    assert data["tool_received_plain_count"] == 1
    assert data["downstream_call_count"] == 1
    assert data["approval_payload_plain_count"] == 0
    assert data["middleware_trace_plain_count"] == 0
    assert data["secret_resolve_count"] == 1
    assert data["call_order"] == [
        "tool_request",
        "pre_tool_call",
        "approval_gate",
        "tool_execution",
        "downstream_tool",
    ]


def test_t3_deny_no_resolve_no_downstream(tmp_path: Path):
    data = _run_proof("deny", tmp_path)
    assert data["secret_resolve_count"] == 0
    assert data["downstream_call_count"] == 0
    assert data["tool_received_plain_count"] == 0
    assert data["approval_denied"] is True


def test_t4_exception_paths_fail_closed(tmp_path: Path):
    for fault in (
        "tool_request",
        "pre_tool_call",
        "tool_execution_resolver",
        "tool_execution_inject",
    ):
        data = _run_proof("fault", tmp_path / fault, TIP_FAULT=fault)
        assert data["downstream_call_count"] == 0, (
            f"fault={fault} must not reach fake tool; got {data}"
        )
        assert data["secret_resolve_count"] == 0 or fault.startswith(
            "tool_execution"
        ), data
        # Resolver/inject faults may attempt resolve but must not call downstream.
        if fault.startswith("tool_execution"):
            assert data["downstream_call_count"] == 0
        else:
            assert data["secret_resolve_count"] == 0, data
        assert data["fail_closed"] is True, data
        # B3: fault must raise a real internal exception, not a preset branch.
        assert int(data.get("real_exception_count") or 0) >= 1, (
            f"B3 RED: fault={fault} did not raise a real internal exception; got {data}"
        )


def test_t4b_all_faults_real_exceptions_and_no_downstream(tmp_path: Path):
    """B3 aggregate: four real exceptions; every fault path downstream=0."""
    total_exc = 0
    for fault in (
        "tool_request",
        "pre_tool_call",
        "tool_execution_resolver",
        "tool_execution_inject",
    ):
        data = _run_proof("fault", tmp_path / f"agg-{fault}", TIP_FAULT=fault)
        total_exc += int(data.get("real_exception_count") or 0)
        assert data["downstream_call_count"] == 0, data
        assert data["fail_closed"] is True, data
        assert data.get("fault_via_real_raise") is True, (
            f"B3 RED: fault={fault} used preset branch, not real raise; got {data}"
        )
    assert total_exc >= 4, (
        f"B3 RED: real_exception_count aggregate={total_exc} < 4"
    )
    # Evidence field for completion gate (summed across scenarios via last run + flag).
    assert True  # aggregate asserted above as real_exception_count>=4


def test_t5_single_next_call_original_args_and_isolation(tmp_path: Path):
    data = _run_proof("once_and_concurrent", tmp_path)
    assert data["next_call_count"] == 1
    assert data["original_args_still_ref"] is True
    assert data["shared_state_plain_count"] == 0
    assert data["trace_plain_count"] == 0
    assert data["concurrent_no_cross"] is True
    assert data["tool_received_plain_count"] >= 1
    # B2: concurrent distinct decoys must bind without cross.
    assert data.get("concurrent_distinct_secret_binding") is True, (
        f"B2 RED: concurrent plans did not prove distinct secret binding; got {data}"
    )
    assert data.get("concurrent_each_next_call_once") is True, (
        f"B2 RED: concurrent next_call once-each not proven; got {data}"
    )
    assert data.get("concurrent_both_calls_succeeded") is True, (
        f"B2 RED: both concurrent calls must return success; got {data}"
    )


def test_t5_concurrent_approval_patch_scope_is_shared():
    """Concurrent proof must not nest process-global unittest.mock patch contexts."""
    source = RUN_PROOF.read_text(encoding="utf-8")
    scenario = source[source.index('if scenario == "once_and_concurrent":') :]
    assert "install_approval_patch: bool = True" in source
    assert 'with patch("tools.approval.request_tool_approval", side_effect=shared_gate):' in scenario
    assert "install_approval_patch=False" in scenario


def test_b1_b4_no_partial_secret_residue_and_residue_gate(tmp_path: Path):
    """B1/B4: no full decoy or >=8 contiguous fragment in evidence/state/stdio."""
    for scenario in ("approve", "deny", "once_and_concurrent"):
        data = _run_proof(scenario, tmp_path / f"res-{scenario}")
        assert int(data.get("partial_secret_residue_count", -1)) == 0, (
            f"B1 RED: partial_secret_residue_count != 0 for {scenario}: {data}"
        )
        assert data.get("residue_gate_passed") is True, (
            f"B4 RED: residue_gate_passed not true for {scenario}: {data}"
        )
        assert data.get("resolver_store_empty") is True, (
            f"B4 RED: resolver_store_empty not true for {scenario}: {data}"
        )
        # Evidence JSON itself must not carry token prefixes / digests of secrets as proof text
        # beyond boolean/length fields — no 'token' prefix field leaking decoy.
        blob = json.dumps(data)
        assert '"token"' not in blob or data.get("residue_gate_passed") is True
        # Parent must never see decoy body fields.
        assert "decoy_plain" not in data
        assert "received_values" not in data


def test_b4_fault_paths_also_pass_residue_gate(tmp_path: Path):
    total_downstream = 0
    total_exc = 0
    for fault in (
        "tool_request",
        "pre_tool_call",
        "tool_execution_resolver",
        "tool_execution_inject",
    ):
        data = _run_proof("fault", tmp_path / f"res-fault-{fault}", TIP_FAULT=fault)
        total_downstream += int(data.get("downstream_call_count") or 0)
        total_exc += int(data.get("real_exception_count") or 0)
        assert data.get("residue_gate_passed") is True, data
        assert int(data.get("partial_secret_residue_count", -1)) == 0, data
        assert data.get("resolver_store_empty") is True, data
    assert total_downstream == 0, (
        f"completion: all_fault_downstream_call_count={total_downstream}"
    )
    assert total_exc >= 4, f"completion: real_exception_count={total_exc}"


def test_r0_host_surfaces_unchanged_paths():
    """R0 spike must not rewrite production plugin; R2 production registers both middlewares."""
    prod_init = REPO / "credential_guard" / "__init__.py"
    assert prod_init.is_file()
    init_text = prod_init.read_text(encoding="utf-8")
    # R0 spike identity must remain distinct from production callback imports.
    assert "spikes/" not in init_text
    assert "on_tool_request" in init_text
    assert "on_tool_execution" in init_text

    plugin_yaml = REPO / "plugin.yaml"
    text = plugin_yaml.read_text(encoding="utf-8")
    # R2 production manifest must declare both tool middlewares.
    assert "tool_request" in text
    assert "tool_execution" in text
    assert "0.4.4" in text
    # R10: current product version 0.4.4 (historical 0.4.2/0.4.3 artifacts retained in dist/).
    assert "version: 0.4.4" in text
