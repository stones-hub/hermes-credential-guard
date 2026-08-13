"""R9 0.4.3 final-ZIP isolated install E2E (opt-in; NOT in no-build corpus).

Filename deliberately outside ``tests/test_*.py`` so
``scripts/run_r5_nobuild_pytest.py`` never collects it. Execute only via
``scripts/run_r9_043_final_zip_tests.py``.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS_PATH = ROOT / "scripts" / "run_r9_043_final_zip_e2e.py"


def _load_harness():
    spec = importlib.util.spec_from_file_location("r9_043_final_zip_harness", HARNESS_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def harness():
    return _load_harness()


def test_r9_043_final_zip_continuity_from_install_tree(harness):
    zip_path = harness.resolve_plugin_zip()
    summary = harness.run_isolated_continuity_e2e(zip_path)
    assert harness.evaluate_r9_043_final_zip_gates(summary) == 0
    assert summary["plugin_version"] == "0.4.3"
    assert summary["installed_from_zip"] is True
    assert summary["installed_module_file_under_source_tree"] is False
    assert summary["plugin_manager_loaded"] is True
    assert summary["large_request_provider_calls"] == 1
    assert summary["collision_provider_calls"] == 1
    assert summary["unresolved_provider_calls"] == 1
    assert summary["protocol_unresolved_provider_calls"] == 0
    assert summary["residual_force_provider_calls"] == 0
    assert summary["scanner_trailing_provider_calls"] == 0
    assert summary["final_gate_blocks_residual"] is True


def test_r9_043_source_fallback_mutation_is_red(harness):
    """Damaged install + healthy source must fail-closed via PluginManager.

    Must not be a path-bool helper that never damages the install copy.
    """
    zip_path = harness.resolve_plugin_zip()
    proof = harness.prove_source_fallback_mutation_red(zip_path)

    assert proof["install_damaged"] is True
    assert proof["source_tree_healthy"] is True
    assert proof["plugin_manager_attempted"] is True
    assert proof["neutral_cwd"] is True
    assert proof["repo_root_not_preferred_on_sys_path"] is True
    assert proof["no_cg_module_cache_pollution"] is True
    assert proof["load_failed_or_fail_closed"] is True
    assert proof["loaded_from_source_tree"] is False
    assert proof["any_cg_module_file_under_source_tree"] is False
    assert proof["installed_from_zip"] is False
    assert proof["middleware_registered"] is False
    assert proof.get("damage_target")
    assert proof.get("failure_mode")

    # Factor control: forcing source onto preferred sys.path must be detected
    # as RED (source fallback), proving the probe is not vacuously always-true.
    # This is never treated as a healthy product path.
    fc = proof["factor_control_source_on_preferred_path"]
    assert fc["source_on_preferred_path"] is True
    assert fc["detected_source_fallback"] is True
    assert fc["installed_from_zip"] is False
    assert fc["any_cg_module_file_under_source_tree"] is True


def test_r9_043_zip_sha_mismatch_is_red(harness):
    with pytest.raises(AssertionError, match="sha drift"):
        harness.resolve_plugin_zip(
            expected_name=harness.EXPECTED_PLUGIN_ZIP,
            expected_sha256="0" * 64,
        )
