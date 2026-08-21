"""R11 0.4.5 final-ZIP isolated install E2E (opt-in; NOT in no-build corpus).

Filename deliberately outside ``tests/test_*.py`` so
``scripts/run_r5_nobuild_pytest.py`` never collects it. Execute only via
``scripts/run_r11_045_final_zip_tests.py``.

Landed stage (``ARTIFACTS_LANDED=True``): every case exercises the real 0.4.5
plugin ZIP installed into a throwaway HOME/HERMES_HOME. Nothing here may fall
back to the repo source tree, to a historical 0.4.4 ZIP, or to xfail/skip.
The pending-stage contract is kept as an explicit branch so a regression that
un-lands the artifacts fails loudly instead of silently skipping.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS_PATH = ROOT / "scripts" / "run_r11_045_final_zip_e2e.py"


def _load_harness():
    spec = importlib.util.spec_from_file_location(
        "r11_045_final_zip_harness", HARNESS_PATH
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def harness():
    return _load_harness()


@pytest.fixture(scope="module")
def landed_zip(harness):
    if not harness.ARTIFACTS_LANDED:
        pytest.fail(
            "ARTIFACTS_LANDED=False: 0.4.5 artifacts are not landed; this suite "
            "must not run against a historical ZIP (strict=True; not a skip)"
        )
    return harness.resolve_plugin_zip()


@pytest.fixture(scope="module")
def continuity_summary(harness, landed_zip):
    return harness.run_isolated_continuity_e2e(landed_zip)


@pytest.fixture(scope="module")
def out_of_box(harness, landed_zip):
    return harness.run_r11_out_of_box_from_install_tree(landed_zip)


def test_r11_045_artifacts_landed_and_hash_bound(harness):
    """Resolve must bind the landed ZIP to the versioned manifest."""
    assert harness.PLUGIN_VERSION == "0.4.5"
    assert harness.STRICT is True
    if not harness.ARTIFACTS_LANDED:
        with pytest.raises(
            FileNotFoundError, match="R11_045_ARTIFACTS_PENDING_BUILD"
        ):
            harness.resolve_plugin_zip()
        return
    path = harness.resolve_plugin_zip()
    assert path.is_file()
    assert path.name == harness.EXPECTED_PLUGIN_ZIP
    # The pending sentinel must no longer be the expected hash.
    assert harness.EXPECTED_PLUGIN_ZIP_SHA256 != harness.PENDING_SENTINEL
    assert len(harness.EXPECTED_PLUGIN_ZIP_SHA256) == 64


def test_r11_045_zip_sha_mismatch_is_red(harness, landed_zip):
    """A wrong expected hash must raise, proving resolve really compares."""
    with pytest.raises(AssertionError, match="sha drift"):
        harness.resolve_plugin_zip(
            expected_name=harness.EXPECTED_PLUGIN_ZIP,
            expected_sha256="0" * 64,
        )


def test_r11_045_final_zip_continuity_from_install_tree(
    harness, continuity_summary
):
    summary = continuity_summary
    assert harness.evaluate_r11_045_final_zip_gates(summary) == 0
    assert summary["plugin_version"] == "0.4.5"
    assert summary["installed_from_zip"] is True
    assert summary["installed_module_file_under_source_tree"] is False
    assert summary["plugin_manager_loaded"] is True
    assert summary["credential_guard_listed"] is True


def test_r11_045_continuity_security_boundary_readings(continuity_summary):
    """Explicit per-case Provider counts — not just the aggregate gate code."""
    s = continuity_summary
    # Must NOT false-block ordinary traffic.
    assert s["large_request_provider_calls"] == 1
    assert s["collision_provider_calls"] == 1
    assert s["unresolved_provider_calls"] == 1
    # Must fail closed.
    assert s["protocol_unresolved_provider_calls"] == 0
    assert s["protocol_registered_secret_provider_calls"] == 0
    assert s["residual_force_provider_calls"] == 0
    assert s["scanner_trailing_provider_calls"] == 0
    assert s["final_gate_blocks_residual"] is True
    assert s["decoy_absent_from_provider"] is True


def test_r11_045_out_of_box_zero_config_and_broken_store(harness, out_of_box):
    """C1: a fresh user can chat; a corrupt store still fails closed.

    Both directions are asserted together on purpose: passing through when
    there is no store is only safe if a *broken* store still blocks. Asserting
    only the pass-through would green a plugin that had stopped guarding.
    """
    assert out_of_box["probes_ran_from_install_tree"] is True
    assert out_of_box["zero_config_chat_provider_calls"] == 1
    assert out_of_box["zero_config_chat_blocked"] is False
    assert out_of_box["broken_store_chat_provider_calls"] == 0
    assert out_of_box["broken_store_chat_blocked"] is True


def test_r11_045_out_of_box_credential_code_and_validate(harness, out_of_box):
    """C6 fixed refusal + C10 offline validate, from the install tree."""
    assert out_of_box["credential_code_recognized"] is True
    assert out_of_box["credential_code_rejects_plain"] is True
    assert "CREDENTIAL_CODE_NOT_USABLE" in out_of_box["credential_code_refusal"]

    assert out_of_box["validate_good_rc"] == 0
    assert "PASS credential" in out_of_box["validate_good_out"]
    assert "VALID" in out_of_box["validate_good_out"]

    assert out_of_box["validate_bad_rc"] == 1
    assert "FAIL" in out_of_box["validate_bad_out"]

    # Counter-case: validate is not permissive — an insecure parent is refused
    # even for an otherwise well-formed config.
    assert out_of_box["validate_insecure_parent_rc"] == 1
    assert "FAIL" in out_of_box["validate_insecure_parent_out"]


def test_r11_045_out_of_box_gate_evaluator_is_load_bearing(harness, out_of_box):
    """The gate must reject each degraded reading, not just accept the good one."""
    assert harness.evaluate_r11_out_of_box_gates(out_of_box) == 0
    degradations = (
        {"probes_ran_from_install_tree": False},
        {"zero_config_chat_provider_calls": 0},
        {"broken_store_chat_provider_calls": 1},
        {"broken_store_chat_blocked": False},
        {"credential_code_recognized": False},
        {"credential_code_refusal": "OK"},
        {"validate_good_rc": 1},
        {"validate_bad_rc": 0},
        {"validate_insecure_parent_rc": 0},
    )
    for delta in degradations:
        mutated = dict(out_of_box)
        mutated.update(delta)
        assert harness.evaluate_r11_out_of_box_gates(mutated) != 0, delta


def test_r11_045_source_fallback_mutation_is_red(harness, landed_zip):
    """Damaged install + healthy source must fail-closed via PluginManager."""
    proof = harness.prove_source_fallback_mutation_red(landed_zip)
    assert proof["install_damaged"] is True
    assert proof["source_tree_healthy"] is True
    assert proof["plugin_manager_attempted"] is True
    assert proof["load_failed_or_fail_closed"] is True
    assert proof["loaded_from_source_tree"] is False
    assert proof["any_cg_module_file_under_source_tree"] is False
    assert proof["installed_from_zip"] is False
    assert proof["middleware_registered"] is False
    # Factor control: the probe must be able to SEE a source fallback, else the
    # negative result above would be vacuous.
    fc = proof["factor_control_source_on_preferred_path"]
    assert fc["detected_source_fallback"] is True
