"""Opt-in gate: R9 0.4.3 final-ZIP runner must stay outside no-build corpus."""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_r9_043_final_zip_module_outside_test_glob():
    path = REPO / "tests" / "r9_043_final_zip_e2e.py"
    assert path.is_file()
    assert not path.name.startswith("test_")


def test_r9_043_final_zip_runner_exists_and_disarms_build_auth():
    runner = (REPO / "scripts" / "run_r9_043_final_zip_tests.py").read_text(
        encoding="utf-8"
    )
    assert "CG_R6_BUILD_AUTHORIZED" in runner
    assert 'env.pop("CG_R6_BUILD_AUTHORIZED", None)' in runner
    assert "tests/r9_043_final_zip_e2e.py" in runner


def test_r9_043_harness_pins_landed_zip_identity():
    harness = (REPO / "scripts" / "run_r9_043_final_zip_e2e.py").read_text(
        encoding="utf-8"
    )
    assert 'PLUGIN_VERSION = "0.4.3"' in harness
    assert 'f"credential-guard-{PLUGIN_VERSION}-hermes-plugin.zip"' in harness
    assert "738bc8ae4e1973a50efba604602a9fb3c7a6739efb95e48024b6a1975e97dacb" in harness
    assert "Never calls" in harness or "build_all" in harness
    assert "PluginManager" in harness
    assert "prove_source_fallback_mutation_red" in harness
    # Real source-fallback mutation must damage the install copy and reload
    # via PluginManager — not merely compare path booleans.
    assert "shutil.rmtree" in harness or "damage_target" in harness
    assert "put_source_preferred" in harness
    assert "load_failed_or_fail_closed" in harness
    assert "factor_control_source_on_preferred_path" in harness
