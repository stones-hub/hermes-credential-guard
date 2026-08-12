"""Opt-in gate: R8 0.4.2 final-ZIP runner must stay outside no-build corpus."""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_r8_042_final_zip_module_outside_test_glob():
    path = REPO / "tests" / "r8_042_final_zip_e2e.py"
    assert path.is_file()
    assert not path.name.startswith("test_")


def test_r8_042_final_zip_runner_exists_and_disarms_build_auth():
    runner = (REPO / "scripts" / "run_r8_042_final_zip_tests.py").read_text(
        encoding="utf-8"
    )
    assert "CG_R6_BUILD_AUTHORIZED" in runner
    assert 'env.pop("CG_R6_BUILD_AUTHORIZED", None)' in runner
    assert "tests/r8_042_final_zip_e2e.py" in runner


def test_r8_042_harness_pins_landed_zip_identity():
    harness = (REPO / "scripts" / "run_r8_042_final_zip_e2e.py").read_text(
        encoding="utf-8"
    )
    assert "credential-guard-0.4.2-hermes-plugin.zip" in harness
    assert "95d96aa82f64701dfc0b5862ba3671feb98b7d5c07a61f350dbe65287fb60ccf" in harness
    assert "build_all" not in harness or "Never calls" in harness
