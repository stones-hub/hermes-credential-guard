"""Opt-in gate: R10 0.4.4 final-ZIP runner must stay outside no-build corpus."""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

LANDED_PLUGIN_ZIP_SHA256 = (
    "d6ee2bf6a92a4ca55ee37f24802cf26316ab38adcbe27b9d59a4ee9e944ae265"
)


def test_r10_044_final_zip_module_outside_test_glob():
    path = REPO / "tests" / "r10_044_final_zip_e2e.py"
    assert path.is_file()
    assert not path.name.startswith("test_")


def test_r10_044_final_zip_runner_exists_and_disarms_build_auth():
    runner = (REPO / "scripts" / "run_r10_044_final_zip_tests.py").read_text(
        encoding="utf-8"
    )
    assert "CG_R6_BUILD_AUTHORIZED" in runner
    assert 'env.pop("CG_R6_BUILD_AUTHORIZED", None)' in runner
    assert "tests/r10_044_final_zip_e2e.py" in runner


def test_r10_044_harness_pins_landed_zip_identity():
    harness_text = (REPO / "scripts" / "run_r10_044_final_zip_e2e.py").read_text(
        encoding="utf-8"
    )
    assert 'PLUGIN_VERSION = "0.4.4"' in harness_text
    assert 'f"credential-guard-{PLUGIN_VERSION}-hermes-plugin.zip"' in harness_text
    assert LANDED_PLUGIN_ZIP_SHA256 in harness_text
    assert "ARTIFACTS_LANDED = True" in harness_text
    assert "STRICT = True" in harness_text
    assert "Never calls" in harness_text or "build_all" in harness_text
    assert "PluginManager" in harness_text
    assert "prove_source_fallback_mutation_red" in harness_text
    assert "protocol_registered_secret_provider_calls" in harness_text
    assert "shutil.rmtree" in harness_text or "damage_target" in harness_text
    assert "put_source_preferred" in harness_text
    assert "load_failed_or_fail_closed" in harness_text
    assert "factor_control_source_on_preferred_path" in harness_text


def test_r10_044_resolve_landed_binds_hash_and_rejects_drift():
    path = REPO / "scripts" / "run_r10_044_final_zip_e2e.py"
    spec = importlib.util.spec_from_file_location("r10_044_optin_harness", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.ARTIFACTS_LANDED is True
    assert mod.STRICT is True
    assert mod.EXPECTED_PLUGIN_ZIP_SHA256 == LANDED_PLUGIN_ZIP_SHA256
    zip_path = mod.resolve_plugin_zip()
    assert zip_path.is_file()
    assert zip_path.name == mod.EXPECTED_PLUGIN_ZIP
    try:
        mod.resolve_plugin_zip(expected_sha256="0" * 64)
    except AssertionError as exc:
        assert "sha drift" in str(exc)
    else:
        raise AssertionError("landed resolve must hard-fail on sha drift")
