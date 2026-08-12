"""R8 0.4.2 final-ZIP isolated install E2E (opt-in; NOT in no-build corpus).

Filename deliberately outside ``tests/test_*.py`` so
``scripts/run_r5_nobuild_pytest.py`` never collects it. Execute only via
``scripts/run_r8_042_final_zip_tests.py``.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS_PATH = ROOT / "scripts" / "run_r8_042_final_zip_e2e.py"


def _load_harness():
    spec = importlib.util.spec_from_file_location("r8_042_final_zip_harness", HARNESS_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def harness():
    return _load_harness()


def test_r8_042_final_zip_http_https_from_install_tree(harness):
    zip_path = harness.resolve_plugin_zip()
    summary = harness.run_isolated_http_scheme_e2e(zip_path)
    assert summary["plugin_version"] == "0.4.2"
    assert summary["installed_from_zip"] is True
    assert summary["installed_module_file_under_source_tree"] is False
    assert summary["http_scheme_accepted"] is True
    assert summary["https_scheme_accepted"] is True
    assert summary["http_url_used"] is True
    assert summary["decoy_scrubbed"] is True


def test_r8_042_zip_sha_mismatch_is_red(harness):
    with pytest.raises(AssertionError, match="sha drift"):
        harness.resolve_plugin_zip(
            expected_name=harness.EXPECTED_PLUGIN_ZIP,
            expected_sha256="0" * 64,
        )
