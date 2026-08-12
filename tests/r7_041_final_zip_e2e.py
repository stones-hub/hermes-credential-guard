"""R7 0.4.1 final-ZIP isolated install E2E (opt-in; NOT in no-build corpus).

Filename deliberately outside ``tests/test_*.py`` so
``scripts/run_r5_nobuild_pytest.py`` never collects it. Execute only via
``scripts/run_r7_041_final_zip_tests.py``.
"""

from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS_PATH = ROOT / "scripts" / "run_r7_041_final_zip_e2e.py"

KEY_ENCODING_KEYS = (
    "raw",
    "base64",
    "urlsafe_base64",
    "percent",
    "json_escape",
    "unicode_escape",
)


def _load_harness():
    spec = importlib.util.spec_from_file_location("r7_041_final_zip_harness", HARNESS_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def harness():
    return _load_harness()


def _healthy_encoding_matrix():
    return {
        key: {"exit": 0, "blocked": True, "provider_delta": 0}
        for key in KEY_ENCODING_KEYS
    }


def _healthy_summary(harness):
    return {
        "plugin_version": harness.PLUGIN_VERSION,
        "installed_from_zip": True,
        "installed_module_file_under_source_tree": False,
        "installed_module_file_under_plugin": True,
        "plugin_path_is_source_tree": False,
        "check_exit": 0,
        "check_has_main_coverage": True,
        "check_has_auxiliary_out_of_scope": True,
        "check_has_title_not_full_coverage_note": True,
        "hello_exit": 0,
        "hello_provider_bodies": 1,
        "hello_has_fake_blocked_model": False,
        "registered_secret_plain_count": 0,
        "registered_secret_ref_count": 1,
        "key_block_exit": 0,
        "key_block_provider_delta": 0,
        "key_encoding_matrix": _healthy_encoding_matrix(),
        "installed_key_urlsafe_provider_calls": 0,
        "fail_closed_exit": 0,
        "fail_closed_provider_delta": 0,
        "fail_closed_has_decoy": False,
        "fail_closed_has_block_msg": True,
        "disabled_exit": 0,
        "disabled_provider_bodies": 1,
        "disabled_plain_visible": True,
        "title_generation_disabled_is_isolation_only": True,
        "opaque_token_smoke": True,
    }


# Field → polluted value that must enter the formal predicate and RED.
_UNBOUND_FIELD_MUTATIONS = (
    ("fail_closed_exit", 99),
    ("fail_closed_has_block_msg", False),
    ("installed_key_urlsafe_provider_calls", 99),
    ("opaque_token_smoke", False),
    ("installed_module_file_under_plugin", False),
)


@pytest.mark.parametrize("field,poison", _UNBOUND_FIELD_MUTATIONS)
def test_mutation_previously_unbound_fields_are_red(harness, field, poison):
    """Each acceptance field must be bound; pollution must not stay green (0)."""
    healthy = _healthy_summary(harness)
    assert harness.evaluate_r7_041_final_zip_gates(healthy) == 0
    poisoned = dict(healthy)
    poisoned[field] = poison
    code = harness.evaluate_r7_041_final_zip_gates(poisoned)
    assert code != 0, f"{field}={poison!r} still green (exit 0); field not in predicate"
    # Prove the field itself is what the predicate consumes (not a sibling).
    restored = dict(poisoned)
    restored[field] = healthy[field]
    assert harness.evaluate_r7_041_final_zip_gates(restored) == 0


@pytest.mark.parametrize(
    "field",
    [f for f, _ in _UNBOUND_FIELD_MUTATIONS]
    + [
        "fail_closed_provider_delta",
        "key_encoding_matrix",
        "key_block_provider_delta",
        "registered_secret_plain_count",
    ],
)
def test_missing_gate_fields_fail_closed(harness, field):
    healthy = _healthy_summary(harness)
    missing = dict(healthy)
    del missing[field]
    assert harness.evaluate_r7_041_final_zip_gates(missing) != 0, field


def test_r7_041_final_zip_suite_passes_outer_gate(harness):
    summary = harness.run_suite()
    code = harness.evaluate_r7_041_final_zip_gates(summary)
    assert code == 0, summary
    matrix = summary.get("key_encoding_matrix")
    assert isinstance(matrix, dict)
    assert set(matrix) == set(KEY_ENCODING_KEYS)
    for key in KEY_ENCODING_KEYS:
        cell = matrix[key]
        assert cell["exit"] == 0, key
        assert cell["blocked"] is True, key
        assert cell["provider_delta"] == 0, key


def test_mutation_source_tree_sys_path_fallback_is_red(harness, tmp_path):
    """If install proof is poisoned to claim source-tree load, gate must RED."""
    summary = _healthy_summary(harness)
    summary.update(
        {
            "installed_from_zip": False,
            "installed_module_file_under_source_tree": True,
            "installed_module_file_under_plugin": False,
            "plugin_path_is_source_tree": True,
        }
    )
    assert harness.evaluate_r7_041_final_zip_gates(summary) == 7

    # Direct prove helper: pointing loaded_file at repo source must not claim zip.
    zip_helpers_path = ROOT / "scripts" / "installed_zip_plugin.py"
    spec = importlib.util.spec_from_file_location("izp_mut", zip_helpers_path)
    assert spec and spec.loader
    izp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(izp)
    proof = izp.prove_installed_module_path(
        ROOT / "credential_guard",
        ROOT,
        ROOT / "credential_guard" / "middleware.py",
    )
    assert proof["installed_from_zip"] is False
    assert proof["installed_module_file_under_source_tree"] is True


def test_mutation_drop_provider_zero_or_boundary_assertions_is_red(harness):
    """Deleting Provider=0 / boundary fields from a green summary must RED."""
    green = _healthy_summary(harness)
    assert harness.evaluate_r7_041_final_zip_gates(green) == 0

    poisoned = dict(green)
    poisoned["key_block_provider_delta"] = 1
    assert harness.evaluate_r7_041_final_zip_gates(poisoned) == 8

    poisoned2 = dict(green)
    poisoned2["check_has_auxiliary_out_of_scope"] = False
    assert harness.evaluate_r7_041_final_zip_gates(poisoned2) == 11

    poisoned3 = dict(green)
    poisoned3["fail_closed_provider_delta"] = 1
    assert harness.evaluate_r7_041_final_zip_gates(poisoned3) == 3


@pytest.mark.parametrize("drop_key", KEY_ENCODING_KEYS)
def test_mutation_drop_encoding_matrix_cell_is_red(harness, drop_key):
    green = _healthy_summary(harness)
    poisoned = copy.deepcopy(green)
    del poisoned["key_encoding_matrix"][drop_key]
    assert harness.evaluate_r7_041_final_zip_gates(poisoned) == 8


@pytest.mark.parametrize("bad_key", KEY_ENCODING_KEYS)
def test_mutation_encoding_matrix_provider_delta_is_red(harness, bad_key):
    green = _healthy_summary(harness)
    poisoned = copy.deepcopy(green)
    poisoned["key_encoding_matrix"][bad_key]["provider_delta"] = 1
    assert harness.evaluate_r7_041_final_zip_gates(poisoned) == 8


@pytest.mark.parametrize("bad_key", KEY_ENCODING_KEYS)
def test_mutation_encoding_matrix_exit_is_red(harness, bad_key):
    green = _healthy_summary(harness)
    poisoned = copy.deepcopy(green)
    poisoned["key_encoding_matrix"][bad_key]["exit"] = 1
    assert harness.evaluate_r7_041_final_zip_gates(poisoned) == 8


@pytest.mark.parametrize("bad_key", KEY_ENCODING_KEYS)
def test_mutation_encoding_matrix_blocked_false_is_red(harness, bad_key):
    green = _healthy_summary(harness)
    poisoned = copy.deepcopy(green)
    poisoned["key_encoding_matrix"][bad_key]["blocked"] = False
    assert harness.evaluate_r7_041_final_zip_gates(poisoned) == 8


def test_mutation_mixed_prompt_aggregate_cannot_replace_encoding_matrix(harness):
    """A single mixed-prompt total delta must not satisfy the six-cell matrix gate."""
    green = _healthy_summary(harness)
    poisoned = dict(green)
    del poisoned["key_encoding_matrix"]
    # Aggregate-only shape that previously claimed all encodings were covered.
    poisoned["key_block_exit"] = 0
    poisoned["key_block_provider_delta"] = 0
    assert harness.evaluate_r7_041_final_zip_gates(poisoned) != 0


def test_mutation_extra_encoding_matrix_key_is_red(harness):
    green = _healthy_summary(harness)
    poisoned = copy.deepcopy(green)
    poisoned["key_encoding_matrix"]["mixed"] = {
        "exit": 0,
        "blocked": True,
        "provider_delta": 0,
    }
    assert harness.evaluate_r7_041_final_zip_gates(poisoned) == 8


def test_json_escape_fixture_authenticity_gate(harness):
    """JSON cell must lack raw PEM markers and rely on JSON-unescape recovery."""
    from credential_guard import sensitive_paths as sp

    _pem, materials = harness.build_key_encoding_materials()
    harness.assert_json_escape_fixture_authentic(materials["json_escape"], sp)


def test_legacy_json_dumps_fixture_fails_authenticity_gate(harness):
    """Historical json.dumps(pem)[1:-1] keeps raw markers → authenticity RED."""
    from credential_guard import sensitive_paths as sp

    pem, _std, _url = harness.urlsafe_distinct_synthetic_pem_b64()
    legacy = harness.legacy_json_dumps_escape(pem)
    with pytest.raises(AssertionError, match="RAW_MARKER_PRESENT"):
        harness.assert_json_escape_fixture_authentic(legacy, sp)


def test_mutation_installed_zip_json_unescape_seam_is_red(harness):
    """Disabling installed-ZIP ``_try_json_unescape`` must miss the JSON fixture."""
    plugin_zip = harness.resolve_plugin_zip()
    _pem, materials = harness.build_key_encoding_materials()
    material = materials["json_escape"]
    # Precondition: authentic fixture (no raw pre-hit).
    from credential_guard import sensitive_paths as sp_src

    harness.assert_json_escape_fixture_authentic(material, sp_src)
    proof = harness.prove_installed_json_unescape_seam_load_bearing(
        plugin_zip, material
    )
    assert proof["json_unescape_disabled_contains_false"] is True
    assert proof["installed_from_zip"] is True
    assert proof["raw_marker_absent"] is True
    assert "cg-r7-041-json-seam-mut-" in proof["installed_module_file"]
