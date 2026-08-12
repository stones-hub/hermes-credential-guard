"""R6 4b: 0.4.0 installed-ZIP full wire matrix (opt-in; NOT in no-build corpus).

Closes KNOWN_GAP_1: manifest↔registry parity on the packaged artifact, plus the
3 adapters × 5 outcomes (approve/deny/timeout/mutate/replay) wire matrix.

Executed only through ``scripts/run_r6_installed_zip_tests.py``. Exclusion from
the default ``tests/test_*.py`` corpus is self-proven by
``tests/test_r6_installed_zip_optin_gate.py``.
"""

from __future__ import annotations

import hashlib
import importlib.util
import shutil
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts" / "run_r6_installed_zip_e2e.py"
ZIP_HELPERS = ROOT / "scripts" / "installed_zip_plugin.py"
PINNED_ZIP = ROOT / "dist" / "credential-guard-0.4.0-hermes-plugin.zip"
PINNED_SHA256 = (
    "1fbc8c38da81226ef8a98f50702f2b3f5b369c5ce4767b8d0de8b2aaad20908d"
)


def _load_harness():
    spec = importlib.util.spec_from_file_location(
        "run_r6_installed_zip_e2e_matrix", HARNESS
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_helpers():
    spec = importlib.util.spec_from_file_location(
        "installed_zip_plugin_matrix", ZIP_HELPERS
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def matrix_summary():
    """One isolated ZIP install + full 15-cell matrix shared by positive tests."""
    harness = _load_harness()
    work = Path(tempfile.mkdtemp(prefix="r6s4b-matrix-"))
    try:
        summary = harness.run_wire_matrix(work)
        harness.evaluate_wire_matrix(summary)
        yield summary
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_matrix_defines_exactly_fifteen_cells():
    harness = _load_harness()
    assert len(harness.MATRIX_SCENARIOS) == 15
    assert len(harness.MATRIX_ADAPTERS) == 3
    assert len(harness.MATRIX_OUTCOMES) == 5
    expected = {
        f"{a}_{o}"
        for a in ("http", "env", "stdin")
        for o in ("approve", "deny", "timeout", "mutate", "replay")
    }
    assert set(harness.MATRIX_SCENARIOS) == expected


def test_manifest_registry_equal_on_installed_zip(matrix_summary):
    mr = matrix_summary["manifest_registry"]
    assert mr["sets_equal"] is True
    assert mr["manifest_tools"] == mr["registry_tools"]
    assert set(mr["manifest_tools"]) == {
        "credential_process_run",
        "http_credential_request",
    }
    assert mr["sanity_match"] is True
    # Loaded register must come from the installed plugin copy, not source tree.
    loaded = Path(mr["loaded_register_file"]).resolve()
    plugin_dest = Path(matrix_summary["plugin_dest"]).resolve()
    assert plugin_dest in loaded.parents
    assert ROOT.resolve() not in loaded.parents


def test_mutation_m_a1_manifest_declares_extra_tool_is_red(tmp_path: Path):
    """M-A1: copy's plugin.yaml gains a tool register() lacks → consistency RED."""
    harness = _load_harness()
    hermes = tmp_path / "hermes"
    hermes.mkdir()
    plugin_dest = harness.install_pinned_zip(hermes, extract_root=tmp_path / "ex")
    # Mutate the unpacked COPY only — never dist/.
    yaml_path = plugin_dest / "plugin.yaml"
    original = yaml_path.read_text(encoding="utf-8")
    assert "phantom_undeclared_tool" not in original
    yaml_path.write_text(
        original.rstrip() + "\n  - phantom_undeclared_tool\n", encoding="utf-8"
    )
    # Dist ZIP identity must remain untouched.
    assert hashlib.sha256(PINNED_ZIP.read_bytes()).hexdigest() == PINNED_SHA256
    with pytest.raises(AssertionError, match="manifest↔registry tool-set mismatch"):
        harness.check_manifest_registry_consistency(plugin_dest)


def test_mutation_m_a2_registry_extra_tool_is_red(tmp_path: Path):
    """M-A2: register() exposes a tool manifest lacks → consistency RED."""
    harness = _load_harness()
    hermes = tmp_path / "hermes"
    hermes.mkdir()
    plugin_dest = harness.install_pinned_zip(hermes, extract_root=tmp_path / "ex")
    real_register, _loaded = harness.load_register_from_plugin(plugin_dest)

    def register_with_extra(ctx):
        real_register(ctx)
        ctx.register_tool(
            name="phantom_runtime_only_tool",
            toolset="credential-guard",
            schema={"name": "phantom_runtime_only_tool"},
            handler=lambda *a, **k: None,
            check_fn=lambda: True,
            description="mutation phantom",
        )

    with pytest.raises(AssertionError, match="manifest↔registry tool-set mismatch"):
        harness.check_manifest_registry_consistency(
            plugin_dest, register_fn=register_with_extra
        )


@pytest.mark.parametrize(
    "scenario",
    [
        f"{a}_{o}"
        for a in ("http", "env", "stdin")
        for o in ("approve", "deny", "timeout", "mutate", "replay")
    ],
)
def test_matrix_cell_green(matrix_summary, scenario):
    cell = matrix_summary["cells"][scenario]
    assert cell["cell_ok"] is True
    forms = cell["provider_encoding_forms"]
    for key in ("plain", "percent", "quote_plus", "base64", "urlsafe_base64"):
        assert forms[key] == 0, (scenario, key, forms)


def test_timeout_distinct_from_deny(matrix_summary):
    for adapter in ("http", "env", "stdin"):
        timeout = matrix_summary["cells"][f"{adapter}_timeout"]
        deny = matrix_summary["cells"][f"{adapter}_deny"]
        assert timeout["approval_outcome"] == "timeout"
        assert deny["approval_outcome"] == "denied"
        assert timeout["approval_is_timeout"] is True
        assert timeout["approval_message"] != deny["approval_message"]
        assert timeout["injection_resolve_delta"] == 0
        assert deny["injection_resolve_delta"] == 0


def test_replay_identity_quad_stable(matrix_summary):
    for adapter in ("http", "env", "stdin"):
        cell = matrix_summary["cells"][f"{adapter}_replay"]
        assert cell["replay_identity_same"] is True
        assert cell["replay_closed"] is True
        ids = cell["tool_request_identities"]
        assert len(ids) >= 2
        for key in ("session_id", "turn_id", "tool_call_id", "args_digest"):
            assert ids[0][key]
            assert ids[0][key] == ids[1][key]


def test_mutation_m_b1_target_hits_points_at_never_fired_counter_is_red(
    matrix_summary,
):
    """M-B1: redirect one approve cell's target-hit assertion to a zero counter."""
    harness = _load_harness()
    raw = matrix_summary["raw"]["http_approve"]
    # Reconstruct a minimal result dict for evaluate_matrix_cell.
    r = {
        **raw,
        "token_in_approval_raw": 0,
        "token_in_result": 0,
        "trace_secret_count": 0,
        "wire_secret_count": raw.get("wire_secret_count") or 0,
        "token_in_provider_raw": 0,
        "http_adapter_delta": 1,
        "process_start_delta": 0,
        "host_approval_raw": {},
        "result2_preview": "",
        "counts": {},
    }
    # The green path must still pass with the real key.
    harness.evaluate_matrix_cell(r, adapter="http", outcome="approve")
    # Point at a counter that stays 0 on a successful approve → RED.
    with pytest.raises(AssertionError):
        harness.evaluate_matrix_cell(
            r,
            adapter="http",
            outcome="approve",
            target_hits_key="non_loopback_original_calls",
        )


def test_loopback_and_isolation(matrix_summary):
    assert matrix_summary["loopback_ok"] is True
    assert matrix_summary["non_loopback_original_calls_total"] == 0
    assert matrix_summary["net_violations_total"] == 0
    home = matrix_summary["home"]
    hermes = matrix_summary["hermes_home"]
    assert home.startswith(
        ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders")
    )
    assert hermes.startswith(
        ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders")
    )
    worker = (Path.home() / ".hermes" / "profiles" / "worker").resolve()
    assert Path(hermes).resolve() != worker
    assert "profiles/worker" not in hermes


def test_matrix_summary_all_fifteen_ok(matrix_summary):
    assert matrix_summary["cells_ok_count"] == 15
    assert matrix_summary["cells_expected"] == 15
    assert hashlib.sha256(PINNED_ZIP.read_bytes()).hexdigest() == PINNED_SHA256
