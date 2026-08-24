"""R6 4b: release installed-ZIP full wire matrix (opt-in; NOT in no-build corpus).

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
PINNED_ZIP = ROOT / "dist" / "credential-guard-0.4.5-hermes-plugin.zip"
PINNED_SHA256 = (
    "399d9c8712d2e567fc2f0708d4bcd9bdc16c81b466a06f203a7ec30c7919b34c"
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
    """Timeout and deny must remain distinguishable, on observer-free evidence.

    R5 THREAD-MODEL ADAPTATION: ``approval_outcome`` / ``approval_is_timeout``
    are derived from the carrier's profiler counter, which cannot see the worker
    thread Hermes now dispatches tools on, so both collapse to "non_timeout".
    The host's own approval record is written by the approval chain itself and
    stays truthful; it is asserted here instead. Guarded by
    ``test_mutation_timeout_deny_distinction_must_red``.
    """
    for adapter in ("http", "env", "stdin"):
        timeout = matrix_summary["cells"][f"{adapter}_timeout"]
        deny = matrix_summary["cells"][f"{adapter}_deny"]
        t_msg = timeout["host_approval_message"]
        d_msg = deny["host_approval_message"]
        assert "timed out without user response" in t_msg, (adapter, t_msg)
        assert "Silence is not consent" in t_msg, (adapter, t_msg)
        assert "timed out without user response" not in d_msg, (adapter, d_msg)
        assert t_msg != d_msg, adapter
        # Neither path may resolve the credential.
        assert timeout["injection_resolve_delta"] == 0
        assert deny["injection_resolve_delta"] == 0
        assert timeout["target_hits"] == 0
        assert deny["target_hits"] == 0


def test_replay_identity_quad_stable(matrix_summary):
    """Replay must be closed, asserted on whole-run production totals.

    R5 THREAD-MODEL ADAPTATION: ``replay_identity_same`` / ``replay_closed`` /
    ``tool_request_identities`` are profiler-derived and empty under the worker
    thread model, so the historical identity-quad comparison cannot run. The
    scenario issues TWO calls on the same reference, so an OPEN replay is
    directly observable in the totals: resolve would be 2, the adapter would run
    twice, and the loopback peer would be hit twice. Guarded by
    ``test_mutation_replay_totals_distinction_must_red``.
    """
    for adapter in ("http", "env", "stdin"):
        cell = matrix_summary["cells"][f"{adapter}_replay"]
        assert cell["injection_resolve_delta"] == 1, adapter
        assert cell["target_hits"] == 1, adapter
        if adapter == "http":
            assert cell["http_adapter_delta"] == 1, adapter
            assert cell["process_start_delta"] == 0, adapter
        else:
            assert cell["process_start_delta"] == 1, adapter
            assert cell["http_adapter_delta"] == 0, adapter
        assert "REFERENCE_PATH_BLOCKED" in (cell["result2_preview"] or ""), adapter


def test_mutation_timeout_deny_distinction_must_red(matrix_summary):
    """The timeout/deny split must fail when the two records are made identical."""
    for adapter in ("http", "env", "stdin"):
        t_msg = matrix_summary["cells"][f"{adapter}_timeout"]["host_approval_message"]
        d_msg = matrix_summary["cells"][f"{adapter}_deny"]["host_approval_message"]

        def _check(a: str, b: str) -> None:
            assert "timed out without user response" in a
            assert "Silence is not consent" in a
            assert "timed out without user response" not in b
            assert a != b

        _check(t_msg, d_msg)
        # Deny record forged to look like a timeout -> must raise.
        with pytest.raises(AssertionError):
            _check(t_msg, t_msg)
        # Timeout record degraded to the deny text -> must raise.
        with pytest.raises(AssertionError):
            _check(d_msg, d_msg)


def test_mutation_replay_totals_distinction_must_red(matrix_summary):
    """An open replay must be detectable in the totals this test now asserts."""
    for adapter in ("http", "env", "stdin"):
        cell = matrix_summary["cells"][f"{adapter}_replay"]

        def _check(c: dict) -> None:
            assert c["injection_resolve_delta"] == 1
            assert c["target_hits"] == 1
            if adapter == "http":
                assert c["http_adapter_delta"] == 1
            else:
                assert c["process_start_delta"] == 1

        _check(cell)
        # Each shape below is a real "the second call executed" reading.
        for key in ("injection_resolve_delta", "target_hits"):
            with pytest.raises(AssertionError):
                _check({**cell, key: 2})
        exec_key = "http_adapter_delta" if adapter == "http" else "process_start_delta"
        with pytest.raises(AssertionError):
            _check({**cell, exec_key: 2})


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
