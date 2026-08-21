"""R6 4a: release installed-ZIP approval chain (opt-in; NOT in the no-build corpus).

Why this file is not named ``tests/test_*.py``
----------------------------------------------
Same boundary as ``tests/r6_real_build_check.py``: the no-build runner owns
selection via the fixed glob ``tests/test_*.py`` and refuses ``-m``/``-k``.
This E2E unpacks a ZIP and drives an isolated Hermes wire path — too heavy
(and side-effecting) for the default full run. It is executed only through
``scripts/run_r6_installed_zip_tests.py``. The exclusion is self-proven by
``tests/test_r6_installed_zip_optin_gate.py``.

This module does NOT flip ``test_r5_wire_full_main_chain_placeholder`` (4b).
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
    "a2d44717edee766f861e3484bbe051e14377409ed274c595ff0786d3b7a9f0e3"
)


def _load_harness():
    spec = importlib.util.spec_from_file_location("run_r6_installed_zip_e2e", HARNESS)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_helpers():
    spec = importlib.util.spec_from_file_location("installed_zip_plugin", ZIP_HELPERS)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def chain_summary():
    """One isolated install + five-scenario wire run shared by positive assertions."""
    harness = _load_harness()
    work = Path(tempfile.mkdtemp(prefix="r6s4a-chain-"))
    try:
        summary = harness.run_approval_chain(work)
        harness.evaluate_approval_chain(summary)
        yield summary
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_pinned_zip_identity_matches_expected():
    harness = _load_harness()
    path = harness.resolve_plugin_zip()
    assert path == PINNED_ZIP.resolve() or path.resolve() == PINNED_ZIP.resolve()
    digest = hashlib.sha256(PINNED_ZIP.read_bytes()).hexdigest()
    assert digest == PINNED_SHA256


def test_zip_identity_mismatch_on_one_byte_copy_is_red(tmp_path: Path):
    """Changing one byte of a ZIP copy must fail the identity gate."""
    harness = _load_harness()
    dist = tmp_path / "dist"
    dist.mkdir()
    victim = dist / harness.EXPECTED_PLUGIN_ZIP
    raw = bytearray(PINNED_ZIP.read_bytes())
    raw[-1] = (raw[-1] + 1) % 256
    victim.write_bytes(bytes(raw))
    bad = hashlib.sha256(victim.read_bytes()).hexdigest()
    assert bad != PINNED_SHA256
    with pytest.raises(AssertionError, match="identity mismatch"):
        harness.resolve_plugin_zip(repo=tmp_path)


def test_installed_from_zip_path_and_module_digest(chain_summary):
    s = chain_summary
    assert s["installed_from_zip"] is True
    assert s["plugin_path_is_source_tree"] is False
    loaded = Path(s["loaded_module_file"]).resolve()
    plugin_dest = Path(s["plugin_dest"]).resolve()
    assert plugin_dest in loaded.parents
    assert ROOT.resolve() not in loaded.parents
    assert s["key_module_match"]["sha256"]
    # Cross-check against the ZIP member directly.
    helpers = _load_helpers()
    member_digest = helpers.zip_member_sha256(
        PINNED_ZIP, "credential-guard/credential_guard/__init__.py"
    )
    assert s["key_module_match"]["sha256"] == member_digest


def test_mutation_m_a1_source_tree_load_is_red(tmp_path: Path):
    """M-A1: forcing the load path back onto the repo source tree must RED."""
    helpers = _load_helpers()
    harness = _load_harness()
    # Install ZIP into an isolated plugin dir (legitimate install).
    hermes = tmp_path / "hermes"
    hermes.mkdir()
    plugin_dest = harness.install_pinned_zip(hermes, extract_root=tmp_path / "ex")
    # Deliberately load from the source tree instead.
    source_cg = ROOT / "credential_guard" / "sensitive_paths.py"
    assert source_cg.is_file()
    proof = helpers.prove_installed_module_path(plugin_dest, ROOT, source_cg)
    assert proof["installed_from_zip"] is False
    assert proof["installed_module_file_under_source_tree"] is True

    # The same contract evaluate_approval_chain uses must reject this proof.
    with pytest.raises(AssertionError, match="installed_from_zip"):
        if proof.get("installed_from_zip") is not True:
            raise AssertionError(f"installed_from_zip proof failed: {proof}")


def test_three_approve_paths(chain_summary):
    s = chain_summary
    for name in ("http_approve", "env_approve", "stdin_approve"):
        r = s["scenarios"][name]
        assert int(r["approval_raw_count"] or 0) >= 1, name
        assert int(r["injection_resolve_delta"] or 0) == 1, name
        assert int(r["wire_secret_count"] or 0) == 0, name
        assert int(r["token_in_provider_raw"] or 0) == 0, name
        assert int(r["token_in_result"] or 0) == 0, name
        if name == "http_approve":
            assert int(r["http_target_hits"] or 0) == 1
            assert int(r["http_target_auth_applied"] or 0) == 1
        else:
            assert r["marker_ok"] is True
            assert int(r["process_start_delta"] or 0) == 1


def test_encoding_forms_zero_on_installed_middleware(chain_summary):
    forms = chain_summary["encoding_probe"]["encoding_forms"]
    for key in ("plain", "percent", "quote_plus", "base64", "urlsafe_base64"):
        assert key in forms
        assert forms[key] == 0, (key, forms)


def test_result_echo_redacted(chain_summary):
    echo = chain_summary["result_echo_redaction"]
    assert echo["echo_secret_count_in_model_view"] == 0
    assert echo["redacted_ok"] is True


def test_deny_and_mutate_fail_closed(chain_summary):
    deny = chain_summary["scenarios"]["http_deny"]
    assert int(deny["injection_resolve_delta"] or 0) == 0
    assert int(deny["http_target_hits"] or 0) == 0
    assert deny["approval_outcome"] == "denied"

    mut = chain_summary["scenarios"]["http_mutate"]
    assert int(mut["injection_resolve_delta"] or 0) == 0
    assert int(mut["http_target_hits"] or 0) == 0
    assert mut["plan_state"] == "invalidated"


def test_loopback_only(chain_summary):
    assert chain_summary["loopback_ok"] is True
    assert chain_summary["non_loopback_original_calls_total"] == 0
    assert chain_summary["net_violations_total"] == 0
    home = chain_summary["home"]
    hermes = chain_summary["hermes_home"]
    assert home.startswith(("/tmp", "/private/tmp", "/var/folders", "/private/var/folders"))
    assert hermes.startswith(
        ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders")
    )


def test_mutation_m_b1_vacuous_needle_is_red():
    """M-B1: pointing the zero-appearance check at an empty needle must RED.

    Guards against a vacuous ``blob.count("") == 0`` style pass.
    """
    helpers = _load_helpers()
    with pytest.raises(AssertionError, match="vacuous needle"):
        helpers.assert_secret_absent_in_blob(b"harmless-provider-body", "")


def test_isolation_declaration(chain_summary):
    """Documented hard boundary: iso homes only; no worker / ssh / real targets."""
    home = Path(chain_summary["home"]).resolve()
    hermes = Path(chain_summary["hermes_home"]).resolve()
    worker = (Path.home() / ".hermes" / "profiles" / "worker").resolve()
    ssh = (Path.home() / ".ssh").resolve()
    assert hermes != worker
    assert worker not in hermes.parents
    assert ssh not in hermes.parents
    assert "profiles/worker" not in str(hermes)
    assert str(home).startswith(
        ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders")
    )
