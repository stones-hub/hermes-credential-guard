"""Self-proving gates for the R7 0.4.1 final-ZIP E2E opt-in boundary."""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NOBUILD_RUNNER = ROOT / "scripts" / "run_r5_nobuild_pytest.py"
OPTIN_RUNNER = ROOT / "scripts" / "run_r7_041_final_zip_tests.py"
E2E_MODULE_REL = "tests/r7_041_final_zip_e2e.py"
HARNESS_REL = "scripts/run_r7_041_final_zip_e2e.py"


def _load_nobuild_runner():
    spec = importlib.util.spec_from_file_location(
        "run_r5_nobuild_pytest", NOBUILD_RUNNER
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_optin_runner():
    spec = importlib.util.spec_from_file_location(
        "run_r7_041_final_zip_tests", OPTIN_RUNNER
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_r7_041_e2e_module_exists_but_is_outside_default_corpus():
    runner = _load_nobuild_runner()
    corpus = list(runner.list_allowed_corpus(ROOT))
    assert E2E_MODULE_REL not in corpus
    globbed = {
        p.relative_to(ROOT).as_posix()
        for p in sorted((ROOT / "tests").rglob("test_*.py"))
    }
    assert E2E_MODULE_REL not in globbed
    assert (ROOT / E2E_MODULE_REL).is_file()


def test_optin_runner_owns_selection_and_never_authorizes_build():
    optin = _load_optin_runner()
    assert tuple(optin.E2E_MODULES) == (E2E_MODULE_REL,)
    argv = optin.build_pytest_argv([])
    assert argv[-1] == E2E_MODULE_REL
    env = optin.build_env({"PATH": "/usr/bin", "CG_R6_BUILD_AUTHORIZED": "1"})
    assert "CG_R6_BUILD_AUTHORIZED" not in env
    assert env["CG_NO_BUILD_TRIPWIRE"] == "1"
    for bad in ("-m", "not real_build", "tests/test_r5_wire_e2e.py", "-k=x"):
        try:
            optin.build_pytest_argv([bad])
        except optin.R7FinalZipRunnerArgError:
            continue
        raise AssertionError(f"opt-in runner accepted selection argument: {bad!r}")


def test_harness_pins_041_zip_and_coverage_boundary():
    src = (ROOT / HARNESS_REL).read_text(encoding="utf-8")
    assert "credential-guard-0.4.1-hermes-plugin.zip" in src
    assert "evaluate_r7_041_final_zip_gates" in src
    assert "COVERAGE_BOUNDARY_MAIN" in src
    assert "COVERAGE_BOUNDARY_AUXILIARY" in src
    assert "installed_zip_plugin" in src
    assert "title_generation_disabled_is_isolation_only" in src
    assert "key_encoding_matrix" in src
    assert "KEY_ENCODING_KEYS" in src
    assert "fail_closed_has_block_msg" in src
    assert "opaque_token_smoke" in src
    assert "installed_module_file_under_plugin" in src
    assert "installed_key_urlsafe_provider_calls" in src
    # Must not claim global protection.
    assert "protects all Hermes model calls" not in src.lower()
    tree = ast.parse(src)
    assert isinstance(tree, ast.Module)
