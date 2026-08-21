"""Self-proving gates for the R6 installed-ZIP E2E opt-in boundary.

Same shape as ``tests/test_r6_build_optin_gate.py``: the E2E modules are named
outside the no-build runner's ``tests/test_*.py`` glob, and a dedicated runner
is the only sanctioned entry. This file inspects those paths as text/AST and
never imports the E2E modules (importing would pull ZIP install + wire helpers
into the default corpus graph).
"""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NOBUILD_RUNNER = ROOT / "scripts" / "run_r5_nobuild_pytest.py"
OPTIN_RUNNER = ROOT / "scripts" / "run_r6_installed_zip_tests.py"
E2E_MODULE_RELS = (
    "tests/r6_installed_zip_approval_chain.py",
    "tests/r6_installed_zip_wire_matrix.py",
)
E2E_MODULE_REL = E2E_MODULE_RELS[0]  # 4a module (back-compat)
E2E_MODULE = ROOT / E2E_MODULE_REL
HARNESS_REL = "scripts/run_r6_installed_zip_e2e.py"


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
        "run_r6_installed_zip_tests", OPTIN_RUNNER
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_installed_zip_e2e_modules_exist_but_are_outside_default_corpus():
    runner = _load_nobuild_runner()
    corpus = list(runner.list_allowed_corpus(ROOT))
    assert corpus, "default corpus unexpectedly empty"

    globbed = {
        p.relative_to(ROOT).as_posix()
        for p in sorted((ROOT / "tests").rglob("test_*.py"))
    }
    assert set(corpus) == globbed

    for rel in E2E_MODULE_RELS:
        path = ROOT / rel
        assert path.is_file(), rel
        assert rel not in corpus, (
            f"installed-ZIP E2E module leaked into the default no-build corpus: {rel}"
        )
        assert rel not in globbed


def test_optin_runner_owns_selection_and_never_authorizes_build():
    optin = _load_optin_runner()
    assert tuple(optin.E2E_MODULES) == E2E_MODULE_RELS
    argv = optin.build_pytest_argv([])
    assert argv[-2:] == list(E2E_MODULE_RELS) or argv[-len(E2E_MODULE_RELS) :] == list(
        E2E_MODULE_RELS
    )
    assert not any(a == "-m" or a == "-k" for a in argv)

    env = optin.build_env({"PATH": "/usr/bin", "CG_R6_BUILD_AUTHORIZED": "1"})
    assert "CG_R6_BUILD_AUTHORIZED" not in env
    assert env["CG_NO_BUILD_TRIPWIRE"] == "1"

    for bad in ("-m", "not real_build", "tests/test_r5_wire_e2e.py", "-k=x"):
        try:
            optin.build_pytest_argv([bad])
        except optin.R6InstalledZipRunnerArgError:
            continue
        raise AssertionError(f"opt-in runner accepted a selection argument: {bad!r}")


def test_harness_pins_expected_zip_sha256():
    src = (ROOT / HARNESS_REL).read_text(encoding="utf-8")
    assert "125af9a681f65900a04edb51099ec52a1ebb01001f4396ab85770875a5951611" in src
    assert "credential-guard-0.4.5-hermes-plugin.zip" in src
    tree = ast.parse(src)
    assert isinstance(tree, ast.Module)
    # Must reuse the shared installer, not re-implement extract/copytree.
    assert "installed_zip_plugin" in src
    assert "run_r3c_wire_e2e" in src  # wraps frozen carrier; does not edit it
    assert "MATRIX_SCENARIOS" in src
    assert "check_manifest_registry_consistency" in src


def test_wire_matrix_module_is_outside_default_corpus_and_owned_by_runner():
    """4b matrix module must stay opt-in (same boundary as 4a)."""
    matrix_rel = "tests/r6_installed_zip_wire_matrix.py"
    assert (ROOT / matrix_rel).is_file()
    runner = _load_nobuild_runner()
    corpus = list(runner.list_allowed_corpus(ROOT))
    assert matrix_rel not in corpus
    optin = _load_optin_runner()
    assert matrix_rel in optin.E2E_MODULES


def test_gap1_placeholder_flip_points_at_matrix_entry():
    """After 4b, the former placeholder asserts the matrix entry exists."""
    ph_src = (ROOT / "tests" / "test_r5_wire_e2e.py").read_text(encoding="utf-8")
    assert "test_r5_wire_full_main_chain_placeholder" not in ph_src
    assert "test_r5_wire_full_main_chain_matrix_closed" in ph_src
    assert "assert False" not in ph_src
    assert "MATRIX_SCENARIOS" in ph_src or "r6_installed_zip" in ph_src
