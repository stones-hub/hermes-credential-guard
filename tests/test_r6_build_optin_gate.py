"""Self-proving gates for the R6 real-build opt-in boundary.

Task 禁 2 / acceptance item 7 require that the real double-build test exists,
is genuinely a build, and is *structurally* excluded from the default no-build
corpus — with the exclusion itself proven, not asserted by comment.

Why the exclusion boundary is a filename and not a marker
---------------------------------------------------------
The suggested design was ``@pytest.mark.real_build`` plus ``-m "not
real_build"`` in ``scripts/run_r5_nobuild_pytest.py``. That is structurally
impossible here:

* the runner owns selection and refuses ``-m``/``-k``/paths/nodeids
  (``R5_NOBUILD_ARGREJECT``), so the exclusion expression could never be
  passed;
* ``DEFAULT_IGNORE`` and ``EXCLUDED_BUILD_MODULES`` are pinned empty by
  ``tests/test_r5_nobuild_runner_gate.py``;
* the corpus is the fixed glob ``tests/test_*.py`` and the fail-closed AST
  preflight rejects the *whole* run when any collected module can reach the
  release builder — a marker would not stop collection, so the default suite
  would become exit 2 rather than merely skipping the test.

The task explicitly sanctions an equivalent scheme. The one used is the
filename: the real-build module is ``tests/r6_real_build_check.py``, outside
the runner's glob, executed only by ``scripts/run_r6_build_tests.py``.

This module inspects both files as *text* (``read_text`` + ``ast``). It never
imports them — importing would enqueue them into this module's own local
import graph and make the default corpus reach the builder.
"""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NOBUILD_RUNNER = ROOT / "scripts" / "run_r5_nobuild_pytest.py"
OPTIN_RUNNER = ROOT / "scripts" / "run_r6_build_tests.py"
REAL_BUILD_MODULE_REL = "tests/r6_real_build_check.py"
REAL_BUILD_MODULE = ROOT / REAL_BUILD_MODULE_REL

# The runner's own idiom: never spell the call as a string constant, or the
# runner's module-wide constant scan would flag this very file.
_BUILD_ALL = "build" + "_all"
_BUILD_CALL = "." + _BUILD_ALL + "("
_BUILDER_MODULE_NAME = "build_release" + "_artifacts"


def _load_nobuild_runner():
    """Load the no-build runner by path (same safe idiom as the R5 gate)."""
    spec = importlib.util.spec_from_file_location(
        "run_r5_nobuild_pytest", NOBUILD_RUNNER
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_optin_runner():
    spec = importlib.util.spec_from_file_location("run_r6_build_tests", OPTIN_RUNNER)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Gate 1 — the real-build module is outside the default corpus.
# ---------------------------------------------------------------------------


def test_real_build_module_exists_but_is_outside_default_corpus():
    assert REAL_BUILD_MODULE.is_file(), REAL_BUILD_MODULE_REL

    runner = _load_nobuild_runner()
    corpus = list(runner.list_allowed_corpus(ROOT))
    assert corpus, "default corpus unexpectedly empty"
    assert REAL_BUILD_MODULE_REL not in corpus, (
        "real-build module leaked into the default no-build corpus"
    )

    # The boundary is the filename: it must not match the runner's glob.
    globbed = {
        p.relative_to(ROOT).as_posix() for p in sorted((ROOT / "tests").rglob("test_*.py"))
    }
    assert REAL_BUILD_MODULE_REL not in globbed
    assert set(corpus) == globbed, "corpus is no longer exactly the tests/test_*.py glob"


def test_default_corpus_is_build_free_including_this_gate():
    """The live default corpus (which contains this file) reaches no builder."""
    runner = _load_nobuild_runner()
    corpus = list(runner.list_allowed_corpus(ROOT))
    assert Path(__file__).relative_to(ROOT).as_posix() in corpus
    runner.preflight_no_build(corpus, repo=ROOT)  # must not raise


# ---------------------------------------------------------------------------
# Gate 2 — the opt-in set is non-empty and really builds.
# ---------------------------------------------------------------------------


def _real_build_tree() -> ast.Module:
    return ast.parse(REAL_BUILD_MODULE.read_text(encoding="utf-8"))


def test_real_build_module_really_invokes_the_builder():
    """Guard against a silently empty opt-in set (e.g. a typo'd module)."""
    source = REAL_BUILD_MODULE.read_text(encoding="utf-8")
    assert _BUILD_CALL in source, "real-build module never calls the builder"
    assert _BUILDER_MODULE_NAME in source, "real-build module never names the builder"

    tree = _real_build_tree()
    test_funcs = [
        node.name
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    ]
    assert len(test_funcs) >= 3, test_funcs
    assert "test_real_double_build_is_byte_identical" in test_funcs

    # It must compare bytes, not sizes or member names (task 禁 3).
    assert "sha256" in source
    # It must never target the repository dist/ (task 禁 1).
    assert "tempfile.mkdtemp" in source
    assert "FORBIDDEN_OUT_DIR" in source


def test_optin_runner_owns_the_only_authorization_channel():
    optin = _load_optin_runner()
    assert optin.REAL_BUILD_MODULE == REAL_BUILD_MODULE_REL
    argv = optin.build_pytest_argv([])
    assert argv[-1] == REAL_BUILD_MODULE_REL
    assert not any(a == "-m" or a == "-k" for a in argv)

    env = optin.build_env({"PATH": "/usr/bin"})
    assert env["CG_R6_BUILD_AUTHORIZED"] == "1"
    assert env["CG_NO_BUILD_TRIPWIRE"] == "1"

    # Selection stays owned by the runner.
    for bad in ("-m", "not real_build", "tests/test_reproducible_release.py", "-k=x"):
        try:
            optin.build_pytest_argv([bad])
        except optin.R6RunnerArgError:
            continue
        raise AssertionError(f"opt-in runner accepted a selection argument: {bad!r}")


def test_nobuild_runner_never_authorizes_a_build():
    """禁 2: the authorization variable is never *introduced* by the default path."""
    runner = _load_nobuild_runner()
    env = runner.sanitize_pytest_env({"PATH": "/usr/bin"})
    assert "CG_R6_BUILD_AUTHORIZED" not in env
    assert env["CG_NO_BUILD_TRIPWIRE"] == "1"

    nobuild_src = NOBUILD_RUNNER.read_text(encoding="utf-8")
    assert "CG_R6_BUILD_AUTHORIZED" not in nobuild_src

    for name in ("pytest.ini", "conftest.py", "tests/conftest.py", ".envrc"):
        path = ROOT / name
        if path.is_file():
            assert "CG_R6_BUILD_AUTHORIZED" not in path.read_text(encoding="utf-8"), name


def test_nobuild_runner_strips_ambient_authorization_and_keeps_tripwire_armed():
    """Ambient ``CG_R6_BUILD_AUTHORIZED`` must not reach the default pytest env.

    R6 slice 3 closes the slice-2 residual: ``sanitize_pytest_env`` strips any
    inherited authorization so a caller shell export cannot silently open the
    tripwire's second layer. The tripwire itself must remain armed after the
    strip (popping authorization must not also disarm ``CG_NO_BUILD_TRIPWIRE``).
    """
    runner = _load_nobuild_runner()
    env = runner.sanitize_pytest_env({"PATH": "/usr/bin", "CG_R6_BUILD_AUTHORIZED": "1"})
    assert "CG_R6_BUILD_AUTHORIZED" not in env, (
        "ambient build authorization must be stripped from the no-build env"
    )
    assert env.get("CG_NO_BUILD_TRIPWIRE") == "1", (
        "stripping authorization must not disarm the no-build tripwire"
    )


# ---------------------------------------------------------------------------
# Gate 3 — mutation: putting the real-build module back in the corpus is RED.
# ---------------------------------------------------------------------------


def test_mutation_including_real_build_module_in_corpus_is_rejected():
    """If the exclusion were removed, the preflight must fail closed."""
    runner = _load_nobuild_runner()
    mutated = list(runner.list_allowed_corpus(ROOT)) + [REAL_BUILD_MODULE_REL]

    hits = runner.transitive_build_reachability(mutated, repo=ROOT)
    assert hits, "AST preflight did not see the builder through the real-build module"
    assert any(REAL_BUILD_MODULE_REL in hit for hit in hits), hits

    try:
        runner.preflight_no_build(mutated, repo=ROOT)
    except runner.RunnerArgError as exc:
        assert _BUILD_ALL in str(exc)
    else:
        raise AssertionError(
            "preflight accepted a corpus containing the real-build module"
        )
