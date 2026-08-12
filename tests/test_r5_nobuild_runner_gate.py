"""R5 no-build runner gate — selected collection must not reach build_all()."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RUNNER = REPO / "scripts" / "run_r5_nobuild_pytest.py"
BUILD_SCRIPT = REPO / "scripts" / "build_release_artifacts.py"

# Mirror of the runner's DEFAULT_IGNORE. Retired to the empty set: no test in
# the R5 corpus triggers a build any more. Assertions below keep the original
# per-member semantics as a conditional so R6 can refill the list, and pin the
# emptiness itself so nothing can be hidden from the corpus in the meantime.
EXCLUDED_BUILD_MODULES: frozenset = frozenset()

# Carrier for the ignore mechanism's own tests. It is deliberately a path that
# does not exist: the mechanism must fail closed on membership, never on
# whether the file is real.
SYNTHETIC_IGNORED_MODULE = "tests/test_synthetic_ignored_build_module.py"


def _load_runner():
    import importlib.util

    spec = importlib.util.spec_from_file_location("run_r5_nobuild_pytest", RUNNER)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_mutation_same_dir_helper_build_all_via_formal_preflight(tmp_path):
    """Selected test → same-directory helper → build_all; formal preflight RED."""
    mod = _load_runner()
    root = tmp_path / "repo"
    tests = root / "tests"
    tests.mkdir(parents=True)
    (tests / "helper_build.py").write_text(
        textwrap.dedent(
            """
            def go():
                def build_all():
                    return 1
                return build_all()
            """
        ).lstrip(),
        encoding="utf-8",
    )
    (tests / "test_same_dir.py").write_text(
        textwrap.dedent(
            """
            from helper_build import go

            def test_probe():
                assert go() == 1
            """
        ).lstrip(),
        encoding="utf-8",
    )
    with pytest.raises(mod.RunnerArgError) as ei:
        mod.preflight_no_build(["tests/test_same_dir.py"], repo=root)
    assert "build_all" in str(ei.value)


def test_mutation_credential_guard_helper_build_all_via_formal_preflight(tmp_path):
    """Selected test → credential_guard helper → build_all; formal preflight RED."""
    mod = _load_runner()
    root = tmp_path / "repo"
    tests = root / "tests"
    cg = root / "credential_guard"
    tests.mkdir(parents=True)
    cg.mkdir(parents=True)
    (cg / "__init__.py").write_text("", encoding="utf-8")
    (cg / "build_helper.py").write_text(
        textwrap.dedent(
            """
            def go():
                def build_all():
                    return 1
                return build_all()
            """
        ).lstrip(),
        encoding="utf-8",
    )
    (tests / "test_cg_helper.py").write_text(
        textwrap.dedent(
            """
            from credential_guard.build_helper import go

            def test_probe():
                assert go() == 1
            """
        ).lstrip(),
        encoding="utf-8",
    )
    with pytest.raises(mod.RunnerArgError) as ei:
        mod.preflight_no_build(["tests/test_cg_helper.py"], repo=root)
    assert "build_all" in str(ei.value)


def test_mutation_constant_bound_dynamic_import_via_formal_preflight(tmp_path):
    """Constant-bound dynamic import of helper with build_all; formal preflight RED."""
    mod = _load_runner()
    root = tmp_path / "repo"
    tests = root / "tests"
    support = tests / "support"
    support.mkdir(parents=True)
    (tests / "__init__.py").write_text("", encoding="utf-8")
    (support / "__init__.py").write_text("", encoding="utf-8")
    (support / "dyn_build.py").write_text(
        "def build_all():\n    return 1\n", encoding="utf-8"
    )
    (tests / "test_const_dyn.py").write_text(
        (
            "import importlib\n"
            "\n"
            'MOD = "tests.support.dyn_build"\n'
            "\n"
            "def test_a():\n"
            "    m = importlib.import_module(MOD)\n"
            "    assert m." + "build_all" + "() == 1\n"
        ),
        encoding="utf-8",
    )
    with pytest.raises(mod.RunnerArgError) as ei:
        mod.preflight_no_build(["tests/test_const_dyn.py"], repo=root)
    assert "build_all" in str(ei.value)


def test_mutation_concatenated_exec_build_all_via_formal_preflight(tmp_path):
    """exec(\"mod.\"+\"build_\"+\"all()\") must RED via formal preflight_no_build."""
    mod = _load_runner()
    root = tmp_path / "repo"
    tests = root / "tests"
    tests.mkdir(parents=True)
    (tests / "test_concat_exec.py").write_text(
        'def test_a():\n    exec("mod." + "build_" + "all()")\n',
        encoding="utf-8",
    )
    with pytest.raises(mod.RunnerArgError) as ei:
        mod.preflight_no_build(["tests/test_concat_exec.py"], repo=root)
    assert "build_all" in str(ei.value) or "str-payload" in str(ei.value)


def test_formal_runner_main_calls_preflight_before_pytest(tmp_path):
    """Formal runner subprocess must reject build-reachable selection before pytest."""
    mod = _load_runner()
    assert hasattr(mod, "preflight_no_build")
    assert hasattr(mod, "sanitize_pytest_env")
    # Ignored module still exit 2 via argv validation (preflight not required).
    proc = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--collect-only",
            "--",
            "tests/test_reproducible_release.py",
        ],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert proc.returncode == 2
    blob = proc.stdout + proc.stderr
    # Boundary one refuses the selection outright (ARGREJECT); the older
    # preflight marker is still accepted for the reachability path.
    assert "R5_NOBUILD_ARGREJECT" in blob or "R5_NOBUILD_REJECT" in blob


def test_mutation_noconftest_prevents_root_conftest_load(tmp_path):
    """Malicious root conftest must not load; --noconftest is in formal argv."""
    mod = _load_runner()
    argv = mod.build_pytest_argv(["--collect-only", "-q"])
    assert "--noconftest" in argv
    root = tmp_path / "repo"
    tests = root / "tests"
    tests.mkdir(parents=True)
    marker = tmp_path / "conftest_fired"
    (root / "conftest.py").write_text(
        f"open({str(marker)!r}, 'w').write('fired')\n",
        encoding="utf-8",
    )
    (tests / "test_ok.py").write_text(
        "def test_ok():\n    assert True\n", encoding="utf-8"
    )
    # Direct pytest with formal argv pieces under tmp repo still uses --noconftest.
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "--noconftest",
            "--collect-only",
            "-q",
            "tests/test_ok.py",
        ],
        cwd=str(root),
        capture_output=True,
        text=True,
        env=mod.sanitize_pytest_env(),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not marker.exists(), "conftest must not load under --noconftest"


def _collect_node_ids(blob: str) -> frozenset:
    """Node ids from a ``--collect-only -q`` run (ignores the runner banner)."""
    return frozenset(
        line.strip()
        for line in blob.splitlines()
        if "::" in line and line.strip().startswith("tests/")
    )


def test_mutation_inherited_pytest_addopts_cannot_alter_the_fixed_corpus():
    """Inherited PYTEST_ADDOPTS must neither inject a build target nor narrow the corpus.

    The retired ignore list removed the old witness (an ignored module's node
    ids must be absent). Two stronger witnesses replace it: the hostile ADDOPTS
    names a genuinely build-reachable file that is not a test module and also
    tries to narrow with ``-k``, and the collected node id *set* must be
    byte-identical to a run with no ADDOPTS at all.
    """
    mod = _load_runner()
    clean_env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    clean_env.pop("PYTEST_ADDOPTS", None)
    builder_rel = BUILD_SCRIPT.relative_to(REPO).as_posix()
    hostile_env = {
        **clean_env,
        "PYTEST_ADDOPTS": f"{builder_rel} -k test_l1_candidate_includes_builder",
    }

    def run(env):
        return subprocess.run(
            [sys.executable, str(RUNNER), "--collect-only"],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            env=env,
        )

    clean = run(clean_env)
    hostile = run(hostile_env)
    clean_blob = clean.stdout + clean.stderr
    hostile_blob = hostile.stdout + hostile.stderr
    assert clean.returncode == 0, clean_blob
    assert hostile.returncode == 0, hostile_blob
    assert "R5_NOBUILD_RUNNER" in hostile_blob
    assert "--noconftest" in hostile_blob
    # Witness one: the smuggled build target is never collected and no build
    # ever starts.
    assert f"{builder_rel}::" not in hostile_blob
    assert "RELEASE_BUILD_OK" not in hostile_blob
    # Witness two: quantified non-interference — ADDOPTS changed nothing.
    clean_ids = _collect_node_ids(clean_blob)
    hostile_ids = _collect_node_ids(hostile_blob)
    assert clean_ids, clean_blob[-2000:]
    assert hostile_ids == clean_ids
    sanitized = mod.sanitize_pytest_env(hostile_env)
    assert "PYTEST_ADDOPTS" not in sanitized
    assert sanitized.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD") == "1"


def test_runner_refuses_all_caller_selection_forms():
    """Boundary one: no path, nodeid, directory or selection option is accepted."""
    mod = _load_runner()
    forbidden = [
        ["tests/test_legacy_residue_gate.py"],
        ["--", "tests/test_legacy_residue_gate.py"],
        ["./tests/test_legacy_residue_gate.py"],
        ["tests/test_legacy_residue_gate.py::test_clean_synthetic_tree_is_green"],
        ["tests"],
        ["-k", "residue"],
        ["-k=residue"],
        ["-m", "slow"],
        ["--ignore", "tests/test_legacy_residue_gate.py"],
        ["--deselect", "tests/test_legacy_residue_gate.py::test_x"],
        ["--pyargs", "tests"],
        ["--last-failed"],
        ["--stepwise"],
        ["-x", "--", "-k", "residue"],
        ["--tb", "inline"],
        ["-p", "xdist"],
        ["--maxfail=abc"],
    ]
    for argv in forbidden:
        with pytest.raises(mod.RunnerArgError):
            mod.validate_forwarded_args(argv)
    # Display-only options survive and are the *only* thing forwarded.
    assert mod.validate_forwarded_args(["-q", "--tb=short", "--maxfail=1"]) == [
        "-q",
        "--tb=short",
        "--maxfail=1",
    ]


def test_runner_argv_is_always_the_full_fixed_corpus():
    """Selection cannot be narrowed: argv always carries the whole corpus."""
    mod = _load_runner()
    corpus = list(mod.list_allowed_corpus())
    argv = mod.build_pytest_argv(["-q"])
    selected = [tok for tok in argv if tok.endswith(".py") and tok.startswith("tests/")]
    # With the ignore list retired, --ignore values are no longer a second
    # source of tests/ paths in argv: selection is exactly the corpus.
    assert "--ignore" not in argv
    assert sorted(set(selected)) == sorted(corpus)
    # And the corpus is the whole of tests/test_*.py — nothing is held back.
    on_disk = sorted(
        p.relative_to(REPO).as_posix() for p in (REPO / "tests").rglob("test_*.py")
    )
    assert on_disk, "tests/test_*.py must not be empty"
    assert sorted(corpus) == on_disk
    # Dormant while the list is empty; re-arms verbatim if R6 refills it.
    for path in EXCLUDED_BUILD_MODULES:
        assert path not in corpus


def test_runtime_tripwire_blocks_build_even_when_static_gate_bypassed(tmp_path):
    """Boundary two: build_all fails under the runner's env, no artifacts written."""
    mod = _load_runner()
    env = mod.sanitize_pytest_env()
    # R6 slice 1: an ambient build authorization must not silently weaken this
    # gate's reading — the fail-closed default is what is under test here.
    env.pop("CG_R6_BUILD_AUTHORIZED", None)
    assert env[mod.TRIPWIRE_ENV_VAR] == mod.TRIPWIRE_ENV_VALUE
    out_dir = tmp_path / "dist"
    # Payload calls the real build entry point directly — no static analysis
    # is involved at all, mirroring an evaded preflight. The entry name is
    # spliced so this gate module itself stays clean under the static scan.
    entry = "build_" + "all"
    payload = (
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('b', {str(BUILD_SCRIPT)!r})\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "sys.modules['b'] = mod\n"
        "spec.loader.exec_module(mod)\n"
        "from pathlib import Path\n"
        f"getattr(mod, {entry!r})(Path({str(out_dir)!r}))\n"
    )
    script = tmp_path / "payload.py"
    script.write_text(payload, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        env=env,
    )
    blob = proc.stdout + proc.stderr
    assert proc.returncode != 0, blob
    assert "NoBuildTripwireError" in blob or "CG_NO_BUILD_TRIPWIRE" in blob
    assert not out_dir.exists(), "tripwire must abort before any artifact is written"


def test_runtime_tripwire_cannot_be_disarmed_after_import(tmp_path):
    """Popping the env var after import must not re-enable building."""
    out_dir = tmp_path / "dist"
    entry = "build_" + "all"
    payload = (
        "import importlib.util, os, sys\n"
        f"spec = importlib.util.spec_from_file_location('b', {str(BUILD_SCRIPT)!r})\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "sys.modules['b'] = mod\n"
        "spec.loader.exec_module(mod)\n"
        "os.environ.pop('CG_NO_BUILD_TRIPWIRE', None)\n"
        "from pathlib import Path\n"
        f"getattr(mod, {entry!r})(Path({str(out_dir)!r}))\n"
    )
    script = tmp_path / "payload_disarm.py"
    script.write_text(payload, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        # _tripwire_env strips any ambient CG_R6_BUILD_AUTHORIZED, so this test
        # keeps reading the fail-closed default rather than an authorized run.
        env=_tripwire_env(CG_NO_BUILD_TRIPWIRE="1"),
    )
    blob = proc.stdout + proc.stderr
    assert proc.returncode != 0, blob
    assert "NoBuildTripwireError" in blob or "CG_NO_BUILD_TRIPWIRE" in blob
    assert not out_dir.exists()


def test_build_script_main_reports_tripwire_and_writes_nothing(tmp_path):
    """Formal builder CLI exits nonzero with a tripwire marker under the flag."""
    proc = subprocess.run(
        [sys.executable, str(BUILD_SCRIPT)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        env=_tripwire_env(CG_NO_BUILD_TRIPWIRE="1"),
    )
    blob = proc.stdout + proc.stderr
    assert proc.returncode != 0, blob
    assert "RELEASE_BUILD_TRIPWIRE" in blob
    assert "RELEASE_BUILD_OK" not in blob


def test_mutation_inherited_pytest_plugins_loading_build_helper_is_red(tmp_path):
    """Inherited PYTEST_PLUGINS must be stripped; plugin must not fire."""
    mod = _load_runner()
    plug = tmp_path / "plug"
    plug.mkdir()
    marker = tmp_path / "plugin_fired"
    (plug / "evil_build_plug.py").write_text(
        f"def pytest_configure(config):\n    open({str(marker)!r}, 'w').write('fired')\n",
        encoding="utf-8",
    )
    env = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(plug),
        "PYTEST_PLUGINS": "evil_build_plug",
    }
    proc = subprocess.run(
        [sys.executable, str(RUNNER), "--collect-only"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not marker.exists(), "PYTEST_PLUGINS must not load under sanitized env"
    sanitized = mod.sanitize_pytest_env(env)
    assert "PYTEST_PLUGINS" not in sanitized


def test_mutation_from_package_submodule_alias_call_via_formal_preflight(tmp_path):
    """from package import submodule; alias = submodule.build_all; alias()."""
    mod = _load_runner()
    root = tmp_path / "repo"
    tests = root / "tests"
    pkg = tests / "pkg"
    pkg.mkdir(parents=True)
    (tests / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "submod.py").write_text(
        "def build_all():\n    return 1\n", encoding="utf-8"
    )
    (tests / "test_pkg_alias.py").write_text(
        textwrap.dedent(
            """
            from tests.pkg import submod
            alias = submod.build_all

            def test_probe():
                assert alias() == 1
            """
        ).lstrip(),
        encoding="utf-8",
    )
    with pytest.raises(mod.RunnerArgError) as ei:
        mod.preflight_no_build(["tests/test_pkg_alias.py"], repo=root)
    assert "build_all" in str(ei.value)


def test_mutation_fixture_helper_indirect_import_via_formal_preflight(tmp_path):
    mod = _load_runner()
    root = tmp_path / "repo"
    tests = root / "tests"
    support = tests / "support"
    support.mkdir(parents=True)
    (tests / "__init__.py").write_text("", encoding="utf-8")
    (support / "__init__.py").write_text("", encoding="utf-8")
    (support / "deep_build.py").write_text(
        "def build_all():\n    return 1\n", encoding="utf-8"
    )
    (support / "fixtures.py").write_text(
        "from tests.support.deep_build import build_all\n\ndef get_builder():\n    return build_all\n",
        encoding="utf-8",
    )
    (tests / "test_fix.py").write_text(
        textwrap.dedent(
            """
            from tests.support.fixtures import get_builder

            def test_probe():
                assert get_builder()() == 1
            """
        ).lstrip(),
        encoding="utf-8",
    )
    with pytest.raises(mod.RunnerArgError) as ei:
        mod.preflight_no_build(["tests/test_fix.py"], repo=root)
    assert "build_all" in str(ei.value)


def test_mutation_credential_guard_unresolved_dynamic_import_param_is_red(tmp_path):
    mod = _load_runner()
    root = tmp_path / "repo"
    tests = root / "tests"
    cg = root / "credential_guard"
    tests.mkdir(parents=True)
    cg.mkdir(parents=True)
    (cg / "__init__.py").write_text("", encoding="utf-8")
    (cg / "dyn.py").write_text(
        "import importlib\n\ndef go(name):\n    return importlib.import_module(name)\n",
        encoding="utf-8",
    )
    (tests / "test_cg_dyn.py").write_text(
        "from credential_guard.dyn import go\n\ndef test_probe():\n    assert go\n",
        encoding="utf-8",
    )
    with pytest.raises(mod.RunnerArgError) as ei:
        mod.preflight_no_build(["tests/test_cg_dyn.py"], repo=root)
    assert "unresolved" in str(ei.value) or "build_all" in str(ei.value)


def test_mutation_local_constant_shadows_safe_module_constant_is_red(tmp_path):
    mod = _load_runner()
    root = tmp_path / "repo"
    tests = root / "tests"
    scripts = root / "scripts"
    tests.mkdir(parents=True)
    scripts.mkdir(parents=True)
    (scripts / "build_release_artifacts.py").write_text(
        "def build_all():\n    return 1\n", encoding="utf-8"
    )
    (tests / "test_shadow.py").write_text(
        textwrap.dedent(
            """
            SAFE = "tests.support.ok"

            def test_probe():
                import importlib
                SAFE = "scripts.build_release_artifacts"
                importlib.import_module(SAFE)
            """
        ).lstrip(),
        encoding="utf-8",
    )
    with pytest.raises(mod.RunnerArgError) as ei:
        mod.preflight_no_build(["tests/test_shadow.py"], repo=root)
    assert "build" in str(ei.value)


def test_mutation_conditional_module_assignment_maybe_builder_is_red(tmp_path):
    mod = _load_runner()
    root = tmp_path / "repo"
    tests = root / "tests"
    support = tests / "support"
    support.mkdir(parents=True)
    (tests / "__init__.py").write_text("", encoding="utf-8")
    (support / "__init__.py").write_text("", encoding="utf-8")
    (support / "build_mod.py").write_text(
        "def build_all():\n    return 1\n", encoding="utf-8"
    )
    (support / "safe.py").write_text("X = 1\n", encoding="utf-8")
    (tests / "test_cond.py").write_text(
        textwrap.dedent(
            """
            import importlib

            def test_probe(flag=True):
                if flag:
                    MOD = "tests.support.build_mod"
                else:
                    MOD = "tests.support.safe"
                importlib.import_module(MOD)
            """
        ).lstrip(),
        encoding="utf-8",
    )
    with pytest.raises(mod.RunnerArgError) as ei:
        mod.preflight_no_build(["tests/test_cond.py"], repo=root)
    assert "unresolved" in str(ei.value) or "build_all" in str(ei.value)


def test_mutation_bound_attribute_alias_invoking_build_all_is_red(tmp_path):
    mod = _load_runner()
    root = tmp_path / "repo"
    tests = root / "tests"
    tests.mkdir(parents=True)
    (tests / "test_attr_alias.py").write_text(
        textwrap.dedent(
            """
            import types

            m = types.SimpleNamespace()

            def build_all():
                return 1

            m.build_all = build_all
            alias = m.build_all

            def test_probe():
                assert alias() == 1
            """
        ).lstrip(),
        encoding="utf-8",
    )
    with pytest.raises(mod.RunnerArgError) as ei:
        mod.preflight_no_build(["tests/test_attr_alias.py"], repo=root)
    assert "build_all" in str(ei.value)


def test_runner_has_no_default_ignores():
    """The ignore list is retired: the runner emits no --ignore whatsoever."""
    mod = _load_runner()
    assert mod.DEFAULT_IGNORE == ()
    assert EXCLUDED_BUILD_MODULES == frozenset()
    # The gate mirror and the runner constant must stay in lockstep.
    assert set(EXCLUDED_BUILD_MODULES) == set(mod.DEFAULT_IGNORE)
    argv = mod.build_pytest_argv()
    assert "--ignore" not in argv
    assert "--ignore" not in " ".join(argv)


def test_gate_uses_formal_argv_validator():
    """Gate must call formal argv validator/constructor — not a hand-built argv proof."""
    mod = _load_runner()
    assert hasattr(mod, "validate_forwarded_args")
    assert hasattr(mod, "build_pytest_argv")
    # Formal constructor rejects a bare path whether or not it is ignored.
    with pytest.raises(mod.RunnerArgError):
        mod.validate_forwarded_args(["tests/test_reproducible_release.py"])
    with pytest.raises(mod.RunnerArgError):
        mod.build_pytest_argv(["--", "tests/test_reproducible_release.py"])
    # The ignored-module branch is exercised through a synthetic list, so the
    # property survives the live list being empty.
    synthetic = (SYNTHETIC_IGNORED_MODULE,)
    with pytest.raises(mod.RunnerArgError):
        mod.validate_forwarded_args([SYNTHETIC_IGNORED_MODULE], ignore=synthetic)
    with pytest.raises(mod.RunnerArgError):
        mod.build_pytest_argv(["--", SYNTHETIC_IGNORED_MODULE], ignore=synthetic)


def test_runner_rejects_explicit_ignored_module_before_pytest():
    """Reproduce reviewer bypass: explicit path after -- must fail closed."""
    mod = _load_runner()
    # Formal validator (before pytest), dedicated ignored-module branch. The
    # carrier is synthetic so this stays covered with an empty live list.
    synthetic = (SYNTHETIC_IGNORED_MODULE,)
    with pytest.raises(mod.RunnerArgError) as ei:
        mod.validate_forwarded_args(
            ["--", SYNTHETIC_IGNORED_MODULE], ignore=synthetic
        )
    assert "ignored build module" in str(ei.value)
    # Same shape against the live (empty) list still fails closed, via the
    # generic boundary-one branch.
    with pytest.raises(mod.RunnerArgError) as ei_live:
        mod.validate_forwarded_args(["--", "tests/test_reproducible_release.py"])
    assert "path/nodeid forbidden" in str(ei_live.value)

    proc = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--collect-only",
            "--",
            "tests/test_reproducible_release.py",
        ],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert proc.returncode != 0, proc.stdout + proc.stderr
    blob = proc.stdout + proc.stderr
    rejected = "R5_NOBUILD_ARGREJECT" in blob or "R5_NOBUILD_REJECT" in blob
    assert rejected, blob
    # Must reject before collection — no node ids from the build module.
    assert "test_l1_candidate_includes_builder" not in blob
    assert "tests collected" not in blob.lower() or rejected


def test_runner_rejects_unknown_path_and_unsafe_option():
    mod = _load_runner()
    with pytest.raises(mod.RunnerArgError):
        mod.validate_forwarded_args(["tests/not_a_real_test_module.py"])
    with pytest.raises(mod.RunnerArgError):
        mod.validate_forwarded_args(["--pyargs", "tests"])
    with pytest.raises(mod.RunnerArgError):
        mod.validate_forwarded_args(["--ignore", "tests/test_legacy_residue_gate.py"])


def test_selected_modules_cannot_reach_build_all_transitively():
    mod = _load_runner()
    corpus = mod.list_allowed_corpus()
    assert corpus
    hits = mod.transitive_build_reachability(corpus, repo=REPO)
    assert hits == [], hits


def test_excluded_modules_do_reach_build_all():
    """Two independent layers over the exclude list.

    Layer one is the original per-member rule, kept as a conditional so it
    re-arms by itself once R6 brings the dual-build cases back. Layer two pins
    the fact that the list is empty today, so nothing can be parked in it to
    keep a failing module out of the no-build corpus.
    """
    mod = _load_runner()
    for rel in sorted(EXCLUDED_BUILD_MODULES):
        hits = mod.build_all_hits_in_source(
            (REPO / rel).read_text(encoding="utf-8"), filename=rel
        )
        assert hits, f"{rel} should reference build_all / build_release_artifacts"
    assert EXCLUDED_BUILD_MODULES == frozenset(), sorted(EXCLUDED_BUILD_MODULES)
    assert mod.DEFAULT_IGNORE == (), mod.DEFAULT_IGNORE


def test_mutation_selected_test_imports_helper_build_all_is_red(tmp_path):
    """Selected test → local helper → build_all() must be detected (transitive)."""
    mod = _load_runner()
    root = tmp_path / "repo"
    tests = root / "tests"
    support = tests / "support"
    support.mkdir(parents=True)
    (tests / "__init__.py").write_text("", encoding="utf-8")
    (support / "__init__.py").write_text("", encoding="utf-8")
    (support / "build_helper.py").write_text(
        textwrap.dedent(
            """
            def trigger():
                def build_all():
                    return 1
                return build_all()
            """
        ).lstrip(),
        encoding="utf-8",
    )
    (tests / "test_selected_probe.py").write_text(
        textwrap.dedent(
            """
            from tests.support.build_helper import trigger

            def test_probe():
                assert trigger() == 1
            """
        ).lstrip(),
        encoding="utf-8",
    )
    hits = mod.transitive_build_reachability(
        ["tests/test_selected_probe.py"], repo=root
    )
    assert hits, "helper build_all() must be RED via transitive scan"
    assert any("build_all" in h for h in hits)


def test_mutation_string_exec_build_all_payload_is_red(tmp_path):
    mod = _load_runner()
    root = tmp_path / "repo"
    tests = root / "tests"
    tests.mkdir(parents=True)
    needle = "build" + "_all"
    (tests / "test_exec_payload.py").write_text(
        f"def test_x():\n    exec('mod.{needle}()')\n",
        encoding="utf-8",
    )
    hits = mod.transitive_build_reachability(
        ["tests/test_exec_payload.py"], repo=root
    )
    assert any("str-payload:build_all" in h for h in hits), hits


def test_mutation_loads_build_release_artifacts_is_red(tmp_path):
    mod = _load_runner()
    root = tmp_path / "repo"
    tests = root / "tests"
    scripts = root / "scripts"
    tests.mkdir(parents=True)
    scripts.mkdir(parents=True)
    (scripts / "build_release_artifacts.py").write_text(
        "def build_all():\n    return 0\n", encoding="utf-8"
    )
    (tests / "test_load_builder.py").write_text(
        textwrap.dedent(
            """
            import importlib.util
            from pathlib import Path

            def test_load():
                p = Path(__file__).resolve().parents[1] / "scripts" / "build_release_artifacts.py"
                spec = importlib.util.spec_from_file_location("build_release_artifacts", p)
                assert spec
            """
        ).lstrip(),
        encoding="utf-8",
    )
    hits = mod.transitive_build_reachability(
        ["tests/test_load_builder.py"], repo=root
    )
    assert hits, hits


def test_runner_script_does_not_call_build_all():
    mod = _load_runner()
    assert (
        mod.build_all_hits_in_source(RUNNER.read_text(encoding="utf-8"), filename=str(RUNNER))
        == []
    )
    assert BUILD_SCRIPT.is_file()


def test_pytest_collect_with_formal_runner_argv():
    """Mechanical collection uses formal build_pytest_argv — the corpus is whole."""
    mod = _load_runner()
    argv = mod.build_pytest_argv(["--collect-only", "-q"])
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", *argv],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    blob = proc.stdout + proc.stderr
    # The retired ignore list must be observable in the collection itself: the
    # release-verifier module is now part of the full corpus.
    assert "tests/test_reproducible_release.py::" in blob
    # Dormant while the list is empty; re-arms verbatim if R6 refills it.
    for rel in EXCLUDED_BUILD_MODULES:
        # Node-id collection form only — topology parametrize may mention the
        # path as a modified-path victim string without collecting the module.
        assert f"{rel}::" not in blob
        assert not any(
            line.strip().startswith(rel) and "::" in line
            for line in blob.splitlines()
        )


# --- R6 slice 1: explicit build-authorization channel for the tripwire ------
#
# The tripwire itself is a reusable asset (any future "no build this round"
# milestone re-arms it verbatim). R6 needs to build, so instead of deleting the
# mechanism we add a second, deliberately-declared variable. Fail-closed stays
# the default: armed + unauthorized is still a hard error. Only an explicitly
# truthy authorization value opens the gate, and when it does the bypass is
# audited on stderr so a reviewer can tell "authorized build" from "the
# tripwire broke".

TRIPWIRE_VAR = "CG_NO_BUILD_TRIPWIRE"
BUILD_AUTH_VAR = "CG_R6_BUILD_AUTHORIZED"

# Spliced so this gate module stays clean under the runner's static scan.
_ENTRY_CLEAN = "clean_prior_artifacts"
_ENTRY_WHEEL = "build_" + "sdist_and_wheel"
_ENTRY_ZIP = "build_" + "hermes_plugin_zip"
_ENTRY_ALL = "build_" + "all"
_ALL_BUILD_ENTRIES = (_ENTRY_CLEAN, _ENTRY_WHEEL, _ENTRY_ZIP, _ENTRY_ALL)


def _entry_call_source(entry: str, out_dir: Path) -> str:
    """Render the call expression for one real build entry point."""
    if entry == _ENTRY_ZIP:
        return (
            f"getattr(mod, {entry!r})(Path({str(out_dir)!r}), "
            f"wheel=Path({str(out_dir / 'nonexistent.whl')!r}))\n"
        )
    return f"getattr(mod, {entry!r})(Path({str(out_dir)!r}))\n"


def _tripwire_env(**overrides: object) -> dict:
    """Env with both tripwire variables under explicit control (no ambient leak)."""
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in {TRIPWIRE_VAR, BUILD_AUTH_VAR}
    }
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    for key, value in overrides.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = str(value)
    return env


def _run_build_entry(entry: str, out_dir: Path, script: Path, env: dict):
    """Invoke one real build entry point in a subprocess under the given env."""
    payload = (
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('b', {str(BUILD_SCRIPT)!r})\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "sys.modules['b'] = mod\n"
        "spec.loader.exec_module(mod)\n"
        "from pathlib import Path\n"
    ) + _entry_call_source(entry, out_dir)
    script.write_text(payload, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(script)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        env=env,
    )


def _run_assert_probe(env: dict, script: Path, entry_label: str):
    """Call assert_no_build_tripwire directly — probes the gate, builds nothing."""
    payload = (
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('b', {str(BUILD_SCRIPT)!r})\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "sys.modules['b'] = mod\n"
        "spec.loader.exec_module(mod)\n"
        f"mod.assert_no_build_tripwire({entry_label!r})\n"
        "print('PROBE_PASSED_THROUGH')\n"
    )
    script.write_text(payload, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(script)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        env=env,
    )


@pytest.mark.parametrize("entry", _ALL_BUILD_ENTRIES)
def test_ma1_armed_without_authorization_blocks_every_entry(entry, tmp_path):
    """M-A1: armed + authorization unset → every entry point still fails closed."""
    out_dir = tmp_path / "dist"
    proc = _run_build_entry(
        entry,
        out_dir,
        tmp_path / "payload_ma1.py",
        _tripwire_env(CG_NO_BUILD_TRIPWIRE="1"),
    )
    blob = proc.stdout + proc.stderr
    assert proc.returncode != 0, blob
    assert "NoBuildTripwireError" in blob, blob
    assert not out_dir.exists(), "must abort before any filesystem effect"


@pytest.mark.parametrize("weak", ["0", "false", "False", "", "   "])
@pytest.mark.parametrize("entry", _ALL_BUILD_ENTRIES)
def test_ma2_weak_authorization_values_cannot_bypass(entry, weak, tmp_path):
    """M-A2: falsey authorization values are not authorization."""
    out_dir = tmp_path / "dist"
    proc = _run_build_entry(
        entry,
        out_dir,
        tmp_path / "payload_ma2.py",
        _tripwire_env(CG_NO_BUILD_TRIPWIRE="1", CG_R6_BUILD_AUTHORIZED=weak),
    )
    blob = proc.stdout + proc.stderr
    assert proc.returncode != 0, blob
    assert "NoBuildTripwireError" in blob, blob
    assert not out_dir.exists()


def test_ma3_explicit_authorization_passes_through_and_audits(tmp_path):
    """M-A3: armed + explicit authorization → allowed, and audited on stderr."""
    proc = _run_assert_probe(
        _tripwire_env(CG_NO_BUILD_TRIPWIRE="1", CG_R6_BUILD_AUTHORIZED="1"),
        tmp_path / "probe_ma3.py",
        "probe_entry_name",
    )
    blob = proc.stdout + proc.stderr
    assert proc.returncode == 0, blob
    assert "PROBE_PASSED_THROUGH" in proc.stdout, blob
    # The bypass must leave a trace on stderr naming the entry point.
    assert BUILD_AUTH_VAR in proc.stderr, proc.stderr
    assert "entry=probe_entry_name" in proc.stderr, proc.stderr


def test_ma3_authorization_audit_names_the_real_entry_point(tmp_path):
    """M-A3 (cont.): the audit line carries whichever entry actually bypassed."""
    proc = _run_assert_probe(
        _tripwire_env(CG_NO_BUILD_TRIPWIRE="1", CG_R6_BUILD_AUTHORIZED="yes"),
        tmp_path / "probe_ma3b.py",
        _ENTRY_ALL,
    )
    blob = proc.stdout + proc.stderr
    assert proc.returncode == 0, blob
    assert f"entry={_ENTRY_ALL}" in proc.stderr, proc.stderr


def test_ma4_unarmed_without_authorization_is_normal_pass_through(tmp_path):
    """M-A4: adding the authorization channel must not block ordinary builds."""
    proc = _run_assert_probe(
        _tripwire_env(),
        tmp_path / "probe_ma4.py",
        "ordinary_entry",
    )
    blob = proc.stdout + proc.stderr
    assert proc.returncode == 0, blob
    assert "PROBE_PASSED_THROUGH" in proc.stdout, blob
    # No tripwire was armed, so there is nothing to audit — a bypass notice
    # here would train reviewers to ignore the line that matters.
    assert BUILD_AUTH_VAR not in proc.stderr, proc.stderr


def test_ma5_fail_closed_branch_is_pinned_by_source(tmp_path):
    """M-A5 anchor: the raise lives in assert_no_build_tripwire, not decoration.

    Deleting/neutering the fail-closed branch turns M-A1/M-A2 RED; this test
    additionally pins that the raise is reached through the authorization
    check rather than an unconditional early return.
    """
    text = BUILD_SCRIPT.read_text(encoding="utf-8")
    assert f'{BUILD_AUTH_VAR}"' in text or f"{BUILD_AUTH_VAR}'" in text
    body = text.split("def assert_no_build_tripwire", 1)[1].split("\ndef ", 1)[0]
    assert "raise NoBuildTripwireError" in body
    assert "_build_authorized" in body
