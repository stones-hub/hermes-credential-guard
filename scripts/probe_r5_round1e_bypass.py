"""Round 1E re-run of the 19 no-build runner BYPASS cases.

Each probe drives the FORMAL runner as a subprocess and then checks real
side effects, never just the exit code:

  * sentinel file — written by the payload only if ``build_all`` actually ran;
  * pytest launch — whether the runner ever reached a pytest process at all.

Verdict per probe:
  BLOCKED_ARGV      selection refused by boundary one, pytest never launched
  BLOCKED_PREFLIGHT static reachability scan refused the corpus, pytest never ran
  BLOCKED_TRIPWIRE  pytest ran, payload executed, boundary two aborted the build
  BYPASS            sentinel exists — the build really happened (failure)

Usage: python3 scripts/probe_r5_round1e_bypass.py [--json]
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO = Path(__file__).resolve().parents[1]
RUNNER = REPO / "scripts" / "run_r5_nobuild_pytest.py"
BUILD_SCRIPT = REPO / "scripts" / "build_release_artifacts.py"
CORPUS_VICTIM = REPO / "tests" / "test_redactor.py"

BUILD_ENTRY = "build_" + "all"


def _payload_source(sentinel: Path) -> str:
    """Body that calls the real build entry point and drops a sentinel."""
    return (
        "import importlib.util as _iu, sys as _sys\n"
        f"_spec = _iu.spec_from_file_location('_b', {str(BUILD_SCRIPT)!r})\n"
        "_mod = _iu.module_from_spec(_spec)\n"
        "_sys.modules['_b'] = _mod\n"
        "_spec.loader.exec_module(_mod)\n"
        "from pathlib import Path as _P\n"
        f"_out = _P({str(sentinel.parent / 'dist')!r})\n"
        f"getattr(_mod, {BUILD_ENTRY!r})(_out)\n"
        f"_P({str(sentinel)!r}).write_text('built')\n"
    )


def _test_module(sentinel: Path) -> str:
    body = _payload_source(sentinel)
    indented = "\n".join("    " + line for line in body.splitlines())
    return "def test_payload():\n" + indented + "\n"


def _obfuscated_test_module(sentinel: Path) -> str:
    """Payload whose build entry name is assembled at runtime.

    The static preflight cannot see a ``build_all`` reference here, only the
    module load of the build script.
    """
    out = str(sentinel.parent / "dist")
    return (
        "import importlib.util as _iu, sys as _sys\n"
        "from pathlib import Path as _P\n\n"
        "def test_obfuscated_payload():\n"
        f"    _spec = _iu.spec_from_file_location('_b', {str(BUILD_SCRIPT)!r})\n"
        "    _mod = _iu.module_from_spec(_spec)\n"
        "    _sys.modules['_b'] = _mod\n"
        "    _spec.loader.exec_module(_mod)\n"
        "    _name = ''.join(['bu', 'ild', '_a', 'll'])\n"
        f"    getattr(_mod, _name)(_P({out!r}))\n"
        f"    _P({str(sentinel)!r}).write_text('built')\n"
    )


def _fully_dynamic_test_module(sentinel: Path, spec_file: Path) -> str:
    """Payload with NO static reference to the build script or its entry.

    Both the script path and the entry-point name are read from a data file at
    run time, so the static preflight has literally nothing to match on. This
    is the probe that proves boundary two (the runtime tripwire) stands on its
    own: pytest really launches, the payload really executes, and the build
    still must not happen.
    """
    out = str(sentinel.parent / "dist")
    return (
        "import importlib.util as _iu, json as _json, sys as _sys\n"
        "from pathlib import Path as _P\n\n"
        "def test_fully_dynamic_payload():\n"
        f"    _cfg = _json.loads(_P({str(spec_file)!r}).read_text())\n"
        "    _spec = _iu.spec_from_file_location('_z', _cfg['s'])\n"
        "    _mod = _iu.module_from_spec(_spec)\n"
        "    _sys.modules['_z'] = _mod\n"
        "    _spec.loader.exec_module(_mod)\n"
        f"    getattr(_mod, _cfg['e'])(_P({out!r}))\n"
        f"    _P({str(sentinel)!r}).write_text('built')\n"
    )


class Probe:
    def __init__(self, name: str, argv: List[str], files: Optional[Dict[str, str]] = None):
        self.name = name
        self.argv = argv
        self.files = files or {}


def _probes(sentinel: Path) -> List[Probe]:
    mod_src = _test_module(sentinel)
    body = _payload_source(sentinel)
    exec_src = (
        "def test_exec_payload():\n"
        f"    src = {body!r}\n"
        "    loc = {}\n"
        "    exec(src, loc, loc)\n"
    )
    eval_src = (
        "def test_eval_payload():\n"
        f"    src = {body!r}\n"
        "    loc = {}\n"
        "    eval(compile(src, '<p>', 'exec'), loc, loc)\n"
    )
    fixture_src = (
        "import pytest\n\n"
        "@pytest.fixture\n"
        "def hop_one():\n"
        "    return 1\n\n"
        "@pytest.fixture\n"
        "def hop_two(hop_one):\n"
        "    return hop_one + 1\n\n"
        "@pytest.fixture\n"
        "def hop_three(hop_two):\n"
        f"{chr(10).join('    ' + l for l in body.splitlines())}\n"
        "    return hop_two\n\n"
        "def test_via_fixture_chain(hop_three):\n"
        "    assert hop_three\n"
    )
    return [
        # --- batch one: import-shape reachability (8) ---------------------
        Probe("v_rel_level1_same_pkg", ["tests/pkg_probe/test_rel1.py"],
              {"tests/pkg_probe/__init__.py": "",
               "tests/pkg_probe/payload.py": body,
               "tests/pkg_probe/test_rel1.py":
                   "from . import payload\n\ndef test_x():\n    assert payload\n"}),
        Probe("v_rel_level2_parent_pkg", ["tests/pkg_probe/sub/test_rel2.py"],
              {"tests/pkg_probe/__init__.py": "",
               "tests/pkg_probe/payload.py": body,
               "tests/pkg_probe/sub/__init__.py": "",
               "tests/pkg_probe/sub/test_rel2.py":
                   "from .. import payload\n\ndef test_x():\n    assert payload\n"}),
        Probe("v_dotdot_relpath", ["../hermes-credential-guard/tests/test_probe_dd.py"],
              {"tests/test_probe_dd.py": mod_src}),
        Probe("v_from_pkg_import_mod_attrchain", ["tests/test_probe_attr.py"],
              {"tests/pkg_probe/__init__.py": "",
               "tests/pkg_probe/payload.py":
                   f"def run():\n{chr(10).join('    ' + l for l in body.splitlines())}\n",
               "tests/test_probe_attr.py":
                   "from tests.pkg_probe import payload\n\n"
                   "def test_x():\n    payload.run()\n"}),
        Probe("v_fixture_chain_multihop", ["tests/test_probe_fixture.py"],
              {"tests/test_probe_fixture.py": fixture_src}),
        Probe("v_cg_package_multilevel_helper", ["tests/test_probe_cg.py"],
              {"credential_guard/probe_helper.py":
                   f"def run():\n{chr(10).join('    ' + l for l in body.splitlines())}\n",
               "tests/test_probe_cg.py":
                   "from credential_guard.probe_helper import run\n\n"
                   "def test_x():\n    run()\n"}),
        Probe("v_samedir_helper", ["tests/test_probe_samedir.py"],
              {"tests/probe_helper_mod.py":
                   f"def run():\n{chr(10).join('    ' + l for l in body.splitlines())}\n",
               "tests/test_probe_samedir.py":
                   "import probe_helper_mod\n\n"
                   "def test_x():\n    probe_helper_mod.run()\n"}),
        Probe("v_pkg_submodule_alias", ["tests/test_probe_alias.py"],
              {"tests/pkg_probe/__init__.py": "",
               "tests/pkg_probe/payload.py":
                   f"def run():\n{chr(10).join('    ' + l for l in body.splitlines())}\n",
               "tests/test_probe_alias.py":
                   "from tests import pkg_probe\n"
                   "alias = pkg_probe.payload.run\n\n"
                   "def test_x():\n    alias()\n"}),
        # --- batch two (6) ------------------------------------------------
        Probe("v_exec_local_var_fixed", ["tests/test_probe_exec.py"],
              {"tests/test_probe_exec.py": exec_src}),
        Probe("v_eval_local_var_fixed", ["tests/test_probe_eval.py"],
              {"tests/test_probe_eval.py": eval_src}),
        Probe("v_nodeid_selection", ["tests/test_probe_node.py::test_payload"],
              {"tests/test_probe_node.py": mod_src}),
        Probe("v_dotslash_prefix", ["./tests/test_probe_dot.py"],
              {"tests/test_probe_dot.py": mod_src}),
        Probe("v_conftest_injection", ["tests/test_probe_conf.py"],
              {"conftest.py": body, "tests/test_probe_conf.py": "def test_x():\n    assert True\n"}),
        Probe("v_addopts_env_selection", ["--collect-only"],
              {"tests/test_probe_addopts.py": mod_src}),
        # --- batch three: options carrying selection (5) ------------------
        Probe("v_dashdash_k_selection", ["--", "-k", "probe"],
              {"tests/test_probe_k.py": mod_src}),
        Probe("v_tb_inline_selection", ["--tb", "inline", "tests/test_probe_tb.py"],
              {"tests/test_probe_tb.py": mod_src}),
        Probe("v_p_value_plugin", ["-p", "probe_plug", "tests/test_probe_p.py"],
              {"probe_plug.py": body, "tests/test_probe_p.py": "def test_x():\n    assert True\n"}),
        Probe("v_maxfail_selection", ["--maxfail=1", "tests/test_probe_mf.py"],
              {"tests/test_probe_mf.py": mod_src}),
        Probe("v_x_flag_selection", ["-x", "tests/test_probe_x.py"],
              {"tests/test_probe_x.py": mod_src}),
        # --- the sharpest one: payload inside an EXISTING corpus module ---
        Probe("v_existing_modified_module_no_new_files", [], {}),
        # --- boundary-two proof: static scan evaded, tripwire must still fire --
        Probe("v_existing_module_obfuscated_entry", [], {}),
        Probe("v_existing_module_fully_dynamic_entry", [], {}),
    ]


def _run(probe: Probe, sentinel: Path, py: str) -> Tuple[str, str]:
    created: List[Path] = []
    backup: Optional[bytes] = None
    try:
        for rel, content in probe.files.items():
            target = REPO / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                created.append(target)
            target.write_text(content, encoding="utf-8")
        if probe.name == "v_existing_modified_module_no_new_files":
            backup = CORPUS_VICTIM.read_bytes()
            CORPUS_VICTIM.write_bytes(
                backup + b"\n\n" + _test_module(sentinel).encode("utf-8")
            )
        elif probe.name == "v_existing_module_obfuscated_entry":
            backup = CORPUS_VICTIM.read_bytes()
            CORPUS_VICTIM.write_bytes(
                backup + b"\n\n" + _obfuscated_test_module(sentinel).encode("utf-8")
            )
        elif probe.name == "v_existing_module_fully_dynamic_entry":
            spec_file = sentinel.parent / "payload_spec.json"
            spec_file.write_text(
                json.dumps({"s": str(BUILD_SCRIPT), "e": BUILD_ENTRY}),
                encoding="utf-8",
            )
            backup = CORPUS_VICTIM.read_bytes()
            CORPUS_VICTIM.write_bytes(
                backup
                + b"\n\n"
                + _fully_dynamic_test_module(sentinel, spec_file).encode("utf-8")
            )
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        if probe.name == "v_addopts_env_selection":
            env["PYTEST_ADDOPTS"] = "tests/test_probe_addopts.py"
        proc = subprocess.run(
            [py, str(RUNNER), *probe.argv],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            env=env,
            timeout=900,
        )
        blob = proc.stdout + proc.stderr
        if sentinel.exists():
            return "BYPASS", blob[-400:]
        last = blob.strip().splitlines()[-1] if blob.strip() else ""
        if "R5_NOBUILD_ARGREJECT" in blob:
            return "BLOCKED_ARGV", last
        if "R5_NOBUILD_REJECT" in blob:
            return "BLOCKED_PREFLIGHT", last
        if "CG_NO_BUILD_TRIPWIRE" in blob or "NoBuildTripwireError" in blob:
            return "BLOCKED_TRIPWIRE", "tripwire raised inside pytest"
        if "R5_NOBUILD_RUNNER" not in blob:
            return "BLOCKED_ARGV", last
        return "BLOCKED_OTHER", blob[-400:]
    finally:
        if backup is not None:
            CORPUS_VICTIM.write_bytes(backup)
        for path in created:
            if path.exists():
                path.unlink()
        for rel in probe.files:
            parent = (REPO / rel).parent
            while parent != REPO and parent.is_dir() and not any(parent.iterdir()):
                parent.rmdir()
                parent = parent.parent
        for stale in (REPO / "dist",):
            if stale.is_dir() and not any(stale.iterdir()):
                shutil.rmtree(stale, ignore_errors=True)
        if sentinel.exists():
            sentinel.unlink()


def main() -> int:
    py = sys.executable
    tmp = Path(tempfile.mkdtemp(prefix="r5-1e-probe-"))
    sentinel = tmp / "build_sentinel"
    results = []
    only = None
    for arg in sys.argv[1:]:
        if arg.startswith("--only="):
            only = arg.split("=", 1)[1]
    try:
        for probe in _probes(sentinel):
            if only and probe.name != only:
                continue
            verdict, detail = _run(probe, sentinel, py)
            results.append({"probe": probe.name, "verdict": verdict, "detail": detail})
            print(f"{verdict:<18} {probe.name}")
            if verdict == "BYPASS":
                print(f"    {detail}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    bypassed = [r for r in results if r["verdict"] == "BYPASS"]
    other = [r for r in results if r["verdict"] == "BLOCKED_OTHER"]
    print(f"\ntotal={len(results)} bypass={len(bypassed)} other={len(other)}")
    if "--json" in sys.argv:
        print(json.dumps(results, indent=2))
    return 1 if bypassed else 0


if __name__ == "__main__":
    raise SystemExit(main())
