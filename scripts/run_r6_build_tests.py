#!/usr/bin/env python3
"""R6 opt-in real-build test runner (the ONLY entry that authorizes a build).

``scripts/run_r5_nobuild_pytest.py`` owns the default full run and keeps it at
zero builds: it refuses ``-m``/``-k``/paths/nodeids, its corpus is the fixed
glob ``tests/test_*.py``, and its fail-closed AST preflight rejects the whole
run if any collected module can reach the release builder. A real-build test
therefore cannot live inside that corpus at all.

This runner is the sanctioned opt-in alternative. It runs exactly one module,
``tests/r6_real_build_check.py`` — deliberately named outside the no-build
runner's glob — and it is the only place where the build-authorization
variable ``CG_R6_BUILD_AUTHORIZED`` is set. Per task 禁 2 that variable is
injected solely through this subprocess' ``env=`` mapping: it is never written
to ``.envrc``, shell config, ``pytest.ini``, ``conftest.py``, or any other
script default, and it does not leak into the caller's environment.

Safety (task 禁 1): this runner never passes an output directory to the
builder. Every build performed by the check module writes to
``tempfile.mkdtemp()`` only, and the module hard-asserts that no output
directory resolves to (or under) the repository ``dist/``.

Usage::

    .venv/bin/python scripts/run_r6_build_tests.py [-q|-v] [--tb=...] [--collect-only]
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

REPO = Path(__file__).resolve().parents[1]

#: The single module this runner is allowed to execute.
REAL_BUILD_MODULE = "tests/r6_real_build_check.py"

#: Marker applied to every test in that module (informational; selection here
#: is by path, not by marker expression).
REAL_BUILD_MARKER = "real_build"

#: Authorization channel opened for the child process only.
BUILD_AUTHORIZED_ENV_VAR = "CG_R6_BUILD_AUTHORIZED"
TRIPWIRE_ENV_VAR = "CG_NO_BUILD_TRIPWIRE"

SAFE_DISPLAY_FLAGS = ("-q", "-v", "-x", "--collect-only")
SAFE_TB_VALUES = ("short", "long", "line", "native", "no", "auto")


class R6RunnerArgError(ValueError):
    """Raised when argv asks for anything other than the fixed module."""


def _validate_extra(extra: Sequence[str]) -> List[str]:
    """Allow display-only options; refuse anything that changes selection."""
    out: List[str] = []
    for arg in extra:
        if arg in SAFE_DISPLAY_FLAGS:
            out.append(arg)
            continue
        if arg.startswith("--tb="):
            if arg.split("=", 1)[1] not in SAFE_TB_VALUES:
                raise R6RunnerArgError(f"unsupported --tb value: {arg}")
            out.append(arg)
            continue
        if arg.startswith("--maxfail="):
            if not arg.split("=", 1)[1].isdigit():
                raise R6RunnerArgError(f"unsupported --maxfail value: {arg}")
            out.append(arg)
            continue
        raise R6RunnerArgError(
            f"selection is owned by this runner; refused argument: {arg}"
        )
    return out


def build_pytest_argv(extra: Sequence[str] | None = None) -> List[str]:
    """Fixed argv: display options only, then the single real-build module."""
    argv = ["-p", "no:cacheprovider", "--noconftest"]
    argv.extend(_validate_extra(tuple(extra or ())))
    argv.append(REAL_BUILD_MODULE)
    return argv


def build_env(base: Dict[str, str] | None = None) -> Dict[str, str]:
    """Child environment: tripwire armed AND explicitly authorized."""
    env = dict(os.environ if base is None else base)
    for key in [k for k in env if k.startswith("PYTEST_")]:
        env.pop(key, None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env[TRIPWIRE_ENV_VAR] = "1"
    env[BUILD_AUTHORIZED_ENV_VAR] = "1"
    return env


def _preflight() -> Tuple[Path, str]:
    module = REPO / REAL_BUILD_MODULE
    if not module.is_file():
        raise R6RunnerArgError(f"real-build module missing: {REAL_BUILD_MODULE}")
    return module, module.read_text(encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    extra = list(sys.argv[1:] if argv is None else argv)
    if extra and extra[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    try:
        _preflight()
        py_argv = build_pytest_argv(extra)
    except (R6RunnerArgError, OSError) as exc:
        print(f"R6_BUILD_RUNNER_REJECT {exc}", file=sys.stderr)
        return 2
    env = build_env()
    print(
        "R6_BUILD_RUNNER authorized real-build run: "
        + " ".join([sys.executable, "-m", "pytest", *py_argv])
    )
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", *py_argv], cwd=str(REPO), env=env
    )
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
