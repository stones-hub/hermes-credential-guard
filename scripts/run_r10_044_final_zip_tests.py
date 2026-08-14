#!/usr/bin/env python3
"""R10 0.4.4 final-ZIP E2E opt-in pytest runner.

Runs exactly ``tests/r10_044_final_zip_e2e.py`` (outside the no-build
``tests/test_*.py`` glob). Never sets ``CG_R6_BUILD_AUTHORIZED``.

With ``ARTIFACTS_LANDED=True`` (landed), runs real temporary install +
PluginManager continuity and source-fallback mutation E2E. Never sets
``CG_R6_BUILD_AUTHORIZED``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

REPO = Path(__file__).resolve().parents[1]

E2E_MODULES: Tuple[str, ...] = ("tests/r10_044_final_zip_e2e.py",)

SAFE_DISPLAY_FLAGS = ("-q", "-v", "-x", "--collect-only")
SAFE_TB_VALUES = ("short", "long", "line", "native", "no", "auto")


class R10FinalZipRunnerArgError(ValueError):
    """Raised when argv asks for anything other than the fixed module."""


def _validate_extra(extra: Sequence[str]) -> List[str]:
    out: List[str] = []
    for arg in extra:
        if arg in SAFE_DISPLAY_FLAGS:
            out.append(arg)
            continue
        if arg.startswith("--tb="):
            if arg.split("=", 1)[1] not in SAFE_TB_VALUES:
                raise R10FinalZipRunnerArgError(f"unsupported --tb value: {arg}")
            out.append(arg)
            continue
        if arg.startswith("--maxfail="):
            if not arg.split("=", 1)[1].isdigit():
                raise R10FinalZipRunnerArgError(f"unsupported --maxfail value: {arg}")
            out.append(arg)
            continue
        raise R10FinalZipRunnerArgError(
            f"selection is owned by this runner; refused argument: {arg}"
        )
    return out


def build_pytest_argv(extra: Sequence[str] | None = None) -> List[str]:
    argv = ["-p", "no:cacheprovider", "--noconftest"]
    argv.extend(_validate_extra(tuple(extra or ())))
    argv.extend(E2E_MODULES)
    return argv


def build_env(base: Dict[str, str] | None = None) -> Dict[str, str]:
    env = dict(os.environ if base is None else base)
    for key in [k for k in env if k.startswith("PYTEST_")]:
        env.pop(key, None)
    env.pop("CG_R6_BUILD_AUTHORIZED", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env["CG_NO_BUILD_TRIPWIRE"] = "1"
    return env


def main(argv: Sequence[str] | None = None) -> int:
    extra = list(sys.argv[1:] if argv is None else argv)
    if extra and extra[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    try:
        for rel in E2E_MODULES:
            if not (REPO / rel).is_file():
                raise R10FinalZipRunnerArgError(f"E2E module missing: {rel}")
        py_argv = build_pytest_argv(extra)
    except (R10FinalZipRunnerArgError, OSError) as exc:
        print(f"R10_044_FINAL_ZIP_RUNNER_REJECT {exc}", file=sys.stderr)
        return 2
    env = build_env()
    print(
        "R10_044_FINAL_ZIP_RUNNER opt-in E2E: "
        + " ".join([sys.executable, "-m", "pytest", *py_argv])
    )
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", *py_argv], cwd=str(REPO), env=env
    )
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
