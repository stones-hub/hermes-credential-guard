#!/usr/bin/env python3
"""R6 opt-in runner for installed-ZIP E2E modules (4a approval chain + 4b matrix).

Mirrors the boundary established by ``scripts/run_r6_build_tests.py``:

* the default no-build corpus is the fixed glob ``tests/test_*.py``
* these E2E modules live outside that glob
  (``tests/r6_installed_zip_approval_chain.py``,
  ``tests/r6_installed_zip_wire_matrix.py``)
* selection is owned by this runner — no ``-m``/``-k``/paths/nodeids

Unlike the real-build runner, this entry never sets ``CG_R6_BUILD_AUTHORIZED``
and never invokes the release builder. It only unpacks the already-landed
0.4.0 plugin ZIP into a temp HOME/HERMES_HOME.

Usage::

    .venv/bin/python scripts/run_r6_installed_zip_tests.py [-q|-v] [--tb=...] [--collect-only]
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

REPO = Path(__file__).resolve().parents[1]

E2E_MODULES: Tuple[str, ...] = (
    "tests/r6_installed_zip_approval_chain.py",
    "tests/r6_installed_zip_wire_matrix.py",
)

# Back-compat alias used by the 4a opt-in gate / evidence text.
E2E_MODULE = E2E_MODULES[0]

SAFE_DISPLAY_FLAGS = ("-q", "-v", "-x", "--collect-only")
SAFE_TB_VALUES = ("short", "long", "line", "native", "no", "auto")


class R6InstalledZipRunnerArgError(ValueError):
    """Raised when argv asks for anything other than the fixed modules."""


def _validate_extra(extra: Sequence[str]) -> List[str]:
    out: List[str] = []
    for arg in extra:
        if arg in SAFE_DISPLAY_FLAGS:
            out.append(arg)
            continue
        if arg.startswith("--tb="):
            if arg.split("=", 1)[1] not in SAFE_TB_VALUES:
                raise R6InstalledZipRunnerArgError(f"unsupported --tb value: {arg}")
            out.append(arg)
            continue
        if arg.startswith("--maxfail="):
            if not arg.split("=", 1)[1].isdigit():
                raise R6InstalledZipRunnerArgError(
                    f"unsupported --maxfail value: {arg}"
                )
            out.append(arg)
            continue
        raise R6InstalledZipRunnerArgError(
            f"selection is owned by this runner; refused argument: {arg}"
        )
    return out


def build_pytest_argv(extra: Sequence[str] | None = None) -> List[str]:
    argv = ["-p", "no:cacheprovider", "--noconftest"]
    argv.extend(_validate_extra(tuple(extra or ())))
    argv.extend(E2E_MODULES)
    return argv


def build_env(base: Dict[str, str] | None = None) -> Dict[str, str]:
    """Child env: tripwire armed, authorization NEVER introduced."""
    env = dict(os.environ if base is None else base)
    for key in [k for k in env if k.startswith("PYTEST_")]:
        env.pop(key, None)
    # Ambient build authorization must not leak into this opt-in path either.
    env.pop("CG_R6_BUILD_AUTHORIZED", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env["CG_NO_BUILD_TRIPWIRE"] = "1"
    return env


def _preflight() -> Tuple[Tuple[Path, ...], str]:
    modules = []
    texts = []
    for rel in E2E_MODULES:
        module = REPO / rel
        if not module.is_file():
            raise R6InstalledZipRunnerArgError(f"E2E module missing: {rel}")
        modules.append(module)
        texts.append(module.read_text(encoding="utf-8"))
    return tuple(modules), "\n".join(texts)


def main(argv: Sequence[str] | None = None) -> int:
    extra = list(sys.argv[1:] if argv is None else argv)
    if extra and extra[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    try:
        _preflight()
        py_argv = build_pytest_argv(extra)
    except (R6InstalledZipRunnerArgError, OSError) as exc:
        print(f"R6_INSTALLED_ZIP_RUNNER_REJECT {exc}", file=sys.stderr)
        return 2
    env = build_env()
    print(
        "R6_INSTALLED_ZIP_RUNNER opt-in E2E: "
        + " ".join([sys.executable, "-m", "pytest", *py_argv])
    )
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", *py_argv], cwd=str(REPO), env=env
    )
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
