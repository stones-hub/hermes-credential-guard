#!/usr/bin/env python3
"""R4 non-interference E2E — temporary HOME only; exit 0 on success."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cg-r4-ni-") as td:
        home = Path(td) / "home"
        hermes = Path(td) / "hermes"
        home.mkdir()
        hermes.mkdir()
        store = hermes / "credential-guard"
        store.mkdir(mode=0o700)
        cfg = store / "credential-guard.json"
        cfg.write_text(
            json.dumps({"version": 2, "credentials": {}, "bindings": {}}),
            encoding="utf-8",
        )
        os.chmod(cfg, 0o600)
        env = os.environ.copy()
        env["HOME"] = str(home)
        env["HERMES_HOME"] = str(hermes)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        cmd = [
            sys.executable,
            "-m",
            "pytest",
            str(REPO / "tests" / "test_non_interference_v2.py"),
            "-q",
            "-p",
            "no:cacheprovider",
        ]
        proc = subprocess.run(cmd, cwd=str(REPO), env=env)
        return int(proc.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
