#!/usr/bin/env python3
"""R3C E2E runner — candidate evidence only; does not claim R3/R3C PASS."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def main() -> int:
    cmd = [
        str(REPO / ".venv" / "bin" / "python"),
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "tests/test_r3c_wire_e2e.py",
        "tests/test_r3c_plugin_manager_graph.py",
        "tests/test_r3c_evidence_authenticity_gate.py",
        "tests/test_r3c_historical_identity_gate.py",
    ]
    print("run_r3c_e2e:", " ".join(cmd))
    proc = subprocess.run(cmd, cwd=str(REPO), check=False)
    print(
        "R3C candidate: wire+graph+authenticity+historical gates; "
        "not R3/R3C PASS — awaiting main-agent independent acceptance"
    )
    return int(proc.returncode)


if __name__ == "__main__":
    sys.exit(main())
