#!/usr/bin/env python3
"""R3B E2E runner — candidate evidence only; does not claim R3B/R3 PASS."""

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
        "tests/test_r3b_main_agent_path.py",
        "tests/test_r3b_e2e.py",
        "tests/test_r3b_plugin_manager_graph.py",
        "tests/test_r3b_wire_e2e.py",
        "tests/test_r3b_evidence_authenticity_gate.py",
        "tests/test_r3b_evidence_hygiene.py",
    ]
    print("run_r3b_e2e:", " ".join(cmd))
    proc = subprocess.run(cmd, cwd=str(REPO), check=False)
    print("adapter_ok + wire_secret_count evidence via observers; candidate only")
    return int(proc.returncode)


if __name__ == "__main__":
    sys.exit(main())
