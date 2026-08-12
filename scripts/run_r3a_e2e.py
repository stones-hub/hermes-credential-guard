#!/usr/bin/env python3
"""R3A E2E runner — delegates to R2 runner with R3A adapter transport evidence."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
R2 = ROOT / "scripts" / "run_r2_e2e.py"


def main() -> None:
    if not R2.is_file():
        raise SystemExit("missing scripts/run_r2_e2e.py")
    # Reuse R2 compatibility runner; R3A fake transport + adapter_ok are wired there.
    sys.argv[0] = str(R2)
    runpy.run_path(str(R2), run_name="__main__")


if __name__ == "__main__":
    main()
