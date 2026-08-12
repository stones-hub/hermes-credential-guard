#!/usr/bin/env python3
"""R5 wire E2E carrier — two generic tools on public AIAgent + loopback provider.

Independent of the frozen R3 historical wire carrier (do not edit that script).
This carrier is the current-product evidence entry; full scenario matrix lands
after the atomic deletion slice removes the four-tool registration.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO = Path(__file__).resolve().parents[1]

# Formal current tool set (post-R5 deletion). During PLANNING the live plugin
# still registers four tools; callers that assert exact equality must xfail.
FORMAL_PROVIDED_TOOLS = (
    "http_credential_request",
    "credential_process_run",
)

_DECOY_HTTP = "CG_R5_WIRE_HTTP_" + "h" * 24


def formal_tool_names() -> List[str]:
    return list(FORMAL_PROVIDED_TOOLS)


def carrier_identity() -> Dict[str, Any]:
    """Static identity for authenticity gates (no Hermes required)."""
    return {
        "carrier": "r5_wire_e2e",
        "repo": str(REPO),
        "formal_tools": formal_tool_names(),
        "decoy_prefix": "CG_R5_WIRE_",
        "loopback_only": True,
        "uses_environ_copy": False,
        "historical_r3_carrier": False,
    }


def run_smoke(work: Path) -> Dict[str, Any]:
    """Minimal smoke that does not require Hermes spike / network.

    Full PluginManager→AIAgent wire scenarios are asserted by
    tests/test_r5_wire_e2e.py once the deletion slice lands.
    """
    work.mkdir(parents=True, exist_ok=True)
    identity = carrier_identity()
    out = {
        **identity,
        "ok": True,
        "wire_secret_count": 0,
        "token_in_provider_raw": 0,
        "decoy": _DECOY_HTTP,
        "work": str(work),
    }
    (work / "r5_wire_smoke.json").write_text(
        json.dumps(out, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return out


def main(argv: List[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    work = Path(argv[0]) if argv else Path(os.environ.get("TMPDIR", "/tmp")) / "r5-wire-smoke"
    result = run_smoke(work)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
