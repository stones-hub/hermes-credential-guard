"""R3B evidence hygiene — `.r3b-tdd-evidence.log` must not retain secrets/paths."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
EVIDENCE = REPO / ".r3b-tdd-evidence.log"

_DECOY_BODY = re.compile(
    r"\bCG_(?:SYNTHETIC_DECOY_|R3B_MAIN_|TOCTOU_|R2D_|MAIN_AGENT_|R2_)[A-Za-z0-9_]{4,}\b"
)
_SYNTH_HOST = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:test|example)\b",
    re.IGNORECASE,
)
_SENSITIVE_PATH = re.compile(
    r"(?:/Users/[^/\s]+/\.hermes\b|/Users/[^/\s]+/\.ssh\b|~/\.ssh\b|~/\.hermes\b)"
)
# Absolute program paths under tmp/pytest (should not appear in evidence narrative).
_ABS_PROGRAM = re.compile(r"/private/var/folders/[^\s]+/cg-(?:env|stdin|synth)[^\s]*")


def test_r3b_evidence_log_exists():
    assert EVIDENCE.is_file(), "missing .r3b-tdd-evidence.log"


def test_r3b_evidence_log_has_no_decoy_host_sensitive_or_program_path():
    text = EVIDENCE.read_text(encoding="utf-8")
    assert _DECOY_BODY.findall(text) == []
    assert _SYNTH_HOST.findall(text) == []
    assert _SENSITIVE_PATH.findall(text) == []
    assert _ABS_PROGRAM.findall(text) == []


def test_r3b_evidence_log_retains_tdd_structure():
    text = EVIDENCE.read_text(encoding="utf-8")
    assert "RED" in text or "FAILED" in text or "ImportError" in text
    assert "GREEN" in text or "passed" in text.lower()
    assert "Slice B" in text or "R3B" in text
