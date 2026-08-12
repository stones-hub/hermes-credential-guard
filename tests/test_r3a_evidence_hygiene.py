"""B4: `.r3a-tdd-evidence.log` must not retain full synthetic decoys or hosts."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
EVIDENCE = REPO / ".r3a-tdd-evidence.log"

# Full synthetic decoy bodies (known prefixes + material), not env-var names.
_DECOY_BODY = re.compile(
    r"\bCG_(?:SYNTHETIC_DECOY_|TOCTOU_|R2D_|MAIN_AGENT_|R2_)[A-Za-z0-9_]{4,}\b"
)
# DNS-ish synthetic hosts (e.g. jenkins.example.test)
_SYNTH_HOST = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:test|example)\b",
    re.IGNORECASE,
)
_SENSITIVE_PATH = re.compile(
    r"(?:/Users/[^/\s]+/\.hermes\b|/Users/[^/\s]+/\.ssh\b|~/\.ssh\b|~/\.hermes\b)"
)


def test_b4_evidence_log_exists():
    assert EVIDENCE.is_file(), "missing .r3a-tdd-evidence.log"


def test_b4_evidence_log_has_no_full_decoy_or_host_or_sensitive_path():
    text = EVIDENCE.read_text(encoding="utf-8")
    decoys = _DECOY_BODY.findall(text)
    hosts = _SYNTH_HOST.findall(text)
    paths = _SENSITIVE_PATH.findall(text)
    assert decoys == [], f"full synthetic decoy bodies present: {decoys[:5]}"
    assert hosts == [], f"synthetic hosts present: {hosts[:5]}"
    assert paths == [], f"sensitive paths present: {paths[:5]}"


def test_b4_evidence_log_retains_tdd_structure():
    text = EVIDENCE.read_text(encoding="utf-8")
    assert "RED" in text or "FAILED" in text or "exit" in text.lower()
    assert "GREEN" in text or "passed" in text.lower()
    assert "[SYNTHETIC_DECOY_REDACTED]" in text or "R3A" in text


def test_b4_evidence_log_marks_round3_sandbox_as_historical():
    """Authoritative Round3 non-sandbox counts must supersede sandbox PermissionError snapshot."""
    text = EVIDENCE.read_text(encoding="utf-8")
    assert "主代理 Round3 非沙箱权威复验" in text or "Round3 非沙箱权威复验" in text
    assert "1095 passed" in text
    assert "17e58c4a8124fb11a3880ac04b69fb076a382227e048b6dd021e742fd4931422" in text
    # Prior coding-agent sandbox snapshot must be labeled historical, not final sign-off.
    assert "历史" in text and ("d1f634" in text or "228 files" in text)
    assert "13 passed" in text
    assert "PermissionError" in text or "沙箱" in text
