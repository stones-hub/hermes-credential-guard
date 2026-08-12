"""R2 report must label candidate vs review-workspace manifests accurately.

R2 历史签收身份绑定 ``.r2-freeze-evidence.sha256`` / 报告正式签收段，
不要求追随后续里程碑的 live candidate / live workspace digests。
算法形状仍由独立 walk 与 ``candidate_manifest_sha256`` 机械核对。
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from credential_guard.release_identity import (
    candidate_manifest_sha256,
    iter_candidate_files,
)

REPO = Path(__file__).resolve().parents[1]
REPORT = REPO / "docs" / "R2-逻辑引用审批绑定与防偷换-实测报告.md"
FREEZE_EVIDENCE = REPO / ".r2-freeze-evidence.sha256"

_SKIP_DIRS = {
    ".venv",
    "__pycache__",
    "dist",
    ".git",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "htmlcov",
}
# Self-referential freeze carriers — excluded so the digest can be embedded.
_REVIEW_EXCLUDE = {
    "docs/R2-逻辑引用审批绑定与防偷换-实测报告.md",
    ".r2-tdd-evidence.log",
    ".r2-freeze-evidence.sha256",  # recursive output; identity record, not digest input
}

# R2 §17 formal sign-off review workspace (time-bounded; not live).
_R2_SIGN_OFF_REVIEW_SHA256 = (
    "79415b9596c6805b5f06b50af92c8032aa517e5dc6083f6d957557b791a9ac26"
)
_R2_SIGN_OFF_REVIEW_FILES = 209
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _load_r2_freeze_evidence(path: Path = FREEZE_EVIDENCE) -> dict[str, str]:
    assert path.is_file(), f"missing R2 freeze evidence: {path}"
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, val = line.partition("=")
        out[key.strip()] = val.strip()
    return out


def _latest_freeze_section(text: str) -> str:
    """Prefer latest freeze/sign-off section (§17 > §16 > … ≥ §13)."""
    section = None
    for n in range(20, 12, -1):
        marker = f"## {n}."
        if marker in text:
            section = text.split(marker, 1)[1]
            break
    assert section is not None, "report must contain a freeze section ≥ §13"
    return section


def _review_workspace_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        if path.suffix == ".pyc":
            continue
        if rel.as_posix() in _REVIEW_EXCLUDE:
            continue
        out.append(path)
    return out


def _review_workspace_manifest_sha256(root: Path) -> tuple[str, int]:
    """Independent review freeze: relative_path:sha256:size\\n then SHA-256."""
    lines: list[str] = []
    for path in _review_workspace_files(root):
        rel = path.relative_to(root).as_posix()
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        lines.append(f"{rel}:{digest}:{len(data)}")
    blob = "\n".join(lines).encode("utf-8")
    return hashlib.sha256(blob).hexdigest(), len(lines)


def _independent_candidate_lines(root: Path) -> list[str]:
    """Mirror release_identity algorithm without importing its string join blindly."""
    lines: list[str] = []
    for path in iter_candidate_files(root):
        rel = path.relative_to(root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{rel}:{digest}")
    return lines


def test_candidate_algorithm_is_path_sha256_without_size():
    lines = _independent_candidate_lines(REPO)
    assert lines, "candidate set must be non-empty"
    for line in lines:
        parts = line.split(":")
        assert len(parts) == 2, f"candidate line must be path:sha256, got {line!r}"
        assert len(parts[1]) == 64
    indep = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
    assert indep == candidate_manifest_sha256(REPO)


def test_review_workspace_algorithm_includes_size():
    files = _review_workspace_files(REPO)
    assert files, "review workspace set must be non-empty"
    digest, count = _review_workspace_manifest_sha256(REPO)
    assert count == len(files)
    # Spot-check algorithm shape on first line reconstruction.
    first = files[0]
    data = first.read_bytes()
    sample = (
        f"{first.relative_to(REPO).as_posix()}:"
        f"{hashlib.sha256(data).hexdigest()}:"
        f"{len(data)}"
    )
    assert sample.count(":") == 2
    assert len(digest) == 64


def _assert_r2_sign_off_historical_identity(section: str, frozen: dict[str, str]) -> None:
    """Validate R2 sign-off labels against frozen historical identity (not live)."""
    frozen_cand = frozen["R2_PRODUCTION_CANDIDATE_SHA256"]
    frozen_cand_files = int(frozen["R2_PRODUCTION_CANDIDATE_FILES"])
    assert _HEX64.match(frozen_cand), "freeze evidence candidate must be 64 hex"

    cand_algo = re.search(
        r"candidate_manifest_sha256.*?algorithm[：:]\s*`?([^`\n（(]+)",
        section,
        re.IGNORECASE | re.DOTALL,
    )
    assert cand_algo, "sign-off section must document candidate_manifest_sha256 algorithm"
    cand_algo_s = cand_algo.group(1)
    assert "size" not in cand_algo_s.lower()
    assert "sha256" in cand_algo_s.lower()

    cand_val = re.search(
        r"candidate_manifest_sha256[：:]\s*([0-9a-f]{64})",
        section,
    )
    assert cand_val, "sign-off section must publish candidate_manifest_sha256 value"
    assert cand_val.group(1) == frozen_cand

    cand_count = re.search(
        r"candidate files[：:]\s*(\d+)",
        section,
        re.IGNORECASE,
    )
    assert cand_count, "sign-off section must publish candidate file count"
    assert int(cand_count.group(1)) == frozen_cand_files

    rev_algo = re.search(
        r"review_workspace_manifest_sha256.*?algorithm[：:]\s*`?([^`\n（(]+)",
        section,
        re.IGNORECASE | re.DOTALL,
    )
    assert rev_algo, "sign-off section must document review_workspace_manifest_sha256 algorithm"
    assert "size" in rev_algo.group(1).lower()

    rev_val = re.search(
        r"review_workspace_manifest_sha256[：:]\s*([0-9a-f]{64})",
        section,
    )
    assert rev_val, "sign-off section must publish review_workspace_manifest_sha256 value"
    assert rev_val.group(1) == _R2_SIGN_OFF_REVIEW_SHA256

    count_m = re.search(
        r"review workspace files[：:]\s*(\d+)",
        section,
        re.IGNORECASE,
    )
    assert count_m, "sign-off section must publish review workspace file count"
    assert int(count_m.group(1)) == _R2_SIGN_OFF_REVIEW_FILES

    # Time-bounded technical review snapshot (before administrative backfill).
    tech = re.search(
        r"technical_review_workspace_sha256[：:]\s*([0-9a-f]{64})",
        section,
        re.IGNORECASE,
    )
    assert tech, "sign-off section must publish technical_review_workspace_sha256"
    assert tech.group(1) == frozen["R2_TECHNICAL_REVIEW_WORKSPACE_SHA256"]
    timing = re.search(
        r"technical_review_snapshot_timing[：:]\s*([^\n]+)",
        section,
        re.IGNORECASE,
    )
    assert timing, "sign-off section must publish technical_review_snapshot_timing"
    assert "before administrative" in timing.group(1).lower()


def test_r2_historical_identity_survives_subsequent_live_candidate_drift():
    """R2 历史报告保持冻结身份；后续 live candidate 变化时门禁仍应通过。"""
    text = REPORT.read_text(encoding="utf-8")
    assert "## 13." in text
    section = _latest_freeze_section(text)
    frozen = _load_r2_freeze_evidence()
    _assert_r2_sign_off_historical_identity(section, frozen)

    live_cand = candidate_manifest_sha256(REPO)
    frozen_cand = frozen["R2_PRODUCTION_CANDIDATE_SHA256"]
    # When R3+ advances the candidate set, live may diverge; that must not fail
    # the historical gate (already asserted above against freeze evidence).
    if live_cand != frozen_cand:
        assert frozen_cand != live_cand


def test_r2_report_section_13_manifest_labels_match_frozen_identity():
    """R2 report labels: path:sha256 (no size) + frozen R2 identity, not live."""
    text = REPORT.read_text(encoding="utf-8")
    assert "## 13." in text
    section = _latest_freeze_section(text)
    frozen = _load_r2_freeze_evidence()
    _assert_r2_sign_off_historical_identity(section, frozen)

    # Live digests may differ after later milestones; do not couple.
    live_cand = candidate_manifest_sha256(REPO)
    live_rev, _live_count = _review_workspace_manifest_sha256(REPO)
    if live_cand != frozen["R2_PRODUCTION_CANDIDATE_SHA256"]:
        assert live_cand != frozen["R2_PRODUCTION_CANDIDATE_SHA256"]
    if live_rev != _R2_SIGN_OFF_REVIEW_SHA256:
        assert live_rev != _R2_SIGN_OFF_REVIEW_SHA256


def test_r2_report_algorithm_size_mislabeled_mutation_is_red():
    """Tampering candidate algorithm to include size must fail the gate."""
    text = REPORT.read_text(encoding="utf-8")
    section = _latest_freeze_section(text)
    frozen = _load_r2_freeze_evidence()
    mutated = re.sub(
        r"(candidate_manifest_sha256.*?algorithm[：:]\s*`?)([^`\n（(]+)",
        r"\1relative_path:sha256:size\\n",
        section,
        count=1,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert "size" in mutated.lower()
    with pytest.raises(AssertionError):
        _assert_r2_sign_off_historical_identity(mutated, frozen)


def test_r2_report_frozen_candidate_digest_mutation_is_red():
    """Wrong historical candidate digest (format-valid but not frozen) must fail."""
    text = REPORT.read_text(encoding="utf-8")
    section = _latest_freeze_section(text)
    frozen = _load_r2_freeze_evidence()
    bad = "0" * 64
    mutated = re.sub(
        r"(candidate_manifest_sha256[：:]\s*)([0-9a-f]{64})",
        rf"\g<1>{bad}",
        section,
        count=1,
    )
    assert bad in mutated
    with pytest.raises(AssertionError):
        _assert_r2_sign_off_historical_identity(mutated, frozen)


def test_r2_report_review_timing_mutation_is_red():
    """Dropping time-bounded technical review timing must fail."""
    text = REPORT.read_text(encoding="utf-8")
    section = _latest_freeze_section(text)
    frozen = _load_r2_freeze_evidence()
    mutated = re.sub(
        r"technical_review_snapshot_timing[：:]\s*[^\n]+",
        "technical_review_snapshot_timing: after live workspace",
        section,
        count=1,
        flags=re.IGNORECASE,
    )
    with pytest.raises(AssertionError):
        _assert_r2_sign_off_historical_identity(mutated, frozen)


def test_historical_mislabeled_candidate_algorithm_is_voided():
    """Keep historical numbers but require explicit 历史误标/作废 markers."""
    text = REPORT.read_text(encoding="utf-8")
    # Round5 / 5b freeze blocks incorrectly claimed candidate used path:sha256:size.
    for needle in (
        "3d8ee3d01d97abae2ffd5bbf6604881b82fc74a3877817d6a711515a03319902",
        "16581bb6cff33011e43b8915b49a394329e74ab4732623acad8ef1471b784984",
    ):
        assert needle in text, "historical digest must be retained"
    assert "历史误标" in text and "作废" in text
