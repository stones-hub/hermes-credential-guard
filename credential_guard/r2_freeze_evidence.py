"""R2 independent freeze evidence gate.

Binds SHA-256 of the R2 report and TDD evidence log into a freeze digest.
The freeze algorithm module itself is included in the file set so the digest
binds both the candidate and the algorithm. Only the recursive output file
``.r2-freeze-evidence.sha256`` is excluded from enumeration. Candidate
enumeration for the verifier is intentionally duplicated in tests — production
enumeration alone must not self-certify.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

# Bound evidence carriers — included by content hash, not as recursive digests.
BOUND_EVIDENCE_FILES: Tuple[str, ...] = (
    "docs/R2-逻辑引用审批绑定与防偷换-实测报告.md",
    ".r2-tdd-evidence.log",
)

# Recursive freeze output + named evidence carriers (bound separately).
# The freeze algorithm module itself MUST remain in the file set.
_SELF_EXCLUDES = frozenset(
    {
        ".r2-freeze-evidence.sha256",
        ".r2-tdd-evidence.log",  # bound separately as a named evidence hash
        "docs/R2-逻辑引用审批绑定与防偷换-实测报告.md",
    }
)

_SKIP_DIR_PARTS = frozenset(
    {
        ".venv",
        "__pycache__",
        "dist",
        ".git",
        ".pytest_cache",
        "eggs",
        ".eggs",
        "build",
    }
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def iter_workspace_files(root: Path | None = None) -> List[Path]:
    """Enumerate freeze candidates (excludes caches/dist/output/evidence carriers)."""
    base = root or REPO_ROOT
    out: List[Path] = []
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(base).as_posix()
        if any(part in _SKIP_DIR_PARTS for part in path.relative_to(base).parts):
            continue
        if rel in _SELF_EXCLUDES:
            continue
        if path.suffix == ".pyc":
            continue
        out.append(path)
    return out


def bound_evidence_digests(root: Path | None = None) -> List[Tuple[str, str]]:
    base = root or REPO_ROOT
    rows: List[Tuple[str, str]] = []
    for rel in BOUND_EVIDENCE_FILES:
        path = base / rel
        if not path.is_file():
            raise FileNotFoundError(rel)
        rows.append((rel, _sha256_file(path)))
    return rows


def freeze_lines(
    files: Sequence[Path],
    *,
    root: Path | None = None,
    evidence: Sequence[Tuple[str, str]] | None = None,
) -> str:
    """Build canonical freeze text: path:sha256:size plus evidence bindings."""
    base = root or REPO_ROOT
    lines: List[str] = []
    for path in files:
        rel = path.relative_to(base).as_posix()
        data = path.read_bytes()
        lines.append(f"{rel}:{_sha256_bytes(data)}:{len(data)}")
    lines.append("--evidence--")
    for rel, digest in evidence if evidence is not None else bound_evidence_digests(base):
        lines.append(f"evidence:{rel}:{digest}")
    return "\n".join(lines) + "\n"


def compute_freeze_digest(root: Path | None = None) -> str:
    base = root or REPO_ROOT
    files = iter_workspace_files(base)
    text = freeze_lines(files, root=base)
    return _sha256_bytes(text.encode("utf-8"))


def verify_freeze_stable(root: Path | None = None) -> str:
    """Compute twice; raise if unstable (e.g. self-inclusion recursion)."""
    a = compute_freeze_digest(root)
    b = compute_freeze_digest(root)
    if a != b:
        raise RuntimeError("freeze digest unstable across consecutive computations")
    return a


__all__ = [
    "BOUND_EVIDENCE_FILES",
    "REPO_ROOT",
    "bound_evidence_digests",
    "compute_freeze_digest",
    "freeze_lines",
    "iter_workspace_files",
    "verify_freeze_stable",
]
