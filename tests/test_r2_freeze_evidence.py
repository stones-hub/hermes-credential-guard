"""R2 Round8 B2: freeze algorithm module must be bound into the digest.

All tamper mutations run on tmp_path copies — never write the live candidate.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

import pytest

from credential_guard import r2_freeze_evidence as freeze

REPO = Path(__file__).resolve().parents[1]

_SKIP = frozenset(
    {".venv", "__pycache__", "dist", ".git", ".pytest_cache", "eggs", ".eggs", "build"}
)
# Only the recursive freeze output file is excluded from the file set.
# Report + evidence log remain named evidence bindings (not file-set members).
_FILE_EXCLUDES = frozenset(
    {
        ".r2-freeze-evidence.sha256",
        ".r2-tdd-evidence.log",
        "docs/R2-逻辑引用审批绑定与防偷换-实测报告.md",
    }
)
_FREEZE_MODULE = "credential_guard/r2_freeze_evidence.py"


def _independent_enumerate(root: Path) -> list[Path]:
    """Test-owned enumerator — must not call freeze.iter_workspace_files."""
    out: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if any(part in _SKIP for part in path.relative_to(root).parts):
            continue
        if rel in _FILE_EXCLUDES:
            continue
        if path.suffix == ".pyc":
            continue
        out.append(path)
    return out


def _copy_minimal_candidate(tmp_path: Path) -> Path:
    """Minimal tree: freeze module + a few sources + bound evidence carriers."""
    root = tmp_path / "candidate"
    (root / "credential_guard").mkdir(parents=True)
    (root / "docs").mkdir(parents=True)
    for rel in (
        "credential_guard/r2_freeze_evidence.py",
        "credential_guard/tool_request.py",
        "credential_guard/tool_execution.py",
        "credential_guard/invalid_marker_store.py",
        ".r2-tdd-evidence.log",
        "docs/R2-逻辑引用审批绑定与防偷换-实测报告.md",
    ):
        src = REPO / rel
        if not src.is_file():
            continue
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return root


def test_freeze_stable_twice():
    a = freeze.verify_freeze_stable(REPO)
    b = freeze.verify_freeze_stable(REPO)
    assert a == b
    assert len(a) == 64


def test_freeze_binds_report_and_evidence_log():
    digests = dict(freeze.bound_evidence_digests(REPO))
    assert "docs/R2-逻辑引用审批绑定与防偷换-实测报告.md" in digests
    assert ".r2-tdd-evidence.log" in digests
    report = REPO / "docs/R2-逻辑引用审批绑定与防偷换-实测报告.md"
    log = REPO / ".r2-tdd-evidence.log"
    assert digests["docs/R2-逻辑引用审批绑定与防偷换-实测报告.md"] == hashlib.sha256(
        report.read_bytes()
    ).hexdigest()
    assert digests[".r2-tdd-evidence.log"] == hashlib.sha256(log.read_bytes()).hexdigest()


def test_independent_enumeration_includes_freeze_module_and_matches_production():
    indep = {p.relative_to(REPO).as_posix() for p in _independent_enumerate(REPO)}
    prod = {p.relative_to(REPO).as_posix() for p in freeze.iter_workspace_files(REPO)}
    assert indep == prod
    assert _FREEZE_MODULE in indep
    assert _FREEZE_MODULE in prod
    assert ".r2-tdd-evidence.log" not in indep
    assert ".r2-freeze-evidence.sha256" not in indep


def test_production_enumerator_must_include_freeze_module():
    rels = {
        p.relative_to(REPO).as_posix() for p in freeze.iter_workspace_files(REPO)
    }
    assert _FREEZE_MODULE in rels
    assert ".r2-freeze-evidence.sha256" not in rels


def test_tamper_freeze_module_in_copy_changes_digest(tmp_path):
    root = _copy_minimal_candidate(tmp_path)
    baseline = freeze.compute_freeze_digest(root)
    target = root / _FREEZE_MODULE
    target.write_bytes(target.read_bytes() + b"\n# freeze-algo-tamper\n")
    tampered = freeze.compute_freeze_digest(root)
    assert tampered != baseline


def test_tamper_source_in_copy_changes_digest(tmp_path):
    root = _copy_minimal_candidate(tmp_path)
    baseline = freeze.compute_freeze_digest(root)
    target = root / "credential_guard" / "tool_execution.py"
    target.write_bytes(target.read_bytes() + b"\n# source-tamper\n")
    assert freeze.compute_freeze_digest(root) != baseline


def test_tamper_report_in_copy_changes_digest(tmp_path):
    root = _copy_minimal_candidate(tmp_path)
    baseline = freeze.compute_freeze_digest(root)
    report = root / "docs" / "R2-逻辑引用审批绑定与防偷换-实测报告.md"
    report.write_bytes(report.read_bytes() + b"\n# report-tamper\n")
    assert freeze.compute_freeze_digest(root) != baseline


def test_tamper_evidence_log_in_copy_changes_digest(tmp_path):
    root = _copy_minimal_candidate(tmp_path)
    baseline = freeze.compute_freeze_digest(root)
    log = root / ".r2-tdd-evidence.log"
    log.write_bytes(log.read_bytes() + b"\n# evidence-tamper\n")
    assert freeze.compute_freeze_digest(root) != baseline


def test_mutation_exclude_freeze_module_red(tmp_path, monkeypatch):
    """Restoring freeze-module exclusion must RED the include/tamper contract."""
    root = _copy_minimal_candidate(tmp_path)

    def excluding_iter(root_arg=None):
        base = Path(root_arg) if root_arg is not None else REPO
        out = []
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(base).as_posix()
            if any(part in _SKIP for part in path.relative_to(base).parts):
                continue
            if rel in _FILE_EXCLUDES or rel == _FREEZE_MODULE:
                continue
            if path.suffix == ".pyc":
                continue
            out.append(path)
        return out

    monkeypatch.setattr(freeze, "iter_workspace_files", excluding_iter)
    baseline = freeze.compute_freeze_digest(root)
    target = root / _FREEZE_MODULE
    target.write_bytes(target.read_bytes() + b"\n# excluded-tamper\n")
    # Under exclusion, freeze-module tamper is invisible — contract RED.
    with pytest.raises(AssertionError):
        assert freeze.compute_freeze_digest(root) != baseline
