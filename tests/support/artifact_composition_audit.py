"""Real release-artifact composition audit (opens ZIP / wheel / sdist members).

Closes KNOWN_GAP_3: unlike ``tests/test_production_package_scan.py`` (static
source contract only), this module reads the actual archive member lists and
optional member bytes. It never invokes the release builder.
"""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set

# R5-deleted production modules — any residual member is a hard failure.
DELETED_LEGACY_MODULE_BASENAMES = frozenset(
    {
        "tools.py",
        "mysql_executor.py",
        "ssh_tools.py",
        "ssh_executor.py",
        "targets.py",
        "file_backend.py",
        "deps_integrity.py",
    }
)

_PEM_HEADER_MARKERS = (
    b"BEGIN RSA PRIVATE KEY",
    b"BEGIN PRIVATE KEY",
    b"BEGIN OPENSSH PRIVATE KEY",
)

_TASK_EVIDENCE_SUFFIXES = (
    "-task.md",
    "-evidence.log",
    "-freeze-evidence.sha256",
)
_TASK_EVIDENCE_EXACT = frozenset(
    {
        ".r5-baseline-manifest.sha256",
    }
)


class ArtifactCompositionError(AssertionError):
    """Raised when a real artifact fails the composition contract."""


def iter_production_py_relpaths(repo: Path) -> List[str]:
    """Derive required production module paths from the live source tree.

    Never hand-maintain a parallel checklist — drift would green-wash gaps.
    """
    base = repo / "credential_guard"
    if not base.is_dir():
        raise ArtifactCompositionError(f"production package missing: {base}")
    out: List[str] = []
    for path in sorted(base.rglob("*.py")):
        if any(part == "__pycache__" for part in path.parts):
            continue
        out.append(path.relative_to(repo).as_posix())
    if not out:
        raise ArtifactCompositionError("no production .py modules discovered")
    return out


def list_zip_members(path: Path) -> List[str]:
    with zipfile.ZipFile(path) as zf:
        return sorted(zf.namelist())


def list_tar_members(path: Path) -> List[str]:
    with tarfile.open(path, "r:*") as tf:
        return sorted(tf.getnames())


def read_zip_member(path: Path, name: str) -> bytes:
    with zipfile.ZipFile(path) as zf:
        return zf.read(name)


def read_tar_member(path: Path, name: str) -> bytes:
    with tarfile.open(path, "r:*") as tf:
        member = tf.getmember(name)
        if not member.isfile():
            return b""
        handle = tf.extractfile(member)
        if handle is None:
            return b""
        return handle.read()


def _normalize(name: str) -> str:
    return name.replace("\\", "/").lstrip("./")


def _strip_archive_prefix(name: str, *, kind: str) -> str:
    """Map archive member path → repo-relative / package-relative path."""
    norm = _normalize(name)
    if kind == "plugin_zip":
        prefix = "credential-guard/"
        if norm.startswith(prefix):
            return norm[len(prefix) :]
        return norm
    if kind == "sdist":
        # hermes_credential_guard-<ver>/...
        parts = norm.split("/", 1)
        if len(parts) == 2:
            return parts[1]
        return ""
    # wheel: members are already package-relative / dist-info
    return norm


def find_forbidden_hits(
    members: Sequence[str],
    *,
    kind: str,
    read_bytes: Optional[Callable[[str], bytes]] = None,
) -> List[str]:
    """Return human-readable hits for the seven forbidden classes."""
    hits: List[str] = []
    for raw in members:
        norm = _normalize(raw)
        if norm.endswith("/"):
            continue
        stripped = _strip_archive_prefix(norm, kind=kind)
        lower = norm.lower()
        base = Path(norm).name

        # ① deleted legacy modules (path must be under credential_guard/)
        if any(
            stripped == f"credential_guard/{b}"
            or stripped.endswith(f"/credential_guard/{b}")
            for b in DELETED_LEGACY_MODULE_BASENAMES
        ):
            hits.append(f"legacy-module:{norm}")

        # ② vendored PyMySQL / deps/
        if stripped.startswith("deps/") or "/deps/" in f"/{stripped}":
            hits.append(f"vendored-deps:{norm}")
        if "pymysql" in lower:
            hits.append(f"pymysql:{norm}")

        # ③ test code
        if stripped.startswith("tests/") or "/tests/" in f"/{stripped}":
            hits.append(f"tests-tree:{norm}")
        if base.startswith("test_") and base.endswith(".py"):
            hits.append(f"test-module:{norm}")
        if base == "conftest.py":
            hits.append(f"conftest:{norm}")

        # ④ E2E harness / scripts
        if stripped.startswith("scripts/") or "/scripts/" in f"/{stripped}":
            hits.append(f"scripts-tree:{norm}")
        if "run_" in base and base.endswith("_e2e.py"):
            hits.append(f"e2e-harness:{norm}")
        if base.startswith("audit_") and base.endswith(".py") and "scripts" in lower:
            hits.append(f"audit-script:{norm}")

        # ⑤ private-key material by name
        if base.endswith(".pem") or base.endswith(".key") or base == "id_rsa":
            hits.append(f"key-filename:{norm}")

        # ⑥ task / evidence sidecars
        if base in _TASK_EVIDENCE_EXACT:
            hits.append(f"evidence:{norm}")
        if base.startswith(".r") and any(base.endswith(suf) for suf in _TASK_EVIDENCE_SUFFIXES):
            hits.append(f"task-evidence:{norm}")

        # ⑦ dev residue
        if "__pycache__" in norm.split("/"):
            hits.append(f"pycache:{norm}")
        if base.endswith(".pyc"):
            hits.append(f"pyc:{norm}")
        if ".pytest_cache" in norm.split("/"):
            hits.append(f"pytest-cache:{norm}")
        if ".venv" in norm.split("/"):
            hits.append(f"venv:{norm}")

        # ⑤ content: PEM headers (optional reader)
        if read_bytes is not None and (
            base.endswith((".pem", ".key", ".py", ".txt", ".md", ""))
            or "id_rsa" in base
            or base.endswith(".pem")
        ):
            try:
                blob = read_bytes(raw)
            except (KeyError, OSError):
                blob = b""
            if blob and any(marker in blob for marker in _PEM_HEADER_MARKERS):
                hits.append(f"pem-header:{norm}")

    # Stable unique
    seen: Set[str] = set()
    uniq: List[str] = []
    for h in hits:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    return uniq


def required_members_for_kind(
    production_rels: Sequence[str],
    *,
    kind: str,
) -> List[str]:
    """Map live production relpaths (+ root plugin.yaml where applicable) to archive names."""
    required: List[str] = []
    if kind == "plugin_zip":
        for rel in production_rels:
            required.append(f"credential-guard/{rel}")
        required.append("credential-guard/plugin.yaml")
    elif kind == "wheel":
        required.extend(production_rels)
    elif kind == "sdist":
        # Prefix filled in by caller via versioned top dir discovery, or we
        # match by suffix — see audit_artifact_members.
        required.extend(production_rels)
        required.append("plugin.yaml")
    else:
        raise ArtifactCompositionError(f"unknown artifact kind: {kind}")
    return required


def _missing_required(
    members: Sequence[str],
    required: Sequence[str],
    *,
    kind: str,
) -> List[str]:
    normalized = {_normalize(m) for m in members}
    missing: List[str] = []
    if kind == "sdist":
        # Members are hermes_credential_guard-<ver>/<rel>
        stripped = {_strip_archive_prefix(m, kind="sdist") for m in normalized}
        for rel in required:
            if rel not in stripped:
                missing.append(rel)
        return missing
    for rel in required:
        if rel not in normalized:
            missing.append(rel)
    return missing


def audit_artifact_members(
    members: Sequence[str],
    *,
    kind: str,
    production_rels: Sequence[str],
    artifact_name: str,
    read_bytes: Optional[Callable[[str], bytes]] = None,
    require_plugin_yaml: bool = False,
) -> Dict[str, object]:
    """Fail-loud composition audit. Returns a small report dict on success."""
    if not members:
        raise ArtifactCompositionError(
            f"{artifact_name}: empty member list (auditor must not vacuous-pass)"
        )

    required = required_members_for_kind(production_rels, kind=kind)
    if kind == "plugin_zip" or (kind == "sdist" and require_plugin_yaml):
        pass  # already included
    elif kind == "wheel" and require_plugin_yaml:
        required = list(required) + ["plugin.yaml"]

    missing = _missing_required(members, required, kind=kind)
    if missing:
        raise ArtifactCompositionError(
            f"{artifact_name}: missing required members: {missing[:20]}"
        )

    hits = find_forbidden_hits(members, kind=kind, read_bytes=read_bytes)
    if hits:
        raise ArtifactCompositionError(
            f"{artifact_name}: forbidden composition hits: {hits[:30]}"
        )

    return {
        "artifact": artifact_name,
        "kind": kind,
        "member_count": len(members),
        "required_count": len(required),
        "forbidden_hits": 0,
    }


def audit_zip_artifact(
    path: Path,
    *,
    kind: str,
    production_rels: Sequence[str],
    scan_pem_contents: bool = True,
) -> Dict[str, object]:
    members = list_zip_members(path)

    def _read(name: str) -> bytes:
        return read_zip_member(path, name)

    return audit_artifact_members(
        members,
        kind=kind,
        production_rels=production_rels,
        artifact_name=path.name,
        read_bytes=_read if scan_pem_contents else None,
        require_plugin_yaml=(kind == "plugin_zip"),
    )


def audit_sdist_artifact(
    path: Path,
    *,
    production_rels: Sequence[str],
    scan_pem_contents: bool = True,
) -> Dict[str, object]:
    members = list_tar_members(path)

    def _read(name: str) -> bytes:
        return read_tar_member(path, name)

    # Strategy (from MANIFEST.in): prune tests/scripts/docs — sdist must obey
    # the same forbidden set as wheel/plugin zip. Directory-only tar members
    # are ignored by the forbidden scanner.
    return audit_artifact_members(
        members,
        kind="sdist",
        production_rels=production_rels,
        artifact_name=path.name,
        read_bytes=_read if scan_pem_contents else None,
        require_plugin_yaml=True,
    )


def copy_zip_with_mutations(
    src: Path,
    dest: Path,
    *,
    add: Optional[Dict[str, bytes]] = None,
    drop: Optional[Iterable[str]] = None,
) -> Path:
    """Copy a ZIP while adding/removing members. Never mutates ``src``."""
    drop_set = {_normalize(n) for n in (drop or ())}
    add = add or {}
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(dest, "w") as zout:
        for info in zin.infolist():
            name = _normalize(info.filename)
            if name in drop_set:
                continue
            zout.writestr(info, zin.read(info.filename))
        for name, data in sorted(add.items()):
            zout.writestr(name, data)
    return dest
