"""Release identity: vendored-deps vs full candidate manifests."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List


class ReleaseIdentityError(Exception):
    """Fail-loud release-identity error (never silent empty success)."""


# Production candidate identity — exclude tests/docs/tasks/caches/build outputs.
# Candidate = production source + deps + release config + release builder only.
_CANDIDATE_FILES = (
    "plugin.yaml",
    "requirements.txt",
    "pyproject.toml",
    "setup.py",
    "MANIFEST.in",
    "release-metadata.json",
    "__init__.py",
)
# Explicit whitelist — do not pull in all of scripts/ (E2E/test helpers are not
# part of the release candidate identity).
_CANDIDATE_WHITELIST_FILES = (
    "scripts/build_release_artifacts.py",
)
_CANDIDATE_DIRS = ("credential_guard",)
_SKIP_DIR_NAMES = {
    "__pycache__",
    ".venv",
    ".pytest_cache",
    ".eggs",
    "build",
    "dist",
    "tests",
    "scripts",
    "docs",
}

# Must match scripts/build_release_artifacts.py (kept here to avoid importing
# the builder into the runtime plugin path).
PLUGIN_VERSION = "0.4.6"
EXPECTED_SOURCE_DATE_EPOCH = 1704067200
EXPECTED_PYTHONHASHSEED = "0"
EXPECTED_TZ = "UTC"
WHEEL_FILENAME = f"hermes_credential_guard-{PLUGIN_VERSION}-py3-none-any.whl"
SDIST_FILENAME = f"hermes_credential_guard-{PLUGIN_VERSION}.tar.gz"
PLUGIN_ZIP_FILENAME = f"credential-guard-{PLUGIN_VERSION}-hermes-plugin.zip"
# Versioned so the current release manifest coexists with the frozen historical
# ``dist/artifact-manifest.json`` (0.3.1) without overwriting it.
ARTIFACT_MANIFEST_FILENAME = f"artifact-manifest-{PLUGIN_VERSION}.json"
STANDARD_ARTIFACT_FILENAMES = {
    "wheel": WHEEL_FILENAME,
    "sdist": SDIST_FILENAME,
    "plugin_zip": PLUGIN_ZIP_FILENAME,
}
_ARTIFACT_KINDS = ("wheel", "sdist", "plugin_zip")
_ALLOWED_MANIFEST_TOP_KEYS = frozenset(
    {
        "version",
        "candidate_manifest_sha256",
        "wheel",
        "sdist",
        "plugin_zip",
        "build",
    }
)
_ALLOWED_BUILD_KEYS = frozenset(
    {
        "build_python",
        "normalized_archives",
        "pythonhashseed",
        "source_date_epoch",
        "tz",
    }
)
_ALLOWED_ARTIFACT_ENTRY_KEYS = frozenset({"filename", "sha256", "size"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _require_non_negative_int(value: Any, *, label: str) -> int:
    # bool is a subclass of int — reject explicitly so True/False cannot pass.
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a non-negative int, got {value!r}")
    return value


def _require_exact_keys(obj: Dict[str, Any], allowed: frozenset, *, label: str) -> None:
    keys = set(obj.keys())
    extra = keys - allowed
    missing = allowed - keys
    if extra:
        raise ValueError(f"{label} has unexpected keys: {sorted(extra)}")
    if missing:
        # Keep singular wording when one key is missing (existing test matchers).
        if len(missing) == 1:
            raise ValueError(f"{label} missing key: {next(iter(missing))}")
        raise ValueError(f"{label} missing keys: {sorted(missing)}")


def _plugin_root() -> Path:
    return Path(__file__).resolve().parent.parent


def iter_candidate_files(root: Path | None = None) -> List[Path]:
    """Stable list of production candidate files for identity hashing."""
    base = root or _plugin_root()
    out: List[Path] = []
    for name in _CANDIDATE_FILES:
        path = base / name
        if path.is_file():
            out.append(path)
    for rel in _CANDIDATE_WHITELIST_FILES:
        path = base / rel
        if path.is_file():
            out.append(path)
    for dirname in _CANDIDATE_DIRS:
        d = base / dirname
        if not d.is_dir():
            continue
        for path in sorted(p for p in d.rglob("*") if p.is_file()):
            if any(part in _SKIP_DIR_NAMES for part in path.parts):
                continue
            if path.suffix == ".pyc":
                continue
            out.append(path)
    # Deterministic order by relative posix path.
    out.sort(key=lambda p: p.relative_to(base).as_posix())
    return out


def candidate_manifest_sha256(root: Path | None = None) -> str:
    """SHA-256 over relative path + content digest for the full candidate.

    Full candidate = production source + release config + release builder.
    ``dist/artifact-manifest*.json`` is intentionally excluded (no self-hash cycle).
    """
    base = root or _plugin_root()
    lines: List[str] = []
    for path in iter_candidate_files(base):
        rel = path.relative_to(base).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{rel}:{digest}")
    blob = "\n".join(lines).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def load_release_metadata(root: Path | None = None) -> Dict[str, Any]:
    path = (root or _plugin_root()) / "release-metadata.json"
    if not path.is_file():
        raise FileNotFoundError("release-metadata.json missing")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("release-metadata.json must be an object")
    return data


def measured_release_fields(root: Path | None = None) -> Dict[str, Any]:
    """Actual integrity fields compared against release-metadata.json.

    R5 removed the vendored PyMySQL tree, so the candidate declares no
    third-party runtime dependency and the only measured field is the
    candidate's own source manifest digest.
    """
    base = root or _plugin_root()
    return {"candidate_manifest_sha256": candidate_manifest_sha256(base)}


def release_metadata_matches(
    measured: Dict[str, Any], meta: Dict[str, Any]
) -> bool:
    """True when release-metadata.json declares no third-party dependency.

    Any surviving vendored/PyMySQL declaration is a hard mismatch: the
    candidate no longer measures such a tree, so it could never be verified.
    """
    if not isinstance(meta, dict):
        return False
    return meta == {}


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact_manifest_path(root: Path | None = None) -> Path:
    return (root or _plugin_root()) / "dist" / ARTIFACT_MANIFEST_FILENAME


def load_artifact_manifest(root: Path | None = None) -> Dict[str, Any]:
    path = artifact_manifest_path(root)
    if not path.is_file():
        raise FileNotFoundError(f"{ARTIFACT_MANIFEST_FILENAME} missing: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{ARTIFACT_MANIFEST_FILENAME} must be an object")
    return data


def _require_sha256_hex(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} must be 64-char lowercase hex sha256")
    return value


def _require_safe_basename(filename: Any, *, kind: str) -> str:
    if not isinstance(filename, str) or not filename:
        raise ValueError(f"artifact-manifest.{kind}.filename missing")
    # Basename only: reject absolute paths, ``..``, and directory separators.
    if Path(filename).name != filename:
        raise ValueError(
            f"artifact-manifest.{kind}.filename must be a basename, got {filename!r}"
        )
    if ".." in filename or "/" in filename or "\\" in filename:
        raise ValueError(
            f"artifact-manifest.{kind}.filename must be a basename, got {filename!r}"
        )
    return filename


def verify_artifact_manifest(
    root: Path | None = None,
    *,
    measured: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Fail-loud check: dist artifacts exist, hashes match manifest, candidate/deps match.

    Strict equality gates for version, build identity, standard filenames, and
    path safety. Returns the loaded manifest on success. Raises ValueError on
    any drift/missing/schema violation.
    """
    base = root or _plugin_root()
    manifest = load_artifact_manifest(base)

    _require_exact_keys(
        manifest, _ALLOWED_MANIFEST_TOP_KEYS, label="artifact-manifest"
    )

    version = manifest.get("version")
    if not isinstance(version, str) or version != PLUGIN_VERSION:
        raise ValueError(
            f"artifact-manifest.version must be {PLUGIN_VERSION!r}, "
            f"got {version!r}"
        )

    # Top-level identity digests: type-checked before value compare below.
    _require_sha256_hex(
        manifest.get("candidate_manifest_sha256"),
        label="artifact-manifest.candidate_manifest_sha256",
    )

    build = manifest.get("build")
    if not isinstance(build, dict):
        raise ValueError("artifact-manifest.build must be an object")
    _require_exact_keys(build, _ALLOWED_BUILD_KEYS, label="artifact-manifest.build")

    source_date_epoch = build.get("source_date_epoch")
    # Reject bool: isinstance(True, int) is True in Python.
    if type(source_date_epoch) is not int or source_date_epoch != EXPECTED_SOURCE_DATE_EPOCH:
        raise ValueError(
            "artifact-manifest.build.source_date_epoch must be "
            f"{EXPECTED_SOURCE_DATE_EPOCH}, got {source_date_epoch!r}"
        )
    normalized_archives = build.get("normalized_archives")
    if type(normalized_archives) is not bool or normalized_archives is not True:
        raise ValueError(
            "artifact-manifest.build.normalized_archives must be boolean True, "
            f"got {normalized_archives!r}"
        )
    pythonhashseed = build.get("pythonhashseed")
    if not isinstance(pythonhashseed, str) or pythonhashseed != EXPECTED_PYTHONHASHSEED:
        raise ValueError(
            "artifact-manifest.build.pythonhashseed must be "
            f"{EXPECTED_PYTHONHASHSEED!r}, got {pythonhashseed!r}"
        )
    tz = build.get("tz")
    if not isinstance(tz, str) or tz != EXPECTED_TZ:
        raise ValueError(
            f"artifact-manifest.build.tz must be {EXPECTED_TZ!r}, got {tz!r}"
        )
    build_python = build.get("build_python")
    if not isinstance(build_python, str) or not build_python.strip():
        raise ValueError(
            "artifact-manifest.build.build_python must be a non-empty string "
            "(informational only; not used for security path resolution)"
        )

    dist = base / "dist"
    seen_names: List[str] = []
    for kind in _ARTIFACT_KINDS:
        entry = manifest[kind]
        if not isinstance(entry, dict):
            raise ValueError(f"artifact-manifest.{kind} must be an object")
        _require_exact_keys(
            entry, _ALLOWED_ARTIFACT_ENTRY_KEYS, label=f"artifact-manifest.{kind}"
        )
        filename = _require_safe_basename(entry.get("filename"), kind=kind)
        expected_name = STANDARD_ARTIFACT_FILENAMES[kind]
        if filename != expected_name:
            raise ValueError(
                f"artifact-manifest.{kind}.filename must be {expected_name!r}, "
                f"got {filename!r}"
            )
        if filename in seen_names:
            raise ValueError(
                f"artifact-manifest filenames must be unique, duplicate {filename!r}"
            )
        seen_names.append(filename)
        expected = _require_sha256_hex(
            entry.get("sha256"), label=f"artifact-manifest.{kind}.sha256"
        )
        expected_size = _require_non_negative_int(
            entry.get("size"), label=f"artifact-manifest.{kind}.size"
        )
        path = dist / filename
        # Resolve only via basename under dist/ — never follow manifest paths.
        if path.resolve().parent != dist.resolve():
            raise ValueError(f"artifact path escaped dist/: {path}")
        if not path.is_file():
            raise ValueError(f"artifact missing: {path}")
        actual = file_sha256(path)
        if actual != expected:
            raise ValueError(
                f"artifact hash drift for {filename}: "
                f"manifest={expected} actual={actual}"
            )
        actual_size = path.stat().st_size
        if actual_size != expected_size:
            raise ValueError(
                f"artifact size drift for {filename}: "
                f"manifest={expected_size} actual={actual_size}"
            )

    if len(set(seen_names)) != 3:
        raise ValueError("artifact-manifest filenames must be three distinct basenames")

    fields = measured if measured is not None else measured_release_fields(base)
    cand = _require_sha256_hex(
        fields.get("candidate_manifest_sha256"),
        label="measured candidate_manifest_sha256",
    )
    man_cand = _require_sha256_hex(
        manifest.get("candidate_manifest_sha256"),
        label="artifact-manifest.candidate_manifest_sha256",
    )
    if cand != man_cand:
        raise ValueError(
            "candidate_manifest_sha256 drift vs artifact-manifest: "
            f"measured={cand} manifest={man_cand}"
        )
    return manifest
