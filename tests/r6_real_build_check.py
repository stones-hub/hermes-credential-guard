"""R6 real double-build byte-identity check (opt-in; NOT in the no-build corpus).

Why this file is not named ``tests/test_*.py``
----------------------------------------------
``scripts/run_r5_nobuild_pytest.py`` owns test selection: it refuses ``-m``,
``-k``, paths and nodeids, and its corpus is the fixed glob
``tests/test_*.py``. A real-build test therefore cannot be excluded from the
default run by a marker expression — the runner would reject the very argv
needed to exclude it (``R5_NOBUILD_ARGREJECT``). Worse, the runner's
fail-closed AST preflight (``preflight_no_build``) rejects the *entire* run
when any collected module can reach the release builder, so simply marking a
``tests/test_*.py`` module would turn the whole default suite into exit 2.

The exclusion boundary used here is the filename itself: this module is named
``r6_real_build_check.py``, outside the runner's glob, so the default full run
stays at zero builds. It is executed only through the dedicated opt-in runner
``scripts/run_r6_build_tests.py``. That boundary is self-proven by the gate
tests in ``tests/test_r6_build_optin_gate.py``.

Safety (task 禁 1): every build writes to ``tempfile.mkdtemp()`` only. The
repository ``dist/`` is never passed to the builder, and a hard assertion
refuses any out_dir that resolves to it — protecting the four frozen 0.3.1
assets, which are unrecoverable because this project is not a git repository.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Dict

import pytest

ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = ROOT / "scripts" / "build_release_artifacts.py"
FORBIDDEN_OUT_DIR = (ROOT / "dist").resolve()

pytestmark = pytest.mark.real_build


def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _load_builder():
    spec = importlib.util.spec_from_file_location("cg_r6_builder", BUILDER_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _assert_safe_out_dir(out_dir: Path) -> None:
    """Refuse anything that is (or is inside) the repository dist/."""
    resolved = out_dir.resolve()
    assert resolved != FORBIDDEN_OUT_DIR, f"REFUSING build into repo dist/: {resolved}"
    assert FORBIDDEN_OUT_DIR not in resolved.parents, (
        f"REFUSING build under repo dist/: {resolved}"
    )
    assert str(resolved).startswith(
        ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders")
    ), f"REFUSING build outside a temp dir: {resolved}"


def _repo_build_residue() -> Dict[str, bool]:
    """Intermediates that would let a second build reuse the first one's work."""
    return {
        "build": (ROOT / "build").exists(),
        "egg_info": bool(list(ROOT.glob("*.egg-info"))),
    }


def _build_into(tmp_root: Path, label: str) -> Dict[str, object]:
    """One fully independent build; returns hashes plus the manifest payload."""
    out_dir = Path(tempfile.mkdtemp(prefix=f"r6_realbuild_{label}_", dir=str(tmp_root)))
    _assert_safe_out_dir(out_dir)
    builder = _load_builder()
    result = builder.build_all(out_dir)
    hashes = {
        kind: _sha256(Path(result[kind])) for kind in ("wheel", "sdist", "plugin_zip")
    }
    manifest_path = Path(result["artifact_manifest"])
    return {
        "out_dir": out_dir,
        "names": {
            kind: Path(result[kind]).name
            for kind in ("wheel", "sdist", "plugin_zip")
        },
        "hashes": hashes,
        "manifest_sha256": _sha256(manifest_path),
        "manifest": json.loads(manifest_path.read_text(encoding="utf-8")),
        "build_python": result.get("build_python"),
        "source_date_epoch": result.get("source_date_epoch"),
    }


def test_real_double_build_is_byte_identical(monkeypatch, tmp_path):
    """Two genuinely independent builds must produce byte-identical artifacts.

    Independence is enforced, not assumed:

    * two distinct ``tempfile.mkdtemp()`` output directories;
    * the builder is re-imported per build, so no module-level state carries
      over;
    * every intermediate lives in the builder's own
      ``tempfile.TemporaryDirectory`` (clean source copy + staging dir);
    * ``build/`` and ``*.egg-info`` are asserted absent from the repository
      before, between, and after the two builds, so build #2 cannot reuse
      build #1's compiled output.
    """
    monkeypatch.setenv("CG_NO_BUILD_TRIPWIRE", "1")
    monkeypatch.setenv("CG_R6_BUILD_AUTHORIZED", "1")

    assert _repo_build_residue() == {"build": False, "egg_info": False}, (
        "repository already carries build intermediates; refusing to claim "
        "build independence"
    )

    # Build must not mutate repository dist/ (0.3.1 freeze + any landed 0.4.0).
    dist_dir = ROOT / "dist"
    dist_before = {
        p.name: _sha256(p) for p in dist_dir.iterdir() if p.is_file()
    }

    first = _build_into(tmp_path, "a")
    between = _repo_build_residue()
    second = _build_into(tmp_path, "b")
    after = _repo_build_residue()

    assert between == {"build": False, "egg_info": False}, between
    assert after == {"build": False, "egg_info": False}, after
    assert first["out_dir"] != second["out_dir"]

    # Byte equality (sha256) — never size-only, never member-names-only, and
    # never with a "permitted differences" allowlist (task 禁 3).
    for kind in ("wheel", "sdist", "plugin_zip"):
        assert first["hashes"][kind] == second["hashes"][kind], (
            f"double-build byte drift for {kind}: "
            f"{first['hashes'][kind]} != {second['hashes'][kind]}"
        )
    assert first["manifest_sha256"] == second["manifest_sha256"], (
        f"artifact-manifest drift between builds: "
        f"{first['manifest_sha256']} != {second['manifest_sha256']}"
    )
    assert first["manifest"] == second["manifest"]

    dist_after = {
        p.name: _sha256(p) for p in dist_dir.iterdir() if p.is_file()
    }
    assert dist_before == dist_after, (
        "repository dist/ mutated during temp builds: "
        f"before={sorted(dist_before)} after={sorted(dist_after)}"
    )


def test_real_build_manifest_schema_and_identity(monkeypatch, tmp_path):
    """The freshly built manifest must satisfy the R6 6-key schema."""
    from credential_guard.release_identity import (
        PLUGIN_VERSION,
        PLUGIN_ZIP_FILENAME,
        SDIST_FILENAME,
        WHEEL_FILENAME,
        verify_artifact_manifest,
    )

    monkeypatch.setenv("CG_NO_BUILD_TRIPWIRE", "1")
    monkeypatch.setenv("CG_R6_BUILD_AUTHORIZED", "1")

    built = _build_into(tmp_path, "schema")
    manifest = built["manifest"]

    assert set(manifest) == {
        "version",
        "candidate_manifest_sha256",
        "wheel",
        "sdist",
        "plugin_zip",
        "build",
    }, sorted(manifest)
    assert "vendored_deps_manifest_sha256" not in manifest
    assert manifest["version"] == PLUGIN_VERSION
    assert built["names"]["wheel"] == WHEEL_FILENAME
    assert built["names"]["sdist"] == SDIST_FILENAME
    assert built["names"]["plugin_zip"] == PLUGIN_ZIP_FILENAME
    assert manifest["build"]["source_date_epoch"] == 1704067200
    assert manifest["build"]["pythonhashseed"] == "0"
    assert manifest["build"]["tz"] == "UTC"
    assert manifest["build"]["normalized_archives"] is True

    # Verify against a fake root whose dist/ is the temp output directory, so
    # the repository dist/ is never read or written here.
    fake_root = Path(tempfile.mkdtemp(prefix="r6_verify_root_", dir=str(tmp_path)))
    fake_dist = fake_root / "dist"
    shutil.copytree(built["out_dir"], fake_dist)
    verify_artifact_manifest(
        fake_root,
        measured={"candidate_manifest_sha256": manifest["candidate_manifest_sha256"]},
    )


def test_real_build_requires_explicit_authorization(monkeypatch, tmp_path):
    """Armed tripwire without CG_R6_BUILD_AUTHORIZED must refuse to build."""
    monkeypatch.setenv("CG_NO_BUILD_TRIPWIRE", "1")
    monkeypatch.delenv("CG_R6_BUILD_AUTHORIZED", raising=False)
    builder = _load_builder()
    out_dir = Path(tempfile.mkdtemp(prefix="r6_realbuild_unauth_", dir=str(tmp_path)))
    _assert_safe_out_dir(out_dir)
    with pytest.raises(builder.NoBuildTripwireError):
        builder.build_all(out_dir)
    assert sorted(os.listdir(out_dir)) == []


def test_production_source_single_byte_mutation_changes_identities(
    monkeypatch, tmp_path
):
    """A one-byte production source edit must change candidate + plugin ZIP digests."""
    from credential_guard.release_identity import candidate_manifest_sha256

    monkeypatch.setenv("CG_NO_BUILD_TRIPWIRE", "1")
    monkeypatch.setenv("CG_R6_BUILD_AUTHORIZED", "1")

    victim = ROOT / "credential_guard" / "constants.py"
    assert victim.is_file()
    original = victim.read_bytes()
    dist_before = {
        p.name: _sha256(p) for p in (ROOT / "dist").iterdir() if p.is_file()
    }
    try:
        baseline = _build_into(tmp_path, "mut_base")
        base_candidate = candidate_manifest_sha256(ROOT)
        assert baseline["manifest"]["candidate_manifest_sha256"] == base_candidate

        victim.write_bytes(original + b"#")
        mutated_candidate = candidate_manifest_sha256(ROOT)
        assert mutated_candidate != base_candidate, (
            "single-byte production mutation must change candidate_manifest_sha256"
        )
        mutated = _build_into(tmp_path, "mut_edit")
        assert (
            mutated["manifest"]["candidate_manifest_sha256"] == mutated_candidate
        )
        assert mutated["hashes"]["plugin_zip"] != baseline["hashes"]["plugin_zip"], (
            "single-byte production mutation must change final plugin ZIP identity"
        )
    finally:
        victim.write_bytes(original)
        dist_after = {
            p.name: _sha256(p) for p in (ROOT / "dist").iterdir() if p.is_file()
        }
        assert dist_before == dist_after, "mutation build must not touch repo dist/"
