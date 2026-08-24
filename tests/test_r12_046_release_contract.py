"""R12 / 0.4.6 release contract (source candidate; no build / no dist write).

Strict pending-build phase:
- four current version anchors are 0.4.6;
- standard four filenames bind PLUGIN_VERSION;
- retained twelve historical artifacts (0.4.2/0.4.3/0.4.4) hash-freeze;
- CURRENT_DIST_PHASE is source_candidate_pending_build;
- R12 final-ZIP runner points at 0.4.6 and reuses shared install helpers
  (never silent-skip / never fake-green on missing 0.4.6 ZIP).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from pathlib import Path

from credential_guard.release_identity import (
    ARTIFACT_MANIFEST_FILENAME,
    PLUGIN_VERSION,
    PLUGIN_ZIP_FILENAME,
    SDIST_FILENAME,
    WHEEL_FILENAME,
)
from tests.test_current_dist_policy import CURRENT_DIST_PHASE, STRICT

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"

# Frozen identity of the twelve historical dist members at 0.4.6 source-candidate
# cutover (matches /tmp/cg_046_dist_before.json). Must not drift.
_HISTORICAL_12 = (
    (
        "artifact-manifest-0.4.2.json",
        812,
        "51b4ed98dc244f19e00630c44f32e0c3bfd7c2090e2d979484c4721ac3490752",
    ),
    (
        "artifact-manifest-0.4.3.json",
        812,
        "86321bd8fc7ee4be994d3202f368bae114a23fd18bdea257eb5e810c96231127",
    ),
    (
        "artifact-manifest-0.4.4.json",
        871,
        "a3508d2de9521a3b4381d28425960737f2c9876ea84f7831fc29f019d9137b9a",
    ),
    (
        "credential-guard-0.4.2-hermes-plugin.zip",
        101656,
        "95d96aa82f64701dfc0b5862ba3671feb98b7d5c07a61f350dbe65287fb60ccf",
    ),
    (
        "credential-guard-0.4.3-hermes-plugin.zip",
        111985,
        "738bc8ae4e1973a50efba604602a9fb3c7a6739efb95e48024b6a1975e97dacb",
    ),
    (
        "credential-guard-0.4.4-hermes-plugin.zip",
        112548,
        "d6ee2bf6a92a4ca55ee37f24802cf26316ab38adcbe27b9d59a4ee9e944ae265",
    ),
    (
        "hermes_credential_guard-0.4.2-py3-none-any.whl",
        103229,
        "7e514b6c47ea26867674e189df4f23b917d98f932e2832c2b57b4e4426942954",
    ),
    (
        "hermes_credential_guard-0.4.2.tar.gz",
        85902,
        "97bd5fb3e5ef26efd0964598fedf6f7e3fc751b0bfa3d3c96ff1a425a5ee01d1",
    ),
    (
        "hermes_credential_guard-0.4.3-py3-none-any.whl",
        113560,
        "a7bf91e1ceb263fc2c1f468baac7c6990d6c2899c27409704e31fff13bb1752c",
    ),
    (
        "hermes_credential_guard-0.4.3.tar.gz",
        96318,
        "5f7b939ca37ff6ef38eaaaba381536cafdc0196a80b558705e7016997282033b",
    ),
    (
        "hermes_credential_guard-0.4.4-py3-none-any.whl",
        114120,
        "74371c32da35913f3c371db3b98871dad3dd192c0172bb37bea38546a3c0462e",
    ),
    (
        "hermes_credential_guard-0.4.4.tar.gz",
        96861,
        "96c15aa8129446f55f4ad1ee9df36ac3d9479726fbfb47bf39cdee4288b2ecb4",
    ),
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_builder_version() -> str:
    path = ROOT / "scripts" / "build_release_artifacts.py"
    spec = importlib.util.spec_from_file_location("cg_builder_version_probe", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.PLUGIN_VERSION


def test_r12_046_four_current_version_anchors():
    assert PLUGIN_VERSION == "0.4.6"
    plugin_yaml = (ROOT / "plugin.yaml").read_text(encoding="utf-8")
    assert re.search(r"(?m)^version:\s*0\.4\.6\s*$", plugin_yaml)
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "0.4.6"' in pyproject
    assert _load_builder_version() == "0.4.6"


def test_r12_046_standard_four_filenames_bind_version():
    assert ARTIFACT_MANIFEST_FILENAME == "artifact-manifest-0.4.6.json"
    assert PLUGIN_ZIP_FILENAME == "credential-guard-0.4.6-hermes-plugin.zip"
    assert WHEEL_FILENAME == "hermes_credential_guard-0.4.6-py3-none-any.whl"
    assert SDIST_FILENAME == "hermes_credential_guard-0.4.6.tar.gz"


def test_r12_046_retired_artifacts_are_absent_and_current_set_is_exact():
    """R12 / 0.4.6: superseded artifacts are retired from the tree.

    The previous contract froze twelve historical artifacts here so a rebuild
    could not silently rewrite shipped bytes. That protection now lives at the
    published GitHub Release (each version's assets are immutable there), and
    the user approved retiring the in-tree copies on 2026-08-21. What this gate
    still guarantees is exactness: dist/ holds the current four files and
    nothing else, so a stale or resurrected artifact fails loudly instead of
    being quietly redistributed.
    """
    actual = {p.name for p in DIST.iterdir() if p.is_file()}
    retired_names = {name for name, _size, _sha in _HISTORICAL_12}
    current_four = {
        ARTIFACT_MANIFEST_FILENAME,
        PLUGIN_ZIP_FILENAME,
        WHEEL_FILENAME,
        SDIST_FILENAME,
    }
    resurrected = sorted(actual & retired_names)
    assert resurrected == [], f"retired artifacts back in dist/: {resurrected}"
    if CURRENT_DIST_PHASE == "source_candidate_pending_build":
        assert actual == set()
    else:
        assert actual == current_four
    for name in sorted(retired_names):
        assert not (DIST / name).exists(), f"retired artifact present: {name}"


def test_r12_046_landed_phase_binds_current_artifacts_to_manifest():
    """After the dual build, the 0.4.6 four-file set must be real and bound.

    Mirror image of the pending-phase contract below: pending forbids the
    artifacts, landed requires them AND requires every hash to agree with the
    versioned manifest on disk. Neither phase permits a silent skip.
    """
    assert STRICT is True
    if CURRENT_DIST_PHASE != "artifacts_landed":
        return
    manifest_path = DIST / ARTIFACT_MANIFEST_FILENAME
    assert manifest_path.is_file()
    man = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert man["version"] == "0.4.6"
    for kind, filename in (
        ("wheel", WHEEL_FILENAME),
        ("sdist", SDIST_FILENAME),
        ("plugin_zip", PLUGIN_ZIP_FILENAME),
    ):
        path = DIST / filename
        assert path.is_file(), f"landed 0.4.6 {kind} missing: {filename}"
        assert man[kind]["filename"] == filename
        assert _sha256(path) == man[kind]["sha256"], f"{kind} hash ≠ manifest"
        assert man[kind]["size"] == path.stat().st_size, f"{kind} size ≠ disk"


def test_r12_046_current_phase_is_source_candidate_pending_build():
    assert STRICT is True
    assert CURRENT_DIST_PHASE in {
        "source_candidate_pending_build",
        "artifacts_landed",
    }
    if CURRENT_DIST_PHASE != "source_candidate_pending_build":
        return
    assert not (DIST / PLUGIN_ZIP_FILENAME).exists()
    assert not (DIST / ARTIFACT_MANIFEST_FILENAME).exists()
    assert not (DIST / WHEEL_FILENAME).exists()
    assert not (DIST / SDIST_FILENAME).exists()


def test_r12_046_runner_points_at_046_reuses_shared_zip_helper():
    """Runner/harness wiring contract, phase-aware in BOTH directions.

    The stage flag is not free to drift: the harness' ``ARTIFACTS_LANDED`` must
    agree with ``CURRENT_DIST_PHASE`` in this module, and each phase carries a
    positive obligation —

    * pending — resolve MUST hard-fail with ``R12_046_ARTIFACTS_PENDING_BUILD``;
    * landed  — resolve MUST return the real ZIP whose hash equals the on-disk
      artifact and the versioned manifest, and a wrong expected hash MUST raise.

    Neither branch may skip, xfail, or accept a historical 0.4.4 ZIP.
    """
    harness_path = ROOT / "scripts" / "run_r12_046_final_zip_e2e.py"
    runner_path = ROOT / "scripts" / "run_r12_046_final_zip_tests.py"
    e2e_path = ROOT / "tests" / "r12_046_final_zip_e2e.py"
    assert harness_path.is_file()
    assert runner_path.is_file()
    assert e2e_path.is_file()
    assert not e2e_path.name.startswith("test_")

    harness_text = harness_path.read_text(encoding="utf-8")
    assert 'PLUGIN_VERSION = "0.4.6"' in harness_text
    assert 'f"credential-guard-{PLUGIN_VERSION}-hermes-plugin.zip"' in harness_text
    assert "PENDING_R12_046_DUAL_BUILD_BACKFILL" in harness_text
    assert "STRICT = True" in harness_text
    assert "R12_046_ARTIFACTS_PENDING_BUILD" in harness_text
    assert "installed_zip_plugin" in harness_text
    assert "build_all" in harness_text or "Never calls" in harness_text

    runner = runner_path.read_text(encoding="utf-8")
    assert "CG_R6_BUILD_AUTHORIZED" in runner
    assert 'env.pop("CG_R6_BUILD_AUTHORIZED", None)' in runner
    assert "tests/r12_046_final_zip_e2e.py" in runner

    spec = importlib.util.spec_from_file_location("r12_046_optin_harness", harness_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.PLUGIN_VERSION == "0.4.6"
    assert mod.STRICT is True

    pending = CURRENT_DIST_PHASE == "source_candidate_pending_build"
    assert mod.ARTIFACTS_LANDED is (not pending), (
        "harness ARTIFACTS_LANDED disagrees with CURRENT_DIST_PHASE"
    )

    if pending:
        assert "ARTIFACTS_LANDED = False" in harness_text
        try:
            mod.resolve_plugin_zip()
        except FileNotFoundError as exc:
            assert "R12_046_ARTIFACTS_PENDING_BUILD" in str(exc)
        else:
            raise AssertionError("pending resolve must hard-fail under strict=True")
        return

    assert "ARTIFACTS_LANDED = True" in harness_text
    # The pending sentinel must no longer be used as the expected hash.
    assert mod.EXPECTED_PLUGIN_ZIP_SHA256 != mod.PENDING_SENTINEL
    resolved = mod.resolve_plugin_zip()
    assert resolved.is_file()
    assert resolved.name == PLUGIN_ZIP_FILENAME
    on_disk = _sha256(resolved)
    assert on_disk == mod.EXPECTED_PLUGIN_ZIP_SHA256, "harness hash ≠ on-disk ZIP"
    man = json.loads((DIST / ARTIFACT_MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert on_disk == man["plugin_zip"]["sha256"], "harness hash ≠ manifest"
    # Resolve really compares: a wrong expected hash must raise, not pass.
    try:
        mod.resolve_plugin_zip(
            expected_name=PLUGIN_ZIP_FILENAME, expected_sha256="0" * 64
        )
    except AssertionError as exc:
        assert "sha drift" in str(exc)
    else:
        raise AssertionError("landed resolve must reject a mismatched hash")


def test_r12_046_readme_declares_current_phase_truthfully():
    """README must match the real phase, and never invent an unbuilt hash.

    * pending — declares 源码候选 / 尚未落地 and carries NO parsable 64-hex for
      the 0.4.6 plugin ZIP.
    * landed  — must state the artifacts are built AND publish the 0.4.6 plugin
      ZIP's real hash, which has to equal the on-disk artifact and the manifest.

    In BOTH phases the install recipe must stay pinned to a publicly released,
    verifiable ZIP with its real hash — a user following the README must never
    be pointed at a download that does not exist. Before v0.4.6 was published
    that meant staying on 0.4.4; now that v0.4.6 is tagged and released, the
    recipe points at 0.4.6 and the hash must equal the on-disk artifact.
    """
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "当前版本：`0.4.6`" in text
    assert "EXPECTED_SHA256=" in text
    # Install recipe points at the current, publicly released ZIP.
    assert "credential-guard-0.4.6-hermes-plugin.zip" in text
    assert "releases/download/v0.4.6/" in text
    # Superseded install targets must not linger in the recipe.
    assert "credential-guard-0.4.4-hermes-plugin.zip" not in text
    assert "d6ee2bf6a92a4ca55ee37f24802cf26316ab38adcbe27b9d59a4ee9e944ae265" not in text
    # The published hash must be the real one on disk, never invented.
    on_disk = _sha256(DIST / PLUGIN_ZIP_FILENAME)
    assert f'EXPECTED_SHA256="{on_disk}"' in text

    zip_hash_re = re.compile(
        r"credential-guard-0\.4\.6-hermes-plugin\.zip[`\s|]*`?([0-9a-f]{64})`?"
    )
    if CURRENT_DIST_PHASE == "source_candidate_pending_build":
        assert "源码候选" in text
        assert "尚未落地" in text or "待主代理构建" in text
        assert zip_hash_re.search(text) is None
        return

    assert "源码候选" not in text, "landed README still claims 源码候选"
    assert "尚未落地" not in text, "landed README still claims 尚未落地"
    match = zip_hash_re.search(text)
    assert match is not None, "landed README must publish the real 0.4.6 ZIP hash"
    reported = match.group(1)
    zip_path = DIST / PLUGIN_ZIP_FILENAME
    assert zip_path.is_file()
    assert reported == _sha256(zip_path), "README hash ≠ on-disk plugin ZIP"
    man = json.loads((DIST / ARTIFACT_MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert reported == man["plugin_zip"]["sha256"], "README hash ≠ manifest"
    # v0.4.6 is published, so the download URL must exist and be verifiable.
    assert "releases/download/v0.4.6/" in text


def test_r12_046_designated_report_matches_phase():
    """The designated report must tell the truth about the current phase.

    Two mutually exclusive contracts, so neither phase can fake the other:

    * pending  — the report declares 源码候选 / 待主代理构建 and must NOT contain
      a parsable ``64-hex`` cell for the 0.4.6 plugin ZIP (no invented hashes).
    * landed   — the report must carry the plugin ZIP's REAL hash, and that
      hash must equal both the on-disk artifact and the versioned manifest.
      A stale "pending" wording is rejected outright, so flipping the phase
      flag without backfilling the report cannot pass.
    """
    report = ROOT / "docs" / "R12-0.4.6-验收报告.md"
    assert report.is_file()
    text = report.read_text(encoding="utf-8")
    pat = re.compile(
        r"`credential-guard-0\.4\.6-hermes-plugin\.zip`\s*\|\s*`([0-9a-f]{64})`"
    )
    if CURRENT_DIST_PHASE == "source_candidate_pending_build":
        assert "源码候选" in text
        assert "待主代理构建" in text
        assert pat.search(text) is None
        return

    assert "待主代理构建" not in text, (
        "landed phase report still claims 待主代理构建"
    )
    match = pat.search(text)
    assert match is not None, (
        "landed phase report must bind the real 0.4.6 plugin ZIP hash"
    )
    reported = match.group(1)
    zip_path = DIST / PLUGIN_ZIP_FILENAME
    assert zip_path.is_file()
    assert reported == _sha256(zip_path), "report hash ≠ on-disk plugin ZIP"
    man = json.loads((DIST / ARTIFACT_MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert reported == man["plugin_zip"]["sha256"], "report hash ≠ manifest"
