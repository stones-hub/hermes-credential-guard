"""Current release dist policy: only the active 0.4.2 release is distributed."""

from pathlib import Path

from credential_guard.release_identity import (
    ARTIFACT_MANIFEST_FILENAME,
    PLUGIN_ZIP_FILENAME,
    SDIST_FILENAME,
    WHEEL_FILENAME,
)

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


def test_dist_contains_only_current_release_artifacts():
    expected = {
        ARTIFACT_MANIFEST_FILENAME,
        PLUGIN_ZIP_FILENAME,
        SDIST_FILENAME,
        WHEEL_FILENAME,
    }
    actual = {path.name for path in DIST.iterdir() if path.is_file()}
    assert actual == expected


def test_legacy_unversioned_manifest_is_not_distributed():
    assert not (DIST / "artifact-manifest.json").exists()
