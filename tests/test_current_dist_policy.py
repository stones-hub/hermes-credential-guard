"""Current release dist policy: active 0.4.3 plus retained historical 0.4.2."""

from pathlib import Path

from credential_guard.release_identity import (
    ARTIFACT_MANIFEST_FILENAME,
    PLUGIN_ZIP_FILENAME,
    SDIST_FILENAME,
    WHEEL_FILENAME,
)

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"

# Historical 0.4.2 four-file set retained byte-stable alongside current 0.4.3.
_HISTORICAL_042 = {
    "artifact-manifest-0.4.2.json",
    "credential-guard-0.4.2-hermes-plugin.zip",
    "hermes_credential_guard-0.4.2-py3-none-any.whl",
    "hermes_credential_guard-0.4.2.tar.gz",
}


def test_dist_contains_current_and_retained_042_artifacts():
    expected = _HISTORICAL_042 | {
        ARTIFACT_MANIFEST_FILENAME,
        PLUGIN_ZIP_FILENAME,
        SDIST_FILENAME,
        WHEEL_FILENAME,
    }
    actual = {path.name for path in DIST.iterdir() if path.is_file()}
    assert actual == expected
    assert ARTIFACT_MANIFEST_FILENAME == "artifact-manifest-0.4.3.json"
    assert PLUGIN_ZIP_FILENAME == "credential-guard-0.4.3-hermes-plugin.zip"


def test_legacy_unversioned_manifest_is_not_distributed():
    assert not (DIST / "artifact-manifest.json").exists()
