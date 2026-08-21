"""Current release dist policy: 0.4.5 source candidate + retained 0.4.2/0.4.3/0.4.4.

Phase contract (strict=True):
- ``source_candidate_pending_build``: PLUGIN_VERSION is 0.4.5; dist retains
  historical 0.4.2 + 0.4.3 + landed 0.4.4 four-file sets; 0.4.5 artifacts must
  be absent.
- ``artifacts_landed``: flipped after dual-build copy2; 0.4.5 four files must
  be present alongside retained history.
"""

from pathlib import Path

from credential_guard.release_identity import (
    ARTIFACT_MANIFEST_FILENAME,
    PLUGIN_VERSION,
    PLUGIN_ZIP_FILENAME,
    SDIST_FILENAME,
    WHEEL_FILENAME,
)

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"

# Strict stage flag — flipped to artifacts_landed after the real dual build.
CURRENT_DIST_PHASE = "artifacts_landed"
STRICT = True

_HISTORICAL_042 = {
    "artifact-manifest-0.4.2.json",
    "credential-guard-0.4.2-hermes-plugin.zip",
    "hermes_credential_guard-0.4.2-py3-none-any.whl",
    "hermes_credential_guard-0.4.2.tar.gz",
}
_HISTORICAL_043 = {
    "artifact-manifest-0.4.3.json",
    "credential-guard-0.4.3-hermes-plugin.zip",
    "hermes_credential_guard-0.4.3-py3-none-any.whl",
    "hermes_credential_guard-0.4.3.tar.gz",
}
_HISTORICAL_044 = {
    "artifact-manifest-0.4.4.json",
    "credential-guard-0.4.4-hermes-plugin.zip",
    "hermes_credential_guard-0.4.4-py3-none-any.whl",
    "hermes_credential_guard-0.4.4.tar.gz",
}
_CURRENT_045 = {
    ARTIFACT_MANIFEST_FILENAME,
    PLUGIN_ZIP_FILENAME,
    SDIST_FILENAME,
    WHEEL_FILENAME,
}


def test_dist_phase_contract_is_strict_and_version_aligned():
    assert PLUGIN_VERSION == "0.4.5"
    assert STRICT is True
    assert CURRENT_DIST_PHASE in {
        "source_candidate_pending_build",
        "artifacts_landed",
    }
    assert ARTIFACT_MANIFEST_FILENAME == "artifact-manifest-0.4.5.json"
    assert PLUGIN_ZIP_FILENAME == "credential-guard-0.4.5-hermes-plugin.zip"


def test_dist_contains_retained_history_and_phase_current_set():
    actual = {path.name for path in DIST.iterdir() if path.is_file()}
    retained = _HISTORICAL_042 | _HISTORICAL_043 | _HISTORICAL_044
    if CURRENT_DIST_PHASE == "source_candidate_pending_build":
        assert actual == retained
        # 0.4.5 must not silently appear / be faked during source-candidate.
        assert not (DIST / PLUGIN_ZIP_FILENAME).exists()
        assert not (DIST / ARTIFACT_MANIFEST_FILENAME).exists()
        assert _CURRENT_045.isdisjoint(actual)
    else:
        expected = retained | _CURRENT_045
        assert actual == expected
        assert (DIST / PLUGIN_ZIP_FILENAME).is_file()
        assert (DIST / ARTIFACT_MANIFEST_FILENAME).is_file()


def test_legacy_unversioned_manifest_is_not_distributed():
    assert not (DIST / "artifact-manifest.json").exists()
