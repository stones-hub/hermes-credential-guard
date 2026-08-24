"""Current release dist policy: dist/ holds exactly the current release.

Phase contract (strict=True):
- ``source_candidate_pending_build``: PLUGIN_VERSION is 0.4.6 and the 0.4.6
  artifacts must be absent (dist/ is empty of release files).
- ``artifacts_landed``: flipped after dual-build copy2; the 0.4.6 four-file
  set must be present and nothing else.

R11 / 0.4.5 policy change (user-approved 2026-08-21): superseded releases are
no longer retained in-tree. Every published version is downloadable from its
GitHub Release, so keeping stale binaries here only grew the repo and gave
readers three obsolete install targets to copy from. This gate now asserts
dist/ is exactly the current set — an old artifact reappearing is a failure,
not a tolerated leftover.

R12 / 0.4.6: 0.4.5 joins the retired set. Its four artifacts remain available
from the published v0.4.5 GitHub Release (plugin zip
a2d44717edee766f861e3484bbe051e14377409ed274c595ff0786d3b7a9f0e3), verified
present before removing them here, so retiring them in-tree strands nobody.
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

# Superseded release filenames. They must NOT come back into dist/.
_RETIRED_ARTIFACTS = {
    f"{stem}-{version}{suffix}"
    for version in ("0.4.2", "0.4.3", "0.4.4", "0.4.5")
    for stem, suffix in (
        ("artifact-manifest", ".json"),
        ("credential-guard", "-hermes-plugin.zip"),
        ("hermes_credential_guard", "-py3-none-any.whl"),
        ("hermes_credential_guard", ".tar.gz"),
    )
}
_CURRENT_046 = {
    ARTIFACT_MANIFEST_FILENAME,
    PLUGIN_ZIP_FILENAME,
    SDIST_FILENAME,
    WHEEL_FILENAME,
}


def test_dist_phase_contract_is_strict_and_version_aligned():
    assert PLUGIN_VERSION == "0.4.6"
    assert STRICT is True
    assert CURRENT_DIST_PHASE in {
        "source_candidate_pending_build",
        "artifacts_landed",
    }
    assert ARTIFACT_MANIFEST_FILENAME == "artifact-manifest-0.4.6.json"
    assert PLUGIN_ZIP_FILENAME == "credential-guard-0.4.6-hermes-plugin.zip"


def test_dist_contains_only_the_current_release_set():
    actual = {path.name for path in DIST.iterdir() if path.is_file()}
    if CURRENT_DIST_PHASE == "source_candidate_pending_build":
        assert actual == set()
        # 0.4.6 must not silently appear / be faked during source-candidate.
        assert not (DIST / PLUGIN_ZIP_FILENAME).exists()
        assert not (DIST / ARTIFACT_MANIFEST_FILENAME).exists()
        assert _CURRENT_046.isdisjoint(actual)
    else:
        assert actual == _CURRENT_046
        assert (DIST / PLUGIN_ZIP_FILENAME).is_file()
        assert (DIST / ARTIFACT_MANIFEST_FILENAME).is_file()


def test_retired_release_artifacts_are_not_reintroduced():
    """Old release binaries live on GitHub Releases, never back in dist/."""
    actual = {path.name for path in DIST.iterdir() if path.is_file()}
    resurrected = sorted(actual & _RETIRED_ARTIFACTS)
    assert resurrected == [], f"retired artifacts back in dist/: {resurrected}"


def test_legacy_unversioned_manifest_is_not_distributed():
    assert not (DIST / "artifact-manifest.json").exists()
