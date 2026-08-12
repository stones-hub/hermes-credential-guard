"""Real landed-artifact composition audit (no release build).

Opens wheel / sdist / plugin ZIP already landed under ``dist/`` and checks
member presence / absence. Historical 0.3.1 / 0.4.0 / 0.4.1 bytes stay frozen;
current ``PLUGIN_VERSION`` (0.4.2+) is audited separately and must coexist.

Mutations M-1 / M-2 operate on *copies* of the current plugin ZIP only.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from credential_guard.release_identity import (
    ARTIFACT_MANIFEST_FILENAME,
    PLUGIN_VERSION,
    PLUGIN_ZIP_FILENAME,
    SDIST_FILENAME,
    WHEEL_FILENAME,
    artifact_manifest_path,
    verify_artifact_manifest,
)
from tests.support.artifact_composition_audit import (
    ArtifactCompositionError,
    audit_sdist_artifact,
    audit_zip_artifact,
    copy_zip_with_mutations,
    find_forbidden_hits,
    iter_production_py_relpaths,
    list_tar_members,
    list_zip_members,
)

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"

# 0.3.1 historical freeze — must remain byte-identical.
_HISTORICAL_031 = {
    "artifact-manifest.json": (
        "0c25b34a74d8e4deeaf9343328335d790bdab6018ac4ff4ef864686efaa2ebfa"
    ),
    "credential-guard-0.3.1-hermes-plugin.zip": (
        "7ebc8652d6a763a8ff9fa1d7596919e811bcff92b8eee572af30b61b54651ac6"
    ),
    "hermes_credential_guard-0.3.1-py3-none-any.whl": (
        "72b705f744b292ea2395c0e7ca70ef95b7ad25d9465fa0c42361f1bd511aeac3"
    ),
    "hermes_credential_guard-0.3.1.tar.gz": (
        "ea307f8f47a6328c8c8f3b8ff574d4d3c6c3cccf11b7328d7a54543759779bbb"
    ),
}

# 0.4.0 historical freeze — must coexist with later releases; never overwrite.
_HISTORICAL_040 = {
    "artifact-manifest-0.4.0.json": (
        "be6f2e320cfff32abb81a0bf13701fc1a4e2fec93665f871c0c7c4a972724c7a"
    ),
    "credential-guard-0.4.0-hermes-plugin.zip": (
        "1fbc8c38da81226ef8a98f50702f2b3f5b369c5ce4767b8d0de8b2aaad20908d"
    ),
    "hermes_credential_guard-0.4.0-py3-none-any.whl": (
        "6c457db3641eabee532a380cf0135308dd4ac846c6926b65b00bbcee723b34cf"
    ),
    "hermes_credential_guard-0.4.0.tar.gz": (
        "a7839c48d2f02550c4cfb95f394468783eee5ba18a301edc4e5f571dea9f987e"
    ),
}

# 0.4.1 historical freeze — must coexist with 0.4.2; never overwrite.
_HISTORICAL_041 = {
    "artifact-manifest-0.4.1.json": (
        "55b3bc87b9ac9311097e4661fcd0d5ccbef1084e02bdb1764b42201a91082358"
    ),
    "credential-guard-0.4.1-hermes-plugin.zip": (
        "3bee46a83c45579faae693d8dd4f681d9128373014e36069eaabadbd1677d16c"
    ),
    "hermes_credential_guard-0.4.1-py3-none-any.whl": (
        "df0f783ae1c8a2698e672bf0b4d54943cb3e48033a206c9d6649d9de3369de20"
    ),
    "hermes_credential_guard-0.4.1.tar.gz": (
        "27e67907ecf13e8be5018206bdc54241e5196bc2eee0c149ce62192f18f65020"
    ),
}

def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _current_landed_paths():
    return {
        "wheel": DIST / WHEEL_FILENAME,
        "sdist": DIST / SDIST_FILENAME,
        "plugin_zip": DIST / PLUGIN_ZIP_FILENAME,
        "manifest": artifact_manifest_path(ROOT),
    }


def test_historical_031_four_files_still_byte_frozen():
    for name, digest in _HISTORICAL_031.items():
        path = DIST / name
        assert path.is_file(), name
        assert _sha256(path) == digest, f"{name} drifted from 0.3.1 freeze"


def test_historical_040_four_files_still_byte_frozen():
    for name, digest in _HISTORICAL_040.items():
        path = DIST / name
        assert path.is_file(), name
        assert _sha256(path) == digest, f"{name} drifted from 0.4.0 freeze"


def test_historical_041_four_files_still_byte_frozen():
    for name, digest in _HISTORICAL_041.items():
        path = DIST / name
        assert path.is_file(), name
        assert _sha256(path) == digest, f"{name} drifted from 0.4.1 freeze"


def test_landed_current_artifacts_exist_and_match_versioned_manifest():
    paths = _current_landed_paths()
    for key, path in paths.items():
        assert path.is_file(), f"missing landed {PLUGIN_VERSION} {key}: {path.name}"

    man = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    assert man["version"] == PLUGIN_VERSION
    assert set(man) == {
        "version",
        "candidate_manifest_sha256",
        "wheel",
        "sdist",
        "plugin_zip",
        "build",
    }
    assert paths["manifest"].name == ARTIFACT_MANIFEST_FILENAME

    for kind, path in (
        ("wheel", paths["wheel"]),
        ("sdist", paths["sdist"]),
        ("plugin_zip", paths["plugin_zip"]),
    ):
        assert path.name == man[kind]["filename"]
        assert _sha256(path) == man[kind]["sha256"], f"{kind} hash ≠ manifest"

    verify_artifact_manifest(
        ROOT,
        measured={"candidate_manifest_sha256": man["candidate_manifest_sha256"]},
    )


def test_dist_has_historical_and_current_release_files():
    names = sorted(p.name for p in DIST.iterdir() if p.is_file())
    expected = sorted(
        set(_HISTORICAL_031)
        | set(_HISTORICAL_040)
        | set(_HISTORICAL_041)
        | {
            WHEEL_FILENAME,
            SDIST_FILENAME,
            PLUGIN_ZIP_FILENAME,
            ARTIFACT_MANIFEST_FILENAME,
        }
    )
    assert names == expected
    assert len(expected) == 16


def test_plugin_zip_composition_clean_and_complete():
    prod = iter_production_py_relpaths(ROOT)
    path = DIST / PLUGIN_ZIP_FILENAME
    members = list_zip_members(path)
    assert len(members) < 48, (
        f"{PLUGIN_VERSION} plugin ZIP member count {len(members)} "
        "did not drop vs 0.3.1=48"
    )
    report = audit_zip_artifact(path, kind="plugin_zip", production_rels=prod)
    assert report["forbidden_hits"] == 0
    assert report["required_count"] == len(prod) + 1  # + plugin.yaml

    hits = find_forbidden_hits(members, kind="plugin_zip")
    assert hits == []

    # Runtime package must not carry the vetoed R8 investigation doc.
    assert not any("R8-Hermes" in m for m in members)
    with zipfile_member_text_probe(path) as plugin_yaml:
        assert f"version: {PLUGIN_VERSION}" in plugin_yaml


def test_wheel_composition_clean_and_complete():
    prod = iter_production_py_relpaths(ROOT)
    path = DIST / WHEEL_FILENAME
    report = audit_zip_artifact(path, kind="wheel", production_rels=prod)
    assert report["forbidden_hits"] == 0
    members = list_zip_members(path)
    assert find_forbidden_hits(members, kind="wheel") == []


def test_sdist_composition_follows_manifest_in_prune_policy():
    """MANIFEST.in prunes tests/scripts/docs — sdist uses the same forbid set."""
    prod = iter_production_py_relpaths(ROOT)
    path = DIST / SDIST_FILENAME
    members = list_tar_members(path)
    report = audit_sdist_artifact(path, production_rels=prod)
    assert report["forbidden_hits"] == 0
    assert find_forbidden_hits(members, kind="sdist") == []
    assert not any("/tests/" in m or m.endswith("/tests") for m in members)
    assert not any("R8-Hermes" in m for m in members)


def test_mutation_m1_injected_forbidden_member_is_rejected(tmp_path):
    """M-1: auditor must RED when a copy gains a forbidden tests/ member."""
    src = DIST / PLUGIN_ZIP_FILENAME
    assert src.is_file()
    src_hash = _sha256(src)
    dest = tmp_path / "mutated-m1.zip"
    copy_zip_with_mutations(
        src,
        dest,
        add={
            "credential-guard/tests/test_fake.py": (
                b"def test_fake():\n    assert True\n"
            ),
            "credential-guard/evil.pem": (
                b"-----BEGIN RSA PRIVATE KEY-----\nDECOY\n"
                b"-----END RSA PRIVATE KEY-----\n"
            ),
        },
    )
    prod = iter_production_py_relpaths(ROOT)
    with pytest.raises(ArtifactCompositionError, match="forbidden|tests|PRIVATE KEY"):
        audit_zip_artifact(dest, kind="plugin_zip", production_rels=prod)
    assert _sha256(src) == src_hash


def test_mutation_m2_missing_required_member_is_rejected(tmp_path):
    """M-2: auditor must RED when a required production module is dropped."""
    src = DIST / PLUGIN_ZIP_FILENAME
    assert src.is_file()
    src_hash = _sha256(src)
    prod = iter_production_py_relpaths(ROOT)
    victim_rel = "credential_guard/approval.py"
    assert victim_rel in prod
    victim_member = f"credential-guard/{victim_rel}"
    dest = tmp_path / "mutated-m2.zip"
    copy_zip_with_mutations(src, dest, drop=[victim_member])
    with pytest.raises(ArtifactCompositionError, match="missing required"):
        audit_zip_artifact(dest, kind="plugin_zip", production_rels=prod)
    assert _sha256(src) == src_hash


def zipfile_member_text_probe(path: Path):
    """Context-manager-like helper: yield plugin.yaml text from a plugin ZIP."""

    class _Probe:
        def __enter__(self):
            import zipfile

            with zipfile.ZipFile(path) as zf:
                raw = zf.read("credential-guard/plugin.yaml")
            return raw.decode("utf-8")

        def __exit__(self, *exc):
            return False

    return _Probe()
