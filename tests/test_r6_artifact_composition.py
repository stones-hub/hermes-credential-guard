"""Real landed-artifact composition audit (no release build).

Opens wheel / sdist / plugin ZIP under ``dist/`` and checks member presence /
absence. During the 0.4.5 source-candidate pending-build phase, current
``PLUGIN_VERSION`` files are absent by contract; retained 0.4.4 is audited as
historical evidence. Mutations operate on *copies* of a landed plugin ZIP only.
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
from tests.test_current_dist_policy import CURRENT_DIST_PHASE, STRICT

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"

# Last landed plugin ZIP used for mutation copies while 0.4.5 is pending.
_LANDED_MUTATION_ZIP = DIST / "credential-guard-0.4.4-hermes-plugin.zip"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _current_landed_paths():
    return {
        "wheel": DIST / WHEEL_FILENAME,
        "sdist": DIST / SDIST_FILENAME,
        "plugin_zip": DIST / PLUGIN_ZIP_FILENAME,
        "manifest": artifact_manifest_path(ROOT),
    }


def test_landed_current_artifacts_exist_and_match_versioned_manifest():
    assert PLUGIN_VERSION == "0.4.5"
    assert STRICT is True
    paths = _current_landed_paths()
    if CURRENT_DIST_PHASE == "source_candidate_pending_build":
        for key, path in paths.items():
            assert not path.exists(), (
                f"R11_045_ARTIFACTS_PENDING_BUILD: unexpected landed "
                f"{PLUGIN_VERSION} {key}: {path.name}"
            )
        return

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
        assert type(man[kind]["size"]) is int and man[kind]["size"] >= 0
        assert man[kind]["size"] == path.stat().st_size, f"{kind} size ≠ disk"

    verify_artifact_manifest(
        ROOT,
        measured={"candidate_manifest_sha256": man["candidate_manifest_sha256"]},
    )


def test_dist_has_current_release_files_and_retained_history():
    names = sorted(p.name for p in DIST.iterdir() if p.is_file())
    retained = {
        "artifact-manifest-0.4.2.json",
        "credential-guard-0.4.2-hermes-plugin.zip",
        "hermes_credential_guard-0.4.2-py3-none-any.whl",
        "hermes_credential_guard-0.4.2.tar.gz",
        "artifact-manifest-0.4.3.json",
        "credential-guard-0.4.3-hermes-plugin.zip",
        "hermes_credential_guard-0.4.3-py3-none-any.whl",
        "hermes_credential_guard-0.4.3.tar.gz",
        "artifact-manifest-0.4.4.json",
        "credential-guard-0.4.4-hermes-plugin.zip",
        "hermes_credential_guard-0.4.4-py3-none-any.whl",
        "hermes_credential_guard-0.4.4.tar.gz",
    }
    if CURRENT_DIST_PHASE == "source_candidate_pending_build":
        assert names == sorted(retained)
        assert len(names) == 12
        assert WHEEL_FILENAME.endswith("-0.4.5-py3-none-any.whl")
        assert PLUGIN_ZIP_FILENAME not in names
        return

    expected = sorted(
        retained
        | {
            WHEEL_FILENAME,
            SDIST_FILENAME,
            PLUGIN_ZIP_FILENAME,
            ARTIFACT_MANIFEST_FILENAME,
        }
    )
    assert names == expected
    assert len(expected) == 16
    assert WHEEL_FILENAME.endswith("-0.4.5-py3-none-any.whl")


def _plugin_zip_under_audit() -> Path:
    if CURRENT_DIST_PHASE == "source_candidate_pending_build":
        path = _LANDED_MUTATION_ZIP
        assert path.is_file(), "retained 0.4.4 plugin ZIP missing for pending audit"
        return path
    path = DIST / PLUGIN_ZIP_FILENAME
    assert path.is_file()
    return path


def _production_rels_for_audit(path: Path, *, kind: str) -> list[str]:
    """Required-member set for composition audit.

    Pending-build audits retained historical artifacts; those cannot contain
    post-0.4.4 modules. Intersect with members actually present so we still
    forbid tests/scripts/secrets and keep mutations load-bearing — without
    pretending the historical ZIP is the current 0.4.5 release.
    """
    prod = list(iter_production_py_relpaths(ROOT))
    if CURRENT_DIST_PHASE != "source_candidate_pending_build":
        return prod
    if kind == "plugin_zip":
        members = set(list_zip_members(path))
        prefix = "credential-guard/"
        present = {
            rel
            for rel in prod
            if f"{prefix}{rel}" in members
        }
    elif kind == "wheel":
        members = set(list_zip_members(path))
        present = {rel for rel in prod if rel in members}
    else:  # sdist
        members = set(list_tar_members(path))
        # sdist members are typically hermes_credential_guard-VERSION/rel
        present = set()
        for rel in prod:
            if any(m.endswith("/" + rel) or m == rel for m in members):
                present.add(rel)
    assert present, f"pending audit found no overlapping production modules in {path.name}"
    # New R11 modules must remain absent from retained history (not silently ignored forever).
    new_r11 = {
        "credential_guard/credential_code.py",
        "credential_guard/local_events.py",
        "credential_guard/target_catalog.py",
        "credential_guard/unregistered_warning.py",
    }
    assert new_r11.isdisjoint(present)
    assert new_r11.issubset(set(prod))
    return sorted(present)


def test_plugin_zip_composition_clean_and_complete():
    path = _plugin_zip_under_audit()
    members = list_zip_members(path)
    assert len(members) < 48, (
        f"plugin ZIP member count {len(members)} did not drop vs 0.3.1=48"
    )
    prod = _production_rels_for_audit(path, kind="plugin_zip")
    report = audit_zip_artifact(path, kind="plugin_zip", production_rels=prod)
    assert report["forbidden_hits"] == 0
    # Pending phase audits retained 0.4.4 ZIP; full current required-count waits
    # until 0.4.5 is built. Still forbid tests/scripts/secrets.
    if CURRENT_DIST_PHASE != "source_candidate_pending_build":
        full = list(iter_production_py_relpaths(ROOT))
        assert report["required_count"] == len(full) + 1  # + plugin.yaml

    hits = find_forbidden_hits(members, kind="plugin_zip")
    assert hits == []
    assert not any("R8-Hermes" in m for m in members)
    with zipfile_member_text_probe(path) as plugin_yaml:
        if CURRENT_DIST_PHASE == "source_candidate_pending_build":
            assert "version: 0.4.4" in plugin_yaml
        else:
            assert f"version: {PLUGIN_VERSION}" in plugin_yaml


def test_wheel_composition_clean_and_complete():
    if CURRENT_DIST_PHASE == "source_candidate_pending_build":
        path = DIST / "hermes_credential_guard-0.4.4-py3-none-any.whl"
        assert path.is_file()
    else:
        path = DIST / WHEEL_FILENAME
        assert path.is_file()
    prod = _production_rels_for_audit(path, kind="wheel")
    report = audit_zip_artifact(path, kind="wheel", production_rels=prod)
    assert report["forbidden_hits"] == 0
    members = list_zip_members(path)
    assert find_forbidden_hits(members, kind="wheel") == []


def test_sdist_composition_follows_manifest_in_prune_policy():
    """MANIFEST.in prunes tests/scripts/docs — sdist uses the same forbid set."""
    if CURRENT_DIST_PHASE == "source_candidate_pending_build":
        path = DIST / "hermes_credential_guard-0.4.4.tar.gz"
        assert path.is_file()
    else:
        path = DIST / SDIST_FILENAME
        assert path.is_file()
    prod = _production_rels_for_audit(path, kind="sdist")
    members = list_tar_members(path)
    report = audit_sdist_artifact(path, production_rels=prod)
    assert report["forbidden_hits"] == 0
    assert find_forbidden_hits(members, kind="sdist") == []
    assert not any("/tests/" in m or m.endswith("/tests") for m in members)
    assert not any("R8-Hermes" in m for m in members)


def test_mutation_m1_injected_forbidden_member_is_rejected(tmp_path):
    """M-1: auditor must RED when a copy gains a forbidden tests/ member."""
    src = _plugin_zip_under_audit()
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
    prod = _production_rels_for_audit(src, kind="plugin_zip")
    with pytest.raises(ArtifactCompositionError, match="forbidden|tests|PRIVATE KEY"):
        audit_zip_artifact(dest, kind="plugin_zip", production_rels=prod)
    assert _sha256(src) == src_hash


def test_mutation_m2_missing_required_member_is_rejected(tmp_path):
    """M-2: auditor must RED when a required production module is dropped."""
    src = _plugin_zip_under_audit()
    src_hash = _sha256(src)
    prod = _production_rels_for_audit(src, kind="plugin_zip")
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
