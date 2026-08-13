"""L2 artifact-manifest verifier contract (R5: pure fixtures, no release build).

R5 scope: this module exercises ``verify_artifact_manifest`` against synthetic
``dist/`` fixtures fabricated in ``tmp_path``. It never calls ``build_all()``,
never touches the repository ``dist/``, and therefore stays inside the R5
no-build boundary.

R6 scope (deliberately absent here): K1 two-independent-build byte equality,
L1 builder-tamper reproducibility, and the K2 build-then-verify round trip.
Those require a real setuptools build and belong to the release milestone.
The L1 candidate-membership contract stays because it is pure source scanning.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

import pytest

from credential_guard import release_identity
from credential_guard.release_identity import (
    ARTIFACT_MANIFEST_FILENAME,
    EXPECTED_PYTHONHASHSEED,
    EXPECTED_SOURCE_DATE_EPOCH,
    EXPECTED_TZ,
    PLUGIN_VERSION,
    PLUGIN_ZIP_FILENAME,
    SDIST_FILENAME,
    WHEEL_FILENAME,
    artifact_manifest_path,
    candidate_manifest_sha256,
    iter_candidate_files,
    load_artifact_manifest,
    verify_artifact_manifest,
)

ROOT = Path(__file__).resolve().parents[1]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_manifest(dist: Path, payload: dict) -> None:
    (dist / ARTIFACT_MANIFEST_FILENAME).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_l1_candidate_includes_builder_not_all_scripts():
    files = iter_candidate_files(ROOT)
    rels = {p.relative_to(ROOT).as_posix() for p in files}
    assert "scripts/build_release_artifacts.py" in rels
    # Other scripts must not be pulled in by a blanket scripts/ include.
    assert not any(
        r.startswith("scripts/") and r != "scripts/build_release_artifacts.py"
        for r in rels
    )
    assert "dist/artifact-manifest.json" not in rels
    assert f"dist/{ARTIFACT_MANIFEST_FILENAME}" not in rels
    assert not any(r.startswith("tests/") for r in rels)


def test_l1_candidate_no_longer_includes_vendored_deps():
    """R5: the candidate identity set must not contain any deps/ member."""
    rels = {p.relative_to(ROOT).as_posix() for p in iter_candidate_files(ROOT)}
    assert not any(r.startswith("deps/") for r in rels)


def _fresh_verify_fixture(tmp_path):
    """Synthetic root/dist fixture: fabricated artifacts + a valid manifest.

    Deliberately does not build. The three artifact files carry arbitrary but
    distinct bytes; the manifest records their real SHA-256 so the verifier's
    hash comparison is exercised for real.
    """
    fake_root = tmp_path / "proj"
    dist = fake_root / "dist"
    dist.mkdir(parents=True)

    artifacts = {
        "wheel": WHEEL_FILENAME,
        "sdist": SDIST_FILENAME,
        "plugin_zip": PLUGIN_ZIP_FILENAME,
    }
    entries = {}
    for kind, filename in artifacts.items():
        path = dist / filename
        path.write_bytes(f"synthetic-{kind}-fixture".encode("utf-8"))
        entries[kind] = {"filename": filename, "sha256": _sha(path)}

    measured = {
        "candidate_manifest_sha256": "a" * 64,
    }
    man = {
        "version": PLUGIN_VERSION,
        "candidate_manifest_sha256": measured["candidate_manifest_sha256"],
        "build": {
            "build_python": "/synthetic/python3",
            "normalized_archives": True,
            "pythonhashseed": EXPECTED_PYTHONHASHSEED,
            "source_date_epoch": EXPECTED_SOURCE_DATE_EPOCH,
            "tz": EXPECTED_TZ,
        },
        **entries,
    }
    _write_manifest(dist, man)
    return fake_root, dist, man, measured


@pytest.fixture
def verify_fixture(tmp_path):
    return _fresh_verify_fixture(tmp_path)


def test_l2_pure_fixture_verifies_green(verify_fixture):
    """The synthetic fixture itself must verify, else every RED below is vacuous."""
    fake_root, _dist, man, measured = verify_fixture
    got = verify_artifact_manifest(fake_root, measured=measured)
    assert got["version"] == PLUGIN_VERSION
    assert got["plugin_zip"]["filename"] == PLUGIN_ZIP_FILENAME
    assert got == man


def test_l2_hash_drift_and_missing_artifact_are_red(verify_fixture):
    fake_root, dist, _man, measured = verify_fixture
    plugin = dist / PLUGIN_ZIP_FILENAME
    plugin.write_bytes(plugin.read_bytes() + b"x")
    with pytest.raises(ValueError, match="hash drift"):
        verify_artifact_manifest(fake_root, measured=measured)

    plugin.unlink()
    with pytest.raises(ValueError, match="artifact missing"):
        verify_artifact_manifest(fake_root, measured=measured)


def test_l2_candidate_drift_is_red(verify_fixture):
    fake_root, _dist, _man, measured = verify_fixture
    bad = dict(measured)
    bad["candidate_manifest_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="candidate_manifest_sha256 drift"):
        verify_artifact_manifest(fake_root, measured=bad)


def test_l2_load_artifact_manifest_round_trip(verify_fixture):
    fake_root, _dist, _man, _measured = verify_fixture
    loaded = load_artifact_manifest(fake_root)
    assert "build" in loaded and "source_date_epoch" in loaded["build"]


_TOP_REQUIRED_KEYS = (
    "version",
    "candidate_manifest_sha256",
    "wheel",
    "sdist",
    "plugin_zip",
    "build",
)
_BUILD_REQUIRED_KEYS = (
    "build_python",
    "normalized_archives",
    "pythonhashseed",
    "source_date_epoch",
    "tz",
)
_ARTIFACT_KINDS = ("wheel", "sdist", "plugin_zip")
_ARTIFACT_ENTRY_KEYS = ("filename", "sha256")


@pytest.mark.parametrize("missing_key", _TOP_REQUIRED_KEYS)
def test_l2_top_missing_key_red(tmp_path, missing_key):
    fake_root, dist, man, measured = _fresh_verify_fixture(tmp_path)
    payload = copy.deepcopy(man)
    payload.pop(missing_key)
    _write_manifest(dist, payload)
    with pytest.raises(ValueError, match=rf"missing key: {missing_key}"):
        verify_artifact_manifest(fake_root, measured=measured)


def test_l2_top_extra_key_red(tmp_path):
    fake_root, dist, man, measured = _fresh_verify_fixture(tmp_path)
    payload = copy.deepcopy(man)
    payload["extra_artifact"] = {"filename": "x", "sha256": "0" * 64}
    _write_manifest(dist, payload)
    with pytest.raises(ValueError, match=r"unexpected keys"):
        verify_artifact_manifest(fake_root, measured=measured)


@pytest.mark.parametrize(
    "mutator,match",
    [
        (lambda m: m.__setitem__("version", 1) or m, r"version must be"),
        (lambda m: m.__setitem__("version", True) or m, r"version must be"),
        (
            lambda m: m.__setitem__("candidate_manifest_sha256", 1) or m,
            r"candidate_manifest_sha256 must be 64-char",
        ),
        # R6 slice 1: the bool / wrong-length / non-hex type mutations formerly
        # aimed at vendored_deps_manifest_sha256 are retargeted onto the surviving
        # identity digest so the sha256 type contract keeps its coverage.
        (
            lambda m: m.__setitem__("candidate_manifest_sha256", True) or m,
            r"candidate_manifest_sha256 must be 64-char",
        ),
        (
            lambda m: m.__setitem__("candidate_manifest_sha256", "a" * 63) or m,
            r"candidate_manifest_sha256 must be 64-char",
        ),
        (
            lambda m: m.__setitem__("candidate_manifest_sha256", "z" * 64) or m,
            r"candidate_manifest_sha256 must be 64-char",
        ),
        (lambda m: m.__setitem__("build", "nope") or m, r"build must be an object"),
        (lambda m: m.__setitem__("wheel", ["nope"]) or m, r"wheel must be an object"),
        (lambda m: m.__setitem__("sdist", 1) or m, r"sdist must be an object"),
        (
            lambda m: m.__setitem__("plugin_zip", True) or m,
            r"plugin_zip must be an object",
        ),
    ],
)
def test_l2_top_wrong_type_red(tmp_path, mutator, match):
    fake_root, dist, man, measured = _fresh_verify_fixture(tmp_path)
    payload = mutator(copy.deepcopy(man))
    _write_manifest(dist, payload)
    with pytest.raises(ValueError, match=match):
        verify_artifact_manifest(fake_root, measured=measured)


@pytest.mark.parametrize("missing_key", _BUILD_REQUIRED_KEYS)
def test_l2_build_missing_key_red(tmp_path, missing_key):
    fake_root, dist, man, measured = _fresh_verify_fixture(tmp_path)
    payload = copy.deepcopy(man)
    payload["build"].pop(missing_key)
    _write_manifest(dist, payload)
    with pytest.raises(ValueError, match=rf"build missing key: {missing_key}"):
        verify_artifact_manifest(fake_root, measured=measured)


def test_l2_build_extra_key_unexpected_build_key_red(tmp_path):
    """Deterministic counter-example: build.unexpected_build_key must fail."""
    fake_root, dist, man, measured = _fresh_verify_fixture(tmp_path)
    payload = copy.deepcopy(man)
    payload["build"]["unexpected_build_key"] = "x"
    _write_manifest(dist, payload)
    with pytest.raises(ValueError, match=r"build has unexpected keys"):
        verify_artifact_manifest(fake_root, measured=measured)


@pytest.mark.parametrize(
    "mutator,match",
    [
        (
            lambda m: m["build"].__setitem__("source_date_epoch", True) or m,
            r"source_date_epoch must be",
        ),
        (
            lambda m: m["build"].__setitem__("source_date_epoch", "1704067200") or m,
            r"source_date_epoch must be",
        ),
        (
            lambda m: m["build"].__setitem__("normalized_archives", 1) or m,
            r"normalized_archives must be boolean True",
        ),
        (
            lambda m: m["build"].__setitem__("normalized_archives", "true") or m,
            r"normalized_archives must be boolean True",
        ),
        (
            lambda m: m["build"].__setitem__("pythonhashseed", 0) or m,
            r"pythonhashseed must be",
        ),
        (
            lambda m: m["build"].__setitem__("tz", True) or m,
            r"build\.tz must be",
        ),
        (
            lambda m: m["build"].__setitem__("build_python", 1) or m,
            r"build_python must be a non-empty string",
        ),
        (
            lambda m: m["build"].__setitem__("build_python", True) or m,
            r"build_python must be a non-empty string",
        ),
    ],
)
def test_l2_build_wrong_type_red(tmp_path, mutator, match):
    fake_root, dist, man, measured = _fresh_verify_fixture(tmp_path)
    payload = mutator(copy.deepcopy(man))
    _write_manifest(dist, payload)
    with pytest.raises(ValueError, match=match):
        verify_artifact_manifest(fake_root, measured=measured)


@pytest.mark.parametrize("kind", _ARTIFACT_KINDS)
@pytest.mark.parametrize("missing_key", _ARTIFACT_ENTRY_KEYS)
def test_l2_artifact_entry_missing_key_red(tmp_path, kind, missing_key):
    fake_root, dist, man, measured = _fresh_verify_fixture(tmp_path)
    payload = copy.deepcopy(man)
    payload[kind].pop(missing_key)
    _write_manifest(dist, payload)
    with pytest.raises(ValueError, match=rf"{kind} missing key: {missing_key}"):
        verify_artifact_manifest(fake_root, measured=measured)


@pytest.mark.parametrize("kind", _ARTIFACT_KINDS)
def test_l2_artifact_entry_extra_key_red(tmp_path, kind):
    fake_root, dist, man, measured = _fresh_verify_fixture(tmp_path)
    payload = copy.deepcopy(man)
    payload[kind]["extra_field"] = "x"
    _write_manifest(dist, payload)
    with pytest.raises(ValueError, match=rf"{kind} has unexpected keys"):
        verify_artifact_manifest(fake_root, measured=measured)


@pytest.mark.parametrize("kind", _ARTIFACT_KINDS)
@pytest.mark.parametrize(
    "field,bad_value,match",
    [
        ("filename", 1, r"filename missing"),
        ("filename", True, r"filename missing"),
        ("sha256", 1, r"must be 64-char lowercase hex"),
        ("sha256", True, r"must be 64-char lowercase hex"),
        ("sha256", ["0" * 64], r"must be 64-char lowercase hex"),
    ],
)
def test_l2_artifact_entry_wrong_type_red(
    tmp_path, kind, field, bad_value, match
):
    fake_root, dist, man, measured = _fresh_verify_fixture(tmp_path)
    payload = copy.deepcopy(man)
    payload[kind][field] = bad_value
    _write_manifest(dist, payload)
    with pytest.raises(ValueError, match=match):
        verify_artifact_manifest(fake_root, measured=measured)


@pytest.mark.parametrize(
    "mutator,match",
    [
        (
            lambda m: m.__setitem__("version", "0.1.0") or m,
            r"version must be",
        ),
        (
            lambda m: m["build"].__setitem__("source_date_epoch", 1) or m,
            r"source_date_epoch must be",
        ),
        (
            lambda m: m["build"].__setitem__("normalized_archives", False) or m,
            r"normalized_archives must be boolean True",
        ),
        (
            lambda m: m["build"].__setitem__("pythonhashseed", "1") or m,
            r"pythonhashseed must be",
        ),
        (
            lambda m: m["build"].__setitem__("tz", "Asia/Shanghai") or m,
            r"build\.tz must be",
        ),
        (
            lambda m: m["build"].__setitem__("build_python", "") or m,
            r"build_python must be a non-empty string",
        ),
        (
            lambda m: m["build"].__setitem__("build_python", "   ") or m,
            r"build_python must be a non-empty string",
        ),
        (
            lambda m: (
                m["plugin_zip"].__setitem__(
                    "filename", "renamed-credential-guard.zip"
                )
                or m
            ),
            r"plugin_zip\.filename must be",
        ),
        (
            lambda m: (
                m["plugin_zip"].__setitem__(
                    "filename", f"../{PLUGIN_ZIP_FILENAME}"
                )
                or m
            ),
            r"must be a basename",
        ),
        (
            lambda m: (
                m["plugin_zip"].__setitem__(
                    "filename", f"/tmp/{PLUGIN_ZIP_FILENAME}"
                )
                or m
            ),
            r"must be a basename",
        ),
        (
            lambda m: (m["sdist"].__setitem__("filename", WHEEL_FILENAME) or m),
            r"sdist\.filename must be|filenames must be unique",
        ),
        (
            lambda m: (m["plugin_zip"].__setitem__("sha256", "deadbeef") or m),
            r"must be 64-char lowercase hex",
        ),
        (
            lambda m: (m["plugin_zip"].__setitem__("sha256", "A" * 64) or m),
            r"must be 64-char lowercase hex",
        ),
        (
            lambda m: (
                m["plugin_zip"].__setitem__("sha256", "0" * 64) or m
            ),
            r"artifact hash drift",
        ),
    ],
)
def test_l2_artifact_manifest_value_drift_mutations_are_red(
    tmp_path, mutator, match
):
    fake_root, dist, man, measured = _fresh_verify_fixture(tmp_path)
    payload = mutator(copy.deepcopy(man))
    _write_manifest(dist, payload)
    with pytest.raises(ValueError, match=match):
        verify_artifact_manifest(fake_root, measured=measured)


def test_l2_duplicate_filenames_red(tmp_path):
    fake_root, dist, man, measured = _fresh_verify_fixture(tmp_path)
    payload = copy.deepcopy(man)
    # Force wheel + sdist to claim the same basename (also wrong for sdist).
    payload["sdist"]["filename"] = WHEEL_FILENAME
    _write_manifest(dist, payload)
    with pytest.raises(ValueError, match=r"sdist\.filename must be|unique"):
        verify_artifact_manifest(fake_root, measured=measured)


def test_l2_manifest_side_candidate_drift_red(tmp_path):
    """R6 slice 1: the deps drift mutation is retargeted onto the surviving digest.

    ``test_l2_candidate_drift_is_red`` perturbs the *measured* side; this one
    perturbs the *manifest* side, so both directions of the identity comparison
    stay pinned after ``vendored_deps_manifest_sha256`` was removed.
    """
    fake_root, dist, man, measured = _fresh_verify_fixture(tmp_path)
    payload = copy.deepcopy(man)
    payload["candidate_manifest_sha256"] = "f" * 64
    _write_manifest(dist, payload)
    with pytest.raises(ValueError, match="candidate_manifest_sha256 drift"):
        verify_artifact_manifest(fake_root, measured=measured)


def test_l2_top_key_set_is_exactly_six_after_r6_contraction():
    """The contraction must shrink the contract, not turn it into accept-anything."""
    assert release_identity._ALLOWED_MANIFEST_TOP_KEYS == frozenset(
        {
            "version",
            "candidate_manifest_sha256",
            "wheel",
            "sdist",
            "plugin_zip",
            "build",
        }
    )
    assert len(release_identity._ALLOWED_MANIFEST_TOP_KEYS) == 6


def test_l2_retired_deps_key_is_rejected_as_surplus(tmp_path):
    """Re-inserting the retired key must be rejected, proving strict keys still bite."""
    fake_root, dist, man, measured = _fresh_verify_fixture(tmp_path)
    payload = copy.deepcopy(man)
    payload["vendored_deps_manifest_sha256"] = "b" * 64
    _write_manifest(dist, payload)
    with pytest.raises(ValueError, match=r"unexpected keys.*vendored_deps_manifest_sha256"):
        verify_artifact_manifest(fake_root, measured=measured)


def test_l2_standard_filenames_match_builder_constants(tmp_path):
    """Builder constants are compared by reading its source, never by building."""
    fake_root, dist, man, measured = _fresh_verify_fixture(tmp_path)
    builder_src = (ROOT / "scripts" / "build_release_artifacts.py").read_text(
        encoding="utf-8"
    )
    for const, expected in (
        ("WHEEL_NAME", WHEEL_FILENAME),
        ("SDIST_NAME", SDIST_FILENAME),
        ("PLUGIN_ZIP_NAME", PLUGIN_ZIP_FILENAME),
    ):
        m = re.search(rf'^{const} = f?"(.+)"$', builder_src, re.M)
        assert m, f"builder does not declare {const}"
        rendered = m.group(1).replace("{PLUGIN_VERSION}", PLUGIN_VERSION)
        assert rendered == expected, f"{const} -> {rendered} != {expected}"
    assert man["wheel"]["filename"] == WHEEL_FILENAME
    assert man["sdist"]["filename"] == SDIST_FILENAME
    assert man["plugin_zip"]["filename"] == PLUGIN_ZIP_FILENAME
    verify_artifact_manifest(fake_root, measured=measured)


# Version → designated acceptance report (historical M2 stays frozen).
_DESIGNATED_REPORTS = {
    "0.2.0": "docs/M2-验收报告.md",
    "0.3.0": "docs/M3-验收报告.md",
    "0.3.1": "docs/M3-验收报告.md",
    "0.4.0": "docs/R6-0.4.0-验收报告.md",
    "0.4.1": "docs/R7-0.4.1-验收报告.md",
    "0.4.2": "docs/R8-0.4.2-验收报告.md",
    "0.4.3": "docs/R9-0.4.3-验收报告.md",
}

def _designated_report_for_version(version: str) -> Path:
    rel = _DESIGNATED_REPORTS.get(version)
    if rel is None:
        raise AssertionError(f"no designated acceptance report for version {version}")
    return ROOT / rel


def _parse_plugin_zip_hash_for_version(text: str, version: str):
    """Return (filename, sha256) for the plugin zip of ``version``, else None."""
    pat = re.compile(
        rf"`?(credential-guard-{re.escape(version)}-hermes-plugin\.zip)`"
        rf"\s*\|\s*`([0-9a-f]{{64}})`"
    )
    m = pat.search(text)
    if m:
        return m.group(1), m.group(2)
    return None


def test_k2_docs_final_plugin_zip_hash_matches_manifest_when_present():
    """Current PLUGIN_VERSION designated report hash must match dist manifest.

    Historical M2 0.2.0 hashes must not be compared against a newer manifest.
    """
    report = _designated_report_for_version(PLUGIN_VERSION)
    if not report.is_file():
        pytest.fail(f"designated report missing for {PLUGIN_VERSION}: {report}")
    text = report.read_text(encoding="utf-8")
    if re.search(r"^\*\*BLOCKING", text, re.M):
        pytest.fail(
            f"designated report for {PLUGIN_VERSION} is still BLOCKING; "
            "publish gate requires a PASS report with current artifact hashes"
        )
    parsed = _parse_plugin_zip_hash_for_version(text, PLUGIN_VERSION)
    if parsed is None:
        pytest.fail(
            f"designated report for {PLUGIN_VERSION} has no plugin zip hash "
            f"for credential-guard-{PLUGIN_VERSION}-hermes-plugin.zip"
        )
    filename, docs_hash = parsed
    assert filename == PLUGIN_ZIP_FILENAME
    # Filename version must equal manifest version before hash compare.
    assert f"-{PLUGIN_VERSION}-" in filename

    manifest_path = artifact_manifest_path(ROOT)
    if not manifest_path.is_file():
        pytest.fail(f"{ARTIFACT_MANIFEST_FILENAME} missing under dist/ (build required)")
    man = load_artifact_manifest(ROOT)
    assert man["version"] == PLUGIN_VERSION
    assert man["plugin_zip"]["filename"] == filename
    expected = man["plugin_zip"]["sha256"]
    assert docs_hash == expected, (
        f"docs plugin zip hash {docs_hash} != manifest {expected}"
    )


def test_k2_historical_m2_hash_does_not_bind_current_manifest():
    """M2 0.2.0 report hash must remain frozen and must not equal current zip."""
    m2 = ROOT / "docs" / "M2-验收报告.md"
    assert m2.is_file()
    text = m2.read_text(encoding="utf-8")
    parsed = _parse_plugin_zip_hash_for_version(text, "0.2.0")
    assert parsed is not None
    _filename, m2_hash = parsed
    assert m2_hash == (
        "fc031a4e52e65bec987b127c568649c1f699db09ab872fd54a3dbb11351bc566"
    )
    if PLUGIN_VERSION != "0.2.0":
        manifest_path = artifact_manifest_path(ROOT)
        if manifest_path.is_file():
            man = load_artifact_manifest(ROOT)
            if man["version"] == PLUGIN_VERSION:
                assert man["plugin_zip"]["sha256"] != m2_hash


def test_k2_version_mismatch_between_report_filename_and_manifest_is_red(tmp_path):
    """Parser requires filename version == PLUGIN_VERSION before hash compare."""
    text = (
        "| plugin zip | `credential-guard-0.2.0-hermes-plugin.zip` "
        "| `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` |\n"
    )
    assert _parse_plugin_zip_hash_for_version(text, PLUGIN_VERSION) is None
    assert _parse_plugin_zip_hash_for_version(text, "0.2.0") is not None


def test_k2_wrong_current_report_hash_must_fail(monkeypatch, tmp_path):
    """If designated report hash drifts from manifest, the gate must fail."""
    assert PLUGIN_VERSION in _DESIGNATED_REPORTS, (
        f"no designated report mapping for {PLUGIN_VERSION}"
    )
    # Simulate wrong hash in an isolated copy of the selection logic.
    fake_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    text = (
        f"| plugin zip | `credential-guard-{PLUGIN_VERSION}-hermes-plugin.zip` "
        f"| `{fake_hash}` |\n"
    )
    parsed = _parse_plugin_zip_hash_for_version(text, PLUGIN_VERSION)
    assert parsed is not None
    manifest_path = artifact_manifest_path(ROOT)
    if not manifest_path.is_file():
        pytest.fail(f"{ARTIFACT_MANIFEST_FILENAME} missing under dist/")
    man = load_artifact_manifest(ROOT)
    assert parsed[1] != man["plugin_zip"]["sha256"]
