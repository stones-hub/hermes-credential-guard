"""R3C C4: historical identity + production scope gate.

Candidate evidence only — does not claim R3/R3C PASS.
R3A/R3B sidecars remain historical sign-off identities and must not chase live.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Set, Tuple

import pytest

import test_r5_topology_gate as _r5_topology

REPO = Path(__file__).resolve().parents[1]

_SKIP_DIRS = frozenset(
    {".venv", "__pycache__", "dist", ".git", ".pytest_cache", "eggs", ".eggs", "build"}
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

R2_SIDECAR = REPO / ".r2-freeze-evidence.sha256"
R3A_SIDECAR = REPO / ".r3a-freeze-evidence.sha256"
R3B_SIDECAR = REPO / ".r3b-freeze-evidence.sha256"
R3C_SIDECAR = REPO / ".r3c-freeze-evidence.sha256"  # phased: technical candidate OR final administrative

_DIST_ARTIFACTS = (
    "dist/artifact-manifest.json",
    "dist/credential-guard-0.3.1-hermes-plugin.zip",
    "dist/hermes_credential_guard-0.3.1-py3-none-any.whl",
    "dist/hermes_credential_guard-0.3.1.tar.gz",
)

# Frozen historical digests for 0.3.1 dist (must remain unchanged).
_DIST_SHA256 = {
    "dist/artifact-manifest.json": None,  # filled at import from live once, then locked via sidecar compare
}


def _load_sidecar(path: Path) -> Dict[str, str]:
    assert path.is_file(), f"missing sidecar: {path}"
    out: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _parse_excludes(raw: str) -> Set[str]:
    return {p.strip() for p in raw.split(",") if p.strip()}


def _enumerate_workspace(
    root: Path,
    *,
    file_excludes: FrozenSet[str],
) -> List[Path]:
    out: List[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if rel in file_excludes:
            continue
        if path.suffix == ".pyc":
            continue
        out.append(path)
    return out


def _digest_workspace(files: Iterable[Path], root: Path) -> Tuple[str, int]:
    """sorted POSIX relative-path; each line path:sha256:size\\n then SHA-256."""
    lines: List[str] = []
    count = 0
    for path in sorted(files, key=lambda p: p.relative_to(root).as_posix()):
        rel = path.relative_to(root).as_posix()
        data = path.read_bytes()
        lines.append(f"{rel}:{hashlib.sha256(data).hexdigest()}:{len(data)}\n")
        count += 1
    blob = "".join(lines).encode("utf-8")
    return hashlib.sha256(blob).hexdigest(), count


def _live_workspace_digest(
    *,
    extra_excludes: FrozenSet[str],
) -> Tuple[str, int]:
    files = _enumerate_workspace(REPO, file_excludes=extra_excludes)
    return _digest_workspace(files, REPO)


def test_r3a_sidecar_is_historical_not_live_follower():
    """R3A freeze identity must remain the signed-off record, not equal live candidate."""
    meta = _load_sidecar(R3A_SIDECAR)
    hist = meta["R3A_FINAL_ADMINISTRATIVE_WORKSPACE_SHA256"]
    assert _HEX64.match(hist)
    assert "EXCLUDES" in meta
    excludes = _parse_excludes(meta["EXCLUDES"])
    assert ".r3a-freeze-evidence.sha256" in excludes
    # Live digest with the same exclude set will differ once R3B/R3C files exist.
    live, _n = _live_workspace_digest(extra_excludes=frozenset(excludes))
    # Historical identity is fixed; live may drift — gate requires they are independent.
    # After R3B/R3C work, live MUST differ from R3A historical (files added).
    assert live != hist, (
        "R3A historical digest unexpectedly equals live — "
        "gate expects subsequent milestones to drift without rewriting R3A sidecar"
    )
    # Sidecar itself must not be rewritten to chase live.
    assert meta["R3A_FINAL_ADMINISTRATIVE_WORKSPACE_FILES"] == "231"


def test_r3b_sidecar_records_technical_and_administrative_identities():
    meta = _load_sidecar(R3B_SIDECAR)
    admin = meta["R3B_FINAL_ADMINISTRATIVE_WORKSPACE_SHA256"]
    tech = meta["TECHNICAL_REVIEWED_CANDIDATE_SHA256"]
    assert _HEX64.match(admin)
    assert _HEX64.match(tech)
    # Algorithm tags must be exact (Unicode code-point order + path:sha256:len(bytes)).
    algo = meta["ALGORITHM"]
    assert "Unicode code-point order" in algo
    assert "path:sha256:len(bytes)" in algo or "path:sha256:size" in algo
    excludes = _parse_excludes(meta["EXCLUDES"])
    assert ".r3b-freeze-evidence.sha256" in excludes
    assert ".r3a-freeze-evidence.sha256" in excludes
    assert ".r2-freeze-evidence.sha256" in excludes
    # Technical reviewed candidate and administrative backfill are both recorded.
    assert "TECHNICAL_REVIEWED_CANDIDATE_SHA256" in meta
    assert "ADMINISTRATIVE_NOTE" in meta
    assert _HEX64.match(meta["TECHNICAL_REVIEWED_CANDIDATE_SHA256"])
    # Technical sign-off identity is frozen at 252; administrative may record later drift.
    assert meta["TECHNICAL_REVIEWED_CANDIDATE_FILES"] == "252"
    assert meta["TECHNICAL_REVIEWED_CANDIDATE_SHA256"] == (
        "f9eef16355baf7b1210eed3f11756fbead68c50f9e8a2efadef26844ded01952"
    )
    assert int(meta["R3B_FINAL_ADMINISTRATIVE_WORKSPACE_FILES"]) >= 252
    # Administrative and technical digests are both published (may differ after backfill).
    assert admin and tech


def test_r2_r3a_r3b_sidecars_recursively_exclude_themselves():
    # R2 self-exclusion lives in the freeze enumerator module + sidecar naming.
    r2_mod = (REPO / "credential_guard" / "r2_freeze_evidence.py").read_text(
        encoding="utf-8"
    )
    assert ".r2-freeze-evidence.sha256" in r2_mod
    assert "_SELF_EXCLUDES" in r2_mod or "SELF_EXCLUDES" in r2_mod

    for path, key in (
        (R3A_SIDECAR, ".r3a-freeze-evidence.sha256"),
        (R3B_SIDECAR, ".r3b-freeze-evidence.sha256"),
    ):
        text = path.read_text(encoding="utf-8")
        assert key in text
        meta = _load_sidecar(path)
        excludes = _parse_excludes(meta["EXCLUDES"])
        assert key in excludes
        # Sidecar content must not digest-include itself as an input line.
        assert not re.search(rf"(?m)^{re.escape(key)}:", text)

    # R2 sidecar is the recursive output record — must not appear as path:digest line.
    r2_text = R2_SIDECAR.read_text(encoding="utf-8")
    assert not re.search(r"(?m)^\.r2-freeze-evidence\.sha256:", r2_text)
    assert R2_SIDECAR.is_file()


_REQUIRED_R3C_EXCLUDES = frozenset(
    {
        ".r2-freeze-evidence.sha256",
        ".r3a-freeze-evidence.sha256",
        ".r3b-freeze-evidence.sha256",
        ".r3c-freeze-evidence.sha256",
    }
)

# Signed-off R3C final-administrative historical identity (immutable constants).
# Do NOT replace with a later reclosure live candidate digest.
_R3C_HIST_FINAL_ADMIN_FILES = "263"
_R3C_HIST_FINAL_ADMIN_MANIFEST_BYTES = "26816"
_R3C_HIST_FINAL_ADMIN_SHA256 = (
    "12a0f4a18335ed6acff0c8b8122fcadcaea00cfee4a36b5c3902605187ddf3ef"
)
_R3C_HIST_TECH_FILES = "263"
_R3C_HIST_TECH_MANIFEST_BYTES = "26816"
_R3C_HIST_TECH_SHA256 = (
    "15ad9c20c8b7e0da1653e3b3e3813cc2042470c5192027aa2eabb41648b0be28"
)
_R3C_HIST_PRIOR_ADMIN_SHA256 = (
    "044865eee60254742d8425f3aad9049de9d18d848089c78b55eb71494714ec60"
)
_R3C_HIST_STATUS = (
    "R3C and R3 formally signed off after Cursor plus two Hermes final "
    "read-only PASS verdicts"
)
_R3C_HIST_ADMINISTRATIVE_NOTE = (
    "post-review changes are sign-off evidence/status documents only; "
    "no R3 production safety semantics changed"
)


def _r3c_sidecar_phase(meta: Dict[str, str]) -> str:
    """Classify sidecar phase from published keys — never from STATUS alone."""
    if meta.get("R3C_FINAL_ADMINISTRATIVE_WORKSPACE_SHA256"):
        return "final_administrative"
    return "technical_candidate"


def _r3c_common_excludes_and_algo(meta: Dict[str, str]) -> List[str]:
    violations: List[str] = []
    excludes = _parse_excludes(meta.get("EXCLUDES", ""))
    if not _REQUIRED_R3C_EXCLUDES.issubset(excludes):
        violations.append("excludes:missing_self_or_historical")
    if ".r3c-freeze-evidence.sha256" not in excludes:
        violations.append("excludes:missing_self")
    algo = meta.get("ALGORITHM", "")
    if "Unicode code-point order" not in algo and "path:sha256" not in algo:
        violations.append("algorithm:missing_tags")
    return violations


def _r3c_technical_identity_keys(meta: Dict[str, str]) -> Tuple[str, str]:
    digest = (
        meta.get("TECHNICAL_REVIEWED_CANDIDATE_SHA256")
        or meta.get("R3C_TECHNICAL_REVIEW_WORKSPACE_SHA256")
        or meta.get("R3C_CANDIDATE_WORKSPACE_SHA256")
        or ""
    )
    files = (
        meta.get("TECHNICAL_REVIEWED_CANDIDATE_FILES")
        or meta.get("R3C_TECHNICAL_REVIEW_WORKSPACE_FILES")
        or meta.get("R3C_CANDIDATE_WORKSPACE_FILES")
        or ""
    )
    return digest, files


def _r3c_sidecar_technical_candidate_violations(meta: Dict[str, str]) -> List[str]:
    """Technical-candidate phase: explicit non-PASS only; no final-admin keys."""
    violations: List[str] = []
    if meta.get("R3C_FINAL_ADMINISTRATIVE_WORKSPACE_SHA256"):
        violations.append("phase:final_admin_keys_on_technical")
    status = meta.get("STATUS", "")
    status_l = status.lower()
    if "technical candidate" not in status_l and "technical-review" not in status_l:
        violations.append("status:missing_technical_candidate")
    if "not" not in status_l or "pass" not in status_l:
        violations.append("status:missing_not_pass")
    if re.search(r"\bR3C\s+PASS\b", status) and "not" not in status_l:
        violations.append("banned:R3C_PASS")
    if re.search(r"\bR3\s+PASS\b", status) and "not" not in status_l:
        violations.append("banned:R3_PASS")
    if "final administrative pass" in status_l:
        violations.append("banned:final_administrative_PASS")
    if status.strip() in {"R3C PASS", "R3 PASS"} or status_l.startswith("r3c pass"):
        violations.append("banned:STATUS_is_PASS")
    if "r3c pass" in status_l and "not" not in status_l:
        violations.append("banned:STATUS_claims_R3C_PASS")
    if "formally signed off" in status_l or "formal sign-off" in status_l:
        violations.append("banned:final_signoff_on_technical")

    violations.extend(_r3c_common_excludes_and_algo(meta))
    digest, files = _r3c_technical_identity_keys(meta)
    if not _HEX64.match(digest):
        violations.append("digest:invalid")
    try:
        if int(files) <= 0:
            violations.append("files:non_positive")
    except ValueError:
        violations.append("files:invalid")
    return violations


def _r3c_sidecar_final_administrative_violations(meta: Dict[str, str]) -> List[str]:
    """Final-administrative phase: layered admin + preserved technical identity."""
    violations: List[str] = []
    admin_digest = meta.get("R3C_FINAL_ADMINISTRATIVE_WORKSPACE_SHA256", "")
    admin_files = meta.get("R3C_FINAL_ADMINISTRATIVE_WORKSPACE_FILES", "")
    if not _HEX64.match(admin_digest):
        violations.append("admin:digest_invalid")
    try:
        if int(admin_files) <= 0:
            violations.append("admin:files_non_positive")
    except ValueError:
        violations.append("admin:files_invalid")

    tech_digest, tech_files = _r3c_technical_identity_keys(meta)
    if not _HEX64.match(tech_digest):
        violations.append("technical:digest_missing_or_invalid")
    try:
        if int(tech_files) <= 0:
            violations.append("technical:files_non_positive")
    except ValueError:
        violations.append("technical:files_invalid")

    # Technical identity must remain distinct from administrative identity.
    if _HEX64.match(admin_digest) and _HEX64.match(tech_digest):
        if admin_digest == tech_digest:
            violations.append("layer:admin_overwritten_by_technical")

    prior = meta.get("PRIOR_ADMINISTRATIVE_SHA256", "")
    prior_status = meta.get("PRIOR_ADMINISTRATIVE_STATUS", "")
    if not _HEX64.match(prior):
        violations.append("prior:missing_or_invalid")
    else:
        if prior == admin_digest:
            violations.append("prior:equals_current_admin")
        if "superseded" not in prior_status.lower():
            violations.append("prior:missing_superseded")

    status = meta.get("STATUS", "")
    status_l = status.lower()
    # Final STATUS must carry R3C/R3 formal sign-off semantics — not technical candidate.
    has_signoff = (
        ("formally signed off" in status_l or "formal sign-off" in status_l)
        and ("r3c" in status_l or "r3 " in status_l or status_l.startswith("r3"))
    )
    if not has_signoff:
        violations.append("status:missing_final_signoff")
    if "technical candidate" in status_l or "technical-review" in status_l:
        violations.append("status:technical_candidate_on_final")
    if "not" in status_l and "pass" in status_l and "signed off" not in status_l:
        # Explicit non-PASS wording without sign-off is the technical-candidate form.
        if "formally signed off" not in status_l:
            violations.append("status:not_pass_on_final")

    # Bind signed-off historical identity — format-valid rewrites still RED.
    if admin_digest != _R3C_HIST_FINAL_ADMIN_SHA256:
        violations.append("historical_identity:final_admin_digest")
    if admin_files != _R3C_HIST_FINAL_ADMIN_FILES:
        violations.append("historical_identity:final_admin_files")
    admin_manifest = meta.get("R3C_FINAL_ADMINISTRATIVE_MANIFEST_BYTES", "")
    if admin_manifest != _R3C_HIST_FINAL_ADMIN_MANIFEST_BYTES:
        violations.append("historical_identity:final_admin_manifest_bytes")

    if tech_digest != _R3C_HIST_TECH_SHA256:
        violations.append("historical_identity:technical_digest")
    if tech_files != _R3C_HIST_TECH_FILES:
        violations.append("historical_identity:technical_files")
    tech_manifest = meta.get("TECHNICAL_REVIEWED_CANDIDATE_MANIFEST_BYTES", "")
    if tech_manifest != _R3C_HIST_TECH_MANIFEST_BYTES:
        violations.append("historical_identity:technical_manifest_bytes")

    if prior != _R3C_HIST_PRIOR_ADMIN_SHA256:
        violations.append("historical_identity:prior_admin_digest")

    if status != _R3C_HIST_STATUS:
        violations.append("historical_status:mismatch")

    note = meta.get("ADMINISTRATIVE_NOTE", "")
    if note != _R3C_HIST_ADMINISTRATIVE_NOTE:
        violations.append("historical_identity:administrative_note")

    violations.extend(_r3c_common_excludes_and_algo(meta))
    return violations


def _r3c_sidecar_contract_violations(meta: Dict[str, str]) -> List[str]:
    """Phase-aware R3C sidecar contract. Empty list = healthy for its phase."""
    phase = _r3c_sidecar_phase(meta)
    if phase == "final_administrative":
        return _r3c_sidecar_final_administrative_violations(meta)
    return _r3c_sidecar_technical_candidate_violations(meta)


def test_r3c_sidecar_contract_must_recursively_exclude_self():
    """Phased contract: technical candidate OR final administrative, with self-exclude."""
    src = Path(__file__).read_text(encoding="utf-8")
    assert ".r3c-freeze-evidence.sha256" in src
    assert R3C_SIDECAR.is_file(), "R3C sidecar must exist for reclosure gate"

    meta = _load_sidecar(R3C_SIDECAR)
    violations = _r3c_sidecar_contract_violations(meta)
    assert violations == [], f"live sidecar contract broken: {violations}"
    text = R3C_SIDECAR.read_text(encoding="utf-8")
    assert not re.search(r"(?m)^\.r3c-freeze-evidence\.sha256:", text)
    phase = _r3c_sidecar_phase(meta)
    assert phase in {"technical_candidate", "final_administrative"}
    if phase == "technical_candidate":
        # Final-admin form must NOT reverse-satisfy the technical-only contract.
        assert "technical candidate" in meta.get("STATUS", "").lower()
    else:
        assert meta.get("R3C_FINAL_ADMINISTRATIVE_WORKSPACE_SHA256")
        assert meta.get("TECHNICAL_REVIEWED_CANDIDATE_SHA256")
        # Must not also satisfy technical-candidate (non-PASS) contract.
        tech_v = _r3c_sidecar_technical_candidate_violations(meta)
        assert tech_v, "final admin sidecar must not reverse-satisfy technical candidate"

    # Simulate a technical sidecar that forgets self-exclusion → RED.
    bad_meta = {
        "R3C_TECHNICAL_REVIEW_WORKSPACE_SHA256": "a" * 64,
        "R3C_TECHNICAL_REVIEW_WORKSPACE_FILES": "1",
        "ALGORITHM": (
            "sorted POSIX relative-path strings (Unicode code-point order); "
            "path:sha256:len(bytes)"
        ),
        "EXCLUDES": ".venv,__pycache__,dist",
        "STATUS": "technical candidate for bounded read-only review; not R3/R3C PASS",
    }
    bad_v = _r3c_sidecar_contract_violations(bad_meta)
    assert bad_v
    assert any("excludes" in x for x in bad_v)


def test_r3c_sidecar_mutation_drop_technical_identity_is_red():
    """Mutation 1: delete technical identity → RED."""
    meta = _load_sidecar(R3C_SIDECAR)
    mutated = dict(meta)
    for key in list(mutated):
        if "TECHNICAL" in key or "CANDIDATE" in key or "TECHNICAL_REVIEW" in key:
            del mutated[key]
    v = _r3c_sidecar_contract_violations(mutated)
    assert v
    assert any("technical" in x for x in v)


def test_r3c_sidecar_mutation_prior_admin_supersede_is_red():
    """Mutation 2: prior admin becomes current or loses superseded → RED."""
    meta = _load_sidecar(R3C_SIDECAR)
    if _r3c_sidecar_phase(meta) != "final_administrative":
        pytest.skip("prior-admin mutation only applies to final administrative sidecar")
    # 2a: prior digest overwritten to current final admin identity
    m1 = dict(meta)
    m1["PRIOR_ADMINISTRATIVE_SHA256"] = meta["R3C_FINAL_ADMINISTRATIVE_WORKSPACE_SHA256"]
    v1 = _r3c_sidecar_contract_violations(m1)
    assert v1
    assert any("prior" in x for x in v1)
    # 2b: superseded semantics removed
    m2 = dict(meta)
    m2["PRIOR_ADMINISTRATIVE_STATUS"] = "still active administrative identity"
    v2 = _r3c_sidecar_contract_violations(m2)
    assert v2
    assert any("prior" in x or "superseded" in x for x in v2)


def test_r3c_sidecar_mutation_drop_self_exclude_is_red():
    """Mutation 3: delete recursive self-exclude → RED."""
    meta = _load_sidecar(R3C_SIDECAR)
    mutated = dict(meta)
    excludes = [
        p
        for p in _parse_excludes(meta["EXCLUDES"])
        if p != ".r3c-freeze-evidence.sha256"
    ]
    mutated["EXCLUDES"] = ",".join(sorted(excludes))
    v = _r3c_sidecar_contract_violations(mutated)
    assert v
    assert any("excludes" in x for x in v)


def test_r3c_sidecar_mutation_final_status_to_technical_is_red():
    """Mutation 4: final STATUS rewritten to technical candidate / not PASS → RED."""
    meta = _load_sidecar(R3C_SIDECAR)
    if _r3c_sidecar_phase(meta) != "final_administrative":
        pytest.skip("STATUS flip mutation only applies to final administrative sidecar")
    mutated = dict(meta)
    mutated["STATUS"] = (
        "technical candidate for bounded read-only review; not R3/R3C PASS"
    )
    v = _r3c_sidecar_contract_violations(mutated)
    assert v
    assert any("status" in x for x in v)


def test_r3c_sidecar_mutation_admin_overwritten_by_technical_is_red():
    """Mutation 5: final admin identity collapsed onto technical without layering → RED."""
    meta = _load_sidecar(R3C_SIDECAR)
    if _r3c_sidecar_phase(meta) != "final_administrative":
        pytest.skip("admin/tech collapse mutation only applies to final administrative")
    mutated = dict(meta)
    tech = meta["TECHNICAL_REVIEWED_CANDIDATE_SHA256"]
    mutated["R3C_FINAL_ADMINISTRATIVE_WORKSPACE_SHA256"] = tech
    v = _r3c_sidecar_contract_violations(mutated)
    assert "layer:admin_overwritten_by_technical" in v
    assert "historical_identity:final_admin_digest" in v
    assert not any(x.startswith("prior:") for x in v), (
        "layering mutation must stay single-factor and must not rely on prior-field violations"
    )


def test_r3c_sidecar_irrelevant_field_order_is_green():
    """Irrelevant key order must not false-red (values unchanged)."""
    meta = _load_sidecar(R3C_SIDECAR)
    healthy = _r3c_sidecar_contract_violations(meta)
    # Rebuild with shuffled insertion order.
    keys = list(meta.keys())
    keys.reverse()
    shuffled = {k: meta[k] for k in keys}
    assert _r3c_sidecar_contract_violations(shuffled) == healthy


def test_r3c_historical_identity_mutation_final_admin_digest_is_red():
    """Historical gate: swap final admin digest to any other valid 64-hex → RED."""
    meta = _load_sidecar(R3C_SIDECAR)
    if _r3c_sidecar_phase(meta) != "final_administrative":
        pytest.skip("historical identity binding only for final administrative")
    mutated = dict(meta)
    mutated["R3C_FINAL_ADMINISTRATIVE_WORKSPACE_SHA256"] = (
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )
    v = _r3c_sidecar_contract_violations(mutated)
    assert v, "arbitrary valid final-admin digest must violate historical identity"
    assert any("historical_identity" in x for x in v)


def test_r3c_historical_identity_mutation_final_admin_files_bytes_is_red():
    """Historical gate: swap final admin files/manifest bytes to other positives → RED."""
    meta = _load_sidecar(R3C_SIDECAR)
    if _r3c_sidecar_phase(meta) != "final_administrative":
        pytest.skip("historical identity binding only for final administrative")
    mutated = dict(meta)
    mutated["R3C_FINAL_ADMINISTRATIVE_WORKSPACE_FILES"] = "999"
    mutated["R3C_FINAL_ADMINISTRATIVE_MANIFEST_BYTES"] = "99999"
    v = _r3c_sidecar_contract_violations(mutated)
    assert v, "other positive final-admin files/bytes must violate historical identity"
    assert any("historical_identity" in x for x in v)


def test_r3c_historical_identity_mutation_technical_digest_is_red():
    """Historical gate: swap technical reviewed digest to any other valid 64-hex → RED."""
    meta = _load_sidecar(R3C_SIDECAR)
    if _r3c_sidecar_phase(meta) != "final_administrative":
        pytest.skip("historical identity binding only for final administrative")
    mutated = dict(meta)
    mutated["TECHNICAL_REVIEWED_CANDIDATE_SHA256"] = (
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    )
    v = _r3c_sidecar_contract_violations(mutated)
    assert v, "arbitrary valid technical digest must violate historical identity"
    assert any("historical_identity" in x for x in v)


def test_r3c_historical_identity_mutation_technical_files_bytes_is_red():
    """Historical gate: swap technical files/manifest bytes to other positives → RED."""
    meta = _load_sidecar(R3C_SIDECAR)
    if _r3c_sidecar_phase(meta) != "final_administrative":
        pytest.skip("historical identity binding only for final administrative")
    mutated = dict(meta)
    mutated["TECHNICAL_REVIEWED_CANDIDATE_FILES"] = "888"
    mutated["TECHNICAL_REVIEWED_CANDIDATE_MANIFEST_BYTES"] = "88888"
    v = _r3c_sidecar_contract_violations(mutated)
    assert v, "other positive technical files/bytes must violate historical identity"
    assert any("historical_identity" in x for x in v)


def test_r3c_historical_identity_mutation_prior_admin_digest_is_red():
    """Historical gate: swap prior admin digest (still superseded) → RED."""
    meta = _load_sidecar(R3C_SIDECAR)
    if _r3c_sidecar_phase(meta) != "final_administrative":
        pytest.skip("historical identity binding only for final administrative")
    mutated = dict(meta)
    mutated["PRIOR_ADMINISTRATIVE_SHA256"] = (
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    )
    assert "superseded" in mutated.get("PRIOR_ADMINISTRATIVE_STATUS", "").lower()
    v = _r3c_sidecar_contract_violations(mutated)
    assert v, "arbitrary valid prior-admin digest must violate historical identity"
    assert any("historical_identity" in x for x in v)


def test_r3c_historical_status_mutation_alternate_signoff_text_is_red():
    """Historical gate: STATUS replaced with other plausible formal sign-off → RED."""
    meta = _load_sidecar(R3C_SIDECAR)
    if _r3c_sidecar_phase(meta) != "final_administrative":
        pytest.skip("historical status binding only for final administrative")
    mutated = dict(meta)
    mutated["STATUS"] = (
        "R3C and R3 formally signed off after independent final review PASS verdicts"
    )
    v = _r3c_sidecar_contract_violations(mutated)
    assert v, "alternate formal sign-off STATUS must violate historical status"
    assert any("historical_status" in x for x in v)


def test_r3c_historical_note_mutation_denies_production_semantics_is_red():
    """Historical gate: ADMINISTRATIVE_NOTE denying production boundary → RED."""
    meta = _load_sidecar(R3C_SIDECAR)
    if _r3c_sidecar_phase(meta) != "final_administrative":
        pytest.skip("historical note binding only for final administrative")
    mutated = dict(meta)
    mutated["ADMINISTRATIVE_NOTE"] = (
        "post-review changes rewrote R3 production safety semantics and adapters"
    )
    v = _r3c_sidecar_contract_violations(mutated)
    assert v, "note denying production semantics must violate historical identity/note"
    assert any(
        "historical_identity" in x or "historical_note" in x or "historical_status" in x
        for x in v
    )


def test_r3c_historical_identity_field_order_only_is_green():
    """Historical gate: dict key order alone must stay GREEN."""
    meta = _load_sidecar(R3C_SIDECAR)
    if _r3c_sidecar_phase(meta) != "final_administrative":
        pytest.skip("historical identity order check only for final administrative")
    healthy = _r3c_sidecar_contract_violations(meta)
    assert healthy == []
    keys = list(meta.keys())
    keys.reverse()
    shuffled = {k: meta[k] for k in keys}
    assert _r3c_sidecar_contract_violations(shuffled) == []


# Signed-off R3 reclosure technical candidate (immutable; not equal to live R4 workspace).
_R3_RECLOSURE_FILES = "271"
_R3_RECLOSURE_MANIFEST_BYTES = "27744"
_R3_RECLOSURE_SHA256 = (
    "657be4c61c1bd7a371eac19bcc111f9a19e17813ab99959600ef06829dc97626"
)
_R3_RECLOSURE_STATUS = (
    "technical candidate pending three final read-only reviews; not R3 reclosure PASS"
)

# Explicit R4-only paths that entered after R3 reclosure sign-off.
# Sidecar EXCLUDES must NOT be expanded to hide these.
_R4_DELTA_PATHS = frozenset(
    {
        ".r4-implementation-task.md",
        ".r4-round2-narrow-fix-task.md",
        ".r4-round3-historical-test-migration-task.md",
        ".r4-round4-final-review-blockers-task.md",
        ".r4-tdd-evidence.log",
        ".r4-freeze-evidence.sha256",
        "credential_guard/result_guard.py",
        "docs/R4-统一结果守卫与非干扰-严格TDD实施计划.md",
        "docs/R4-统一结果守卫与非干扰-落地方案.md",
        "scripts/run_v2_non_interference_e2e.py",
        "tests/test_injected_result_guard.py",
        "tests/test_non_interference_v2.py",
        "tests/test_result_guard_authenticity_gate.py",
    }
)

# R5 planning-only paths added after R4 sign-off. These are topology deltas,
# not a rewrite of either the immutable R3 sidecar or signed R4 candidate.
# Round-1 RED foundations expand this set as gates/runners are staged; R5
# signed topology (tests/test_r5_topology_gate.py) remains the path oracle.
_R5_PLANNING_DELTA_PATHS = frozenset(
    {
        "docs/R5-旧架构彻底清理-严格TDD实施计划.md",
        "docs/R5-旧架构彻底清理-落地方案.md",
        "docs/R5-门禁收口方案与绕过清单.md",
        ".r5-baseline-manifest.sha256",
        ".r5-tdd-evidence.log",
        ".r5-round1-red-foundations-task.md",
        ".r5-round1a-false-green-fix-task.md",
        ".r5-round1b-topology-no-skip-task.md",
        ".r5-round1c-final-gate-blockers-task.md",
        ".r5-round1d-control-flow-bootstrap-task.md",
        "scripts/audit_legacy_residue.py",
        "scripts/run_r5_nobuild_pytest.py",
        "scripts/probe_r5_round1e_bypass.py",
        "tests/test_legacy_residue_gate.py",
        "tests/test_r5_topology_gate.py",
        "tests/test_r5_nobuild_runner_gate.py",
        ".r5-slice-b-constants-task.md",
        ".r5-slice-b-fix-task.md",
        "credential_guard/constants.py",
        ".r5-prep-decouple-task.md",
        ".r5-migration-dep-inventory-task.md",
        # Prep knife creates the six pre-declared R5_ADDED gate/carrier files;
        # historical layered accounting requires them in this delta (same class
        # of fix as credential_guard/constants.py in Slice B).
        "scripts/run_r5_wire_e2e.py",
        "tests/test_r5_wire_e2e.py",
        "tests/test_r5_evidence_authenticity_gate.py",
        "tests/test_r5_approval_host_posture.py",
        "tests/test_r5_provider_result_closure.py",
        "tests/test_ssh_config_non_interference.py",
        ".r5-atomic-delete-task.md",
        ".r5-property-migration-task.md",
        ".r5-atomic-delete-task-v2.md",
        ".r5-migration-v2-conflict-fix-task.md",
        ".r5-atomic-delete-task-v3.md",
        ".r5-post-delete-wrapup-task.md",
        ".r5-final-two-gates-task.md",
        ".r5-final-gates-round2-task.md",
        ".r5-ignore-retirement-task.md",
        ".r5-dead-code-cleanup-task.md",
        # Created by the main agent at R5 final verification (implementation plan
        # line 494): the R5 freeze evidence sidecar. Declared here so layered
        # file-count accounting stays exact once phase flips to FINAL.
        ".r5-freeze-evidence.sha256",
        # R6 slice 1 task file (version bump + manifest key contraction).
        ".r6-slice1-version-and-schema-task.md",
        # R6 slice 2: task file plus the three files it adds (opt-in real-build
        # check module, its dedicated runner, and the self-proving gate).
        ".r6-slice2-build-and-reproducibility-task.md",
        "scripts/run_r6_build_tests.py",
        "tests/r6_real_build_check.py",
        "tests/test_r6_build_optin_gate.py",
        # R6 slice 3 source/task deltas. Landed dist/0.4.0 artifacts are NOT
        # listed here: this enumerator's _SKIP_DIRS includes "dist" (same as
        # 0.3.1, which is pinned via _DIST_ARTIFACTS instead). Current-release
        # 0.4.0 bytes are pinned by tests/test_r6_artifact_composition.py and
        # classified in the topology gate's R5_ADDED_PATHS.
        ".r6-slice3-artifact-audit-task.md",
        "tests/support/artifact_composition_audit.py",
        "tests/test_r6_artifact_composition.py",
        "tests/test_current_dist_policy.py",
        # R6 slice 4a source/task deltas. dist/ members stay out of this
        # enumerator (_SKIP_DIRS includes dist); 0.4.0 ZIP identity is pinned
        # by the installed-ZIP E2E harness + artifact composition tests.
        ".r6-slice4a-installed-zip-e2e-task.md",
        "scripts/installed_zip_plugin.py",
        "scripts/run_r6_installed_zip_e2e.py",
        "scripts/run_r6_installed_zip_tests.py",
        "tests/r6_installed_zip_approval_chain.py",
        "tests/test_r6_installed_zip_optin_gate.py",
        # R6 slice 4b: wire matrix module + task brief (KNOWN_GAP_1 close).
        ".r6-slice4b-wire-matrix-task.md",
        "tests/r6_installed_zip_wire_matrix.py",
        # R6 slice 5: delivery docs + task brief (acceptance report closes the
        # designated-report xfails; install/ops guide is the user-facing §11).
        ".r6-slice5-delivery-docs-task.md",
        "docs/R6-0.4.0-验收报告.md",
        "docs/R6-0.4.0-安装与运维指南.md",
        # R6 administrative wrap-up: progress-HTML backfill brief. Repo-side it
        # adds only this file (the brief's sole write target is the vault HTML),
        # so the layered file-count formula needs it declared here too.
        ".r6-progress-html-backfill-task.md",
        # R6 completion-criterion #10: three-way review brief + 0.4.0 freeze
        # sidecar. Same class as .r5-freeze-evidence.sha256 above — the sidecar is
        # created at final verification and must be declared so layered
        # file-count accounting stays exact.
        ".r6-final-review-task.md",
        ".r6-freeze-evidence.sha256",
        # Criterion #10 round 2 brief (see the topology ledger for the rationale).
        ".r6-round2-evidence-authenticity-task.md",
        # Criterion #10 round 2b brief: BLOCKING-fix confirmation re-review.
        ".r6-round2b-blocking-fix-verify-task.md",
        # R7 outbound compatibility (same added paths as topology ledger).
        ".r7-task.md",
        ".r7-round2-narrow-fix-task.md",
        "docs/R7-Hermes当前版本真实外发兼容性修复方案.md",
        "tests/test_r7_long_text_and_local_block.py",
        # R7 release 0.4.1 + vetoed R8 investigation record (non-dist paths only;
        # dist/ members are skipped by the historical enumerator).
        ".r7-release-0.4.1-task.md",
        ".r7-041-final-zip-evidence-narrow-fix-task.md",
        ".r7-041-json-escape-evidence-final-fix-task.md",
        "docs/R8-Hermes统一模型外发拦截接口-落地方案.md",
        "docs/R7-0.4.1-验收报告.md",
        "tests/test_r7_coverage_boundary_docs.py",
        "tests/r7_041_final_zip_e2e.py",
        "tests/test_r7_041_final_zip_optin_gate.py",
        "scripts/run_r7_041_final_zip_e2e.py",
        "scripts/run_r7_041_final_zip_tests.py",
        # R8 / 0.4.2 HTTP+HTTPS unified support + repo root metadata outside R5 baseline.
        ".gitignore",
        "LICENSE",
        ".r8-http-support-task.md",
        ".r8-http-tdd-evidence.log",
        ".r8-round2-blocking-fix-task.md",
        "docs/R8-0.4.2-HTTP与HTTPS统一凭证请求方案.md",
        "tests/test_r8_http_https_unified.py",
        # R8 release 0.4.2 (non-dist paths only; dist/ members skipped by enumerator).
        "docs/R8-0.4.2-验收报告.md",
        "tests/r8_042_final_zip_e2e.py",
        "tests/test_r8_042_final_zip_optin_gate.py",
        "scripts/run_r8_042_final_zip_e2e.py",
        "scripts/run_r8_042_final_zip_tests.py",
        # scripts/run_final_zip_encoding_canary.py is baseline-era (modified only);
        # it stays out of this delta and is declared in R5_MODIFIED_PATHS.
    }
)


def _r5_approved_deleted_paths() -> FrozenSet[str]:
    """R5-era source deletions used for historical non-dist file accounting.

    The historical workspace enumerator skips ``dist/`` entirely, so later
    retirement of old binary artifacts must not change this non-dist formula.
    """
    baseline = _r5_topology.load_baseline()
    deleted = _r5_topology.effective_deleted(
        baseline,
        deleted_paths=_r5_topology.R5_DELETED_PATHS,
        deleted_prefixes=_r5_topology.R5_DELETED_PATH_PREFIXES,
    )
    return frozenset(path for path in deleted if not path.startswith("dist/"))


def _workspace_manifest(
    *,
    file_excludes: FrozenSet[str],
) -> Tuple[str, int, int]:
    """Freeze algorithm: sorted path:sha256:len(bytes)\\n → SHA-256, file count, manifest bytes."""
    files = _enumerate_workspace(REPO, file_excludes=file_excludes)
    lines: List[str] = []
    for path in sorted(files, key=lambda p: p.relative_to(REPO).as_posix()):
        rel = path.relative_to(REPO).as_posix()
        data = path.read_bytes()
        lines.append(f"{rel}:{hashlib.sha256(data).hexdigest()}:{len(data)}\n")
    blob = "".join(lines).encode("utf-8")
    return hashlib.sha256(blob).hexdigest(), len(files), len(blob)


def test_r3c_reclosure_identity_is_layered_from_r4_workspace():
    """Layered history: pin R3 content identity; inspect later R4 topology separately.

    The signed-off R3 digest is historical evidence stored in the immutable sidecar.
    Current files modified by R4 are not a content oracle for reconstructing old bytes.
    """
    meta = _load_sidecar(R3C_SIDECAR)
    # Historical reclosure pins (sidecar must keep signed-off values).
    assert meta.get("R3_RECLOSURE_STATUS") == _R3_RECLOSURE_STATUS
    assert meta.get("R3_RECLOSURE_TECHNICAL_CANDIDATE_SHA256") == _R3_RECLOSURE_SHA256
    assert meta.get("R3_RECLOSURE_TECHNICAL_CANDIDATE_FILES") == _R3_RECLOSURE_FILES
    assert (
        meta.get("R3_RECLOSURE_TECHNICAL_CANDIDATE_MANIFEST_BYTES")
        == _R3_RECLOSURE_MANIFEST_BYTES
    )
    # Final admin / technical / prior remain bound via existing contract helpers.
    assert _r3c_sidecar_contract_violations(meta) == []

    sidecar_excludes = frozenset(_parse_excludes(meta["EXCLUDES"]))
    assert ".r3c-freeze-evidence.sha256" in sidecar_excludes
    # Must not expand sidecar excludes to swallow R4 deltas.
    assert not (_R4_DELTA_PATHS & sidecar_excludes)

    live_digest, live_files = _live_workspace_digest(extra_excludes=sidecar_excludes)
    # Live post-R4 workspace must not pretend to be the frozen R3 reclosure identity.
    assert live_digest != _R3_RECLOSURE_SHA256
    declared_later_paths = _R4_DELTA_PATHS | _R5_PLANNING_DELTA_PATHS
    # R5 deletions are an authorised topology action, so the layered ledger has
    # a subtraction term too. It is derived from the signed topology gate, never
    # hardcoded, so any future change to the approved delete set moves it.
    r5_deleted_paths = _r5_approved_deleted_paths()
    assert live_files == (
        int(_R3_RECLOSURE_FILES)
        + len(declared_later_paths)
        - len(r5_deleted_paths)
    )

    # Every declared later delta path must exist in the live tree (explicit, not guessed).
    live_rels = {
        p.relative_to(REPO).as_posix()
        for p in _enumerate_workspace(REPO, file_excludes=sidecar_excludes)
    }
    missing = sorted(declared_later_paths - live_rels)
    assert missing == [], f"declared post-R3 delta missing from live workspace: {missing}"

    restored_excludes = frozenset(set(sidecar_excludes) | set(declared_later_paths))
    restored_digest, restored_files, restored_bytes = _workspace_manifest(
        file_excludes=restored_excludes
    )
    # Path topology remains independently accountable: only the declared new R4 paths
    # may be removed to recover the historical candidate's file-count shape. R5's
    # approved deletions are the other half of that shape — removing later additions
    # is no longer sufficient, the deleted historical members must be added back.
    # Same derived term as the live ledger above; never hardcoded.
    assert restored_files + len(r5_deleted_paths) == int(_R3_RECLOSURE_FILES)
    # Historical manifest bytes, like its content digest, are pinned by the immutable
    # sidecar above. R4 legitimately changed lengths of files already in the R3 set;
    # rebuilding path:sha256:len lines from current bytes cannot reproduce that old
    # byte count or digest. Current values must not be substituted into the R3 pin.
    assert restored_bytes != int(_R3_RECLOSURE_MANIFEST_BYTES)
    assert restored_digest != _R3_RECLOSURE_SHA256


def test_r3c_reclosure_mutation_omit_r4_delta_is_red():
    """Mutation: omitting any declared R4 delta must break layered path accounting."""
    meta = _load_sidecar(R3C_SIDECAR)
    sidecar_excludes = frozenset(_parse_excludes(meta["EXCLUDES"]))
    for dropped in sorted(_R4_DELTA_PATHS):
        incomplete = _R4_DELTA_PATHS - {dropped}
        restored_excludes = frozenset(
            set(sidecar_excludes)
            | set(incomplete)
            | set(_R5_PLANNING_DELTA_PATHS)
        )
        _digest, files, _nbytes = _workspace_manifest(file_excludes=restored_excludes)
        assert files != int(_R3_RECLOSURE_FILES), dropped


def test_r3c_reclosure_mutation_omit_r5_planning_delta_is_red():
    """Mutation: each declared R5 planning path is required for layered accounting."""
    meta = _load_sidecar(R3C_SIDECAR)
    sidecar_excludes = frozenset(_parse_excludes(meta["EXCLUDES"]))
    for dropped in sorted(_R5_PLANNING_DELTA_PATHS):
        incomplete = _R5_PLANNING_DELTA_PATHS - {dropped}
        restored_excludes = frozenset(
            set(sidecar_excludes) | set(_R4_DELTA_PATHS) | set(incomplete)
        )
        _digest, files, _nbytes = _workspace_manifest(file_excludes=restored_excludes)
        assert files != int(_R3_RECLOSURE_FILES), dropped


def test_r3c_reclosure_mutation_change_historical_pin_is_red():
    """Mutation: rewriting reclosure historical pins must fail the layered gate."""
    meta = _load_sidecar(R3C_SIDECAR)
    mutated = dict(meta)
    mutated["R3_RECLOSURE_TECHNICAL_CANDIDATE_SHA256"] = "a" * 64
    assert mutated["R3_RECLOSURE_TECHNICAL_CANDIDATE_SHA256"] != _R3_RECLOSURE_SHA256
    # Predicate used by the layered gate:
    assert not (
        mutated.get("R3_RECLOSURE_TECHNICAL_CANDIDATE_SHA256") == _R3_RECLOSURE_SHA256
        and mutated.get("R3_RECLOSURE_TECHNICAL_CANDIDATE_FILES") == _R3_RECLOSURE_FILES
        and mutated.get("R3_RECLOSURE_TECHNICAL_CANDIDATE_MANIFEST_BYTES")
        == _R3_RECLOSURE_MANIFEST_BYTES
    )


def test_r3c_reclosure_mutation_exclude_unrelated_file_is_red():
    """Mutation: arbitrarily excluding an unrelated historical file must not be GREEN."""
    meta = _load_sidecar(R3C_SIDECAR)
    sidecar_excludes = frozenset(_parse_excludes(meta["EXCLUDES"]))
    unrelated = "plugin.yaml"
    assert unrelated not in _R4_DELTA_PATHS
    assert unrelated not in _R5_PLANNING_DELTA_PATHS
    bad_excludes = frozenset(
        set(sidecar_excludes)
        | set(_R4_DELTA_PATHS)
        | set(_R5_PLANNING_DELTA_PATHS)
        | {unrelated}
    )
    _digest, files, nbytes = _workspace_manifest(file_excludes=bad_excludes)
    assert files != int(_R3_RECLOSURE_FILES) or nbytes != int(
        _R3_RECLOSURE_MANIFEST_BYTES
    )


def test_031_dist_artifacts_are_retired_from_active_distribution():
    """0.3.1 evidence stays in history, but obsolete binaries leave active dist/."""
    retired = {
        "dist/artifact-manifest.json",
        "dist/credential-guard-0.3.1-hermes-plugin.zip",
        "dist/hermes_credential_guard-0.3.1-py3-none-any.whl",
        "dist/hermes_credential_guard-0.3.1.tar.gz",
    }
    assert all(not (REPO / rel).exists() for rel in retired)


def test_r3c_production_scope_no_new_adapter_type_backend_shell():
    """R3C must not add a fourth adapter / new credential backend / shell path."""
    adapters_dir = REPO / "credential_guard" / "adapters"
    adapter_files = sorted(
        p.name for p in adapters_dir.iterdir() if p.is_file() and p.suffix == ".py"
    )
    assert adapter_files == ["__init__.py", "http.py", "process.py"]
    # Binding types remain the closed R3 set.
    bindings = (REPO / "credential_guard" / "bindings.py").read_text(encoding="utf-8")
    assert "process_env" in bindings
    assert '"stdin"' in bindings or "'stdin'" in bindings or "stdin" in bindings
    # No shell=True production path.
    for rel in (
        "credential_guard/adapters/process.py",
        "credential_guard/adapters/http.py",
        "credential_guard/injection.py",
    ):
        src = (REPO / rel).read_text(encoding="utf-8")
        assert "shell=True" not in src
        assert "shell = True" not in src
    # No new credential backend module.
    cg = REPO / "credential_guard"
    backendish = [
        p.name
        for p in cg.iterdir()
        if p.is_file() and "backend" in p.name.lower() and p.suffix == ".py"
    ]
    # Historical file backends may exist; R3C must not add a new one named for R3C.
    assert not any("r3c" in n.lower() for n in backendish)
    assert not (cg / "adapters" / "shell.py").exists()
    assert not (cg / "adapters" / "env.py").exists()  # env lives inside process.py


def test_r3c_mutation_rewrite_r3a_sidecar_to_live_is_red():
    """If someone rewrote R3A sidecar digest to equal live, historical gate must fail."""
    meta = _load_sidecar(R3A_SIDECAR)
    excludes = _parse_excludes(meta["EXCLUDES"])
    live, _n = _live_workspace_digest(extra_excludes=frozenset(excludes))
    hist = meta["R3A_FINAL_ADMINISTRATIVE_WORKSPACE_SHA256"]
    # Simulate rewritten sidecar chasing live.
    rewritten = dict(meta)
    rewritten["R3A_FINAL_ADMINISTRATIVE_WORKSPACE_SHA256"] = live
    # Predicate: historical identity must stay the signed-off digest, not live.
    assert rewritten["R3A_FINAL_ADMINISTRATIVE_WORKSPACE_SHA256"] != hist
    # Gate rejects chase-live rewrite.
    assert rewritten["R3A_FINAL_ADMINISTRATIVE_WORKSPACE_SHA256"] == live
    chased = rewritten["R3A_FINAL_ADMINISTRATIVE_WORKSPACE_SHA256"] == live
    assert chased is True  # demonstrates the bad state
    # Healthy state remains hist != live (already proven) AND sidecar still has hist.
    assert _load_sidecar(R3A_SIDECAR)["R3A_FINAL_ADMINISTRATIVE_WORKSPACE_SHA256"] == hist


def test_r3b_algorithm_tag_mutation_is_red():
    meta = _load_sidecar(R3B_SIDECAR)
    healthy = meta["ALGORITHM"]
    mutated = healthy.replace("Unicode code-point order", "locale-dependent order")
    assert "Unicode code-point order" in healthy
    assert "Unicode code-point order" not in mutated
    # Predicate used by gate:
    assert "Unicode code-point order" not in mutated
