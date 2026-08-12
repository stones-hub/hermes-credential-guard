"""R5 signed topology gate — planning vs final path accounting.

Parses `.r5-baseline-manifest.sha256` strictly. Phase is derived from
repository state (not a user CLI/env switch): planning while every approved
deleted path remains; final only when all approved deleted paths are absent
and all approved added paths exist; partial deletion is a transition
violation. Never treats R3/R4 sidecar digests as current live bytes.
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Mapping, Optional, Set, Tuple

import pytest

REPO = Path(__file__).resolve().parents[1]
BASELINE_MANIFEST = REPO / ".r5-baseline-manifest.sha256"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_LINE_RE = re.compile(r"^(.+):([0-9a-f]{64}):(\d+)$")

# Closed skip policy for live enumeration — not caller-supplied in production.
CLOSED_SKIP_DIRS_LIVE: FrozenSet[str] = frozenset(
    {".venv", "__pycache__", ".git", ".pytest_cache", "eggs", ".eggs", "build"}
)
# dist/ is IN the baseline — do not skip it during live enumeration.

# ---------------------------------------------------------------------------
# Planning-time allowlists (must match approved R5 plan; fail loudly if unsure)
# ---------------------------------------------------------------------------

R5_ADDED_PATHS: FrozenSet[str] = frozenset(
    {
        # Plan §1.1
        "credential_guard/constants.py",
        "scripts/audit_legacy_residue.py",
        "tests/test_legacy_residue_gate.py",
        "scripts/run_r5_wire_e2e.py",
        "tests/test_r5_wire_e2e.py",
        "tests/test_r5_evidence_authenticity_gate.py",
        "tests/test_r5_topology_gate.py",
        "tests/test_r5_approval_host_posture.py",
        "tests/test_r5_provider_result_closure.py",
        "tests/test_ssh_config_non_interference.py",
        ".r5-tdd-evidence.log",
        ".r5-baseline-manifest.sha256",
        ".r5-freeze-evidence.sha256",
        # Round-1 task + no-build runner (documented in .r5-tdd-evidence.log)
        ".r5-round1-red-foundations-task.md",
        ".r5-round1a-false-green-fix-task.md",
        ".r5-round1b-topology-no-skip-task.md",
        ".r5-round1c-final-gate-blockers-task.md",
        ".r5-round1d-control-flow-bootstrap-task.md",
        "scripts/run_r5_nobuild_pytest.py",
        "tests/test_r5_nobuild_runner_gate.py",
        # Round 1E gate-closure plan + bypass inventory + re-run probe
        "docs/R5-门禁收口方案与绕过清单.md",
        "scripts/probe_r5_round1e_bypass.py",
        # Slice B / Task 3 — decouple TOOLSET_NAME
        ".r5-slice-b-constants-task.md",
        # Slice B fix — isolation helper side-effect leak
        ".r5-slice-b-fix-task.md",
        # Prep knife — decouple 3 module-level deletion blockers
        ".r5-prep-decouple-task.md",
        # Pre-existing read-only inventory task (present before this knife; was
        # unclassified and broke PHASE_PLANNING until declared).
        ".r5-migration-dep-inventory-task.md",
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
        # R6 slice 1 task file. Registered in the existing R5 added-paths ledger
        # (no separate R6 topology ledger) so the live-workspace classifier and
        # the layered file-count formula stay exact.
        ".r6-slice1-version-and-schema-task.md",
        # R6 slice 2 task file plus the three files the slice adds: the opt-in
        # real-build check module (named outside the no-build runner's
        # tests/test_*.py glob on purpose), its dedicated runner, and the gate
        # that self-proves the exclusion boundary.
        ".r6-slice2-build-and-reproducibility-task.md",
        "scripts/run_r6_build_tests.py",
        "tests/r6_real_build_check.py",
        "tests/test_r6_build_optin_gate.py",
        # R6 slice 3: real artifact composition audit + landed 0.4.0 dist members.
        # 0.4.0 artifacts are current-release pins (not R3 historical freeze);
        # they must still be classified so FINAL topology accounting stays exact.
        ".r6-slice3-artifact-audit-task.md",
        "tests/support/artifact_composition_audit.py",
        "tests/test_r6_artifact_composition.py",
        # Current release distribution policy: the active tree ships only 0.4.2.
        # Historical release reports and freeze sidecars remain, but old binaries do not.
        "tests/test_current_dist_policy.py",
        # R6 slice 4a: installed-ZIP approval-chain E2E (opt-in; outside
        # tests/test_*.py), shared ZIP install helpers, dedicated runner, and
        # the self-proving opt-in gate. Task file is the slice brief.
        ".r6-slice4a-installed-zip-e2e-task.md",
        "scripts/installed_zip_plugin.py",
        "scripts/run_r6_installed_zip_e2e.py",
        "scripts/run_r6_installed_zip_tests.py",
        "tests/r6_installed_zip_approval_chain.py",
        "tests/test_r6_installed_zip_optin_gate.py",
        # R6 slice 4b: full wire matrix (KNOWN_GAP_1 close) + task brief.
        ".r6-slice4b-wire-matrix-task.md",
        "tests/r6_installed_zip_wire_matrix.py",
        # R6 slice 5: delivery docs (acceptance report + install/ops guide) and
        # the slice task brief. No code/product behavior change beyond designated
        # report mapping in tests/test_reproducible_release.py.
        ".r6-slice5-delivery-docs-task.md",
        "docs/R6-0.4.0-验收报告.md",
        "docs/R6-0.4.0-安装与运维指南.md",
        # R6 administrative wrap-up: the progress-HTML backfill brief. It touches
        # no repo file (its only write target is the vault progress HTML), but it
        # lives in the workspace, so FINAL topology accounting must classify it
        # exactly like every other slice brief.
        ".r6-progress-html-backfill-task.md",
        # R6 completion-criterion #10: the three-way independent read-only review
        # brief, plus the 0.4.0 freeze sidecar that anchors the reviewed identity.
        # The sidecar excludes itself (see its own EXCLUDES line) when computing
        # the digest it records, exactly as .r5-freeze-evidence.sha256 does, but it
        # is still a live file and must be classified here.
        ".r6-final-review-task.md",
        ".r6-freeze-evidence.sha256",
        # Criterion #10 round 2: the evidence-authenticity brief, re-dispatched on a
        # different kernel after round 1's third route died on upstream rate limiting.
        ".r6-round2-evidence-authenticity-task.md",
        # Criterion #10 round 2b: narrow re-review confirming the single valid
        # BLOCKING from round 2 (stale FULL_NOBUILD_PYTEST in the sidecar) is closed.
        ".r6-round2b-blocking-fix-verify-task.md",
        # R7: Hermes current-version outbound compatibility fix (long-text false
        # block + llm_request local terminate). Task brief, scheme doc, regression.
        ".r7-task.md",
        # R7 Round 2: independent-review blocker narrow fix brief.
        ".r7-round2-narrow-fix-task.md",
        "docs/R7-Hermes当前版本真实外发兼容性修复方案.md",
        "tests/test_r7_long_text_and_local_block.py",
        # R7 release 0.4.1: administrative close + build/E2E/report (plugin-only).
        ".r7-release-0.4.1-task.md",
        # R7 0.4.1 final-ZIP E2E evidence narrow-fix brief (independent review).
        ".r7-041-final-zip-evidence-narrow-fix-task.md",
        # R7 0.4.1 final JSON-escape evidence fix brief. This task changes only
        # the final-ZIP harness/tests/report and must remain explicit topology.
        ".r7-041-json-escape-evidence-final-fix-task.md",
        "docs/R8-Hermes统一模型外发拦截接口-落地方案.md",
        "docs/R7-0.4.1-验收报告.md",
        "tests/test_r7_coverage_boundary_docs.py",
        "tests/r7_041_final_zip_e2e.py",
        "tests/test_r7_041_final_zip_optin_gate.py",
        "scripts/run_r7_041_final_zip_e2e.py",
        "scripts/run_r7_041_final_zip_tests.py",
        # Historical 0.4.1 reports/harnesses remain for traceability; their old
        # binary release artifacts are intentionally absent from active dist/.
        # R8 / 0.4.2: HTTP+HTTPS unified credential request (task, evidence, scheme, tests).
        # Workspace also gained repo root .gitignore + LICENSE (git init metadata) which
        # are outside the R5 baseline and must be classified as added, not preserved.
        ".gitignore",
        "LICENSE",
        ".r8-http-support-task.md",
        ".r8-http-tdd-evidence.log",
        ".r8-round2-blocking-fix-task.md",
        "docs/R8-0.4.2-HTTP与HTTPS统一凭证请求方案.md",
        "tests/test_r8_http_https_unified.py",
        # R8 release 0.4.2: designated report, ZIP E2E, versioned dist members.
        "docs/R8-0.4.2-验收报告.md",
        "tests/r8_042_final_zip_e2e.py",
        "tests/test_r8_042_final_zip_optin_gate.py",
        "scripts/run_r8_042_final_zip_e2e.py",
        "scripts/run_r8_042_final_zip_tests.py",
        "dist/artifact-manifest-0.4.2.json",
        "dist/credential-guard-0.4.2-hermes-plugin.zip",
        "dist/hermes_credential_guard-0.4.2-py3-none-any.whl",
        "dist/hermes_credential_guard-0.4.2.tar.gz",
    }
)

R5_DELETED_PATHS: FrozenSet[str] = frozenset(
    {
        # Production modules
        "credential_guard/tools.py",
        "credential_guard/mysql_executor.py",
        "credential_guard/ssh_tools.py",
        "credential_guard/ssh_executor.py",
        "credential_guard/targets.py",
        "credential_guard/file_backend.py",
        "credential_guard/deps_integrity.py",
        "deps/.gitignore",
        # Old product tests/scripts
        "tests/test_mysql_tools.py",
        "tests/test_mysql_executor_docker.py",
        "tests/test_targets.py",
        "tests/test_ssh_tools.py",
        "tests/test_ssh_executor.py",
        "tests/test_ssh_target_backend.py",
        "tests/test_file_backend.py",
        "tests/test_approval_gate.py",
        "tests/test_m2_approval_fix_gates.py",
        "tests/test_m2_release_blockers.py",
        "tests/test_m2_e2e_gates.py",
        "tests/test_m3_e2e_gates.py",
        "scripts/run_m2_e2e.py",
        "scripts/run_m3_e2e.py",
        "tests/support/mysql_harness.py",
        "tests/support/mysql_write_probe.py",
        "tests/support/ssh_harness.py",
        # Current distribution retirement: historical 0.3.1 binaries were in the
        # signed baseline, so their removal is an explicit approved deletion.
        "dist/artifact-manifest.json",
        "dist/credential-guard-0.3.1-hermes-plugin.zip",
        "dist/hermes_credential_guard-0.3.1-py3-none-any.whl",
        "dist/hermes_credential_guard-0.3.1.tar.gz",
    }
)

# Vendored trees are directory deletes; pin representative members from baseline
# plus the directory roots for planning presence checks.
R5_DELETED_PATH_PREFIXES: FrozenSet[str] = frozenset(
    {
        "deps/pymysql/",
        "deps/pymysql-1.2.0.dist-info/",
    }
)

R5_MODIFIED_PATHS: FrozenSet[str] = frozenset(
    {
        "credential_guard/__init__.py",
        "credential_guard/cli.py",
        "credential_guard/approval.py",
        "credential_guard/reference_tools.py",
        "credential_guard/process_tools.py",
        "credential_guard/config.py",
        "credential_guard/bindings.py",
        "credential_guard/runtime_config.py",
        "credential_guard/migration.py",
        "credential_guard/release_identity.py",
        "credential_guard/sensitive_paths.py",
        "plugin.yaml",
        "pyproject.toml",
        "requirements.txt",
        "MANIFEST.in",
        "release-metadata.json",
        "scripts/build_release_artifacts.py",
        "SECURITY.md",
        "README.md",
        "tests/test_plugin_registration.py",
        "tests/test_check_tool_middlewares.py",
        "tests/test_tool_request_analysis.py",
        "tests/test_reference_approval.py",
        "tests/test_file_registry_bridge.py",
        "tests/test_profile_write_boundary.py",
        "tests/test_r3c_historical_identity_gate.py",
        # A2 decision: 5 wire cases retired to R3-historical scope because the
        # AST-frozen carrier still pins the R3 four-tuple (Slice C left two).
        "tests/test_r3c_wire_e2e.py",
        "tests/test_config_v2.py",
        "tests/test_runtime_config_v2.py",
        "tests/test_config_migration.py",
        "tests/test_production_package_scan.py",
        "tests/test_reproducible_release.py",
        # R6 slice 1: the plugin-version assertions (0.3.1 -> 0.4.0) live in this
        # file, so it is no longer byte-identical to the R5 baseline. Declared as
        # modified rather than left as a silently drifting preserved path.
        "tests/test_tool_injection_foundation.py",
        # R6 slice 2: the `real_build` marker used by the opt-in check module is
        # registered here. Only the marker line was added -- no environment
        # variable and no authorization channel (禁 2).
        "pytest.ini",
        # R6 slice 4a: historical encoding canary now delegates ZIP install/load
        # to scripts/installed_zip_plugin.py and pins main() to the frozen 0.3.1
        # ZIP (so the 0.4.0 approval-chain E2E can own the current artifact).
        "scripts/run_final_zip_encoding_canary.py",
        "tests/companions/credential_guard_test/__init__.py",
        "tests/test_sensitive_paths.py",
        "tests/test_execute_code_sensitive_paths.py",
        "tests/test_target_catalog_boundary.py",
        "CLAUDE.md",
        "HANDOVER.md",
        # R7 production + E2E/canary contract updates (content drifted from baseline).
        "credential_guard/middleware.py",
        "scripts/run_canary_e2e.py",
        "tests/hermes_e2e_helpers.py",
        "tests/test_canary_gates.py",
        "tests/test_hermes_cli_e2e.py",
        "docs/R5-旧架构彻底清理-严格TDD实施计划.md",
        "docs/R5-旧架构彻底清理-落地方案.md",
        "docs/Credential-Guard-通用凭证边界实施计划.md",
        # R8: HTTP/HTTPS unified transport + gate flips (content drifted from baseline).
        "credential_guard/adapters/http.py",
        "tests/test_r3a_http_binding_schema.py",
        "tests/test_r3a_production_transport.py",
        "tests/test_r3c_evidence_authenticity_gate.py",
    }
)

PHASE_PLANNING = "planning"
PHASE_FINAL = "final"
PHASE_TRANSITION = "transition"


def parse_baseline_manifest(text: str) -> Dict[str, Tuple[str, int]]:
    """Strict parse: each line path:sha256:length. Reject blanks/dupes/bad hex."""
    out: Dict[str, Tuple[str, int]] = {}
    lines = text.splitlines()
    if not lines:
        raise ValueError("empty baseline manifest")
    for i, raw in enumerate(lines, 1):
        if not raw.strip():
            raise ValueError(f"blank line at {i}")
        m = _LINE_RE.match(raw)
        if not m:
            raise ValueError(f"malformed baseline line {i}: {raw[:80]!r}")
        path, digest, length_s = m.group(1), m.group(2), m.group(3)
        if path in out:
            raise ValueError(f"duplicate baseline path: {path}")
        if not _HEX64.match(digest):
            raise ValueError(f"bad digest at line {i}")
        length = int(length_s)
        if length < 0:
            raise ValueError(f"negative length at line {i}")
        out[path] = (digest, length)
    return out


def load_baseline() -> Dict[str, Tuple[str, int]]:
    assert BASELINE_MANIFEST.is_file(), "missing .r5-baseline-manifest.sha256"
    return parse_baseline_manifest(BASELINE_MANIFEST.read_text(encoding="utf-8"))


def effective_deleted(
    baseline_paths: Iterable[str],
    *,
    deleted_paths: FrozenSet[str] = R5_DELETED_PATHS,
    deleted_prefixes: FrozenSet[str] = R5_DELETED_PATH_PREFIXES,
) -> Set[str]:
    deleted = set(deleted_paths)
    for p in baseline_paths:
        if any(p.startswith(pref) for pref in deleted_prefixes):
            deleted.add(p)
    return deleted


def derive_preserved(
    baseline_paths: Iterable[str],
    *,
    deleted_paths: FrozenSet[str] = R5_DELETED_PATHS,
    deleted_prefixes: FrozenSet[str] = R5_DELETED_PATH_PREFIXES,
    modified_paths: FrozenSet[str] = R5_MODIFIED_PATHS,
) -> FrozenSet[str]:
    base = set(baseline_paths)
    deleted = effective_deleted(
        base, deleted_paths=deleted_paths, deleted_prefixes=deleted_prefixes
    )
    modified = set(modified_paths)
    overlap_dm = deleted & modified
    if overlap_dm:
        raise AssertionError(
            f"plan classifies paths as both deleted and modified: {sorted(overlap_dm)}"
        )
    exact_missing = set(deleted_paths) - base
    if exact_missing:
        raise AssertionError(
            f"R5_DELETED_PATHS not in baseline (fail loudly): {sorted(exact_missing)}"
        )
    unknown_modified = modified - base
    if unknown_modified:
        raise AssertionError(
            f"R5_MODIFIED_PATHS not in baseline (fail loudly): {sorted(unknown_modified)}"
        )
    preserved = base - deleted - modified
    return frozenset(preserved)


def validate_skip_policy(
    skip_dirs: Optional[Iterable[str]],
    *,
    closed: FrozenSet[str] = CLOSED_SKIP_DIRS_LIVE,
    preserved_sample: Optional[Iterable[str]] = None,
) -> List[str]:
    """Reject forged enumerator exclusions (closed policy only)."""
    errors: List[str] = []
    if skip_dirs is None:
        return errors
    skip_set = frozenset(skip_dirs)
    if skip_set != closed:
        extra = sorted(skip_set - closed)
        missing = sorted(closed - skip_set)
        if extra:
            errors.append(f"forged skip extras not in closed policy: {extra[:20]}")
        if missing:
            errors.append(f"closed skip entries omitted: {missing[:20]}")
    # Attempt to exclude preserved paths by name must be visible as forgery.
    if preserved_sample:
        for p in preserved_sample:
            # Directory-name style exclusion of a preserved file's parent leaf
            leaf = Path(p).name
            if leaf in skip_set and leaf not in closed:
                errors.append(f"forged skip of preserved path leaf: {p}")
            if p in skip_set:
                errors.append(f"forged skip of preserved path: {p}")
    return errors


def enumerate_live(
    root: Path,
    *,
    skip_dirs: Optional[Iterable[str]] = None,
) -> Tuple[Dict[str, Tuple[str, int]], List[str]]:
    """Enumerate live files. Production must pass skip_dirs=None (closed policy).

    Returns (live_map, skip_policy_errors).
    """
    policy_errors = validate_skip_policy(skip_dirs)
    effective_skip = (
        CLOSED_SKIP_DIRS_LIVE if skip_dirs is None else frozenset(skip_dirs)
    )
    out: Dict[str, Tuple[str, int]] = {}
    if policy_errors:
        # Still enumerate with closed policy so callers can see content errors too,
        # but forged policy is always reported.
        effective_skip = CLOSED_SKIP_DIRS_LIVE
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if any(part in effective_skip for part in path.relative_to(root).parts):
            continue
        if path.suffix == ".pyc":
            continue
        data = path.read_bytes()
        out[rel] = (hashlib.sha256(data).hexdigest(), len(data))
    return out, policy_errors


def detect_phase(
    *,
    baseline: Mapping[str, Tuple[str, int]],
    live: Mapping[str, Tuple[str, int]],
    added_paths: FrozenSet[str] = R5_ADDED_PATHS,
    deleted_paths: FrozenSet[str] = R5_DELETED_PATHS,
    deleted_prefixes: FrozenSet[str] = R5_DELETED_PATH_PREFIXES,
) -> str:
    """Phase from repository state — not a user CLI/env switch."""
    deleted = effective_deleted(
        baseline, deleted_paths=deleted_paths, deleted_prefixes=deleted_prefixes
    )
    live_paths = set(live)
    missing_deletes = sorted(p for p in deleted if p not in live_paths)
    present_deletes = sorted(p for p in deleted if p in live_paths)
    missing_adds = sorted(p for p in added_paths if p not in live_paths)

    if not missing_deletes and present_deletes:
        # Deletion has not started — planning (added may be incremental).
        return PHASE_PLANNING
    if not present_deletes and not missing_adds:
        return PHASE_FINAL
    # Partial deletion or incomplete final adds after deletes started.
    return PHASE_TRANSITION


def classify_workspace(
    *,
    baseline: Mapping[str, Tuple[str, int]],
    live: Mapping[str, Tuple[str, int]],
    phase: Optional[str] = None,
    added_paths: FrozenSet[str] = R5_ADDED_PATHS,
    deleted_paths: FrozenSet[str] = R5_DELETED_PATHS,
    deleted_prefixes: FrozenSet[str] = R5_DELETED_PATH_PREFIXES,
    modified_paths: FrozenSet[str] = R5_MODIFIED_PATHS,
    skip_policy_errors: Optional[List[str]] = None,
) -> List[str]:
    """Return human-readable violations (empty = pass).

    Explicit added/deleted/modified/prefix sets are injectable for mutations;
    production callers use module constants.
    """
    errors: List[str] = []
    if skip_policy_errors:
        errors.extend(skip_policy_errors)

    deleted = effective_deleted(
        baseline, deleted_paths=deleted_paths, deleted_prefixes=deleted_prefixes
    )
    preserved = derive_preserved(
        baseline,
        deleted_paths=deleted_paths,
        deleted_prefixes=deleted_prefixes,
        modified_paths=modified_paths,
    )
    live_paths = set(live)
    base_paths = set(baseline)

    if phase is None:
        phase = detect_phase(
            baseline=baseline,
            live=live,
            added_paths=added_paths,
            deleted_paths=deleted_paths,
            deleted_prefixes=deleted_prefixes,
        )

    unexpected = live_paths - base_paths - set(added_paths)
    if unexpected:
        errors.append(f"unclassified live paths: {sorted(unexpected)[:20]}")

    present_added = live_paths & set(added_paths)

    if phase == PHASE_TRANSITION:
        missing_deletes = sorted(p for p in deleted if p not in live_paths)
        present_deletes = sorted(p for p in deleted if p in live_paths)
        errors.append(
            "transition: partial deletion is not planning GREEN "
            f"missing_deletes={missing_deletes[:10]} "
            f"present_deletes={present_deletes[:10]}"
        )
        return errors

    if phase == PHASE_PLANNING:
        missing_deletes = sorted(p for p in deleted if p not in live_paths)
        if missing_deletes:
            errors.append(
                f"planning: planned-deleted paths already missing: {missing_deletes[:20]}"
            )
        for p in sorted(preserved):
            if p not in live:
                errors.append(f"planning: preserved path missing: {p}")
                continue
            if live[p][0] != baseline[p][0]:
                errors.append(f"planning: preserved path content drifted: {p}")
        for p in sorted(modified_paths):
            if p not in live_paths:
                errors.append(f"planning: modified path missing early: {p}")
        expected = base_paths | present_added
        if live_paths != expected:
            extra = sorted(live_paths - expected)[:20]
            missing = sorted(expected - live_paths)[:20]
            errors.append(
                f"planning: live≠baseline∪added_present extra={extra} missing={missing}"
            )
    elif phase == PHASE_FINAL:
        expected = (base_paths - deleted) | set(added_paths)
        if live_paths != expected:
            extra = sorted(live_paths - expected)[:20]
            missing = sorted(expected - live_paths)[:20]
            errors.append(
                f"final: live≠baseline−deleted+added extra={extra} missing={missing}"
            )
        for p in sorted(preserved):
            if p not in live:
                errors.append(f"final: preserved missing: {p}")
            elif live[p][0] != baseline[p][0]:
                errors.append(f"final: preserved drifted: {p}")
        for p in sorted(modified_paths):
            if p not in live_paths:
                errors.append(f"final: modified path missing: {p}")
        for p in sorted(deleted):
            if p in live_paths:
                errors.append(f"final: deleted path still present: {p}")
        for p in sorted(added_paths):
            if p not in live_paths:
                errors.append(f"final: added path missing: {p}")
    else:
        errors.append(f"unknown phase: {phase}")

    # Never require live bytes to equal R3/R4 sidecar digests.
    for sidecar in (".r3c-freeze-evidence.sha256", ".r4-freeze-evidence.sha256"):
        if sidecar in live and sidecar in baseline:
            pass

    return errors


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def _healthy_final_live(
    baseline: Mapping[str, Tuple[str, int]],
    *,
    added_paths: FrozenSet[str] = R5_ADDED_PATHS,
    deleted_paths: FrozenSet[str] = R5_DELETED_PATHS,
    deleted_prefixes: FrozenSet[str] = R5_DELETED_PATH_PREFIXES,
    modified_paths: FrozenSet[str] = R5_MODIFIED_PATHS,
) -> Dict[str, Tuple[str, int]]:
    """Healthy FINAL map: adds present, deletes absent, modifies present, preserved match."""
    deleted = effective_deleted(
        baseline, deleted_paths=deleted_paths, deleted_prefixes=deleted_prefixes
    )
    preserved = derive_preserved(
        baseline,
        deleted_paths=deleted_paths,
        deleted_prefixes=deleted_prefixes,
        modified_paths=modified_paths,
    )
    live: Dict[str, Tuple[str, int]] = {}
    for p in preserved:
        live[p] = baseline[p]
    for p in modified_paths:
        dig, length = baseline[p]
        # Content may change in final; keep length, alter digest.
        live[p] = ("b" * 64 if dig == "a" * 64 else "c" * 64, length)
    for p in added_paths:
        live[p] = ("a" * 64, 1)
    # Ensure no deleted paths remain.
    for p in deleted:
        live.pop(p, None)
    return live


def _healthy_planning_live(
    baseline: Mapping[str, Tuple[str, int]],
    *,
    added_paths: FrozenSet[str] = R5_ADDED_PATHS,
) -> Dict[str, Tuple[str, int]]:
    """Healthy PLANNING map: every baseline path at its baseline digest + adds.

    Built from the baseline rather than from the live tree so the partial
    deletion property stays testable after the atomic delete. An on-disk copy
    tree cannot serve here: reproducing the baseline SHA-256 of 294 files would
    require their original bytes, and several are already deleted.
    """
    live: Dict[str, Tuple[str, int]] = dict(baseline)
    for p in added_paths:
        live.setdefault(p, ("a" * 64, 1))
    return live


def _error_names_victim(errors: List[str], victim: str) -> bool:
    return any(victim in e for e in errors)


def test_baseline_manifest_parses_strictly():
    baseline = load_baseline()
    assert len(baseline) == 294
    for path, (digest, length) in baseline.items():
        assert _HEX64.match(digest)
        assert length >= 0
        assert path != ".r5-baseline-manifest.sha256"


def test_baseline_rejects_malformed_lines():
    with pytest.raises(ValueError):
        parse_baseline_manifest("not-a-valid-line\n")
    with pytest.raises(ValueError):
        parse_baseline_manifest("a.bin:" + ("0" * 64) + ":1\na.bin:" + ("1" * 64) + ":1\n")
    with pytest.raises(ValueError):
        parse_baseline_manifest("a.bin:zzzz:" + "1\n")


def test_preserved_derived_from_baseline_without_guessing():
    baseline = load_baseline()
    preserved = derive_preserved(baseline)
    assert "plugin.yaml" not in preserved  # modified
    assert "credential_guard/tools.py" not in preserved  # deleted
    assert "scripts/run_r3c_wire_e2e.py" in preserved  # must stay frozen
    assert ".r3c-freeze-evidence.sha256" in preserved
    assert ".r4-freeze-evidence.sha256" in preserved


def test_live_workspace_uses_phase_detector_and_classify():
    """Formal live test: phase from repo state; always calls classify_workspace().

    R5 deletion is complete, so the live workspace must now be FINAL: every
    approved deletion applied and every approved add present. PHASE_PLANNING is
    no longer an acceptable live state -- accepting it would let a reverted or
    half-restored old architecture pass as green. PHASE_TRANSITION is likewise
    rejected by classify_workspace() (partial deletion is never green).
    """
    baseline = load_baseline()
    live, skip_errs = enumerate_live(REPO, skip_dirs=None)
    assert skip_errs == []
    phase = detect_phase(baseline=baseline, live=live)
    assert phase == PHASE_FINAL, (
        "live workspace must be FINAL after the R5 atomic delete; "
        f"got {phase!r}"
    )
    errors = classify_workspace(
        baseline=baseline, live=live, phase=phase, skip_policy_errors=skip_errs
    )
    assert errors == [], errors


def test_synthetic_valid_planning_and_final_maps():
    digest = "a" * 64
    baseline = {
        "keep.py": (digest, 1),
        "gone.py": (digest, 1),
        "edit.py": (digest, 1),
        "vend/pkg/x.py": (digest, 1),
    }
    added = frozenset({"new.py"})
    deleted = frozenset({"gone.py"})
    prefixes = frozenset({"vend/"})
    modified = frozenset({"edit.py"})

    planning_live = {
        "keep.py": (digest, 1),
        "gone.py": (digest, 1),
        "edit.py": (digest, 1),
        "vend/pkg/x.py": (digest, 1),
        "new.py": (digest, 1),
    }
    assert (
        detect_phase(
            baseline=baseline,
            live=planning_live,
            added_paths=added,
            deleted_paths=deleted,
            deleted_prefixes=prefixes,
        )
        == PHASE_PLANNING
    )
    assert (
        classify_workspace(
            baseline=baseline,
            live=planning_live,
            phase=PHASE_PLANNING,
            added_paths=added,
            deleted_paths=deleted,
            deleted_prefixes=prefixes,
            modified_paths=modified,
        )
        == []
    )

    final_live = {
        "keep.py": (digest, 1),
        "edit.py": ("b" * 64, 1),
        "new.py": (digest, 1),
    }
    assert (
        detect_phase(
            baseline=baseline,
            live=final_live,
            added_paths=added,
            deleted_paths=deleted,
            deleted_prefixes=prefixes,
        )
        == PHASE_FINAL
    )
    assert (
        classify_workspace(
            baseline=baseline,
            live=final_live,
            phase=PHASE_FINAL,
            added_paths=added,
            deleted_paths=deleted,
            deleted_prefixes=prefixes,
            modified_paths=modified,
        )
        == []
    )


def test_partial_deletion_is_transition_not_planning_green():
    """Removing one approved delete from a planning tree is TRANSITION, never GREEN.

    The scenario is constructed from the baseline instead of the live tree: the
    property ("a half-finished deletion must not read as planning GREEN") is
    permanent, but the live tree is no longer in the planning state that the
    earlier live-tree construction depended on.
    """
    baseline = load_baseline()
    victim = "credential_guard/tools.py"
    assert victim in R5_DELETED_PATHS
    assert victim in baseline

    # Control: the intact planning map is genuinely GREEN, so the RED below is
    # caused by the partial deletion and not by a broken fixture.
    planning_live = _healthy_planning_live(baseline)
    assert detect_phase(baseline=baseline, live=planning_live) == PHASE_PLANNING
    assert (
        classify_workspace(
            baseline=baseline, live=planning_live, phase=PHASE_PLANNING
        )
        == []
    )

    live = dict(planning_live)
    del live[victim]
    phase = detect_phase(baseline=baseline, live=live)
    assert phase == PHASE_TRANSITION
    errors = classify_workspace(baseline=baseline, live=live, phase=phase)
    assert errors
    assert any("transition" in e for e in errors)
    assert _error_names_victim(errors, victim), errors


def test_omission_mutation_families_victim_specific_zero_skip_full_coverage():
    """Meta: delete/prefix/add/modify omission families name victims; zero skip/xfail."""
    src = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    families = {
        "test_mutation_omit_each_added_path_calls_formal_predicate": "R5_ADDED_PATHS",
        "test_mutation_omit_each_exact_deleted_path_calls_formal_predicate": "R5_DELETED_PATHS",
        "test_mutation_omit_each_deleted_prefix_calls_formal_predicate": "R5_DELETED_PATH_PREFIXES",
        "test_mutation_omit_each_modified_path_calls_formal_predicate": "R5_MODIFIED_PATHS",
    }
    for fn_name, const_name in families.items():
        target = None
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == fn_name:
                target = node
                break
        assert target is not None, fn_name
        for n in ast.walk(target):
            if not isinstance(n, ast.Call):
                continue
            func = n.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr in {"skip", "xfail"}
                and isinstance(func.value, ast.Name)
                and func.value.id == "pytest"
            ):
                raise AssertionError(f"{fn_name} must not pytest.skip/xfail")
            if isinstance(func, ast.Name) and func.id in {"skip", "skipif", "xfail"}:
                raise AssertionError(f"{fn_name} must not skip/xfail")
        # Must assert victim-specific naming helper / victim in errors — not bare bool(errors).
        body_src = ast.get_source_segment(src, target) or ""
        assert "_error_names_victim" in body_src or "victim in" in body_src or "prefix" in fn_name
        if "prefix" in fn_name:
            assert "expanded" in body_src or "_error_names_victim" in body_src
        covered = None
        for dec in target.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            func = dec.func
            if not (isinstance(func, ast.Attribute) and func.attr == "parametrize"):
                continue
            if len(dec.args) < 2:
                continue
            arg1 = dec.args[1]
            if (
                isinstance(arg1, ast.Call)
                and isinstance(arg1.func, ast.Name)
                and arg1.func.id == "sorted"
                and arg1.args
                and isinstance(arg1.args[0], ast.Name)
                and arg1.args[0].id == const_name
            ):
                covered = const_name
        assert covered == const_name, fn_name


@pytest.mark.parametrize("victim", sorted(R5_ADDED_PATHS))
def test_mutation_omit_each_added_path_calls_formal_predicate(victim):
    """Omit each approved add from injected set; classify_workspace must name victim."""
    baseline = load_baseline()
    # Healthy final with victim present, then omit victim from added allowlist.
    live = _healthy_final_live(baseline)
    assert victim in live
    shrunk = frozenset(set(R5_ADDED_PATHS) - {victim})
    errors = classify_workspace(
        baseline=baseline,
        live=live,
        phase=PHASE_FINAL,
        added_paths=shrunk,
    )
    assert errors, f"omitting added {victim} must RED via classify_workspace"
    assert _error_names_victim(errors, victim), (
        f"errors must name omitted added victim {victim}: {errors[:5]}"
    )


@pytest.mark.parametrize("victim", sorted(R5_DELETED_PATHS))
def test_mutation_omit_each_exact_deleted_path_calls_formal_predicate(victim):
    """Healthy FINAL omitting exactly one delete declaration must name that victim."""
    baseline = load_baseline()
    # Healthy final built as if victim were still a planned delete (absent from live).
    live = _healthy_final_live(baseline)
    assert victim not in live
    shrunk = frozenset(set(R5_DELETED_PATHS) - {victim})
    errors = classify_workspace(
        baseline=baseline,
        live=live,
        phase=PHASE_FINAL,
        deleted_paths=shrunk,
        added_paths=R5_ADDED_PATHS,
        deleted_prefixes=R5_DELETED_PATH_PREFIXES,
        modified_paths=R5_MODIFIED_PATHS,
    )
    assert errors, f"omitting deleted {victim} must RED via classify_workspace"
    assert _error_names_victim(errors, victim), (
        f"errors must name omitted deleted victim {victim}: {errors[:8]}"
    )


@pytest.mark.parametrize("prefix", sorted(R5_DELETED_PATH_PREFIXES))
def test_mutation_omit_each_deleted_prefix_calls_formal_predicate(prefix):
    """Omit exactly one deleted prefix; errors must name a prefix-expanded victim."""
    baseline = load_baseline()
    live = _healthy_final_live(baseline)
    expanded = sorted(p for p in baseline if p.startswith(prefix))
    assert expanded, prefix
    # Representative expanded victim is absent in healthy final.
    sample = expanded[0]
    assert sample not in live
    shrunk = frozenset(set(R5_DELETED_PATH_PREFIXES) - {prefix})
    errors = classify_workspace(
        baseline=baseline,
        live=live,
        phase=PHASE_FINAL,
        deleted_prefixes=shrunk,
        deleted_paths=R5_DELETED_PATHS,
        added_paths=R5_ADDED_PATHS,
        modified_paths=R5_MODIFIED_PATHS,
    )
    assert errors, f"omitting deleted prefix {prefix} must RED"
    assert any(_error_names_victim(errors, v) for v in expanded), (
        f"errors must name a prefix-expanded victim under {prefix}: {errors[:8]}"
    )


@pytest.mark.parametrize("victim", sorted(R5_MODIFIED_PATHS))
def test_mutation_omit_each_modified_path_calls_formal_predicate(victim):
    """Omit each modified path; healthy FINAL/planning must name that victim."""
    baseline = load_baseline()
    live = _healthy_final_live(baseline)
    shrunk = frozenset(set(R5_MODIFIED_PATHS) - {victim})
    # With victim omitted from modified, it becomes preserved; healthy final has
    # altered digest ⇒ preserved drift must name victim.
    errors = classify_workspace(
        baseline=baseline,
        live=live,
        phase=PHASE_FINAL,
        modified_paths=shrunk,
        added_paths=R5_ADDED_PATHS,
        deleted_paths=R5_DELETED_PATHS,
        deleted_prefixes=R5_DELETED_PATH_PREFIXES,
    )
    assert errors, f"omitting modified {victim} must RED via classify_workspace"
    assert _error_names_victim(errors, victim), (
        f"errors must name omitted modified victim {victim}: {errors[:8]}"
    )


def test_mutation_fake_exclude_forged_skip_policy_is_red():
    """Attack enumerator exclusion policy — forged extras/preserved must be rejected."""
    baseline = load_baseline()
    preserved = derive_preserved(baseline)
    victim = "scripts/run_r3c_wire_e2e.py"
    assert victim in preserved
    forged = set(CLOSED_SKIP_DIRS_LIVE) | {"run_r3c_wire_e2e.py", "unexpected_extra"}
    live, skip_errs = enumerate_live(REPO, skip_dirs=forged)
    assert skip_errs, "forged skip policy must produce errors"
    skip_errs = validate_skip_policy(
        forged, preserved_sample=[victim, "scripts/run_r3c_wire_e2e.py"]
    )
    assert skip_errs
    errors = classify_workspace(
        baseline=baseline,
        live=live,
        phase=PHASE_PLANNING,
        skip_policy_errors=skip_errs,
    )
    assert errors
    assert any("forged" in e or "skip" in e for e in errors)


def test_mutation_delete_preserved_path_is_red():
    baseline = load_baseline()
    live, _ = enumerate_live(REPO)
    live = dict(live)
    preserved = derive_preserved(baseline)
    victim = sorted(p for p in preserved if p.startswith("credential_guard/"))[0]
    del live[victim]
    errors = classify_workspace(baseline=baseline, live=live, phase=PHASE_PLANNING)
    assert any("preserved" in e or "missing" in e for e in errors)


def test_mutation_offset_preserved_deletion_with_unrelated_addition_planning_and_final():
    baseline = load_baseline()
    live, _ = enumerate_live(REPO)
    live = dict(live)
    preserved = derive_preserved(baseline)
    victim = sorted(p for p in preserved if p.endswith(".py"))[0]
    del live[victim]
    live["unrelated_offset_file.txt"] = ("a" * 64, 1)

    plan_errors = classify_workspace(
        baseline=baseline, live=live, phase=PHASE_PLANNING
    )
    assert plan_errors
    assert any(
        "unclassified" in e or "preserved" in e or "live≠" in e for e in plan_errors
    )

    # Final: remove all deleted, keep unrelated offset — still RED.
    deleted = effective_deleted(baseline)
    final_live = {p: h for p, h in live.items() if p not in deleted}
    final_live["unrelated_offset_file.txt"] = ("a" * 64, 1)
    # Ensure all added present for final detector shape.
    for p in R5_ADDED_PATHS:
        final_live.setdefault(p, ("a" * 64, 1))
    final_errors = classify_workspace(
        baseline=baseline, live=final_live, phase=PHASE_FINAL
    )
    assert final_errors
    assert any(
        "unclassified" in e or "preserved" in e or "live≠" in e for e in final_errors
    )


def test_r3_r4_sidecars_not_treated_as_live_digest_oracles():
    """Sidecar files stay baseline-preserved; their STATUS digests are not live targets."""
    baseline = load_baseline()
    for sidecar in (".r3c-freeze-evidence.sha256", ".r4-freeze-evidence.sha256"):
        assert sidecar in baseline
        assert sidecar in derive_preserved(baseline)
        text = (REPO / sidecar).read_text(encoding="utf-8")
        assert "STATUS=" in text or "TECHNICAL" in text or "R3" in text or "R4" in text
        live_digest = hashlib.sha256((REPO / sidecar).read_bytes()).hexdigest()
        assert live_digest == baseline[sidecar][0]
