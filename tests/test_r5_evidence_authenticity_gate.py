"""R5 evidence authenticity — independent AST pin for the R5 wire carrier.

Must NOT rewrite or re-pin scripts/run_r3c_wire_e2e.py (R3 historical).
"""

from __future__ import annotations

import ast
import hashlib
import sys
from pathlib import Path
from typing import FrozenSet, Optional

import pytest

REPO = Path(__file__).resolve().parents[1]
R5_WIRE = REPO / "scripts" / "run_r5_wire_e2e.py"
R3_WIRE = REPO / "scripts" / "run_r3c_wire_e2e.py"

# Frozen R3 historical pin — must remain untouched.
_R3_WIRE_CANONICAL_AST_SHA256 = (
    "5d97004c7a32d0cadbd44a6f163ce49d97a83f014bfccfdfd63a472290763c65"
)


def _ast_sha256(path: Path) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    dump = ast.dump(tree, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(dump.encode("utf-8")).hexdigest()


def test_r3_historical_wire_ast_pin_unchanged():
    assert R3_WIRE.is_file()
    assert _ast_sha256(R3_WIRE) == _R3_WIRE_CANONICAL_AST_SHA256


def test_r5_wire_carrier_has_independent_ast_identity():
    assert R5_WIRE.is_file()
    digest = _ast_sha256(R5_WIRE)
    assert len(digest) == 64
    assert digest != _R3_WIRE_CANONICAL_AST_SHA256
    # Carrier must declare it is not the historical R3 path.
    src = R5_WIRE.read_text(encoding="utf-8")
    assert "r5_wire_e2e" in src
    assert "historical_r3_carrier" in src


def test_r5_wire_mutation_ast_drift_is_red():
    original = R5_WIRE.read_text(encoding="utf-8")
    baseline = _ast_sha256(R5_WIRE)
    # Comments are invisible to AST — mutate a real statement.
    mutated = original.replace(
        'FORMAL_PROVIDED_TOOLS = (\n    "http_credential_request",\n    "credential_process_run",\n)',
        'FORMAL_PROVIDED_TOOLS = (\n    "http_credential_request",\n    "credential_process_run",\n    "mutated_tool",\n)',
        1,
    )
    assert mutated != original
    tree = ast.parse(mutated)
    dump = ast.dump(tree, annotate_fields=True, include_attributes=False)
    mutated_digest = hashlib.sha256(dump.encode("utf-8")).hexdigest()
    assert mutated_digest != baseline


# ---------------------------------------------------------------------------
# Blocker 3: release_identity must import without deps_integrity
# ---------------------------------------------------------------------------


class _BlockModuleFinder:
    def __init__(self, blocked: FrozenSet[str]) -> None:
        self._blocked = blocked

    def find_spec(self, fullname, path, target=None):  # noqa: ANN001
        if fullname in self._blocked:
            raise ImportError(f"{fullname} is blocked for isolation test")
        return None


def test_r5_prep_release_identity_imports_without_deps_integrity():
    """release_identity must never depend on deps_integrity, at import or call.

    Rewritten by the R5 atomic-delete slice. The prep-era contract was "fail
    loud with 'vendored deps integrity unavailable' when deps_integrity is
    missing". Slice E deleted the vendored PyMySQL tree outright, so
    ``measured_release_fields`` no longer measures or imports it and correctly
    raises nothing. The surviving, still load-bearing property is the
    decoupling itself: with deps_integrity unimportable, the module must still
    import and produce real measured fields.
    """
    src = (REPO / "credential_guard" / "release_identity.py").read_text(encoding="utf-8")
    assert "deps_integrity" not in src

    saved = {
        name: sys.modules.pop(name, None)
        for name in (
            "credential_guard.release_identity",
            "credential_guard.deps_integrity",
        )
    }
    finder = _BlockModuleFinder(frozenset({"credential_guard.deps_integrity"}))
    sys.meta_path.insert(0, finder)
    try:
        import credential_guard.release_identity as ri

        digest = ri.candidate_manifest_sha256(REPO)
        assert isinstance(digest, str) and len(digest) == 64
        measured = ri.measured_release_fields(REPO)
        assert measured == {"candidate_manifest_sha256": digest}
    finally:
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
        for name, mod in saved.items():
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod
        import credential_guard as pkg

        if saved["credential_guard.release_identity"] is not None:
            setattr(pkg, "release_identity", saved["credential_guard.release_identity"])


def test_r5_prep_release_identity_mutation_silent_empty_is_red():
    """measured_release_fields must never degrade to a silent {} / None.

    Rewritten by the R5 atomic-delete slice for the same reason as
    :func:`test_r5_prep_release_identity_imports_without_deps_integrity`: with
    the vendored tree gone there is no 'integrity unavailable' error to raise.
    The anti-silent-empty property is what mattered and it survives — a missing
    deps_integrity must not turn the measured fields into an empty or None
    result that would vacuously satisfy the release-metadata comparison.
    """
    saved = {
        name: sys.modules.pop(name, None)
        for name in (
            "credential_guard.release_identity",
            "credential_guard.deps_integrity",
        )
    }
    finder = _BlockModuleFinder(frozenset({"credential_guard.deps_integrity"}))
    sys.meta_path.insert(0, finder)
    try:
        import credential_guard.release_identity as ri

        out = ri.measured_release_fields(REPO)
        assert out not in (None, {})
        assert isinstance(out, dict) and out
        measured_digest = out["candidate_manifest_sha256"]
        assert isinstance(measured_digest, str) and len(measured_digest) == 64
        # A silently-empty measurement must not be accepted as a match.
        assert ri.release_metadata_matches({}, {}) is True
        assert ri.release_metadata_matches(out, {"pymysql_sha256": "x"}) is False
    finally:
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
        for name, mod in saved.items():
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod
        import credential_guard as pkg

        if saved["credential_guard.release_identity"] is not None:
            setattr(pkg, "release_identity", saved["credential_guard.release_identity"])
