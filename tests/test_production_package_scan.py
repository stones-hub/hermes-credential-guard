"""Production package scan: pure static source / package-member contract.

R5 migrated this module away from a real setuptools build. It no longer calls
``build_all()`` and never writes to ``dist/``; everything here reads source or
synthetic trees only, so the module is safe to reason about without running a
release. The two-independent-build reproducibility contract belongs to R6.

Contract covered here:

* declared package membership excludes the deleted vendored PyMySQL tree;
* the runtime layout predicate treats any ``deps/pymysql`` member as failure;
* release declarations (requirements / pyproject / MANIFEST / metadata) carry
  no third-party runtime dependency;
* production source contains no DDL/DML SQL-shaped strings, and that scanner
  stays load-bearing under mutation.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tests.support.ddl_dml_ast_scan import find_ddl_dml_hits

ROOT = Path(__file__).resolve().parents[1]

_BANNED_PATH_PARTS = (
    "/tests/",
    "companions/",
    "credential_guard_test",
    "approval_ticket",
    "ssh_harness",
    "run_m3_e2e",
    "run_m2_e2e",
    "run_canary_e2e",
)
_REQUIRED_ROOT = (
    "plugin.yaml",
    "requirements.txt",
    "release-metadata.json",
)
# Any packaged member under these prefixes is a hard failure after R5.
_FORBIDDEN_MEMBER_PREFIXES = ("deps/pymysql", "deps/")


def _scan_tree(root: Path, *, artifact_name: str) -> None:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.as_posix().lower()
        for banned in _BANNED_PATH_PARTS:
            assert banned not in rel, f"{artifact_name} contains {banned}: {rel}"
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace")
        assert "probe_write_denied" not in text, path
        assert "CREDENTIAL_GUARD_TEST_" not in text, path
        assert "approval_ticket" not in text, path
        if "credential_guard/" in path.as_posix() or (
            len(path.parts) >= 2 and path.parts[-2] == "credential_guard"
        ):
            hits = find_ddl_dml_hits(text, filename=str(path))
            assert not hits, f"DDL/DML in {path}: {hits}"
            assert path.name != "approval_ticket.py"


def assert_member_set_is_clean(members, *, artifact_name: str) -> None:
    """Package-member gate: any vendored deps member fails closed."""
    for rel in members:
        norm = str(rel).replace("\\", "/").lstrip("./")
        for bad in _FORBIDDEN_MEMBER_PREFIXES:
            assert not norm.startswith(bad), (
                f"{artifact_name} declares forbidden vendored member: {norm}"
            )
        assert "pymysql" not in norm.lower(), (
            f"{artifact_name} declares PyMySQL member: {norm}"
        )


def _assert_has_runtime_layout(root: Path, *, require_root_meta: bool) -> None:
    assert (root / "credential_guard").is_dir(), "credential_guard/ missing"
    assert not (root / "deps").exists(), "vendored deps/ must not be packaged"
    members = [
        p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()
    ]
    assert_member_set_is_clean(members, artifact_name=str(root))
    if require_root_meta:
        for name in _REQUIRED_ROOT:
            assert (root / name).is_file(), f"missing {name}"


# ---------------------------------------------------------------------------
# Static release declarations — no build, no dist/ access
# ---------------------------------------------------------------------------


def test_requirements_declares_no_third_party_dependency():
    text = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    assert lines == [], f"requirements.txt must stay empty, got {lines}"


def test_pyproject_has_empty_dependencies_and_no_deps_package():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "dependencies = []" in text
    assert "pymysql" not in text.lower()
    assert 'include = ["credential_guard*"]' in text
    assert "deps*" not in text
    assert "package-data" not in text


def test_manifest_in_does_not_ship_deps():
    text = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("prune"):
            continue
        assert "deps" not in stripped, stripped
        assert "pymysql" not in stripped.lower(), stripped


def test_release_metadata_is_exactly_empty_object():
    data = json.loads((ROOT / "release-metadata.json").read_text(encoding="utf-8"))
    assert data == {}


def test_vendored_pymysql_tree_is_absent_from_source():
    assert not (ROOT / "deps").exists()
    assert not (ROOT / "credential_guard" / "deps_integrity.py").exists()


def test_member_gate_flags_any_deps_pymysql_member():
    """Package-member gate must fail closed on a vendored member."""
    with pytest.raises(AssertionError):
        assert_member_set_is_clean(
            ["credential_guard/__init__.py", "deps/pymysql/__init__.py"],
            artifact_name="synthetic",
        )
    with pytest.raises(AssertionError):
        assert_member_set_is_clean(
            ["deps/pymysql-1.2.0.dist-info/RECORD"], artifact_name="synthetic"
        )
    # Clean member set passes.
    assert_member_set_is_clean(
        ["credential_guard/__init__.py", "plugin.yaml"], artifact_name="synthetic"
    )


def test_runtime_layout_predicate_rejects_packaged_deps(tmp_path):
    root = tmp_path / "tree"
    (root / "credential_guard").mkdir(parents=True)
    (root / "credential_guard" / "__init__.py").write_text("", encoding="utf-8")
    _assert_has_runtime_layout(root, require_root_meta=False)

    (root / "deps" / "pymysql").mkdir(parents=True)
    (root / "deps" / "pymysql" / "__init__.py").write_text("", encoding="utf-8")
    with pytest.raises(AssertionError):
        _assert_has_runtime_layout(root, require_root_meta=False)


def test_builder_source_no_longer_depends_on_vendored_deps():
    text = (ROOT / "scripts" / "build_release_artifacts.py").read_text(
        encoding="utf-8"
    )
    assert "deps_integrity" not in text
    assert "deps/pymysql" not in text
    assert "vendored_tree_manifest_sha256" not in text


def test_production_source_tree_scan_is_clean():
    """Live credential_guard/ source passes the artifact content scan."""
    root = ROOT
    for path in (root / "credential_guard").rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace")
        assert "probe_write_denied" not in text, path
        assert "CREDENTIAL_GUARD_TEST_" not in text, path
        hits = find_ddl_dml_hits(text, filename=str(path))
        assert not hits, f"DDL/DML in {path}: {hits}"


# ---------------------------------------------------------------------------
# DDL/DML AST scanner contract (unchanged from the pre-R5 module)
# ---------------------------------------------------------------------------

_REAL_SQL_LITERALS = (
    '"DELETE FROM t"',
    '"UPDATE t SET x=1"',
    '"INSERT INTO t VALUES (1)"',
    '"CREATE TABLE t (id INT)"',
    '"DROP TABLE t"',
    '"ALTER TABLE t ADD COLUMN x INT"',
    '"TRUNCATE TABLE t"',
)


def test_ast_scan_bare_http_delete_is_clean():
    """Lone HTTP method enum token must not be treated as DML."""
    src = 'ALLOWED_HTTP_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")\n'
    assert find_ddl_dml_hits(src, filename="<http-enum>") == []


@pytest.mark.parametrize("literal", _REAL_SQL_LITERALS)
def test_ast_scan_real_sql_literals_are_hits(literal: str):
    src = f"SQL = {literal}\n"
    hits = find_ddl_dml_hits(src, filename="<sql>")
    assert hits, f"expected DDL/DML hit for {literal}"


def test_ast_scan_english_and_schema_enum_are_clean():
    src = (
        'DESC = "Please delete the obsolete row carefully"\n'
        'HINT = "create something useful for operators"\n'
        'ENUM = "create"\n'
        'METHOD = "DELETE"\n'
    )
    assert find_ddl_dml_hits(src, filename="<english>") == []


def test_ast_scan_foldable_concat_delete_from_is_hit():
    """Static concat that forms obvious SQL should still hit when foldable."""
    src = 'q = "DELETE " + "FROM t"\n'
    assert find_ddl_dml_hits(src, filename="<concat>")


def test_ast_scan_fstring_update_with_dynamic_target_is_hit():
    """f-string with dynamic table must not drop UPDATE…SET shape (review P1)."""
    src = 'q = f"UPDATE {table} SET x=1"\n'
    assert find_ddl_dml_hits(src, filename="<fstring-update>")


def test_ast_scan_bytes_delete_from_is_hit():
    """bytes literals carrying SQL must still trip the gate."""
    src = 'q = b"DELETE FROM t"\n'
    assert find_ddl_dml_hits(src, filename="<bytes-sql>")


def test_ast_scan_multiline_comment_then_delete_from_is_hit():
    """SQL-shaped statement after a leading comment line must still hit."""
    src = 'q = "-- probe\\nDELETE FROM t"\n'
    assert find_ddl_dml_hits(src, filename="<sql-comment-prefix>")


def test_ast_scan_dynamic_only_boundary_documented():
    """Fully dynamic assembly has no SQL-shaped constant; static AST gate may miss.

    Boundary: release gate requires clear string literals or foldable constant
    concat/format templates. Runtime-only verb+rest assembly is out of scope.
    """
    src = 'q = verb + " " + rest\n'
    assert find_ddl_dml_hits(src, filename="<dynamic>") == []


def test_reference_tools_production_source_has_no_sql_shaped_strings():
    text = (ROOT / "credential_guard" / "reference_tools.py").read_text(encoding="utf-8")
    assert find_ddl_dml_hits(text, filename="reference_tools.py") == []


def test_reference_tools_injected_delete_from_scan_is_red(tmp_path):
    """Mutation: temporary copy with real SQL must trip the scanner (gate stays live)."""
    original = (ROOT / "credential_guard" / "reference_tools.py").read_text(encoding="utf-8")
    poisoned = original + '\n_PACKAGE_SCAN_PROBE = "DELETE FROM x"\n'
    target = tmp_path / "reference_tools.py"
    target.write_text(poisoned, encoding="utf-8")
    # Do not mutate production reference_tools.py — only the temp copy.
    assert find_ddl_dml_hits(target.read_text(encoding="utf-8"), filename=str(target))
    tree_root = tmp_path / "pkg"
    (tree_root / "credential_guard").mkdir(parents=True)
    shutil.copy2(target, tree_root / "credential_guard" / "reference_tools.py")
    with pytest.raises(AssertionError, match="DDL/DML"):
        _scan_tree(tree_root, artifact_name="mutation-injected-delete-from")
