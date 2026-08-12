"""Tests-only AST/semantic DDL/DML scanner for production package gates.

Scans Python str/bytes constants (and foldable constant concatenations / f-string
literal fragments / str.format templates). A hit requires SQL *statement shape*:
keyword plus target/structure — not a bare HTTP method token like ``"DELETE"``.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

# Keyword + SQL target/structure. Bare tokens (HTTP DELETE, schema enum "create")
# and mid-sentence English do not match. CREATE/ALTER/DROP require a SQL object kind.
# MULTILINE: a statement after a leading comment line inside one string still hits.
_SQL_OBJECT_KIND = (
    r"(?:TABLE|INDEX|VIEW|DATABASE|SCHEMA|TRIGGER|PROCEDURE|FUNCTION|"
    r"EVENT|SEQUENCE|ROLE|USER|MATERIALIZED\s+VIEW)\b"
)
_SQL_STMT_SHAPE = re.compile(
    rf"""(?imx)^\s*(?:
        CREATE\s+(?:OR\s+REPLACE\s+)?(?:TEMPORARY\s+)?{_SQL_OBJECT_KIND}|
        ALTER\s+{_SQL_OBJECT_KIND}|
        DROP\s+(?:TEMPORARY\s+)?{_SQL_OBJECT_KIND}|
        INSERT\s+INTO\b|
        UPDATE\s+\S+\s+SET\b|
        DELETE\s+FROM\b|
        TRUNCATE\s+(?:TABLE\s+)?\S
    )"""
)

# Non-empty sentinel for f-string FormattedValue so UPDATE {t} SET / TRUNCATE
# keep a SQL target token under static fold.
_DYNAMIC_TOKEN = "x"


@dataclass(frozen=True)
class DdlDmlHit:
    lineno: int
    text: str


def _as_text(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return bytes(value).decode("latin-1", errors="replace")
    return None


def looks_like_ddl_dml_sql(value: str) -> bool:
    """Return True iff *value* looks like a SQL DDL/DML statement (not a bare token)."""
    return bool(_SQL_STMT_SHAPE.search(value))


def _fold_constant_str(node: ast.AST) -> str | None:
    """Fold simple constant string/bytes expressions for static scanning."""
    if isinstance(node, ast.Constant):
        return _as_text(node.value)
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                text = _as_text(value.value)
                if text is None:
                    return None
                parts.append(text)
            elif isinstance(value, ast.FormattedValue):
                # Keep a non-empty target token so UPDATE {t} SET still matches.
                parts.append(_DYNAMIC_TOKEN)
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _fold_constant_str(node.left)
        right = _fold_constant_str(node.right)
        if left is not None and right is not None:
            return left + right
        return None
    if isinstance(node, ast.Call):
        func = node.func
        # "DELETE FROM {}".format(table) — scan the format template.
        if isinstance(func, ast.Attribute) and func.attr == "format":
            return _fold_constant_str(func.value)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        # "DELETE FROM %s" % name — scan the format template.
        return _fold_constant_str(node.left)
    return None


def find_ddl_dml_hits(source: str, *, filename: str = "<string>") -> list[DdlDmlHit]:
    """Scan Python source via AST; return hits for SQL-shaped string constants."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:
        # Unparseable production source is a separate packaging failure; do not
        # pretend SQL was found.
        return []

    hits: list[DdlDmlHit] = []
    seen: set[tuple[int, str]] = set()

    def _record(lineno: int, text: str) -> None:
        key = (lineno, text)
        if key in seen:
            return
        if not looks_like_ddl_dml_sql(text):
            return
        seen.add(key)
        hits.append(DdlDmlHit(lineno=lineno, text=text[:160]))

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant):
            text = _as_text(node.value)
            if text is not None:
                _record(getattr(node, "lineno", 0) or 0, text)
            continue
        if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.Call)):
            folded = _fold_constant_str(node)
            if folded is not None:
                _record(getattr(node, "lineno", 0) or 0, folded)

    return hits
