"""R7 product coverage-boundary contract (docs + CLI; no Hermes patches).

Credential Guard protects the main-chat conversation loop and main-chain tool
results. Hermes auxiliary_client paths are a host plugin-interface boundary,
not a plugin bug to "fix" via monkey patch. Tests here mechanically reject
over-claims such as "protects all Hermes model calls".
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from credential_guard.cli import (
    CHECK_HELP,
    COVERAGE_BOUNDARY_AUXILIARY,
    COVERAGE_BOUNDARY_MAIN,
    COVERAGE_BOUNDARY_NOTE,
)

ROOT = Path(__file__).resolve().parents[1]

_OVERCLAIM_PATTERNS = (
    r"保护所有\s*Hermes\s*模型调用",
    r"全局外发均受保护",
    r"protects?\s+all\s+Hermes\s+model\s+calls",
    r"global\s+outbound\s+(?:is|are)\s+protected",
    r"all\s+auxiliary\s+(?:paths?\s+)?(?:are\s+)?protected",
)

_REQUIRED_DOCS = (
    "docs/R7-Hermes当前版本真实外发兼容性修复方案.md",
    "docs/R7-0.4.1-验收报告.md",
    "CLAUDE.md",
    "HANDOVER.md",
)

_PRODUCT_BOUNDARY_CN = (
    "Credential Guard 0.4.1 保护 Hermes 主聊天 conversation loop 的模型请求以及主链工具结果；"
    "不保证自动标题、上下文压缩、vision、oneshot、session_search 及其他 auxiliary 模型调用。"
)


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_cli_constants_state_main_covered_and_auxiliary_out_of_scope():
    assert "main-chat conversation loop" in COVERAGE_BOUNDARY_MAIN
    assert "main-chain tool results" in COVERAGE_BOUNDARY_MAIN
    assert "does not cover auxiliary_client.call_llm" in COVERAGE_BOUNDARY_AUXILIARY
    assert "title_generation" in COVERAGE_BOUNDARY_AUXILIARY
    assert "not equivalent to full outbound coverage" in COVERAGE_BOUNDARY_NOTE
    assert "main-chat" in CHECK_HELP
    assert "auxiliary_client" in CHECK_HELP
    for pat in _OVERCLAIM_PATTERNS:
        for text in (
            COVERAGE_BOUNDARY_MAIN,
            COVERAGE_BOUNDARY_AUXILIARY,
            COVERAGE_BOUNDARY_NOTE,
            CHECK_HELP,
        ):
            assert re.search(pat, text, re.I) is None, text


def test_check_help_wired_into_setup_parser():
    src = (ROOT / "credential_guard" / "cli.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr != "add_parser":
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant):
                continue
            if node.args[0].value != "check":
                continue
            for kw in node.keywords:
                if kw.arg == "help" and isinstance(kw.value, ast.Name):
                    assert kw.value.id == "CHECK_HELP"
                    found = True
    assert found, "check subparser must use CHECK_HELP constant"


def test_release_docs_state_main_chain_and_auxiliary_boundary():
    report = _read("docs/R7-0.4.1-验收报告.md")
    assert "产品覆盖边界" in report
    assert _PRODUCT_BOUNDARY_CN in report
    assert "不保证" in report
    assert "auxiliary" in report.lower() or "auxiliary" in report

    scheme = _read("docs/R7-Hermes当前版本真实外发兼容性修复方案.md")
    assert "宿主能力边界" in scheme or "插件接口不覆盖" in scheme
    assert "不宣称" in scheme or "不保证" in scheme
    assert "title_generation" in scheme

    for rel in ("CLAUDE.md", "HANDOVER.md"):
        text = _read(rel)
        assert "宿主" in text and ("不覆盖" in text or "不保证" in text)
        assert "主聊天" in text or "conversation loop" in text


def test_r8_remains_vetoed_investigation_record():
    text = _read("docs/R8-Hermes统一模型外发拦截接口-落地方案.md")
    assert "已否决" in text
    assert "禁止执行" in text
    assert "不是实施方案" in text or "调查记录" in text


def _overclaim_hits(text: str) -> list[str]:
    """Flag affirmative over-claims; allow task-book quotes that forbid them."""
    hits: list[str] = []
    for pat in _OVERCLAIM_PATTERNS:
        for m in re.finditer(pat, text, re.I):
            start = max(0, m.start() - 24)
            window = text[start : m.end()]
            if re.search(r"(不宣称|不得出现|禁止声称|不得声称|不得|禁止)", window):
                continue
            hits.append(m.group(0))
    return hits


def test_docs_must_not_overclaim_global_protection():
    blobs = [_read(rel) for rel in _REQUIRED_DOCS]
    blobs.append(COVERAGE_BOUNDARY_MAIN)
    blobs.append(COVERAGE_BOUNDARY_AUXILIARY)
    for text in blobs:
        hits = _overclaim_hits(text)
        assert hits == [], hits


def test_mutation_drop_main_boundary_constant_is_red(monkeypatch):
    """Deleting the main-chain coverage constant must fail the contract test."""
    import credential_guard.cli as cli

    monkeypatch.setattr(cli, "COVERAGE_BOUNDARY_MAIN", "coverage: unspecified")
    with pytest.raises(AssertionError):
        assert "main-chat conversation loop" in cli.COVERAGE_BOUNDARY_MAIN
        assert "main-chain tool results" in cli.COVERAGE_BOUNDARY_MAIN


def test_mutation_overclaim_auxiliary_full_coverage_is_red(tmp_path):
    """Replacing the report boundary with a global-protection claim must RED."""
    report = ROOT / "docs" / "R7-0.4.1-验收报告.md"
    original = report.read_text(encoding="utf-8")
    poisoned = original.replace(
        _PRODUCT_BOUNDARY_CN,
        "Credential Guard 0.4.1 保护所有 Hermes 模型调用；全局外发均受保护。",
    )
    assert poisoned != original
    hits = _overclaim_hits(poisoned)
    assert hits, "poisoned overclaim must match the forbid scanner"


def test_mutation_delete_product_boundary_section_is_red():
    report = _read("docs/R7-0.4.1-验收报告.md")
    stripped = report.replace("产品覆盖边界", "").replace(_PRODUCT_BOUNDARY_CN, "")
    assert "产品覆盖边界" not in stripped
    assert _PRODUCT_BOUNDARY_CN not in stripped
    with pytest.raises(AssertionError):
        assert "产品覆盖边界" in stripped
        assert _PRODUCT_BOUNDARY_CN in stripped
