"""Mechanical gate: R2 Framework/compat evidence must not use callback wrappers.

Rejects false-green patterns called out in round-7 evidence review:
- post-register override of PluginManager callback lists
- deregister + counted-handler re-register
- hardcoded formal/handler/dispatch True evidence
- clearing transform_tool_result to dodge the registered path
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
MAIN_AGENT = REPO / "tests" / "test_r2_main_agent_path.py"
R2_E2E_RUNNER = REPO / "scripts" / "run_r2_e2e.py"

_TARGET_FILES = (MAIN_AGENT, R2_E2E_RUNNER)

_CALLBACK_ASSIGN_RES = (
    re.compile(r"""mgr\._middleware\[\s*['"]tool_request['"]\s*\]\s*="""),
    re.compile(r"""mgr\._middleware\[\s*['"]tool_execution['"]\s*\]\s*="""),
    re.compile(r"""mgr\._hooks\[\s*['"]pre_tool_call['"]\s*\]\s*="""),
)

_TRANSFORM_CLEAR_RE = re.compile(
    r"""mgr\._hooks\[\s*['"]transform_tool_result['"]\s*\]\s*=\s*\[\s*\]"""
)

_HARDCODED_EVIDENCE_RES = (
    re.compile(r"""['"]formal_tool_registered['"]\s*:\s*True\b"""),
    re.compile(r"""['"]handler_identity_ok['"]\s*:\s*True\b"""),
    re.compile(r"""['"]registry_dispatch['"]\s*:\s*True\b"""),
    re.compile(r"""evidence\[\s*['"]formal_tool_registered['"]\s*\]\s*=\s*True\b"""),
    re.compile(r"""evidence\[\s*['"]handler_identity_ok['"]\s*\]\s*=\s*True\b"""),
    # Constant True assignment without tying to observed handler count is forbidden.
    # Allowed form: evidence["registry_dispatch"] = evidence["handler_call_count"] > 0
    re.compile(
        r"""evidence\[\s*['"]registry_dispatch['"]\s*\]\s*=\s*True\b"""
    ),
)


def _read(path: Path) -> str:
    assert path.is_file(), f"missing {path}"
    return path.read_text(encoding="utf-8")


def _probe_source_from_main_agent(text: str) -> str:
    """Extract the embedded PROBE string if present; else whole file."""
    tree = ast.parse(text)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "PROBE":
                    if isinstance(node.value, ast.Call):
                        # textwrap.dedent(r"""...""")
                        if node.value.args and isinstance(
                            node.value.args[0], ast.Constant
                        ):
                            return str(node.value.args[0].value)
                    if isinstance(node.value, ast.Constant):
                        return str(node.value.value)
    return text


@pytest.mark.parametrize("path", _TARGET_FILES, ids=lambda p: p.name)
def test_gate_rejects_post_register_callback_list_override(path: Path):
    text = _read(path)
    scan = _probe_source_from_main_agent(text) if path == MAIN_AGENT else text
    hits = []
    for cre in _CALLBACK_ASSIGN_RES:
        for m in cre.finditer(scan):
            hits.append(m.group(0))
    assert hits == [], (
        f"{path.name}: post-register callback list override forbidden: {hits}"
    )


@pytest.mark.parametrize("path", _TARGET_FILES, ids=lambda p: p.name)
def test_gate_rejects_transform_tool_result_clear(path: Path):
    text = _read(path)
    scan = _probe_source_from_main_agent(text) if path == MAIN_AGENT else text
    assert _TRANSFORM_CLEAR_RE.search(scan) is None, (
        f"{path.name}: clearing transform_tool_result callback list is forbidden"
    )


@pytest.mark.parametrize("path", _TARGET_FILES, ids=lambda p: p.name)
def test_gate_rejects_counted_handler_reregister(path: Path):
    text = _read(path)
    scan = _probe_source_from_main_agent(text) if path == MAIN_AGENT else text
    assert "counted_handler" not in scan, (
        f"{path.name}: counted_handler re-register of formal handler is forbidden"
    )
    # deregister + register of the HTTP reference tool after initial register()
    if "registry.deregister" in scan and "HTTP_REFERENCE_TOOL" in scan:
        # Allow Ctx.register_tool's try/except deregister during plugin register.
        # Forbidden: post-register observation wrapper rebind.
        assert "def counted_handler" not in scan
        assert "wrap_pre" not in scan
        assert "wrap_req" not in scan
        assert "wrap_exec" not in scan
        assert "wrap_tool_request" not in scan


@pytest.mark.parametrize("path", _TARGET_FILES, ids=lambda p: p.name)
def test_gate_rejects_hardcoded_formal_handler_dispatch_true(path: Path):
    text = _read(path)
    scan = _probe_source_from_main_agent(text) if path == MAIN_AGENT else text
    hits = []
    for cre in _HARDCODED_EVIDENCE_RES:
        for m in cre.finditer(scan):
            hits.append(m.group(0))
    assert hits == [], (
        f"{path.name}: hardcoded evidence True forbidden: {hits}"
    )


def test_gate_rejects_local_wrap_callback_helpers_in_evidence_paths():
    """Local wrap_* helpers used to overlay mgr callback lists are forbidden."""
    for path in _TARGET_FILES:
        text = _read(path)
        scan = _probe_source_from_main_agent(text) if path == MAIN_AGENT else text
        for name in ("wrap_req", "wrap_pre", "wrap_exec", "wrap_tool_request"):
            assert f"def {name}" not in scan, (
                f"{path.name}: def {name} overlay helper is forbidden"
            )


def test_mutation_restoring_wrapper_override_turns_gate_red(tmp_path):
    """If evidence paths regain wrap overlay of callback lists, gate must RED."""
    victim = tmp_path / "run_r2_e2e.py"
    victim.write_text(
        'mgr._middleware["tool_request"] = [wrap_req]\n'
        'mgr._middleware["tool_execution"] = [wrap_exec]\n'
        'mgr._hooks["pre_tool_call"] = [wrap_pre]\n'
        "def wrap_req(**kw): return None\n",
        encoding="utf-8",
    )
    text = victim.read_text(encoding="utf-8")
    hits = []
    for cre in _CALLBACK_ASSIGN_RES:
        hits.extend(m.group(0) for m in cre.finditer(text))
    assert hits, "mutation fixture must contain forbidden overrides"
    assert "def wrap_req" in text


def test_mutation_hardcoded_formal_true_turns_gate_red():
    bad = '"formal_tool_registered": True, "handler_identity_ok": True, "registry_dispatch": True'
    hits = []
    for cre in _HARDCODED_EVIDENCE_RES:
        hits.extend(m.group(0) for m in cre.finditer(bad))
    assert len(hits) >= 3
