"""R3B evidence authenticity gate — reject known false-green patterns.

Round5 Blocker C: unified evidence completeness predicate must receive
mutated text and return non-empty violations (never re-assert originals).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Sequence, Tuple

import pytest

REPO = Path(__file__).resolve().parents[1]

_TARGETS = (
    REPO / "tests" / "test_r3b_main_agent_path.py",
    REPO / "tests" / "test_r3b_e2e.py",
    REPO / "tests" / "test_r3b_plugin_manager_graph.py",
    REPO / "tests" / "test_r3b_wire_e2e.py",
    REPO / "scripts" / "run_r3b_e2e.py",
    REPO / "scripts" / "run_r3b_wire_e2e.py",
)

_FORBIDDEN = (
    re.compile(r"""mgr\._middleware\[\s*['"]tool_request['"]\s*\]\s*="""),
    re.compile(r"""mgr\._middleware\[\s*['"]tool_execution['"]\s*\]\s*="""),
    re.compile(r"""mgr\._hooks\[\s*['"]pre_tool_call['"]\s*\]\s*="""),
    re.compile(r"""['"]adapter_ok['"]\s*:\s*True\b"""),
    re.compile(r"""['"]process_start_delta['"]\s*:\s*1\b"""),
    re.compile(r"""order\s*=\s*\[\s*['"]tool_request['"].*['"]adapter['"]\s*\]"""),
    re.compile(r"""counts\[\s*['"]consume['"]\s*\]\s*=\s*1\b"""),
    re.compile(r"""counts\[\s*['"]resolve['"]\s*\]\s*=\s*1\b"""),
    re.compile(r"""counts\[\s*['"]adapter['"]\s*\]\s*=\s*1\b"""),
    # Hardcoded wire secret zero without computing from captures.
    re.compile(r"""wire_secret_count\s*=\s*0\b"""),
    # Hardcoded loopback / environ-copy evidence constants (must be derived).
    re.compile(r"""['"]loopback_only['"]\s*:\s*True\b"""),
    re.compile(r"""['"]used_environ_copy['"]\s*:\s*False\b"""),
)

# Embedded PROBE / wire harness must not self-register via hand-rolled Ctx.
_PROBE_FORBIDDEN = (
    re.compile(r"""class\s+Ctx\s*:"""),
    re.compile(r"""registry\.deregister\s*\("""),
    re.compile(r"""register\s*\(\s*Ctx\s*\("""),
    re.compile(r"""os\.environ\.copy\s*\("""),
    re.compile(r"""dict\s*\(\s*os\.environ\s*\)"""),
    re.compile(r"""os\.environ\s*\|\s*"""),
    re.compile(r"""mgr\._middleware\[\s*['"]tool_request['"]\s*\]\s*="""),
    re.compile(r"""mgr\._hooks\[\s*['"]pre_tool_call['"]\s*\]\s*\.clear\s*\("""),
    re.compile(r"""['"]loopback_only['"]\s*:\s*True\b"""),
    re.compile(r"""['"]used_environ_copy['"]\s*:\s*False\b"""),
)

# Required evidence contracts by carrier kind.
_REQUIRED_BY_KIND = {
    "wire_script": (
        "raw_requests",
        "approval_raw",
        "wire_secret_count",
        "127.0.0.1",
        "raw_http_has_request_line",
        "raw_http_has_headers",
        "raw_http_has_body",
        "non_loopback_original_calls",
        "_bomb_connect",
        "_guard_connect",
        "_minimal_child_env",
    ),
    "wire_tests": (
        "provider_raw_request_count",
        "approval_raw",
        "wire_secret_count",
        "token_in_provider_raw",
        "token_in_approval_raw",
        "raw_http_has_request_line",
        "non_loopback_original_calls",
        "guard_enabled",
    ),
    "main_agent": (
        "get_injection_secret_resolve_count",
        "process_start_count",
        "execute_process",
        "InjectionPlanStore.consume",
        "resolve_one_for_execution",
        "sys.setprofile",
        "CG_DROP_SEAM",
        "discover_plugins",
        "identity_unchanged",
    ),
    "probe_graph": (
        "discover_plugins",
        "sys.setprofile",
        "identity_unchanged",
    ),
    "any": (),
}


def _scan_false_green(text: str) -> List[Tuple[str, str]]:
    """Production test predicate: return (pattern, match) hits for false-green text."""
    hits: List[Tuple[str, str]] = []
    for cre in _FORBIDDEN:
        for m in cre.finditer(text):
            line_start = text.rfind("\n", 0, m.start()) + 1
            line_end = text.find("\n", m.start())
            if line_end < 0:
                line_end = len(text)
            line = text[line_start:line_end]
            if line.lstrip().startswith("assert "):
                continue
            hits.append((cre.pattern, m.group(0)))
    return hits


def _scan_probe_forbidden(text: str) -> List[Tuple[str, str]]:
    """Production test predicate: probe/harness authenticity forbidden patterns."""
    hits: List[Tuple[str, str]] = []
    for cre in _PROBE_FORBIDDEN:
        for m in cre.finditer(text):
            hits.append((cre.pattern, m.group(0)))
    return hits


def _missing_evidence_contracts(text: str, kind: str) -> List[str]:
    """Return required evidence symbols/structures missing from text for kind."""
    required = _REQUIRED_BY_KIND.get(kind, ())
    missing: List[str] = []
    for sym in required:
        if sym not in text:
            missing.append(f"missing:{sym}")
    if kind == "wire_script":
        if re.search(r"""['"]loopback_only['"]\s*:\s*True\b""", text):
            missing.append("hardcoded:loopback_only_True")
        if re.search(r"""['"]used_environ_copy['"]\s*:\s*False\b""", text):
            missing.append("hardcoded:used_environ_copy_False")
        if "os.environ.copy" in text:
            missing.append("forbidden:os.environ.copy")
        # Full request capture — body-only append is incomplete evidence.
        if "raw_requests.append(body)" in text and "raw_http_has_request_line" not in text:
            missing.append("incomplete:raw_http_body_only")
        # loopback_only must be derived, not a constant assignment True.
        if re.search(r"""loopback_only\s*=\s*True\b""", text):
            missing.append("hardcoded:loopback_only_assign_True")
        # Minimal env must not be a full environ clone.
        if re.search(r"""os\.environ\.copy\s*\(""", text) or re.search(
            r"""dict\s*\(\s*os\.environ\s*\)""", text
        ):
            missing.append("forbidden:full_environ_clone")
    if kind == "wire_tests":
        if "raw_http_has_request_line" not in text and "raw_request_line" not in text:
            missing.append("missing:raw_http_request_line_assert")
    return missing


def validate_evidence_source(text: str, kind: str) -> List[str]:
    """Unified evidence completeness / authenticity predicate.

    Returns a list of violation strings. Healthy carriers must yield [].
    Mutations must feed *mutated* text here and observe non-empty violations —
    never re-assert the original carrier text as mutation evidence.
    """
    violations: List[str] = []
    for pat, match in _scan_false_green(text):
        violations.append(f"false_green:{pat}:{match}")
    if kind in {"wire_script", "probe_graph", "main_agent", "any"} or kind.startswith(
        "probe"
    ):
        for pat, match in _scan_probe_forbidden(text):
            violations.append(f"probe_forbidden:{pat}:{match}")
    for miss in _missing_evidence_contracts(text, kind):
        violations.append(miss)
    return violations


def _false_green_samples() -> List[str]:
    return [
        'mgr._middleware["tool_request"] = []\n',
        'mgr._hooks["pre_tool_call"] = []\n',
        '{"adapter_ok": True, "x": 1}\n',
        '{"process_start_delta": 1}\n',
        'order = ["tool_request", "tool_execution", "pre_tool_call", "approval_gate", "handler", "consume", "resolve", "adapter"]\n',
        'counts["consume"] = 1\n',
        "wire_secret_count = 0\n",
        '{"loopback_only": True}\n',
        '{"used_environ_copy": False}\n',
    ]


@pytest.mark.parametrize("path", _TARGETS, ids=lambda p: p.name)
def test_r3b_gate_rejects_false_green_patterns(path: Path):
    assert path.is_file(), path
    text = path.read_text(encoding="utf-8")
    hits = _scan_false_green(text)
    assert hits == [], f"{path.name} false-green hits: {hits}"


@pytest.mark.parametrize("path", _TARGETS, ids=lambda p: p.name)
def test_r3b_gate_probe_forbids_self_register_and_environ_copy(path: Path):
    text = path.read_text(encoding="utf-8")
    hits = _scan_probe_forbidden(text)
    assert hits == [], f"{path.name} probe authenticity hits: {hits}"


def test_r3b_gate_requires_live_process_observer_symbols():
    main = (REPO / "tests" / "test_r3b_main_agent_path.py").read_text(encoding="utf-8")
    assert validate_evidence_source(main, "main_agent") == []
    assert "class Ctx" not in main
    assert "registry.deregister" not in main
    assert "os.environ.copy" not in main
    runner = (REPO / "scripts" / "run_r3b_e2e.py").read_text(encoding="utf-8")
    assert "process_start" in runner or "adapter_ok" in runner


def test_r3b_gate_rejects_wrapper_or_constant_full_order():
    main = (REPO / "tests" / "test_r3b_main_agent_path.py").read_text(encoding="utf-8")
    assert "code_labels[id(cb.__code__)]" in main or "code_labels[id(" in main
    assert "def wrap_" not in main
    assert 'order = ["tool_request", "tool_execution", "pre_tool_call"' not in main


def test_r3b_gate_requires_real_plugin_manager_graph_probe():
    graph = (REPO / "tests" / "test_r3b_plugin_manager_graph.py").read_text(encoding="utf-8")
    assert validate_evidence_source(graph, "probe_graph") == []
    assert "class Ctx" not in graph
    assert "registry.deregister" not in graph
    assert "os.environ.copy" not in graph


def test_r3b_gate_requires_wire_provider_and_approval_raw_asserts():
    wire = (REPO / "scripts" / "run_r3b_wire_e2e.py").read_text(encoding="utf-8")
    assert validate_evidence_source(wire, "wire_script") == []
    tests = (REPO / "tests" / "test_r3b_wire_e2e.py").read_text(encoding="utf-8")
    assert validate_evidence_source(tests, "wire_tests") == []


def test_r3b_gate_mutation_deleting_wire_asserts_hits_unified_predicate():
    """Text mutation must feed mutated text into validate_evidence_source (RED)."""
    wire = (REPO / "scripts" / "run_r3b_wire_e2e.py").read_text(encoding="utf-8")
    assert validate_evidence_source(wire, "wire_script") == []

    mutated_raw = wire.replace("raw_requests", "raw_reqs_dropped")
    v_raw = validate_evidence_source(mutated_raw, "wire_script")
    assert v_raw, "renaming raw_requests must yield violations on mutated text"
    assert any("raw_requests" in x for x in v_raw)

    mutated_appr = wire.replace("approval_raw", "approval_dropped")
    v_appr = validate_evidence_source(mutated_appr, "wire_script")
    assert v_appr, "renaming approval_raw must yield violations on mutated text"
    assert any("approval_raw" in x for x in v_appr)

    mutated_http = (
        wire.replace("raw_http_has_request_line", "raw_http_dropped_line")
        .replace("raw_http_has_headers", "raw_http_dropped_headers")
        .replace("raw_http_has_body", "raw_http_dropped_body")
    )
    v_http = validate_evidence_source(mutated_http, "wire_script")
    assert v_http, "removing request-line/header/body evidence must violate"
    assert any("raw_http" in x for x in v_http)

    mutated_loop = re.sub(
        r"loopback_only\s*=\s*\([^)]+\)",
        'loopback_only = True',
        wire,
        count=1,
        flags=re.DOTALL,
    )
    # Also plant the forbidden constant JSON form the gate scans for.
    mutated_loop = mutated_loop + '\nprint({"loopback_only": True})\n'
    v_loop = validate_evidence_source(mutated_loop, "wire_script")
    assert v_loop, "hardcoding loopback_only must violate on mutated text"

    mutated_env = wire.replace(
        "def _minimal_child_env",
        "def _minimal_child_env_unused",
    ).replace(
        "env = {\n        \"PATH\"",
        "env = os.environ.copy()\n    _drop = {\n        \"PATH\"",
        1,
    )
    # Ensure the forbidden clone appears as live code for the probe scan.
    if "os.environ.copy" not in mutated_env:
        mutated_env = mutated_env + "\nenv = os.environ.copy()\n"
    v_env = validate_evidence_source(mutated_env, "wire_script")
    assert v_env, "os.environ.copy mutation must violate on mutated text"
    assert any("environ" in x or "copy" in x for x in v_env)


def test_r3b_gate_mutation_false_green_text_hits_predicate():
    """Mutation must feed mutated text into _scan_false_green (not re-assert original)."""
    for sample in _false_green_samples():
        hits = _scan_false_green(sample)
        assert hits, f"predicate missed false-green sample: {sample!r}"
        # Unified predicate must also see them.
        assert validate_evidence_source(sample, "any"), sample


def test_r3b_gate_mutation_probe_forbidden_hits_predicate():
    samples = [
        "class Ctx:\n    pass\n",
        "registry.deregister(name)\n",
        "register(Ctx(mgr))\n",
        "env = os.environ.copy()\n",
        'print({"loopback_only": True})\n',
        'out = {"used_environ_copy": False}\n',
    ]
    for sample in samples:
        hits = _scan_probe_forbidden(sample)
        assert hits, f"predicate missed probe-forbidden sample: {sample!r}"
        assert validate_evidence_source(sample, "wire_script"), sample


def test_r3b_gate_main_agent_uses_discover_not_ctx():
    main = (REPO / "tests" / "test_r3b_main_agent_path.py").read_text(encoding="utf-8")
    assert _scan_probe_forbidden(main) == []
    assert validate_evidence_source(main, "main_agent") == []
    assert "discover_plugins" in main
    assert "CG_PLUGIN_SRC" in main
    assert "CG_DROP_SEAM" in main


def test_r3b_gate_all_carriers_pass_unified_predicate():
    """Every formal evidence carrier must pass the same validate_evidence_source."""
    carriers: Sequence[Tuple[Path, str]] = (
        (REPO / "scripts" / "run_r3b_wire_e2e.py", "wire_script"),
        (REPO / "tests" / "test_r3b_wire_e2e.py", "wire_tests"),
        (REPO / "tests" / "test_r3b_main_agent_path.py", "main_agent"),
        (REPO / "tests" / "test_r3b_plugin_manager_graph.py", "probe_graph"),
    )
    for path, kind in carriers:
        text = path.read_text(encoding="utf-8")
        violations = validate_evidence_source(text, kind)
        assert violations == [], f"{path.name}/{kind}: {violations}"
