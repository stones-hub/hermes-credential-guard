"""R3A evidence authenticity gate — reject known false-green patterns."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

_TARGETS = (
    REPO / "tests" / "test_r3a_main_agent_path.py",
    REPO / "tests" / "test_r3a_e2e.py",
    REPO / "tests" / "test_r2_main_agent_path.py",
    REPO / "scripts" / "run_r2_e2e.py",
)

_FORBIDDEN = (
    re.compile(r"""mgr\._middleware\[\s*['"]tool_request['"]\s*\]\s*="""),
    re.compile(r"""mgr\._middleware\[\s*['"]tool_execution['"]\s*\]\s*="""),
    re.compile(r"""mgr\._hooks\[\s*['"]pre_tool_call['"]\s*\]\s*="""),
    re.compile(r"""mgr\._hooks\[\s*['"]transform_tool_result['"]\s*\]\s*=\s*\[\s*\]"""),
    re.compile(r"""['"]adapter_ok['"]\s*:\s*True\b"""),
    re.compile(r"""['"]injection_resolve_delta['"]\s*:\s*1\b"""),
    re.compile(r"""evidence\[\s*['"]adapter_ok['"]\s*\]\s*=\s*True\b"""),
    # Constant order / counted-handler false greens
    re.compile(r"""order\s*=\s*\[\s*['"]tool_request['"].*['"]adapter['"]\s*\]"""),
    re.compile(r"""counts\[\s*['"]consume['"]\s*\]\s*=\s*1\b"""),
    re.compile(r"""counts\[\s*['"]resolve['"]\s*\]\s*=\s*1\b"""),
    re.compile(r"""counts\[\s*['"]adapter['"]\s*\]\s*=\s*1\b"""),
)


@pytest.mark.parametrize("path", _TARGETS, ids=lambda p: p.name)
def test_r3a_gate_rejects_false_green_patterns(path: Path):
    assert path.is_file(), path
    text = path.read_text(encoding="utf-8")
    hits = []
    for cre in _FORBIDDEN:
        for m in cre.finditer(text):
            # Allow assertions in test files (assert data["adapter_ok"] is True)
            line_start = text.rfind("\n", 0, m.start()) + 1
            line = text[line_start : text.find("\n", m.start())]
            if line.lstrip().startswith("assert "):
                continue
            hits.append((cre.pattern, m.group(0), line.strip()[:120]))
    assert hits == [], f"{path.name} false-green hits: {hits}"


def test_r3a_gate_requires_live_injection_observer_symbols():
    main = (REPO / "tests" / "test_r2_main_agent_path.py").read_text(encoding="utf-8")
    assert "get_injection_secret_resolve_count" in main
    assert "get_http_adapter_invoke_count" in main
    assert "set_http_transport_override_for_tests" in main
    assert "InjectionPlanStore.consume" in main
    assert "resolve_one_for_execution" in main
    assert "execute_http" in main
    assert '"consume"' in main and '"resolve"' in main and '"adapter"' in main
    assert "sys.setprofile" in main
    assert "CG_DROP_SEAM" in main
    runner = (REPO / "scripts" / "run_r2_e2e.py").read_text(encoding="utf-8")
    assert "get_injection_secret_resolve_count" in runner
    assert "adapter_ok" in runner


def test_r3a_gate_rejects_wrapper_or_constant_full_order():
    """Authenticity: full order must come from setprofile code_labels, not literals."""
    main = (REPO / "tests" / "test_r2_main_agent_path.py").read_text(encoding="utf-8")
    # Must bind production code objects — not a counted wrapper list.
    assert "code_labels[id(cb.__code__)]" in main or "code_labels[id(" in main
    assert "InjectionPlanStore.consume" in main
    assert "def wrap_" not in main
    # Must not hardcode the full approve order into the probe output.
    assert 'order = ["tool_request", "tool_execution", "pre_tool_call"' not in main
    assert '["consume", "resolve", "adapter"]' not in main.replace(" ", "")
