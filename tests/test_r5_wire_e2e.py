"""R5/R6 current wire E2E — independent of the frozen R3 carrier."""

from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WIRE_SCRIPT = REPO / "scripts" / "run_r5_wire_e2e.py"
R3_WIRE_SCRIPT = REPO / "scripts" / "run_r3c_wire_e2e.py"
MATRIX_HARNESS = REPO / "scripts" / "run_r6_installed_zip_e2e.py"
MATRIX_MODULE = REPO / "tests" / "r6_installed_zip_wire_matrix.py"
OPTIN_RUNNER = REPO / "scripts" / "run_r6_installed_zip_tests.py"


def _load_carrier():
    assert WIRE_SCRIPT.is_file(), "missing scripts/run_r5_wire_e2e.py"
    spec = importlib.util.spec_from_file_location("run_r5_wire_e2e", WIRE_SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_matrix_harness():
    assert MATRIX_HARNESS.is_file(), "missing scripts/run_r6_installed_zip_e2e.py"
    spec = importlib.util.spec_from_file_location(
        "run_r6_installed_zip_e2e_gap1", MATRIX_HARNESS
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_r5_wire_carrier_exists_and_is_not_r3_copy():
    assert WIRE_SCRIPT.is_file()
    assert R3_WIRE_SCRIPT.is_file()
    r5 = WIRE_SCRIPT.read_bytes()
    r3 = R3_WIRE_SCRIPT.read_bytes()
    assert r5 != r3
    assert b"run_r3c_wire_e2e" not in r5
    tree = ast.parse(r5.decode("utf-8"))
    assert isinstance(tree, ast.Module)


def test_r5_wire_smoke_zero_secrets(tmp_path: Path):
    mod = _load_carrier()
    work = tmp_path / "wire"
    result = mod.run_smoke(work)
    assert result["ok"] is True
    assert result["wire_secret_count"] == 0
    assert result["token_in_provider_raw"] == 0
    assert result["formal_tools"] == [
        "http_credential_request",
        "credential_process_run",
    ]
    saved = json.loads((work / "r5_wire_smoke.json").read_text(encoding="utf-8"))
    assert saved["wire_secret_count"] == 0


def test_r5_wire_live_plugin_registers_exactly_two_tools():
    """After atomic delete, PluginManager register() must expose only two tools."""
    from credential_guard import register

    class Ctx:
        def __init__(self) -> None:
            self.tools = []
            self.middlewares = []
            self.hooks = []
            self.cli = []

        def register_tool(self, **kwargs):
            self.tools.append(kwargs)

        def register_middleware(self, *a, **k):
            self.middlewares.append((a, k))

        def register_hook(self, *a, **k):
            self.hooks.append((a, k))

        def register_cli_command(self, **kwargs):
            self.cli.append(kwargs)

    ctx = Ctx()
    register(ctx)
    names = sorted(t["name"] for t in ctx.tools)
    assert names == ["credential_process_run", "http_credential_request"]


def test_r5_wire_full_main_chain_matrix_closed():
    """KNOWN_GAP_1 closed: 0.4.0 installed-ZIP wire matrix covers 3×5 + manifest↔registry.

    Heavy E2E execution stays opt-in (``scripts/run_r6_installed_zip_tests.py``).
    This default-corpus assertion pins that the matrix entry, 15 cells, and
    consistency API are present and wired — the opt-in run proves all 15 green.
    """
    assert MATRIX_HARNESS.is_file()
    assert MATRIX_MODULE.is_file()
    assert OPTIN_RUNNER.is_file()
    harness = _load_matrix_harness()
    assert len(harness.MATRIX_SCENARIOS) == 15
    expected = {
        f"{a}_{o}"
        for a in ("http", "env", "stdin")
        for o in ("approve", "deny", "timeout", "mutate", "replay")
    }
    assert set(harness.MATRIX_SCENARIOS) == expected
    assert hasattr(harness, "check_manifest_registry_consistency")
    assert hasattr(harness, "run_wire_matrix")
    assert hasattr(harness, "evaluate_wire_matrix")
    assert frozenset(harness.EXPECTED_TOOL_SET) == frozenset(
        {"credential_process_run", "http_credential_request"}
    )
    runner_src = OPTIN_RUNNER.read_text(encoding="utf-8")
    assert "tests/r6_installed_zip_wire_matrix.py" in runner_src
    matrix_src = MATRIX_MODULE.read_text(encoding="utf-8")
    assert "check_manifest_registry_consistency" in matrix_src or (
        "manifest_registry" in matrix_src
    )
    assert "test_mutation_m_a1" in matrix_src
    assert "test_mutation_m_a2" in matrix_src
    assert "test_mutation_m_b1" in matrix_src
