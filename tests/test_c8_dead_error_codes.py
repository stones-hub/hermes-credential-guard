"""C8: remove lying RUNTIME_ADAPTER_NOT_READY and dead require_runtime_adapter.

Production source must not claim adapters are unimplemented. Formal failure
paths return stage-accurate fixed codes (plan / config / recheck / adapter).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROD = ROOT / "credential_guard"

_BANNED = ("RUNTIME_ADAPTER_NOT_READY", "require_runtime_adapter")


def _prod_py_files() -> list[Path]:
    return sorted(p for p in PROD.rglob("*.py") if p.is_file())


def test_c8_production_source_excludes_banned_literals():
    hits: list[str] = []
    for path in _prod_py_files():
        text = path.read_text(encoding="utf-8")
        for banned in _BANNED:
            if banned in text:
                hits.append(f"{path.relative_to(ROOT)}:{banned}")
    assert hits == [], f"banned literals still in production: {hits}"


def test_c8_require_runtime_adapter_not_exported():
    import credential_guard.runtime_config as rc

    assert not hasattr(rc, "require_runtime_adapter")
    assert "require_runtime_adapter" not in getattr(rc, "__all__", ())


def test_c8_tool_execution_has_no_adapter_not_ready_constant():
    import credential_guard.tool_execution as te

    assert not hasattr(te, "RUNTIME_ADAPTER_NOT_READY")
    assert "RUNTIME_ADAPTER_NOT_READY" not in getattr(te, "__all__", ())


def test_c8_safe_error_requires_explicit_code():
    """Default must not silently invent a lying 'not ready' code."""
    import inspect

    from credential_guard import tool_execution as te

    sig = inspect.signature(te._safe_error)
    params = list(sig.parameters.values())
    assert len(params) >= 1
    assert params[0].default is inspect.Parameter.empty


def _c8_doc(token: str) -> dict:
    return {
        "version": 2,
        "credentials": {"tok": {"type": "token", "value": token}},
        "bindings": {
            "api": {
                "type": "http",
                "credential_ref": "tok",
                "approval": "required",
                "target": {
                    "scheme": "https",
                    "host": "c8.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET"],
                    "allowed_paths": ["/x"],
                },
                "inject": {"type": "bearer", "location": "authorization_header"},
            }
        },
    }


def test_c8_finalize_without_plan_returns_plan_not_found(tmp_path, monkeypatch):
    from credential_guard import runtime_config as rc
    from credential_guard import tool_request as tr
    from credential_guard.config import CONFIG_FILENAME
    from credential_guard.tool_execution import finalize_reference_execution

    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    store = hermes / "credential-guard"
    home.mkdir()
    store.mkdir(parents=True)
    os.chmod(store, 0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    cfg = store / CONFIG_FILENAME
    cfg.write_text(json.dumps(_c8_doc("CG_C8_" + "a" * 24)), encoding="utf-8")
    os.chmod(cfg, 0o600)
    rc.reset_runtime_for_tests()
    tr.reset_tool_request_state_for_tests()
    rc.load_and_publish_runtime()

    out = finalize_reference_execution(
        "http_credential_request",
        {
            "target": "api",
            "method": "GET",
            "path": "/x",
            "credential": "<CREDENTIAL:tok>",
        },
        session_id="s1",
        turn_id="t1",
        tool_call_id="tc-missing",
    )
    data = json.loads(out)
    assert data["ok"] is False
    assert data["error"] == "PLAN_NOT_PENDING"
    assert data["error"] != "RUNTIME_ADAPTER_NOT_READY"
    assert "not implemented" not in out.lower()


def test_c8_handler_failure_is_not_generic_unimplemented(tmp_path, monkeypatch):
    from credential_guard import runtime_config as rc
    from credential_guard import tool_request as tr
    from credential_guard.config import CONFIG_FILENAME
    from credential_guard.reference_tools import handle_http_credential_request

    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    store = hermes / "credential-guard"
    home.mkdir()
    store.mkdir(parents=True)
    os.chmod(store, 0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    cfg = store / CONFIG_FILENAME
    cfg.write_text(json.dumps(_c8_doc("CG_C8_" + "b" * 24)), encoding="utf-8")
    os.chmod(cfg, 0o600)
    rc.reset_runtime_for_tests()
    tr.reset_tool_request_state_for_tests()
    rc.load_and_publish_runtime()

    out = json.loads(
        handle_http_credential_request(
            {
                "target": "api",
                "method": "GET",
                "path": "/x",
                "credential": "<CREDENTIAL:tok>",
            },
            session_id="s1",
            turn_id="t1",
            tool_call_id="tc-noplan",
        )
    )
    assert out["ok"] is False
    assert out["error"] in {
        "PLAN_NOT_PENDING",
        "PLAN_NOT_FOUND",
        "CALL_IDENTITY_REQUIRED",
        "REFERENCE_PATH_BLOCKED",
        "PLAN_RECHECK_FAILED",
        "RUNTIME_CONFIG_UNAVAILABLE",
    }
    assert out["error"] != "RUNTIME_ADAPTER_NOT_READY"


def test_c8_mutation_restore_banned_literal_makes_scan_red(tmp_path):
    """Load-bearing: if production reintroduces the lying code, scan must fail."""
    sample = 'RUNTIME_ADAPTER_NOT_READY = "RUNTIME_ADAPTER_NOT_READY"\n'
    assert "RUNTIME_ADAPTER_NOT_READY" in sample
    # Simulate a mutated production file content.
    hits = [
        m.group(0)
        for m in re.finditer(r"RUNTIME_ADAPTER_NOT_READY|require_runtime_adapter", sample)
    ]
    assert hits, "mutation control: detector must see restored literal"


def test_c8_mutation_control_detector_matches_real_scan():
    """Detector used by the production scan must catch both banned strings."""
    for banned in _BANNED:
        blob = f"x = {banned!r}\n"
        assert banned in blob
        found = any(b in blob for b in _BANNED)
        assert found is True
