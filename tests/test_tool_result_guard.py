from __future__ import annotations

import json
import os
import secrets
from urllib.parse import quote, quote_plus

import pytest

from credential_guard.hooks import on_transform_tool_result
from credential_guard.result_guard import RESULT_GUARD_FAIL_TEXT
from credential_guard.state import get_registry


def _runtime_canary_with_specials() -> str:
    return "cg_" + secrets.token_hex(8) + "_p@ss 特殊"


@pytest.fixture(autouse=True)
def _isolated_empty_store(tmp_path, monkeypatch):
    hermes = tmp_path / "hermes_home"
    store = hermes / "credential-guard"
    store.mkdir(parents=True)
    os.chmod(store, 0o700)
    cfg = store / "credential-guard.json"
    cfg.write_text(
        json.dumps({"version": 2, "credentials": {}, "bindings": {}}),
        encoding="utf-8",
    )
    os.chmod(cfg, 0o600)
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    get_registry().clear()


def test_transform_tool_result_redacts_json_and_keeps_json_parseable():
    reg = get_registry()
    reg.register("api", "token", "decoy_token_ABC12345")
    raw = json.dumps({"result": "token=decoy_token_ABC12345"})
    redacted = on_transform_tool_result(result=raw, tool_name="dummy", arguments={})
    parsed = json.loads(redacted)
    assert parsed["result"] == "token=<CREDENTIAL:api>"
    assert "decoy_token_ABC12345" not in redacted
    # Registry internal token contract remains <SECRET:cg_...> — not used on tool result.
    assert "<SECRET:" not in redacted


def test_transform_tool_result_redacts_plain_string():
    reg = get_registry()
    reg.register("db", "password", "decoy_password_QWER1234")
    out = on_transform_tool_result(
        result="error decoy_password_QWER1234",
        tool_name="dummy",
        arguments={},
    )
    assert out == "error <CREDENTIAL:db>"


def test_transform_tool_result_failure_returns_safe_message_without_secret(monkeypatch):
    reg = get_registry()
    reg.register("db", "password", "decoy_password_QWER1234")

    def boom(*_args, **_kwargs):
        raise RuntimeError("decode decoy_password_QWER1234")

    monkeypatch.setattr("credential_guard.result_guard.redact_registered", boom)
    out = on_transform_tool_result(result="raw", tool_name="dummy", arguments={})
    assert out == RESULT_GUARD_FAIL_TEXT
    assert "decoy_password_QWER1234" not in out
    assert out.count("decoy_password_QWER1234") == 0


def test_transform_tool_result_failure_mutation_legacy_json_is_red(monkeypatch):
    """Mutation: legacy SAFE JSON body must not pass as R4 fail-closed."""
    reg = get_registry()
    reg.register("db", "password", "decoy_password_QWER1234")

    def boom(*_args, **_kwargs):
        raise RuntimeError("decode decoy_password_QWER1234")

    monkeypatch.setattr("credential_guard.result_guard.redact_registered", boom)
    out = on_transform_tool_result(result="raw", tool_name="dummy", arguments={})
    assert out == RESULT_GUARD_FAIL_TEXT
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


def test_t1_tool_result_redacts_percent_and_quote_plus_variants():
    canary = _runtime_canary_with_specials()
    pct = quote(canary, safe="")
    qp = quote_plus(canary)
    reg = get_registry()
    reg.register("db", "password", canary)

    out_pct = on_transform_tool_result(
        result=f"leak {pct}", tool_name="dummy", arguments={}
    )
    out_qp = on_transform_tool_result(
        result=f"leak {qp}", tool_name="dummy", arguments={}
    )
    assert canary not in out_pct and pct not in out_pct
    assert canary not in out_qp and qp not in out_qp
    assert "<CREDENTIAL:db>" in out_pct
    assert "<CREDENTIAL:db>" in out_qp
    assert "<SECRET:" not in out_pct
    assert "<SECRET:" not in out_qp
