"""C9: unify tool-result placeholders to conservative registry tokens.

Decision: llm_request and transform_tool_result both emit CredentialValue.token
``<SECRET:cg_[0-9a-f]{16}>``. Must NOT upgrade to usable ``<CREDENTIAL:name>``.
"""

from __future__ import annotations

import base64
import json
import os
import re
from copy import deepcopy
from urllib.parse import quote, quote_plus

import pytest

from credential_guard.credential_code import (
    credential_code_not_usable_error,
    is_redacted_credential_code,
)
from credential_guard.hooks import on_transform_tool_result
from credential_guard.middleware import on_llm_request
from credential_guard.process_tools import handle_credential_process_run
from credential_guard.reference_tools import handle_http_credential_request
from credential_guard.result_guard import guard_tool_result
from credential_guard.state import get_registry

_SECRET_TOKEN_RE = re.compile(r"^<SECRET:cg_[0-9a-f]{16}>$")
_KEY = "demo-svc"
_FIELD = "value"
_SECRET = "cg_c9_decoy_token_ABCDEF12!@#"


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


def _variants(secret: str) -> list[str]:
    raw = secret.encode("utf-8")
    out = [
        secret,
        quote(secret, safe=""),
        quote_plus(secret),
        base64.b64encode(raw).decode("ascii"),
        base64.urlsafe_b64encode(raw).decode("ascii"),
    ]
    # Deduplicate while preserving order (plain may equal an encoding).
    seen: set[str] = set()
    uniq: list[str] = []
    for v in out:
        if v and v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


def test_c9_llm_and_tool_result_emit_same_registry_token():
    item = get_registry().register(_KEY, _FIELD, _SECRET)
    token = item.token
    assert _SECRET_TOKEN_RE.fullmatch(token)
    assert is_redacted_credential_code(token)

    # Token must not embed secret / key / field plaintext.
    assert _SECRET not in token
    assert _KEY not in token
    assert _FIELD not in token
    assert "demo" not in token

    for variant in _variants(_SECRET):
        req = {
            "messages": [{"role": "user", "content": f"leak {variant} here"}],
        }
        out_req = on_llm_request(request=deepcopy(req))["request"]
        content = out_req["messages"][0]["content"]
        assert variant not in content
        assert _SECRET not in content
        assert token in content
        assert f"<CREDENTIAL:{_KEY}>" not in content
        assert "<CREDENTIAL:" not in content

        guarded = guard_tool_result(f"out {variant}", get_registry())
        assert variant not in guarded
        assert _SECRET not in guarded
        assert token in guarded
        assert f"<CREDENTIAL:{_KEY}>" not in guarded
        assert "<CREDENTIAL:" not in guarded

        hooked = on_transform_tool_result(
            result=f"hook {variant}",
            tool_name="dummy",
            arguments={},
        )
        assert variant not in hooked
        assert _SECRET not in hooked
        assert token in hooked
        assert f"<CREDENTIAL:{_KEY}>" not in hooked
        assert "<CREDENTIAL:" not in hooked


def test_c9_registry_token_rejected_by_both_formal_handlers(monkeypatch):
    item = get_registry().register(_KEY, _FIELD, _SECRET)
    token = item.token
    assert is_redacted_credential_code(token)

    calls: list[str] = []

    def _boom(label: str):
        def _inner(*_a, **_k):
            calls.append(label)
            raise AssertionError(f"{label} must not run for C9 redacted token")

        return _inner

    # One-call-fails seams: validation / approval / finalize / adapter / Provider.
    monkeypatch.setattr(
        "credential_guard.reference_tools.validate_http_credential_request_args",
        _boom("http_validate"),
    )
    monkeypatch.setattr(
        "credential_guard.process_tools.validate_credential_process_run_args",
        _boom("proc_validate"),
    )
    monkeypatch.setattr(
        "credential_guard.reference_tools.finalize_reference_execution",
        _boom("http_finalize"),
    )
    monkeypatch.setattr(
        "credential_guard.process_tools.finalize_reference_execution",
        _boom("proc_finalize"),
    )
    # Approval / plan / adapter / Provider seams inside finalize path.
    monkeypatch.setattr(
        "credential_guard.tool_execution.finalize_reference_execution",
        _boom("tool_execution_finalize"),
    )
    monkeypatch.setattr(
        "credential_guard.adapters.http.execute_http",
        _boom("http_adapter"),
    )
    monkeypatch.setattr(
        "credential_guard.adapters.process.execute_process",
        _boom("proc_adapter"),
    )
    monkeypatch.setattr(
        "credential_guard.middleware.on_llm_request",
        _boom("provider_llm_request"),
    )

    expected = json.loads(credential_code_not_usable_error())
    http_out = handle_http_credential_request(
        {
            "target": "any",
            "method": "GET",
            "path": "/x",
            "credential": token,
        }
    )
    proc_out = handle_credential_process_run(
        {"target": "any", "credential": token}
    )
    assert json.loads(http_out) == expected
    assert json.loads(proc_out) == expected
    assert calls == []
