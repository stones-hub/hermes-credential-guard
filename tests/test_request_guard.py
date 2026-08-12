from __future__ import annotations

import json
import os
import secrets
from urllib.parse import quote, quote_plus

import pytest

from credential_guard.middleware import SAFE_BLOCK_MESSAGE, on_llm_execution, on_llm_request
from credential_guard.state import get_registry


def _runtime_canary_with_specials() -> str:
    """Synthetic secret that differs under percent vs quote-plus encoding."""
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


def test_llm_request_returns_provider_bound_copy():
    reg = get_registry()
    item = reg.register("db", "password", "decoy_db_password_123")
    original = {"messages": [{"content": "decoy_db_password_123"}]}
    out = on_llm_request(request=original)
    assert out["request"]["messages"][0]["content"] == item.token
    assert original["messages"][0]["content"] == "decoy_db_password_123"


def test_llm_execution_calls_downstream_once_when_clean():
    reg = get_registry()
    reg.register("db", "password", "decoy_db_password_123")
    calls = []

    def next_call(request):
        calls.append(request)
        return {"ok": True}

    result = on_llm_execution(
        request={"messages": [{"content": "decoy_db_password_123"}]},
        next_call=next_call,
    )
    assert result == {"ok": True}
    assert len(calls) == 1


def test_llm_execution_blocks_when_internal_failure_without_calling_downstream(monkeypatch):
    reg = get_registry()
    reg.register("db", "password", "decoy_db_password_123")
    calls = []

    def next_call(request):
        calls.append(request)
        return {"ok": True}

    def boom(*_args, **_kwargs):
        raise RuntimeError("redactor failed")

    monkeypatch.setattr("credential_guard.middleware.redact_payload", boom)
    blocked = on_llm_execution(
        request={"messages": [{"content": "decoy_db_password_123"}]},
        next_call=next_call,
    )
    assert len(calls) == 0
    assert getattr(blocked, "model", "") == "credential-guard-blocked"
    assert blocked.choices[0].message.content == SAFE_BLOCK_MESSAGE
    assert blocked.choices[0].message.tool_calls is None


def test_t1_percent_and_quote_plus_variants_redacted_before_provider():
    """Registered secret percent / quote-plus forms must not reach next_call."""
    canary = _runtime_canary_with_specials()
    pct = quote(canary, safe="")
    qp = quote_plus(canary)
    assert pct != qp
    assert pct != canary
    assert qp != canary

    reg = get_registry()
    item = reg.register("db", "password", canary)
    calls = []

    def next_call(request):
        calls.append(request)
        return {"ok": True}

    result = on_llm_execution(
        request={
            "messages": [
                {"role": "user", "content": f"pct={pct}"},
                {"role": "user", "content": f"qp={qp}"},
            ]
        },
        next_call=next_call,
    )
    assert result == {"ok": True}
    assert len(calls) == 1
    wire = json.dumps(calls[0], ensure_ascii=False)
    assert wire.count(canary) == 0
    assert wire.count(pct) == 0
    assert wire.count(qp) == 0
    assert wire.count(item.token) >= 2


def test_t2_base64_and_urlsafe_variants_redacted_before_provider():
    import base64

    canary = "cg_" + secrets.token_hex(12) + "_b64!"
    std = base64.b64encode(canary.encode("utf-8")).decode("ascii")
    url = base64.urlsafe_b64encode(canary.encode("utf-8")).decode("ascii")
    # Ensure URL-safe differs when canary has characters that map differently,
    # or at least both encodings are distinct from plain.
    assert std != canary and url != canary

    reg = get_registry()
    item = reg.register("db", "password", canary)
    # Innocent unrelated Base64 must survive.
    innocent = base64.b64encode(b"not_a_registered_secret_xx").decode("ascii")
    calls = []

    def next_call(request):
        calls.append(request)
        return {"ok": True}

    result = on_llm_execution(
        request={
            "messages": [
                {"role": "user", "content": f"std={std}"},
                {"role": "user", "content": f"url={url}"},
                {"role": "user", "content": f"innocent={innocent}"},
            ]
        },
        next_call=next_call,
    )
    assert result == {"ok": True}
    assert len(calls) == 1
    wire = json.dumps(calls[0], ensure_ascii=False)
    assert wire.count(canary) == 0
    assert wire.count(std) == 0
    assert wire.count(url) == 0
    assert innocent in wire
    assert wire.count(item.token) >= 2

    from credential_guard.redactor import contains_plain_secret

    assert contains_plain_secret({"v": std}, reg) is True
    assert contains_plain_secret({"v": url}, reg) is True
    assert contains_plain_secret({"v": item.token}, reg) is False


def test_t3_json_escape_variant_redacted_before_provider():
    """JSON-escape interior (quote/backslash + non-ASCII \\u form) must redact."""
    canary = 'cg_' + secrets.token_hex(8) + '_说"\\密'
    # ensure_ascii=True produces \\uXXXX for non-ASCII; False produces \" / \\.
    esc_ascii = json.dumps(canary, ensure_ascii=True)[1:-1]
    esc_unicode = json.dumps(canary, ensure_ascii=False)[1:-1]
    assert "\\u" in esc_ascii or "\\U" in esc_ascii
    assert '\\"' in esc_unicode or "\\\\" in esc_unicode
    assert esc_ascii != canary
    assert esc_unicode != canary

    reg = get_registry()
    item = reg.register("db", "password", canary)
    original = {
        "messages": [
            {"role": "user", "content": f"a={esc_ascii}"},
            {"role": "user", "content": f"u={esc_unicode}"},
        ]
    }
    original_snapshot = json.dumps(original, ensure_ascii=False)
    calls = []

    def next_call(request):
        calls.append(request)
        return {"ok": True}

    result = on_llm_execution(request=original, next_call=next_call)
    assert result == {"ok": True}
    assert len(calls) == 1
    # Original object must not be mutated.
    assert json.dumps(original, ensure_ascii=False) == original_snapshot
    assert original["messages"][0]["content"] == f"a={esc_ascii}"
    assert original["messages"][1]["content"] == f"u={esc_unicode}"
    content_a = calls[0]["messages"][0]["content"]
    content_u = calls[0]["messages"][1]["content"]
    assert canary not in content_a and canary not in content_u
    assert esc_ascii not in content_a
    assert esc_unicode not in content_u
    assert content_a == f"a={item.token}"
    assert content_u == f"u={item.token}"
    # Redacted payload must remain JSON-serializable.
    json.dumps(calls[0], ensure_ascii=False)
