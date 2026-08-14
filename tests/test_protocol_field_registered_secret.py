"""Protocol-field *values* with registered secrets must fail-closed (Provider=0).

0.4.3 redacts registered variants into logical tokens even when they appear as
``model`` / ``role`` / ``name`` / ``tool_call_id`` values, then continues to the
Provider. 0.4.4 narrows that gap: those protocol skeleton values must block
locally before replacement, without echoing synthetic material.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from copy import deepcopy

import pytest

from credential_guard.middleware import (
    LocalBlockRequest,
    is_blocked_response_content,
    on_llm_execution,
    on_llm_request,
)
from credential_guard.state import get_registry

# Explicit synthetic decoys — never real credentials.
SYNTHETIC_PROTOCOL_SECRET = "SYNTHETIC_CG044_PROTOCOL_FIELD_DECOY_001"
SYNTHETIC_CONTENT_SECRET = "SYNTHETIC_CG044_CONTENT_FIELD_DECOY_002"
SYNTHETIC_ARGS_SECRET = "SYNTHETIC_CG044_ARGUMENTS_FIELD_DECOY_003"


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


def _assert_fail_closed_no_leak(out: dict, *, secret: str, token: str) -> None:
    assert isinstance(out["request"], LocalBlockRequest)
    calls: list = []
    blocked = on_llm_execution(
        request=out["request"],
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []
    text = blocked.choices[0].message.content
    assert is_blocked_response_content(text)
    assert "代码：CG-RESIDUAL-SECRET" in text
    carrier_blob = json.dumps(out["request"], ensure_ascii=False)
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    for surface in (carrier_blob, text):
        assert secret not in surface
        assert token not in surface
        assert digest not in surface
        # Length / hash metadata must not be derived into block surfaces.
        assert f"len={len(secret)}" not in surface
        assert f"length={len(secret)}" not in surface
        assert f"sha256={digest}" not in surface


@pytest.mark.parametrize(
    "field,build_request",
    [
        (
            "model",
            lambda secret: {
                "model": secret,
                "messages": [{"role": "user", "content": "continue"}],
            },
        ),
        (
            "role",
            lambda secret: {
                "model": "m",
                "messages": [
                    {"role": "user", "content": "hi"},
                    {"role": secret, "content": "oops"},
                    {"role": "user", "content": "continue"},
                ],
            },
        ),
        (
            "name",
            lambda secret: {
                "model": "m",
                "messages": [
                    {
                        "role": "tool",
                        "name": secret,
                        "content": "tool ok",
                        "tool_call_id": "call_1",
                    },
                    {"role": "user", "content": "continue"},
                ],
            },
        ),
        (
            "tool_call_id",
            lambda secret: {
                "model": "m",
                "messages": [
                    {
                        "role": "tool",
                        "name": "search_files",
                        "content": "tool ok",
                        "tool_call_id": secret,
                    },
                    {"role": "user", "content": "continue"},
                ],
            },
        ),
    ],
    ids=["model", "role", "name", "tool_call_id"],
)
def test_protocol_field_registered_secret_fail_closed_provider_zero(
    field, build_request, caplog
):
    item = get_registry().register("synth", "password", SYNTHETIC_PROTOCOL_SECRET)
    request = build_request(SYNTHETIC_PROTOCOL_SECRET)
    original = deepcopy(request)

    with caplog.at_level(logging.DEBUG, logger="credential_guard"):
        out = on_llm_request(request=request)

    _assert_fail_closed_no_leak(
        out, secret=SYNTHETIC_PROTOCOL_SECRET, token=item.token
    )
    assert request == original
    assert SYNTHETIC_PROTOCOL_SECRET not in caplog.text
    assert item.token not in caplog.text
    digest = hashlib.sha256(SYNTHETIC_PROTOCOL_SECRET.encode("utf-8")).hexdigest()
    assert digest not in caplog.text


def test_content_registered_secret_still_tokenizes_provider_one():
    item = get_registry().register("synth", "password", SYNTHETIC_CONTENT_SECRET)
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": f"leak {SYNTHETIC_CONTENT_SECRET} please"},
            {"role": "user", "content": "continue"},
        ],
    }
    original = deepcopy(request)
    out = on_llm_request(request=request)
    assert not isinstance(out["request"], LocalBlockRequest)
    pb = out["request"]
    assert SYNTHETIC_CONTENT_SECRET not in json.dumps(pb, ensure_ascii=False)
    assert item.token in pb["messages"][0]["content"]
    assert request == original
    calls: list = []
    assert on_llm_execution(
        request=pb,
        next_call=lambda req: calls.append(req) or {"ok": True},
    ) == {"ok": True}
    assert len(calls) == 1
    assert SYNTHETIC_CONTENT_SECRET not in json.dumps(calls[0], ensure_ascii=False)


def test_arguments_registered_secret_still_tokenizes_provider_one():
    item = get_registry().register("synth", "token", SYNTHETIC_ARGS_SECRET)
    args = json.dumps({"body": SYNTHETIC_ARGS_SECRET})
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "run"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "write_file",
                            "arguments": args,
                        },
                    }
                ],
            },
            {"role": "user", "content": "continue"},
        ],
    }
    original = deepcopy(request)
    out = on_llm_request(request=request)
    assert not isinstance(out["request"], LocalBlockRequest)
    pb = out["request"]
    wire = json.dumps(pb, ensure_ascii=False)
    assert SYNTHETIC_ARGS_SECRET not in wire
    sent_args = pb["messages"][1]["tool_calls"][0]["function"]["arguments"]
    assert item.token in sent_args
    assert request == original
    calls: list = []
    assert on_llm_execution(
        request=pb,
        next_call=lambda req: calls.append(req) or {"ok": True},
    ) == {"ok": True}
    assert len(calls) == 1


def test_mutation_bypass_protocol_registered_secret_gate_reopens_provider_one(
    monkeypatch,
):
    """One-factor mutation: disable protocol-value gate → old Provider=1 returns."""
    import credential_guard.middleware as mw

    monkeypatch.setattr(mw, "_is_protocol_field_value_path", lambda *_a, **_k: False)

    item = get_registry().register("synth", "password", SYNTHETIC_PROTOCOL_SECRET)
    out = on_llm_request(
        request={
            "model": SYNTHETIC_PROTOCOL_SECRET,
            "messages": [{"role": "user", "content": "continue"}],
        }
    )
    # Old 0.4.3 gap: tokenize protocol value and continue to Provider.
    assert not isinstance(out["request"], LocalBlockRequest)
    assert out["request"]["model"] == item.token
    calls: list = []
    assert on_llm_execution(
        request=out["request"],
        next_call=lambda req: calls.append(req) or {"ok": True},
    ) == {"ok": True}
    assert len(calls) == 1
    assert SYNTHETIC_PROTOCOL_SECRET not in json.dumps(calls[0], ensure_ascii=False)


def test_protocol_field_normal_fixed_values_not_blocked():
    get_registry().register("synth", "password", SYNTHETIC_PROTOCOL_SECRET)
    request = {
        "model": "gpt-test-model",
        "messages": [
            {"role": "user", "name": "alice", "content": "hi"},
            {
                "role": "tool",
                "name": "search_files",
                "tool_call_id": "call_abc",
                "content": "ok",
            },
            {"role": "user", "content": "continue"},
        ],
    }
    out = on_llm_request(request=request)
    assert not isinstance(out["request"], LocalBlockRequest)
    calls: list = []
    assert on_llm_execution(
        request=out["request"],
        next_call=lambda req: calls.append(req) or {"ok": True},
    ) == {"ok": True}
    assert len(calls) == 1


def test_protocol_field_non_string_values_not_misblocked():
    get_registry().register("synth", "password", SYNTHETIC_PROTOCOL_SECRET)
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "hi", "name": None},
            {"role": "user", "content": "continue", "tool_call_id": 12345},
        ],
        # Non-string model sibling must not trip string-only protocol gate.
        "temperature": 0.2,
    }
    out = on_llm_request(request=request)
    assert not isinstance(out["request"], LocalBlockRequest)


def test_protocol_dict_key_collision_protection_still_blocks(monkeypatch):
    """Core protocol *keys* still fail closed on redaction collision (not values)."""
    import credential_guard.middleware as mw
    from credential_guard.redactor import RedactionCollisionError

    def boom(payload, registry, *, _path=()):
        raise RedactionCollisionError(
            "dict key collision after redaction",
            path=("messages", 0, "<key>"),
        )

    monkeypatch.setattr(mw, "redact_payload", boom)
    get_registry().register("synth", "password", SYNTHETIC_PROTOCOL_SECRET)
    out = on_llm_request(
        request={
            "model": "m",
            "messages": [{"role": "user", "content": "continue"}],
        }
    )
    assert isinstance(out["request"], LocalBlockRequest)
    assert out["request"].block_detail.code == "CG-REDACTION-COLLISION"
    calls: list = []
    on_llm_execution(
        request=out["request"],
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []


def test_content_whole_field_allowlist_not_reused_for_protocol_registered_secret(
    monkeypatch,
):
    """Widening content allowlist must not become the protocol registered-secret rule."""
    import credential_guard.middleware as mw

    monkeypatch.setattr(
        mw, "_is_approved_whole_field_fallback_path", lambda *_a, **_k: True
    )
    get_registry().register("synth", "password", SYNTHETIC_PROTOCOL_SECRET)
    out = on_llm_request(
        request={
            "model": SYNTHETIC_PROTOCOL_SECRET,
            "messages": [{"role": "user", "content": "continue"}],
        }
    )
    # Registered-secret protocol gate is independent of PEM whole-field allowlist.
    assert isinstance(out["request"], LocalBlockRequest)
    calls: list = []
    on_llm_execution(
        request=out["request"],
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []
