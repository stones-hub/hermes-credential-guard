"""Protocol / skeleton fields must fail-closed on boundary-unknown encoded keys.

Whole-field replace remains allowed only for content-class fields (messages[*].content
and tool_calls[*].function.arguments). model / role / name / tool_call_id must not
be replaced with a placeholder and then sent to the Provider.
"""

from __future__ import annotations

import base64
import json
import os
from copy import deepcopy

import pytest

from credential_guard.middleware import (
    LocalBlockRequest,
    REDACTED_UNRESOLVED_SENSITIVE_FIELD,
    is_blocked_response_content,
    on_llm_execution,
    on_llm_request,
)
from credential_guard.state import get_registry

OPENSSH_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
-----END OPENSSH PRIVATE KEY-----
"""


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


def _encoded_openssh_key() -> str:
    encoded = base64.b64encode(OPENSSH_KEY.encode("utf-8")).decode("ascii")
    assert "BEGIN" not in encoded
    assert "PRIVATE KEY" not in encoded
    return encoded


def _assert_provider_zero(out: dict) -> None:
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
    assert REDACTED_UNRESOLVED_SENSITIVE_FIELD not in json.dumps(
        out["request"], ensure_ascii=False
    )


@pytest.mark.parametrize(
    "field,build_request",
    [
        (
            "model",
            lambda enc: {
                # Value is the synthetic encoded blob itself so the scanner hits.
                "model": enc,
                "messages": [{"role": "user", "content": "continue"}],
            },
        ),
        (
            "role",
            lambda enc: {
                "model": "m",
                "messages": [
                    {"role": "user", "content": "hi"},
                    {"role": enc, "content": "oops"},
                    {"role": "user", "content": "continue"},
                ],
            },
        ),
        (
            "name",
            lambda enc: {
                "model": "m",
                "messages": [
                    {
                        "role": "tool",
                        "name": enc,
                        "content": "tool ok",
                        "tool_call_id": "call_1",
                    },
                    {"role": "user", "content": "continue"},
                ],
            },
        ),
        (
            "tool_call_id",
            lambda enc: {
                "model": "m",
                "messages": [
                    {
                        "role": "tool",
                        "name": "search_files",
                        "content": "tool ok",
                        "tool_call_id": enc,
                    },
                    {"role": "user", "content": "continue"},
                ],
            },
        ),
    ],
    ids=["model", "role", "name", "tool_call_id"],
)
def test_protocol_field_boundary_unknown_fail_closed_provider_zero(
    field, build_request
):
    """Core protocol fields with unlocalizable encoded key → Provider=0."""
    encoded = _encoded_openssh_key()
    request = build_request(encoded)
    original = deepcopy(request)

    out = on_llm_request(request=request)
    _assert_provider_zero(out)
    assert request == original
    # Must not leak the synthetic encoded blob into the local block carrier.
    carrier_blob = json.dumps(out["request"], ensure_ascii=False)
    assert encoded not in carrier_blob
    assert OPENSSH_KEY not in carrier_blob


def test_content_whole_field_replace_semantics_unchanged():
    """Approved content-class fields still whole-field replace and continue."""
    encoded = _encoded_openssh_key()
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "context"},
            {"role": "assistant", "content": "ack"},
            {"role": "tool", "name": "t", "content": f"blob {encoded}"},
            {"role": "user", "content": "continue"},
        ],
    }
    original = deepcopy(request)
    out = on_llm_request(request=request)
    assert not isinstance(out["request"], LocalBlockRequest)
    pb = out["request"]
    assert pb["messages"][2]["content"] == REDACTED_UNRESOLVED_SENSITIVE_FIELD
    assert pb["messages"][2]["name"] == "t"
    assert pb["messages"][3]["content"] == "continue"
    assert request == original
    calls: list = []
    assert on_llm_execution(
        request=pb,
        next_call=lambda req: calls.append(req) or {"ok": True},
    ) == {"ok": True}
    assert len(calls) == 1
    assert encoded not in json.dumps(calls[0], ensure_ascii=False)


def test_arguments_whole_field_replace_semantics_unchanged():
    encoded = _encoded_openssh_key()
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
                            "arguments": json.dumps({"body": encoded}),
                        },
                    }
                ],
            },
            {"role": "user", "content": "continue"},
        ],
    }
    out = on_llm_request(request=request)
    assert not isinstance(out["request"], LocalBlockRequest)
    args = out["request"]["messages"][1]["tool_calls"][0]["function"]["arguments"]
    assert args == REDACTED_UNRESOLVED_SENSITIVE_FIELD
    calls: list = []
    assert on_llm_execution(
        request=out["request"],
        next_call=lambda req: calls.append(req) or {"ok": True},
    ) == {"ok": True}
    assert len(calls) == 1


def test_mutation_old_unrestricted_whole_field_fallback_must_red(monkeypatch):
    """If allowlist is bypassed (old unrestricted fallback) → protocol continues."""
    import credential_guard.middleware as mw

    monkeypatch.setattr(
        mw, "_is_approved_whole_field_fallback_path", lambda *_a, **_k: True
    )
    encoded = _encoded_openssh_key()
    out = on_llm_request(
        request={
            "model": encoded,
            "messages": [{"role": "user", "content": "continue"}],
        }
    )
    # Old unrestricted semantics: placeholder + Provider continues (gap reopened).
    assert not isinstance(out["request"], LocalBlockRequest)
    assert out["request"]["model"] == REDACTED_UNRESOLVED_SENSITIVE_FIELD
    calls: list = []
    assert on_llm_execution(
        request=out["request"],
        next_call=lambda req: calls.append(req) or {"ok": True},
    ) == {"ok": True}
    assert len(calls) == 1
