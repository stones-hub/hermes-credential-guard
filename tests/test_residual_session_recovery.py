"""CG-RESIDUAL-SECRET long-session auto-recovery (narrow TDD)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

import credential_guard.middleware as mw
from credential_guard.middleware import (
    LocalBlockRequest,
    is_blocked_response_content,
    on_llm_execution,
    on_llm_request,
)
from credential_guard.redactor import redact_payload
from credential_guard.state import get_registry

QUARANTINE_MARK = "<CREDENTIAL_GUARD_QUARANTINED_HISTORY_FIELD>"


def _glue_secret(left: str, right: str, *, role: str) -> str:
    """Registered variant formed only across adjacent JSON message boundaries."""
    return left + '"}, {"role": "' + role + '", "content": "' + right


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
    yield
    get_registry().clear()


def _provider_once(request: dict) -> tuple[dict, dict]:
    original = deepcopy(request)
    out = on_llm_request(request=request)
    assert request == original
    assert not isinstance(out["request"], LocalBlockRequest), getattr(
        getattr(out["request"], "block_detail", None), "code", out["request"]
    )
    calls: list = []
    result = on_llm_execution(
        request=out["request"],
        next_call=lambda req: calls.append(deepcopy(req)) or {"ok": True},
    )
    assert result == {"ok": True}
    assert len(calls) == 1
    return out["request"], calls[0]


def _leaky_redact_reinject(secret: str, message_index: int):
    """Narrow mutation: first redact_payload leaves one registered secret in history."""

    def _mut(payload, registry, **_kwargs):
        out = redact_payload(payload, registry)
        out = deepcopy(out)
        messages = out.get("messages")
        if isinstance(messages, list) and 0 <= message_index < len(messages):
            msg = messages[message_index]
            if isinstance(msg, dict):
                msg["content"] = f"tool keep-context leaked {secret} tail"
        return out

    return _mut


def test_historical_assistant_metadata_dynamic_key_value_recovers(monkeypatch, caplog):
    """B1: ordinary metadata dynamic-key VALUE residual must quarantine, not Provider=0."""
    secret = "residual_meta_dyn_value_decoy_b1"
    dynamic_key = "dyn_meta_safe_branch_xyz"
    get_registry().register("db", "password", secret)

    def identity(payload, registry, **_kwargs):
        return deepcopy(payload)

    monkeypatch.setattr(mw, "redact_payload", identity)
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "start-keep"},
            {
                "role": "assistant",
                "content": "assistant-keep",
                "metadata": {
                    "keep_sibling": "sibling-keep",
                    dynamic_key: f"leaked {secret} in meta",
                },
            },
            {"role": "user", "content": "continue-keep"},
        ],
    }
    original = deepcopy(request)
    import logging

    with caplog.at_level(logging.DEBUG, logger="credential_guard"):
        pb, sent = _provider_once(request)
    assert request == original
    assert pb["messages"][0]["content"] == "start-keep"
    assert pb["messages"][1]["content"] == "assistant-keep"
    assert pb["messages"][2]["content"] == "continue-keep"
    meta = pb["messages"][1]["metadata"]
    assert meta["keep_sibling"] == "sibling-keep"
    assert dynamic_key in meta
    assert secret not in meta[dynamic_key]
    assert QUARANTINE_MARK in meta[dynamic_key] or "隔离" in str(meta[dynamic_key])
    wire = json.dumps(sent, ensure_ascii=False)
    assert secret not in wire
    assert secret not in caplog.text
    digest = hashlib.sha256(secret.encode()).hexdigest()
    assert digest not in wire
    assert digest not in caplog.text
    # Block/prompt path must never echo the dynamic key; success logs also must not.
    assert dynamic_key not in caplog.text


def test_historical_extension_dynamic_key_value_recovers(monkeypatch):
    """B1 sibling: ordinary extension dynamic-key VALUE residual recovers."""
    secret = "residual_ext_dyn_value_decoy_b1"
    dynamic_key = "dyn_ext_branch_abc"
    get_registry().register("db", "password", secret)

    def identity(payload, registry, **_kwargs):
        return deepcopy(payload)

    monkeypatch.setattr(mw, "redact_payload", identity)
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "start"},
            {
                "role": "tool",
                "tool_call_id": "t_ext",
                "content": "tool-keep",
                "extension": {
                    "keep": "ext-sibling",
                    dynamic_key: f"ext leaked {secret}",
                },
            },
            {"role": "user", "content": "go"},
        ],
    }
    pb, sent = _provider_once(request)
    assert pb["messages"][1]["content"] == "tool-keep"
    assert pb["messages"][1]["tool_call_id"] == "t_ext"
    ext = pb["messages"][1]["extension"]
    assert ext["keep"] == "ext-sibling"
    assert secret not in ext[dynamic_key]
    assert secret not in json.dumps(sent, ensure_ascii=False)


def test_historical_metadata_dynamic_key_itself_fail_closed(monkeypatch, caplog):
    """B1 negative: residual ON the dynamic key itself must not silent-rewrite."""
    secret = "residual_meta_dyn_key_decoy_b1"
    get_registry().register("db", "password", secret)

    def identity(payload, registry, **_kwargs):
        return deepcopy(payload)

    monkeypatch.setattr(mw, "redact_payload", identity)
    import logging

    with caplog.at_level(logging.DEBUG, logger="credential_guard"):
        out = on_llm_request(
            request={
                "model": "m",
                "messages": [
                    {"role": "user", "content": "start"},
                    {
                        "role": "assistant",
                        "content": "ok",
                        "metadata": {f"k_{secret}_k": "plain-value"},
                    },
                    {"role": "user", "content": "go"},
                ],
            }
        )
    assert isinstance(out["request"], LocalBlockRequest)
    assert out["request"].block_detail.code == "CG-RESIDUAL-SECRET"
    blocked = on_llm_execution(
        request=out["request"],
        next_call=lambda req: {"ok": True},
    )
    prompt = blocked.choices[0].message.content
    assert secret not in prompt
    assert secret not in caplog.text
    assert f"k_{secret}_k" not in prompt
    assert f"k_{secret}_k" not in caplog.text


def test_historical_tool_residual_auto_recovers(monkeypatch):
    secret = "residual_hist_tool_decoy_001"
    get_registry().register("db", "password", secret)
    monkeypatch.setattr(mw, "redact_payload", _leaky_redact_reinject(secret, 2))

    request = {
        "model": "m",
        "messages": [
            {"role": "system", "content": "sys-keep"},
            {"role": "user", "content": "please continue the long task"},
            {
                "role": "tool",
                "name": "search_files",
                "content": f"tool keep-context leaked {secret} tail",
                "tool_call_id": "call_hist_1",
            },
            {"role": "user", "content": "next step after tool"},
        ],
    }
    original = deepcopy(request)
    pb, sent = _provider_once(request)
    assert request == original
    assert pb["messages"][0]["content"] == "sys-keep"
    assert pb["messages"][1]["content"] == "please continue the long task"
    assert pb["messages"][3]["content"] == "next step after tool"
    assert pb["messages"][2]["role"] == "tool"
    assert pb["messages"][2]["tool_call_id"] == "call_hist_1"
    assert pb["messages"][2]["name"] == "search_files"
    assert secret not in pb["messages"][2]["content"]
    assert QUARANTINE_MARK in pb["messages"][2]["content"] or "隔离" in pb["messages"][2]["content"]
    wire = json.dumps(sent, ensure_ascii=False)
    assert secret not in wire
    assert hashlib.sha256(secret.encode()).hexdigest() not in wire
    assert str(len(secret)) not in wire


def test_same_session_two_rounds_stable(monkeypatch):
    """E1: each round is on_llm_request → (deepcopy seam) → on_llm_execution spy."""
    secret = "residual_stable_decoy_002"
    get_registry().register("db", "password", secret)
    monkeypatch.setattr(mw, "redact_payload", _leaky_redact_reinject(secret, 1))
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "earlier"},
            {
                "role": "tool",
                "content": f"leaked {secret}",
                "tool_call_id": "c1",
            },
            {"role": "user", "content": "continue"},
        ],
    }
    original = deepcopy(request)

    def _round(canonical: dict) -> tuple[dict, dict]:
        out = on_llm_request(request=canonical)
        assert not isinstance(out["request"], LocalBlockRequest)
        # Hermes apply_llm_request_middleware deepcopies the returned request.
        provider_bound = deepcopy(out["request"])
        calls: list = []
        result = on_llm_execution(
            request=provider_bound,
            next_call=lambda req: calls.append(deepcopy(req)) or {"ok": True},
        )
        assert result == {"ok": True}
        assert len(calls) == 1
        return out["request"], calls[0]

    pb1, sent1 = _round(request)
    pb2, sent2 = _round(request)
    assert request == original
    assert pb1 == pb2
    assert sent1 == sent2
    assert json.dumps(pb1, sort_keys=True) == json.dumps(pb2, sort_keys=True)
    assert json.dumps(sent1, sort_keys=True) == json.dumps(sent2, sort_keys=True)


def test_multiple_historical_residuals_bounded_clear(monkeypatch):
    secret_a = "residual_multi_decoy_a_003"
    secret_b = "residual_multi_decoy_b_003"
    get_registry().register("db", "password", secret_a)
    get_registry().register("api", "token", secret_b)
    real = redact_payload

    def leak_two(payload, registry, **_kwargs):
        out = deepcopy(real(payload, registry))
        out["messages"][1]["content"] = f"first {secret_a}"
        out["messages"][3]["content"] = f"second {secret_b}"
        return out

    monkeypatch.setattr(mw, "redact_payload", leak_two)
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "start"},
            {"role": "tool", "content": f"first {secret_a}", "tool_call_id": "t1"},
            {"role": "assistant", "content": "mid-keep"},
            {"role": "tool", "content": f"second {secret_b}", "tool_call_id": "t2"},
            {"role": "user", "content": "go on"},
        ],
    }
    pb, sent = _provider_once(request)
    assert pb["messages"][0]["content"] == "start"
    assert pb["messages"][2]["content"] == "mid-keep"
    assert pb["messages"][4]["content"] == "go on"
    assert secret_a not in pb["messages"][1]["content"]
    assert secret_b not in pb["messages"][3]["content"]
    wire = json.dumps(sent, ensure_ascii=False)
    assert secret_a not in wire
    assert secret_b not in wire


def test_current_user_input_not_silently_swallowed(monkeypatch):
    secret = "residual_current_user_decoy_004"
    get_registry().register("db", "password", secret)

    def identity(payload, registry, **_kwargs):
        return deepcopy(payload)

    monkeypatch.setattr(mw, "redact_payload", identity)
    calls: list = []
    blocked = on_llm_execution(
        request={
            "model": "m",
            "messages": [
                {"role": "user", "content": "old history ok"},
                {"role": "assistant", "content": "ack"},
                {"role": "user", "content": f"please use {secret} now"},
            ],
        },
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []
    text = blocked.choices[0].message.content
    assert is_blocked_response_content(text)
    assert "代码：CG-RESIDUAL-SECRET" in text
    assert "无需新建 Session" in text
    assert "编辑当前输入" in text
    assert secret not in text
    assert "old history ok" not in text or "位置：" in text


def test_historical_user_and_trailing_tool_recoverable(monkeypatch):
    secret_u = "residual_hist_user_decoy_005"
    secret_t = "residual_tool_loop_decoy_005"
    get_registry().register("db", "password", secret_u)
    get_registry().register("api", "token", secret_t)
    real = redact_payload

    def leak(payload, registry, **_kwargs):
        out = deepcopy(real(payload, registry))
        out["messages"][0]["content"] = f"early user {secret_u}"
        out["messages"][3]["content"] = f"tool loop {secret_t}"
        return out

    monkeypatch.setattr(mw, "redact_payload", leak)
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": f"early user {secret_u}"},
            {"role": "assistant", "content": "working", "tool_calls": [
                {
                    "id": "call_x",
                    "type": "function",
                    "function": {"name": "run", "arguments": "{}"},
                }
            ]},
            {"role": "user", "content": "not current — followed by tool"},
            {
                "role": "tool",
                "content": f"tool loop {secret_t}",
                "tool_call_id": "call_x",
            },
        ],
    }
    pb, sent = _provider_once(request)
    assert secret_u not in pb["messages"][0]["content"]
    assert secret_t not in pb["messages"][3]["content"]
    assert pb["messages"][1]["tool_calls"][0]["id"] == "call_x"
    assert pb["messages"][3]["tool_call_id"] == "call_x"
    assert secret_u not in json.dumps(sent)
    assert secret_t not in json.dumps(sent)


def test_system_core_residual_still_blocks(monkeypatch):
    secret = "residual_system_core_decoy_006"
    get_registry().register("db", "password", secret)

    def identity(payload, registry, **_kwargs):
        return deepcopy(payload)

    monkeypatch.setattr(mw, "redact_payload", identity)
    calls: list = []
    blocked = on_llm_execution(
        request={
            "model": "m",
            "messages": [
                {"role": "system", "content": f"system rules {secret}"},
                {"role": "user", "content": "continue same session"},
            ],
        },
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []
    text = blocked.choices[0].message.content
    assert is_blocked_response_content(text)
    assert "代码：CG-RESIDUAL-SECRET" in text
    assert "同一 Session" in text or "Credential Guard Bug" in text
    assert "新建 Session" not in text.split("处理：", 1)[-1] or "无需" in text
    assert secret not in text
    # Must not have deleted system prompt to force a green path.
    out = on_llm_request(
        request={
            "model": "m",
            "messages": [
                {"role": "system", "content": f"system rules {secret}"},
                {"role": "user", "content": "continue same session"},
            ],
        }
    )
    assert isinstance(out["request"], LocalBlockRequest)


def test_second_pass_residual_still_blocks(monkeypatch):
    secret = "residual_second_pass_decoy_007"
    get_registry().register("db", "password", secret)
    monkeypatch.setattr(mw, "redact_payload", _leaky_redact_reinject(secret, 1))

    real_quarantine = mw._quarantine_residual_path

    def poison_placeholder(payload, path, finding):
        # Quarantine "succeeds" but leaves another residual for final gate.
        out = real_quarantine(payload, path, finding)
        out = deepcopy(out)
        out["messages"][1]["content"] = f"still {secret}"
        return out

    monkeypatch.setattr(mw, "_quarantine_residual_path", poison_placeholder)
    calls: list = []
    blocked = on_llm_execution(
        request={
            "model": "m",
            "messages": [
                {"role": "user", "content": "hist"},
                {"role": "tool", "content": f"x {secret}", "tool_call_id": "t"},
                {"role": "user", "content": "go"},
            ],
        },
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []
    assert "CG-RESIDUAL-SECRET" in blocked.choices[0].message.content


def test_mutation_skip_final_recheck_must_red(monkeypatch):
    """Skip final gate after poisoned quarantine → zero-egress assert would RED."""
    secret = "residual_skip_recheck_decoy_008"
    get_registry().register("db", "password", secret)
    monkeypatch.setattr(mw, "redact_payload", _leaky_redact_reinject(secret, 1))
    real_quarantine = mw._quarantine_residual_path

    def poison_once(payload, path, finding):
        # First call quarantines; then leave a residual that only final gate catches
        # if recovery stops after one successful-looking quarantine.
        out = real_quarantine(payload, path, finding)
        out = deepcopy(out)
        # Plant residual on a *different* historical leaf so recovery's next scan
        # would still see it — unless final gate is the only remaining check after
        # we also stub scan to empty post-recovery.
        out["messages"][0]["content"] = f"plant {secret}"
        return out

    monkeypatch.setattr(mw, "_quarantine_residual_path", poison_once)
    # Production still blocks via recovery loop / final gate.
    calls: list = []
    blocked = on_llm_execution(
        request={
            "model": "m",
            "messages": [
                {"role": "user", "content": "hist"},
                {"role": "tool", "content": f"x {secret}", "tool_call_id": "t"},
                {"role": "user", "content": "go"},
            ],
        },
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []
    assert "CG-RESIDUAL-SECRET" in blocked.choices[0].message.content

    # Mutation: single quarantine then skip final gate (planted residual escapes).
    def recover_once_poison(payload, registry, root):
        findings = mw._scan_residuals(payload, registry, root)
        if not findings:
            return payload
        return poison_once(payload, findings[0].path, findings[0])

    monkeypatch.setattr(mw, "_recover_residuals", recover_once_poison)
    monkeypatch.setattr(mw, "_final_residual_gate", lambda *_a, **_k: None)
    out = on_llm_request(
        request={
            "model": "m",
            "messages": [
                {"role": "user", "content": "hist"},
                {"role": "tool", "content": f"x {secret}", "tool_call_id": "t"},
                {"role": "user", "content": "go"},
            ],
        }
    )
    assert not isinstance(out["request"], LocalBlockRequest)
    wire = json.dumps(out["request"], ensure_ascii=False)
    assert secret in wire
    with pytest.raises(AssertionError):
        assert secret not in wire


def test_aggregate_only_historical_recovers(monkeypatch):
    # Leaves clean; JSON glue forms registered variant across two tool messages.
    left = "AGGLEFT"
    right = "AGGRIGHT"
    glue_secret = _glue_secret(left, right, role="tool")
    get_registry().register("db", "password", glue_secret)

    def identity(payload, registry, **_kwargs):
        return deepcopy(payload)

    monkeypatch.setattr(mw, "redact_payload", identity)
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "start"},
            # No tool_call_id: keep adjacent content→role glue for aggregate-only.
            {"role": "tool", "content": left},
            {"role": "tool", "content": right},
            {"role": "user", "content": "continue"},
        ],
    }
    flat = json.dumps(request, ensure_ascii=False)
    assert glue_secret in flat
    assert glue_secret not in left
    assert glue_secret not in right
    pb, sent = _provider_once(request)
    wire = json.dumps(sent, ensure_ascii=False)
    assert glue_secret not in wire
    assert pb["messages"][0]["content"] == "start"
    assert pb["messages"][3]["content"] == "continue"


def test_two_independent_aggregate_only_residuals_recover(monkeypatch):
    """B2: two aggregate-only hits must recover stepwise; Round-1 one-shot clean fails."""
    left_a, right_a = "AGGA1", "AGGA2"
    left_b, right_b = "AGGB1", "AGGB2"
    glue_a = _glue_secret(left_a, right_a, role="tool")
    glue_b = _glue_secret(left_b, right_b, role="assistant")
    get_registry().register("db", "password", glue_a)
    get_registry().register("api", "token", glue_b)

    def identity(payload, registry, **_kwargs):
        return deepcopy(payload)

    monkeypatch.setattr(mw, "redact_payload", identity)
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "keep-start"},
            {"role": "tool", "content": left_a},
            {"role": "tool", "content": right_a},
            {"role": "assistant", "content": left_b},
            {"role": "assistant", "content": right_b},
            {"role": "user", "content": "keep-mid"},
            {"role": "assistant", "content": "keep-context"},
            {"role": "user", "content": "keep-end"},
        ],
    }
    flat = json.dumps(request, ensure_ascii=False)
    assert glue_a in flat and glue_b in flat
    assert glue_a not in left_a and glue_a not in right_a
    assert glue_b not in left_b and glue_b not in right_b
    # Each structured leaf alone is clean.
    for leaf in (left_a, right_a, left_b, right_b):
        assert glue_a not in leaf and glue_b not in leaf

    original = deepcopy(request)
    pb, sent = _provider_once(request)
    assert request == original
    wire = json.dumps(sent, ensure_ascii=False)
    assert glue_a not in wire
    assert glue_b not in wire
    assert pb["messages"][0]["content"] == "keep-start"
    assert pb["messages"][5]["content"] == "keep-mid"
    assert pb["messages"][6]["content"] == "keep-context"
    assert pb["messages"][7]["content"] == "keep-end"
    # At least one side of each glue pair was isolated (break aggregate).
    pair_a = (pb["messages"][1]["content"], pb["messages"][2]["content"])
    pair_b = (pb["messages"][3]["content"], pb["messages"][4]["content"])
    assert any(
        c != left_a and c != right_a and (QUARANTINE_MARK in c or "隔离" in c)
        for c in pair_a
    ) or (left_a not in wire or right_a not in wire)
    assert any(
        c != left_b and c != right_b and (QUARANTINE_MARK in c or "隔离" in c)
        for c in pair_b
    ) or (left_b not in wire or right_b not in wire)


def test_aggregate_only_core_unrecoverable_blocks(monkeypatch):
    left = "SYSLEFT"
    right = "SYSRIGHT"
    glue_secret = _glue_secret(left, right, role="user")
    get_registry().register("db", "password", glue_secret)

    def identity(payload, registry, **_kwargs):
        return deepcopy(payload)

    monkeypatch.setattr(mw, "redact_payload", identity)
    request = {
        "model": "m",
        "messages": [
            {"role": "system", "content": left},
            {"role": "user", "content": right},
        ],
    }
    assert glue_secret in json.dumps(request, ensure_ascii=False)
    calls: list = []
    blocked = on_llm_execution(
        request=request,
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []
    text = blocked.choices[0].message.content
    assert is_blocked_response_content(text)
    assert "CG-RESIDUAL-SECRET" in text
    assert glue_secret not in text


def test_protocol_tool_call_skeleton_preserved(monkeypatch):
    secret = "residual_tool_args_decoy_009"
    get_registry().register("db", "password", secret)

    def identity(payload, registry, **_kwargs):
        return deepcopy(payload)

    monkeypatch.setattr(mw, "redact_payload", identity)
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "run tools"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_keep_1",
                        "type": "function",
                        "function": {
                            "name": "http_credential_request",
                            "arguments": json.dumps({"token": secret, "x": 1}),
                        },
                    },
                    {
                        "id": "call_keep_2",
                        "type": "function",
                        "function": {
                            "name": "credential_process_run",
                            "arguments": json.dumps({"ok": True}),
                        },
                    },
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "call_keep_1",
                "content": "result-1",
            },
            {
                "role": "tool",
                "tool_call_id": "call_keep_2",
                "content": "result-2",
            },
            {"role": "user", "content": "continue"},
        ],
    }
    pb, sent = _provider_once(request)
    tcs = pb["messages"][1]["tool_calls"]
    assert tcs[0]["id"] == "call_keep_1"
    assert tcs[1]["id"] == "call_keep_2"
    assert tcs[0]["function"]["name"] == "http_credential_request"
    assert tcs[1]["function"]["name"] == "credential_process_run"
    args0 = tcs[0]["function"]["arguments"]
    assert isinstance(args0, str)
    json.loads(args0)  # legal JSON string
    assert secret not in args0
    assert pb["messages"][2]["tool_call_id"] == "call_keep_1"
    assert pb["messages"][3]["tool_call_id"] == "call_keep_2"
    assert secret not in json.dumps(sent)


def test_recovery_budget_fail_closed(monkeypatch):
    """E2: real progressive residuals must respect a small iteration cap."""
    secrets = [
        "residual_budget_decoy_010a",
        "residual_budget_decoy_010b",
        "residual_budget_decoy_010c",
    ]
    for i, secret in enumerate(secrets):
        get_registry().register(f"db{i}", "password", secret)

    real = redact_payload

    def leak_three(payload, registry, **_kwargs):
        out = deepcopy(real(payload, registry))
        out["messages"][1]["content"] = f"first {secrets[0]}"
        out["messages"][2]["content"] = f"second {secrets[1]}"
        out["messages"][3]["content"] = f"third {secrets[2]}"
        return out

    monkeypatch.setattr(mw, "redact_payload", leak_three)
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "start"},
            {"role": "tool", "content": f"first {secrets[0]}", "tool_call_id": "t1"},
            {"role": "tool", "content": f"second {secrets[1]}", "tool_call_id": "t2"},
            {"role": "tool", "content": f"third {secrets[2]}", "tool_call_id": "t3"},
            {"role": "user", "content": "go"},
        ],
    }

    # Cap=2: three independent recoverable residuals → must fail closed (budget).
    monkeypatch.setattr(mw, "MAX_RESIDUAL_RECOVERY_ITERATIONS", 2)
    out_blocked = on_llm_request(request=deepcopy(request))
    assert isinstance(out_blocked["request"], LocalBlockRequest)
    assert out_blocked["request"].block_detail.code == "CG-RESIDUAL-SECRET"

    # Cap=3: exactly enough progressive steps → Provider continues, wire clean.
    monkeypatch.setattr(mw, "MAX_RESIDUAL_RECOVERY_ITERATIONS", 3)
    pb, sent = _provider_once(deepcopy(request))
    wire = json.dumps(sent, ensure_ascii=False)
    for secret in secrets:
        assert secret not in wire
    assert pb["messages"][0]["content"] == "start"
    assert pb["messages"][4]["content"] == "go"

    # Cap=4 also succeeds (headroom).
    monkeypatch.setattr(mw, "MAX_RESIDUAL_RECOVERY_ITERATIONS", 4)
    pb4, sent4 = _provider_once(deepcopy(request))
    assert all(s not in json.dumps(sent4) for s in secrets)
    assert pb4["messages"][0]["content"] == "start"


def test_scanner_error_not_residual_recovery(monkeypatch):
    from credential_guard.sensitive_paths import EncodedPrivateKeyScanError

    def boom(_payload):
        raise EncodedPrivateKeyScanError("boundary")

    monkeypatch.setattr(mw, "_redact_locatable_private_keys", boom)
    out = on_llm_request(
        request={"model": "m", "messages": [{"role": "user", "content": "x"}]}
    )
    assert isinstance(out["request"], LocalBlockRequest)
    # _redact_locatable_private_keys raising EncodedPrivateKeyScanError escapes
    # to generic handler unless wrapped — production should yield scanner/config.
    code = out["request"].block_detail.code
    assert code in {"CG-SCANNER-ERROR", "CG-CONFIG-UNAVAILABLE"}


def test_config_unavailable_not_residual(monkeypatch):
    from credential_guard.runtime_config import RuntimeConfigError

    def boom():
        raise RuntimeConfigError("missing")

    monkeypatch.setattr(mw, "get_egress_registry_snapshot", boom)
    out = on_llm_request(
        request={"model": "m", "messages": [{"role": "user", "content": "x"}]}
    )
    assert isinstance(out["request"], LocalBlockRequest)
    assert out["request"].block_detail.code == "CG-CONFIG-UNAVAILABLE"


def test_collision_not_residual(monkeypatch):
    from credential_guard.redactor import RedactionCollisionError

    def boom(payload, registry, **_k):
        raise RedactionCollisionError("dict key collision", path=("messages", 0, "<key>"))

    monkeypatch.setattr(mw, "redact_payload", boom)
    out = on_llm_request(
        request={"model": "m", "messages": [{"role": "user", "content": "x"}]}
    )
    assert isinstance(out["request"], LocalBlockRequest)
    assert out["request"].block_detail.code == "CG-REDACTION-COLLISION"


def test_prompt_and_logs_zero_leak(monkeypatch, caplog):
    secret = "residual_leak_surface_decoy_011"
    get_registry().register("db", "password", secret)

    def identity(payload, registry, **_kwargs):
        return deepcopy(payload)

    monkeypatch.setattr(mw, "redact_payload", identity)
    import logging

    with caplog.at_level(logging.DEBUG, logger="credential_guard"):
        blocked = on_llm_execution(
            request={
                "model": "m",
                "messages": [{"role": "user", "content": f"use {secret}"}],
            },
            next_call=lambda req: {"ok": True},
        )
    text = blocked.choices[0].message.content
    assert secret not in text
    assert hashlib.sha256(secret.encode()).hexdigest() not in text
    assert secret not in caplog.text
    assert "use " not in text


# --- mutation load-bearing -------------------------------------------------


def test_mutation_disable_quarantine_historical_reds(monkeypatch):
    secret = "residual_mut_no_quarantine_012"
    get_registry().register("db", "password", secret)
    monkeypatch.setattr(mw, "redact_payload", _leaky_redact_reinject(secret, 1))
    monkeypatch.setattr(
        mw, "_quarantine_residual_path", lambda payload, path, finding: payload
    )
    out = on_llm_request(
        request={
            "model": "m",
            "messages": [
                {"role": "user", "content": "h"},
                {"role": "tool", "content": secret, "tool_call_id": "t"},
                {"role": "user", "content": "go"},
            ],
        }
    )
    # With quarantine disabled, must fail closed (not Provider with secret).
    if not isinstance(out["request"], LocalBlockRequest):
        assert secret in json.dumps(out["request"])
        pytest.fail("quarantine disabled must not Provider-continue cleanly")
    assert out["request"].block_detail.code == "CG-RESIDUAL-SECRET"


def test_mutation_direct_release_residual_reds(monkeypatch):
    """Skip recovery + final gate → secret on wire; zero-egress assert would RED."""
    secret = "residual_mut_direct_release_013"
    get_registry().register("db", "password", secret)

    def identity(payload, registry, **_kwargs):
        return deepcopy(payload)

    monkeypatch.setattr(mw, "redact_payload", identity)
    monkeypatch.setattr(mw, "_recover_residuals", lambda payload, registry, root: payload)
    monkeypatch.setattr(mw, "_final_residual_gate", lambda *_a, **_k: None)
    out = on_llm_request(
        request={
            "model": "m",
            "messages": [
                {"role": "tool", "content": secret, "tool_call_id": "t"},
                {"role": "user", "content": "go"},
            ],
        }
    )
    assert not isinstance(out["request"], LocalBlockRequest)
    wire = json.dumps(out["request"], ensure_ascii=False)
    assert secret in wire
    with pytest.raises(AssertionError):
        assert secret not in wire


def test_mutation_swallow_current_user_as_history_reds(monkeypatch):
    """Treat current user as history → Provider continues; current-input guard RED."""
    secret = "residual_mut_swallow_user_014"
    get_registry().register("db", "password", secret)

    def identity(payload, registry, **_kwargs):
        return deepcopy(payload)

    monkeypatch.setattr(mw, "redact_payload", identity)
    monkeypatch.setattr(mw, "_is_current_user_input_path", lambda *_a, **_k: False)
    out = on_llm_request(
        request={
            "model": "m",
            "messages": [{"role": "user", "content": f"now {secret}"}],
        }
    )
    assert not isinstance(out["request"], LocalBlockRequest)
    assert secret not in json.dumps(out["request"], ensure_ascii=False)
    with pytest.raises(AssertionError):
        assert isinstance(out["request"], LocalBlockRequest)


def test_mutation_remove_budget_cap_reds(monkeypatch):
    """E2 mutation: amplify/remove cap so over-budget case incorrectly Provider=1 → RED."""
    secrets = [
        "residual_mut_budget_015a",
        "residual_mut_budget_015b",
        "residual_mut_budget_015c",
    ]
    for i, secret in enumerate(secrets):
        get_registry().register(f"db{i}", "password", secret)
    real = redact_payload

    def leak_three(payload, registry, **_kwargs):
        out = deepcopy(real(payload, registry))
        out["messages"][1]["content"] = f"first {secrets[0]}"
        out["messages"][2]["content"] = f"second {secrets[1]}"
        out["messages"][3]["content"] = f"third {secrets[2]}"
        return out

    monkeypatch.setattr(mw, "redact_payload", leak_three)
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "start"},
            {"role": "tool", "content": f"first {secrets[0]}", "tool_call_id": "t1"},
            {"role": "tool", "content": f"second {secrets[1]}", "tool_call_id": "t2"},
            {"role": "tool", "content": f"third {secrets[2]}", "tool_call_id": "t3"},
            {"role": "user", "content": "go"},
        ],
    }

    # Production load-bearing: small cap must block before all three clear.
    monkeypatch.setattr(mw, "MAX_RESIDUAL_RECOVERY_ITERATIONS", 2)
    healthy = on_llm_request(request=deepcopy(request))
    assert isinstance(healthy["request"], LocalBlockRequest)

    # Mutation: raise cap so the same 3-residual request escapes the small-cap gate.
    monkeypatch.setattr(mw, "MAX_RESIDUAL_RECOVERY_ITERATIONS", 10**9)
    mutated = on_llm_request(request=deepcopy(request))
    assert not isinstance(mutated["request"], LocalBlockRequest)
    with pytest.raises(AssertionError):
        assert isinstance(mutated["request"], LocalBlockRequest)


def test_mutation_hash_derived_placeholder_reds(monkeypatch):
    """Hash/length-derived quarantine marker → metadata-independence assert RED."""
    secret = "residual_mut_hash_placeholder_016"
    get_registry().register("db", "password", secret)
    monkeypatch.setattr(mw, "redact_payload", _leaky_redact_reinject(secret, 1))
    digest = hashlib.sha256(secret.encode()).hexdigest()[:16]

    def hash_placeholder(payload, path, finding):
        out = deepcopy(payload)
        cur = out
        for part in path[:-1]:
            cur = cur[part]
        cur[path[-1]] = f"<Q:{digest}:{len(secret)}>"
        return out

    monkeypatch.setattr(mw, "_quarantine_residual_path", hash_placeholder)
    out = on_llm_request(
        request={
            "model": "m",
            "messages": [
                {"role": "user", "content": "h"},
                {"role": "tool", "content": secret, "tool_call_id": "t"},
                {"role": "user", "content": "go"},
            ],
        }
    )
    assert not isinstance(out["request"], LocalBlockRequest)
    wire = json.dumps(out["request"], ensure_ascii=False)
    assert digest in wire
    assert str(len(secret)) in wire
    with pytest.raises(AssertionError):
        assert digest not in wire
    with pytest.raises(AssertionError):
        assert str(len(secret)) not in wire


def test_mutation_global_map_cross_session_reds(monkeypatch):
    """E3: inject process-global map on real quarantine path; Sessions must not couple."""
    secret = "residual_mut_global_map_017"
    get_registry().register("db", "password", secret)
    monkeypatch.setattr(mw, "redact_payload", _leaky_redact_reinject(secret, 0))

    # Healthy production has no persistent/global recovery map.
    assert not hasattr(mw, "_QUARANTINE_SESSION_MAP")

    req_a = {
        "model": "m",
        "messages": [
            {"role": "tool", "content": secret, "tool_call_id": "t"},
            {"role": "user", "content": "session-a-tail"},
        ],
    }
    req_b = {
        "model": "m",
        "messages": [
            {"role": "tool", "content": secret, "tool_call_id": "t"},
            {"role": "user", "content": "session-b-tail"},
        ],
    }

    # Same canonical shape (tool residual) across sessions → identical Provider copies
    # for the quarantined tool leaf; tails remain session-specific.
    out_a1 = on_llm_request(request=deepcopy(req_a))
    out_b1 = on_llm_request(request=deepcopy(req_b))
    out_a2 = on_llm_request(request=deepcopy(req_a))
    assert not isinstance(out_a1["request"], LocalBlockRequest)
    assert not isinstance(out_b1["request"], LocalBlockRequest)
    assert out_a1["request"] == out_a2["request"]
    assert out_a1["request"]["messages"][0]["content"] == out_b1["request"]["messages"][0]["content"]
    assert out_a1["request"]["messages"][-1]["content"] == "session-a-tail"
    assert out_b1["request"]["messages"][-1]["content"] == "session-b-tail"

    # Mutation: wrap real quarantine with a process-global counter/map that makes
    # Session B's quarantine marker depend on Session A's prior recovery count.
    real_quarantine = mw._quarantine_residual_path
    poison_state = {"count": 0, "by_session_tail": {}}

    def mapped_quarantine(payload, path, finding):
        out = real_quarantine(payload, path, finding)
        poison_state["count"] += 1
        # Stamp a side-channel derived from global counter into the quarantined leaf
        # so a later session's wire differs if the global map is consulted.
        try:
            messages = out.get("messages")
            if isinstance(messages, list) and messages:
                tail = None
                for msg in reversed(messages):
                    if isinstance(msg, dict) and msg.get("role") == "user":
                        tail = msg.get("content")
                        break
                marker = f"{mw.QUARANTINED_HISTORY_MESSAGE}#g{poison_state['count']}"
                # Only mutate tool content quarantine result.
                idx = path[1] if len(path) >= 2 and isinstance(path[1], int) else 0
                if isinstance(messages[idx], dict) and messages[idx].get("role") == "tool":
                    messages[idx] = dict(messages[idx])
                    messages[idx]["content"] = marker
                    if tail is not None:
                        poison_state["by_session_tail"][tail] = marker
        except Exception:
            pass
        return out

    monkeypatch.setattr(mw, "_quarantine_residual_path", mapped_quarantine)
    # Install a visible process-global map attribute the mutation "uses".
    monkeypatch.setattr(mw, "_QUARANTINE_SESSION_MAP", poison_state, raising=False)

    mut_a = on_llm_request(request=deepcopy(req_a))
    mut_b = on_llm_request(request=deepcopy(req_b))
    assert not isinstance(mut_a["request"], LocalBlockRequest)
    assert not isinstance(mut_b["request"], LocalBlockRequest)
    # Global counter couples sessions: tool quarantine markers differ across A/B
    # even though the recoverable leaf content was identical.
    assert (
        mut_a["request"]["messages"][0]["content"]
        != mut_b["request"]["messages"][0]["content"]
    )
    # Product invariant that must RED under this mutation: identical residual leaf
    # across sessions yields identical quarantined tool content.
    with pytest.raises(AssertionError):
        assert (
            mut_a["request"]["messages"][0]["content"]
            == mut_b["request"]["messages"][0]["content"]
        )
    # Clean up marker: production module must not keep the map after test (monkeypatch).
    assert mw._QUARANTINE_SESSION_MAP is poison_state


def test_old_semantics_immediate_block_mutation_evidence(tmp_path):
    """E4: monkeypatch recovery→immediate RequestBlock; record real product-test RED counts."""
    plugin = tmp_path / "old_residual_semantics_plugin.py"
    plugin.write_text(
        "import credential_guard.middleware as mw\n"
        "from credential_guard.middleware import RequestBlock\n"
        "from credential_guard.redactor import contains_plain_secret\n"
        "\n"
        "def pytest_configure(config):\n"
        "    def old_recover(payload, registry, root):\n"
        "        findings = mw._scan_residuals(payload, registry, root)\n"
        "        if findings:\n"
        "            raise RequestBlock(mw._block_for_finding(root, findings[0]))\n"
        "        if contains_plain_secret(payload, registry):\n"
        "            raise RequestBlock(\n"
        "                mw._detail_residual('request', action_kind='unrecoverable')\n"
        "            )\n"
        "        return payload\n"
        "    mw._recover_residuals = old_recover\n",
        encoding="utf-8",
    )

    must_red = [
        "test_historical_tool_residual_auto_recovers",
        "test_historical_assistant_metadata_dynamic_key_value_recovers",
        "test_historical_extension_dynamic_key_value_recovers",
        "test_same_session_two_rounds_stable",
        "test_multiple_historical_residuals_bounded_clear",
        "test_historical_user_and_trailing_tool_recoverable",
        "test_aggregate_only_historical_recovers",
        "test_two_independent_aggregate_only_residuals_recover",
        "test_protocol_tool_call_skeleton_preserved",
    ]
    must_green = [
        "test_current_user_input_not_silently_swallowed",
        "test_system_core_residual_still_blocks",
        "test_aggregate_only_core_unrecoverable_blocks",
        "test_historical_metadata_dynamic_key_itself_fail_closed",
    ]
    node_ids = [
        f"tests/test_residual_session_recovery.py::{name}"
        for name in (must_red + must_green)
    ]
    repo_root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = (
        str(tmp_path) + os.pathsep + env.get("PYTHONPATH", "")
    ).rstrip(os.pathsep)
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--tb=no",
            "-p",
            "no:cacheprovider",
            "-p",
            "old_residual_semantics_plugin",
            *node_ids,
        ],
        cwd=str(repo_root),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    summary = None
    for line in reversed(output.splitlines()):
        if re.search(r"\d+\s+(failed|passed)", line):
            summary = line.strip()
            break
    failed_count = int(m.group(1)) if (m := re.search(r"(\d+)\s+failed", output)) else 0
    passed_count = int(m.group(1)) if (m := re.search(r"(\d+)\s+passed", output)) else 0
    failed_nodes = set(re.findall(r"FAILED .*::(test_[\w]+)", output))

    evidence = tmp_path / "old_semantics_mutation_evidence.txt"
    evidence.write_text(
        f"summary_line={summary!r}\n"
        f"failed_count={failed_count}\n"
        f"passed_count={passed_count}\n"
        f"exit_code={proc.returncode}\n"
        f"failed_nodes={sorted(failed_nodes)}\n"
        f"output:\n{output}\n",
        encoding="utf-8",
    )

    for name in must_red:
        assert name in failed_nodes, (
            f"old-semantics mutation must RED {name}; "
            f"failed={sorted(failed_nodes)} summary={summary!r}\n{output}"
        )
    for name in must_green:
        assert name not in failed_nodes, (
            f"fail-closed positive {name} must stay GREEN under old semantics; "
            f"failed={sorted(failed_nodes)} summary={summary!r}\n{output}"
        )
    assert failed_count == len(must_red), (
        f"expected exactly {len(must_red)} failed recovery products, "
        f"got failed={failed_count} passed={passed_count} summary={summary!r}\n{output}"
    )
    assert passed_count == len(must_green), (
        f"expected exactly {len(must_green)} green fail-closed positives, "
        f"got failed={failed_count} passed={passed_count} summary={summary!r}\n{output}"
    )
