"""CG-SCANNER-ERROR long-session field-level recovery (narrow TDD)."""

from __future__ import annotations

import hashlib
import json
import logging
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
from credential_guard.sensitive_paths import MAX_PRIVATE_KEY_SCAN_BYTES
from credential_guard.state import get_registry

SCANNER_QUARANTINE_MARK = "<CREDENTIAL_GUARD_SCANNER_QUARANTINED_HISTORY_FIELD>"


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


def _oversized_plain(prefix: str = "hist_scan_") -> str:
    # Plain ASCII filler: exceeds single-field scanner byte budget, no PEM markers.
    pad = "A" * (MAX_PRIVATE_KEY_SCAN_BYTES + 64)
    return prefix + pad


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


def test_s1_historical_oversized_tool_content_recovers():
    """S1: early tool content over MAX_PRIVATE_KEY_SCAN_BYTES must quarantine, not pin Session."""
    huge = _oversized_plain("tool_hist_")
    request = {
        "model": "m",
        "messages": [
            {"role": "system", "content": "sys-keep"},
            {"role": "user", "content": "please begin"},
            {
                "role": "tool",
                "name": "search_files",
                "tool_call_id": "call_hist_scan_1",
                "content": huge,
            },
            {"role": "assistant", "content": "assistant-keep"},
            {"role": "user", "content": "继续"},
        ],
    }
    original = deepcopy(request)
    pb, sent = _provider_once(request)
    assert request == original
    assert pb["messages"][0]["content"] == "sys-keep"
    assert pb["messages"][1]["content"] == "please begin"
    assert pb["messages"][3]["content"] == "assistant-keep"
    assert pb["messages"][4]["content"] == "继续"
    tool = pb["messages"][2]
    assert tool["role"] == "tool"
    assert tool["tool_call_id"] == "call_hist_scan_1"
    assert tool["name"] == "search_files"
    assert tool["content"] != huge
    assert huge not in tool["content"]
    assert (
        SCANNER_QUARANTINE_MARK in tool["content"]
        or "扫描器" in tool["content"]
        or "隔离" in tool["content"]
    )
    wire = json.dumps(sent, ensure_ascii=False)
    assert huge not in wire
    assert hashlib.sha256(huge.encode()).hexdigest() not in wire
    assert str(len(huge)) not in wire
    assert pb == sent


def test_s1_historical_oversized_assistant_content_recovers():
    """S1 sibling: early assistant content over scan budget also quarantines."""
    huge = _oversized_plain("asst_hist_")
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "start-keep"},
            {"role": "assistant", "content": huge},
            {"role": "user", "content": "继续"},
        ],
    }
    original = deepcopy(request)
    pb, sent = _provider_once(request)
    assert request == original
    assert pb["messages"][0]["content"] == "start-keep"
    assert pb["messages"][2]["content"] == "继续"
    assert huge not in pb["messages"][1]["content"]
    assert (
        SCANNER_QUARANTINE_MARK in pb["messages"][1]["content"]
        or "隔离" in pb["messages"][1]["content"]
    )
    assert huge not in json.dumps(sent, ensure_ascii=False)


def test_s2_historical_metadata_dynamic_key_value_recovers(caplog):
    """S2: oversized ordinary metadata dynamic-key VALUE quarantines; key+sibling kept."""
    huge = _oversized_plain("meta_dyn_")
    dynamic_key = "dyn_meta_scan_branch_xyz"
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "start-keep"},
            {
                "role": "assistant",
                "content": "assistant-keep",
                "metadata": {
                    "keep_sibling": "sibling-keep",
                    dynamic_key: huge,
                },
            },
            {"role": "user", "content": "继续"},
        ],
    }
    original = deepcopy(request)
    with caplog.at_level(logging.DEBUG, logger="credential_guard"):
        pb, sent = _provider_once(request)
    assert request == original
    assert pb["messages"][0]["content"] == "start-keep"
    assert pb["messages"][1]["content"] == "assistant-keep"
    assert pb["messages"][2]["content"] == "继续"
    meta = pb["messages"][1]["metadata"]
    assert meta["keep_sibling"] == "sibling-keep"
    assert dynamic_key in meta
    assert meta[dynamic_key] != huge
    assert huge not in meta[dynamic_key]
    assert (
        SCANNER_QUARANTINE_MARK in meta[dynamic_key]
        or "隔离" in str(meta[dynamic_key])
    )
    wire = json.dumps(sent, ensure_ascii=False)
    assert huge not in wire
    assert dynamic_key not in wire or dynamic_key in json.dumps(pb)
    # Public/logs must not echo dynamic key as a leak surface beyond structure.
    assert dynamic_key not in caplog.text
    digest = hashlib.sha256(huge.encode()).hexdigest()
    assert digest not in wire
    assert digest not in caplog.text


def test_s2_historical_extension_dynamic_key_value_recovers():
    """S2 sibling: extension dynamic-key VALUE over scan budget recovers."""
    huge = _oversized_plain("ext_dyn_")
    dynamic_key = "dyn_ext_scan_branch_abc"
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "start"},
            {
                "role": "tool",
                "tool_call_id": "t_ext_scan",
                "content": "tool-keep",
                "extension": {
                    "keep": "ext-sibling",
                    dynamic_key: huge,
                },
            },
            {"role": "user", "content": "继续"},
        ],
    }
    pb, sent = _provider_once(request)
    assert pb["messages"][1]["content"] == "tool-keep"
    assert pb["messages"][1]["tool_call_id"] == "t_ext_scan"
    ext = pb["messages"][1]["extension"]
    assert ext["keep"] == "ext-sibling"
    assert dynamic_key in ext
    assert huge not in ext[dynamic_key]
    assert huge not in json.dumps(sent, ensure_ascii=False)


def test_s3_historical_tool_call_arguments_recovers():
    """S3: oversized historical tool_calls arguments → fixed JSON {}, skeleton kept."""
    huge = _oversized_plain("tc_args_")
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "start-keep"},
            {
                "role": "assistant",
                "content": "calling",
                "tool_calls": [
                    {
                        "id": "call_scan_args_1",
                        "type": "function",
                        "function": {
                            "name": "run_query",
                            "arguments": huge,
                        },
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "call_scan_args_1",
                "content": "tool-result-keep",
            },
            {"role": "user", "content": "继续"},
        ],
    }
    original = deepcopy(request)
    pb, sent = _provider_once(request)
    assert request == original
    assert pb["messages"][0]["content"] == "start-keep"
    assert pb["messages"][2]["content"] == "tool-result-keep"
    assert pb["messages"][3]["content"] == "继续"
    tc = pb["messages"][1]["tool_calls"][0]
    assert tc["id"] == "call_scan_args_1"
    assert tc["type"] == "function"
    assert tc["function"]["name"] == "run_query"
    assert tc["function"]["arguments"] == "{}"
    json.loads(tc["function"]["arguments"])
    wire = json.dumps(sent, ensure_ascii=False)
    assert huge not in wire
    assert hashlib.sha256(huge.encode()).hexdigest() not in wire


def test_s4_multiple_scanner_failures_bounded_recovery(monkeypatch):
    """S4: ≥3 recoverable oversized history fields; budget < hits → 0, == hits → 1."""
    h1 = _oversized_plain("multi_a_")
    h2 = _oversized_plain("multi_b_")
    h3 = _oversized_plain("multi_c_")
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "start-keep"},
            {"role": "tool", "content": h1, "tool_call_id": "t1"},
            {"role": "assistant", "content": h2},
            {"role": "tool", "content": h3, "tool_call_id": "t2"},
            {"role": "user", "content": "继续"},
        ],
    }

    monkeypatch.setattr(mw, "MAX_RESIDUAL_RECOVERY_ITERATIONS", 2)
    out_blocked = on_llm_request(request=deepcopy(request))
    assert isinstance(out_blocked["request"], LocalBlockRequest)
    assert out_blocked["request"].block_detail.code == "CG-SCANNER-ERROR"

    monkeypatch.setattr(mw, "MAX_RESIDUAL_RECOVERY_ITERATIONS", 3)
    pb, sent = _provider_once(deepcopy(request))
    assert pb["messages"][0]["content"] == "start-keep"
    assert pb["messages"][4]["content"] == "继续"
    wire = json.dumps(sent, ensure_ascii=False)
    for huge in (h1, h2, h3):
        assert huge not in wire
    for idx in (1, 2, 3):
        body = pb["messages"][idx]["content"]
        assert (
            SCANNER_QUARANTINE_MARK in body
            or "隔离" in body
        )

    monkeypatch.setattr(mw, "MAX_RESIDUAL_RECOVERY_ITERATIONS", 4)
    pb4, sent4 = _provider_once(deepcopy(request))
    assert pb4["messages"][0]["content"] == "start-keep"
    assert all(h not in json.dumps(sent4) for h in (h1, h2, h3))


def test_s5_same_session_two_rounds_and_cross_session():
    """S5: two rounds + Session A/B identical; no global map/counter/hash derivation."""
    huge = _oversized_plain("stable_scan_")
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "earlier-keep"},
            {
                "role": "tool",
                "content": huge,
                "tool_call_id": "c_scan_stable",
            },
            {"role": "user", "content": "继续"},
        ],
    }
    original = deepcopy(request)

    def _round(canonical: dict) -> tuple[dict, dict]:
        out = on_llm_request(request=canonical)
        assert not isinstance(out["request"], LocalBlockRequest)
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

    # Explicit Session A / B (independent canonical copies).
    req_a = deepcopy(original)
    req_b = deepcopy(original)
    pb_a, sent_a = _round(req_a)
    pb_b, sent_b = _round(req_b)
    assert pb_a == pb_b
    assert sent_a == sent_b
    assert json.dumps(pb_a, sort_keys=True) == json.dumps(pb_b, sort_keys=True)


def test_s6_systemic_scanner_failure_stays_blocked(monkeypatch):
    """S6: scanner that fails on ALL inputs (incl. quarantine markers) → Provider=0."""
    from credential_guard.sensitive_paths import EncodedPrivateKeyScanError

    def boom(_text):
        raise EncodedPrivateKeyScanError("systemic scanner broken")

    monkeypatch.setattr(mw, "contains_private_key_material", boom)
    monkeypatch.setattr(
        "credential_guard.middleware.contains_private_key_material", boom
    )
    # Also poison redact_private_keys used in pre-redact walk.
    monkeypatch.setattr(
        "credential_guard.middleware.redact_private_keys",
        lambda text: (_ for _ in ()).throw(EncodedPrivateKeyScanError("systemic")),
    )

    huge = _oversized_plain("sys_fail_")
    calls: list = []
    blocked = on_llm_execution(
        request={
            "model": "m",
            "messages": [
                {"role": "user", "content": "start"},
                {"role": "tool", "content": huge, "tool_call_id": "t"},
                {"role": "user", "content": "继续"},
            ],
        },
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []
    text = blocked.choices[0].message.content
    assert is_blocked_response_content(text)
    assert "代码：CG-SCANNER-ERROR" in text
    assert "同一 Session" in text or "报告 Credential Guard Bug" in text

    # Ordinary small strings alone also must not Provider-continue under systemic boom.
    calls2: list = []
    blocked2 = on_llm_execution(
        request={
            "model": "m",
            "messages": [{"role": "user", "content": "tiny ok text"}],
        },
        next_call=lambda req: calls2.append(req) or {"ok": True},
    )
    assert calls2 == []
    assert "代码：CG-SCANNER-ERROR" in blocked2.choices[0].message.content


def test_s6_quarantine_marker_still_unscannable_blocks(monkeypatch):
    """S6 refine: after isolating history, marker/other safe fields still failing → block."""
    from credential_guard.sensitive_paths import (
        EncodedPrivateKeyScanError,
        contains_private_key_material as real_scan,
    )

    markers = {
        mw.QUARANTINED_SCANNER_HISTORY_FIELD,
        mw.QUARANTINED_SCANNER_HISTORY_MESSAGE,
        mw.QUARANTINED_HISTORY_FIELD,
        mw.QUARANTINED_HISTORY_MESSAGE,
    }

    def selective(text):
        if text in markers or len(text.encode("utf-8")) > MAX_PRIVATE_KEY_SCAN_BYTES:
            raise EncodedPrivateKeyScanError("marker or oversize")
        return real_scan(text)

    monkeypatch.setattr(mw, "contains_private_key_material", selective)
    monkeypatch.setattr(
        "credential_guard.middleware.contains_private_key_material", selective
    )

    huge = _oversized_plain("marker_fail_")
    calls: list = []
    blocked = on_llm_execution(
        request={
            "model": "m",
            "messages": [
                {"role": "user", "content": "start-keep"},
                {"role": "tool", "content": huge, "tool_call_id": "t"},
                {"role": "user", "content": "继续"},
            ],
        },
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []
    assert "代码：CG-SCANNER-ERROR" in blocked.choices[0].message.content


def _assert_scanner_blocked(request: dict, *, current_input: bool = False) -> str:
    calls: list = []
    blocked = on_llm_execution(
        request=request,
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []
    text = blocked.choices[0].message.content
    assert is_blocked_response_content(text)
    assert "代码：CG-SCANNER-ERROR" in text
    if current_input:
        assert "编辑或分段" in text
        assert "无需新建 Session" in text
    else:
        assert "同一 Session" in text or "报告 Credential Guard Bug" in text
    return text


def test_s7_current_user_oversized_stays_blocked():
    """S7: current last user content oversize → Provider=0 + edit/split hint."""
    huge = _oversized_plain("cur_user_")
    text = _assert_scanner_blocked(
        {
            "model": "m",
            "messages": [
                {"role": "user", "content": "old history ok"},
                {"role": "assistant", "content": "ack"},
                {"role": "user", "content": huge},
            ],
        },
        current_input=True,
    )
    assert huge not in text


# --- Round 2 BLOCKING regressions (must RED on Round-1 blacklist recovery) ---


def test_r2_blocking_current_user_metadata_dynamic_value_stays_blocked(caplog):
    """BLOCKING#1: current last-user metadata dynamic VALUE scanner-error → Provider=0."""
    huge = _oversized_plain("cur_meta_")
    dynamic_key = "dyn_cur_user_meta_scan_zzz"
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "earlier-keep"},
            {"role": "assistant", "content": "ack-keep"},
            {
                "role": "user",
                "content": "继续",
                "metadata": {
                    "keep_sibling": "sibling-keep",
                    dynamic_key: huge,
                },
            },
        ],
    }
    original = deepcopy(request)
    with caplog.at_level(logging.DEBUG, logger="credential_guard"):
        text = _assert_scanner_blocked(request, current_input=True)
    assert request == original
    assert huge not in text
    assert dynamic_key not in text
    assert huge not in caplog.text
    assert dynamic_key not in caplog.text
    digest = hashlib.sha256(huge.encode()).hexdigest()
    assert digest not in text
    assert digest not in caplog.text


def test_r2_blocking_current_user_unknown_field_stays_blocked(caplog):
    """BLOCKING#2: current last-user unknown field scanner-error → Provider=0."""
    huge = _oversized_plain("cur_unk_")
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "earlier-keep"},
            {"role": "assistant", "content": "ack-keep"},
            {
                "role": "user",
                "content": "继续",
                "unknown_scan_branch": huge,
            },
        ],
    }
    original = deepcopy(request)
    with caplog.at_level(logging.DEBUG, logger="credential_guard"):
        text = _assert_scanner_blocked(request, current_input=True)
    assert request == original
    assert huge not in text
    assert "unknown_scan_branch" not in text
    assert huge not in caplog.text
    assert hashlib.sha256(huge.encode()).hexdigest() not in text


def test_r2_blocking_historical_assistant_name_stays_blocked(monkeypatch, caplog):
    """BLOCKING#3: historical assistant name scanner-error → Provider=0."""
    from credential_guard.sensitive_paths import EncodedPrivateKeyScanError

    boom_name = "asst_name_scan_fail_token"
    real = mw.contains_private_key_material

    def name_boom(text):
        if text == boom_name:
            raise EncodedPrivateKeyScanError(f"name boom {boom_name}")
        return real(text)

    monkeypatch.setattr(mw, "contains_private_key_material", name_boom)
    monkeypatch.setattr(
        "credential_guard.middleware.contains_private_key_material", name_boom
    )
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "start-keep"},
            {
                "role": "assistant",
                "name": boom_name,
                "content": "assistant-keep",
            },
            {"role": "user", "content": "继续"},
        ],
    }
    original = deepcopy(request)
    with caplog.at_level(logging.DEBUG, logger="credential_guard"):
        text = _assert_scanner_blocked(request)
    assert request == original
    assert boom_name not in text
    assert boom_name not in caplog.text
    assert "name boom" not in text
    assert "name boom" not in caplog.text


def test_r2_blocking_historical_tool_name_stays_blocked(monkeypatch, caplog):
    """BLOCKING#4: historical tool name scanner-error → Provider=0."""
    from credential_guard.sensitive_paths import EncodedPrivateKeyScanError

    boom_name = "tool_name_scan_fail_token"
    real = mw.contains_private_key_material

    def name_boom(text):
        if text == boom_name:
            raise EncodedPrivateKeyScanError(f"tool name boom {boom_name}")
        return real(text)

    monkeypatch.setattr(mw, "contains_private_key_material", name_boom)
    monkeypatch.setattr(
        "credential_guard.middleware.contains_private_key_material", name_boom
    )
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "start-keep"},
            {
                "role": "tool",
                "name": boom_name,
                "tool_call_id": "call_hist_name_1",
                "content": "tool-keep",
            },
            {"role": "user", "content": "继续"},
        ],
    }
    original = deepcopy(request)
    with caplog.at_level(logging.DEBUG, logger="credential_guard"):
        text = _assert_scanner_blocked(request)
    assert request == original
    assert boom_name not in text
    assert boom_name not in caplog.text
    assert "tool name boom" not in text


def test_r2_blocking_top_level_metadata_value_stays_blocked(caplog):
    """BLOCKING#5: top-level request metadata value scanner-error → Provider=0."""
    huge = _oversized_plain("top_meta_")
    request = {
        "model": "m",
        "metadata": {"keep": "top-sibling", "dyn_top_meta_scan": huge},
        "messages": [
            {"role": "user", "content": "start-keep"},
            {"role": "assistant", "content": "ack-keep"},
            {"role": "user", "content": "继续"},
        ],
    }
    original = deepcopy(request)
    with caplog.at_level(logging.DEBUG, logger="credential_guard"):
        text = _assert_scanner_blocked(request)
    assert request == original
    assert huge not in text
    assert "dyn_top_meta_scan" not in text
    assert huge not in caplog.text
    assert hashlib.sha256(huge.encode()).hexdigest() not in text


# --- Round 3: current user = last role=user (not necessarily array tail) ---


def test_r3_current_user_oversized_with_trailing_assistant_tool_stays_blocked(caplog):
    """Round3: last user + trailing assistant/tool still current-input CG-SCANNER-ERROR."""
    huge = _oversized_plain("r3_cur_trail_")
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "early-keep"},
            {"role": "user", "content": huge},
            {"role": "assistant", "content": "retry-ack-keep"},
            {
                "role": "tool",
                "name": "search_files",
                "tool_call_id": "call_r3_trail_1",
                "content": "tool-ack-keep",
            },
        ],
    }
    original = deepcopy(request)
    with caplog.at_level(logging.DEBUG, logger="credential_guard"):
        text = _assert_scanner_blocked(request, current_input=True)
    assert request == original
    assert huge not in text
    assert huge not in caplog.text
    digest = hashlib.sha256(huge.encode()).hexdigest()
    assert digest not in text
    assert digest not in caplog.text
    assert str(len(huge)) not in text


def test_r3_earlier_oversized_user_recovers_when_newer_user_present():
    """Round3 positive: earlier oversized user is history; newer user kept (trail ok)."""
    huge = _oversized_plain("r3_hist_user_")
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": huge},
            {"role": "user", "content": "继续"},
            {"role": "assistant", "content": "assistant-keep"},
            {
                "role": "tool",
                "name": "search_files",
                "tool_call_id": "call_r3_hist_1",
                "content": "tool-keep",
            },
        ],
    }
    original = deepcopy(request)
    pb, sent = _provider_once(request)
    assert request == original
    assert pb["messages"][1]["content"] == "继续"
    assert pb["messages"][2]["content"] == "assistant-keep"
    assert pb["messages"][3]["content"] == "tool-keep"
    assert pb["messages"][3]["name"] == "search_files"
    assert pb["messages"][3]["tool_call_id"] == "call_r3_hist_1"
    assert huge not in pb["messages"][0]["content"]
    assert (
        SCANNER_QUARANTINE_MARK in pb["messages"][0]["content"]
        or "扫描器" in pb["messages"][0]["content"]
        or "隔离" in pb["messages"][0]["content"]
    )
    wire = json.dumps(sent, ensure_ascii=False)
    assert huge not in wire
    assert hashlib.sha256(huge.encode()).hexdigest() not in wire
    assert pb == sent


def test_r3_current_user_metadata_with_trailing_assistant_stays_blocked(caplog):
    """Round3: current-user metadata scanner-error stays blocked with trailing assistant."""
    huge = _oversized_plain("r3_cur_meta_")
    dynamic_key = "dyn_r3_cur_meta_scan"
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "earlier-keep"},
            {
                "role": "user",
                "content": "继续",
                "metadata": {
                    "keep_sibling": "sibling-keep",
                    dynamic_key: huge,
                },
            },
            {"role": "assistant", "content": "retry-ack-keep"},
        ],
    }
    original = deepcopy(request)
    with caplog.at_level(logging.DEBUG, logger="credential_guard"):
        text = _assert_scanner_blocked(request, current_input=True)
    assert request == original
    assert huge not in text
    assert dynamic_key not in text
    assert huge not in caplog.text
    assert dynamic_key not in caplog.text


def test_r3_current_user_unknown_with_trailing_tool_stays_blocked(caplog):
    """Round3: current-user unknown field scanner-error stays blocked with trailing tool."""
    huge = _oversized_plain("r3_cur_unk_")
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "earlier-keep"},
            {
                "role": "user",
                "content": "继续",
                "unknown_r3_scan_branch": huge,
            },
            {
                "role": "tool",
                "name": "search_files",
                "tool_call_id": "call_r3_unk_1",
                "content": "tool-ack-keep",
            },
        ],
    }
    original = deepcopy(request)
    with caplog.at_level(logging.DEBUG, logger="credential_guard"):
        text = _assert_scanner_blocked(request, current_input=True)
    assert request == original
    assert huge not in text
    assert "unknown_r3_scan_branch" not in text
    assert huge not in caplog.text
    assert hashlib.sha256(huge.encode()).hexdigest() not in text


# --- E1: role / unknown / core closed-set matrix ---


def test_e1_role_scanner_error_stays_blocked(monkeypatch):
    from credential_guard.sensitive_paths import EncodedPrivateKeyScanError

    boom = "role_scan_fail_token"
    real = mw.contains_private_key_material

    def role_boom(text):
        if text == boom:
            raise EncodedPrivateKeyScanError("role boom")
        return real(text)

    monkeypatch.setattr(mw, "contains_private_key_material", role_boom)
    monkeypatch.setattr(
        "credential_guard.middleware.contains_private_key_material", role_boom
    )
    _assert_scanner_blocked(
        {
            "model": "m",
            "messages": [
                {"role": boom, "content": "start"},
                {"role": "user", "content": "继续"},
            ],
        }
    )


def test_e1_historical_unknown_field_stays_blocked():
    huge = _oversized_plain("hist_unk_")
    _assert_scanner_blocked(
        {
            "model": "m",
            "messages": [
                {"role": "user", "content": "start-keep"},
                {
                    "role": "assistant",
                    "content": "assistant-keep",
                    "unknown_hist_scan_field": huge,
                },
                {"role": "user", "content": "继续"},
            ],
        }
    )


def test_e1_top_level_unknown_field_stays_blocked():
    huge = _oversized_plain("top_unk_")
    _assert_scanner_blocked(
        {
            "model": "m",
            "unknown_top_scan_field": huge,
            "messages": [
                {"role": "user", "content": "start-keep"},
                {"role": "user", "content": "继续"},
            ],
        }
    )


def test_s7_system_content_stays_blocked():
    huge = _oversized_plain("sys_content_")
    _assert_scanner_blocked(
        {
            "model": "m",
            "messages": [
                {"role": "system", "content": huge},
                {"role": "user", "content": "继续"},
            ],
        }
    )


def test_s7_model_and_core_protocol_stay_blocked(monkeypatch):
    from credential_guard.sensitive_paths import EncodedPrivateKeyScanError

    # Force scanner error on the model field only (core protocol).
    real = mw.contains_private_key_material

    def model_boom(text):
        if text == "evil-model-scan-fail":
            raise EncodedPrivateKeyScanError("model field boom")
        return real(text)

    monkeypatch.setattr(mw, "contains_private_key_material", model_boom)
    monkeypatch.setattr(
        "credential_guard.middleware.contains_private_key_material", model_boom
    )
    _assert_scanner_blocked(
        {
            "model": "evil-model-scan-fail",
            "messages": [{"role": "user", "content": "继续"}],
        }
    )

    # tool_call_id core field
    def id_boom(text):
        if text == "call_core_boom":
            raise EncodedPrivateKeyScanError("id boom")
        return real(text)

    monkeypatch.setattr(mw, "contains_private_key_material", id_boom)
    monkeypatch.setattr(
        "credential_guard.middleware.contains_private_key_material", id_boom
    )
    _assert_scanner_blocked(
        {
            "model": "m",
            "messages": [
                {"role": "user", "content": "start"},
                {
                    "role": "tool",
                    "tool_call_id": "call_core_boom",
                    "content": "ok",
                },
                {"role": "user", "content": "继续"},
            ],
        }
    )


def test_s7_dynamic_key_itself_stays_blocked(monkeypatch):
    from credential_guard.sensitive_paths import EncodedPrivateKeyScanError

    huge_key = _oversized_plain("dyn_key_")
    # Key scan fails in pre-redact; must Provider=0 (cannot rewrite keys).
    out = on_llm_request(
        request={
            "model": "m",
            "messages": [
                {"role": "user", "content": "start"},
                {
                    "role": "assistant",
                    "content": "ok",
                    "metadata": {huge_key: "plain-value"},
                },
                {"role": "user", "content": "继续"},
            ],
        }
    )
    assert isinstance(out["request"], LocalBlockRequest)
    assert out["request"].block_detail.code == "CG-SCANNER-ERROR"
    # Also via contains path on residual finder for key material.
    real = mw.contains_private_key_material

    def key_only_boom(text):
        if text.startswith("dyn_key_fail_"):
            raise EncodedPrivateKeyScanError("key boom")
        return real(text)

    monkeypatch.setattr(mw, "contains_private_key_material", key_only_boom)
    monkeypatch.setattr(
        "credential_guard.middleware.contains_private_key_material", key_only_boom
    )
    # Leave values scannable; key triggers scanner-error with targets_key.
    _assert_scanner_blocked(
        {
            "model": "m",
            "messages": [
                {"role": "user", "content": "start"},
                {
                    "role": "assistant",
                    "content": "ok",
                    "metadata": {"dyn_key_fail_abc": "plain"},
                },
                {"role": "user", "content": "继续"},
            ],
        }
    )


def test_s7_unlocated_request_level_scanner_error(monkeypatch):
    from credential_guard.sensitive_paths import EncodedPrivateKeyScanError

    def boom_prepare(_request):
        raise EncodedPrivateKeyScanError("unlocated request-level")

    monkeypatch.setattr(mw, "_redact_locatable_private_keys", boom_prepare)
    out = on_llm_request(
        request={"model": "m", "messages": [{"role": "user", "content": "x"}]}
    )
    assert isinstance(out["request"], LocalBlockRequest)
    assert out["request"].block_detail.code == "CG-SCANNER-ERROR"


def test_s7_variant_construction_fault_stays_blocked(monkeypatch):
    """E2: variant/registry-scan seam fault → CG-SCANNER-ERROR (not config)."""
    from credential_guard.redactor import VariantBuildError

    get_registry().register("db", "password", "variant_fault_decoy_e2_001")

    def boom_variants(*_a, **_k):
        raise VariantBuildError(
            "variant construction exploded decoy=variant_fault_decoy_e2_001"
        )

    # Registry snapshot stays healthy; only the variant construction seam fails.
    monkeypatch.setattr(mw, "collect_protected_replacements", boom_variants)
    monkeypatch.setattr(
        "credential_guard.redactor.collect_protected_replacements", boom_variants
    )
    calls: list = []
    blocked = on_llm_execution(
        request={"model": "m", "messages": [{"role": "user", "content": "继续"}]},
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []
    text = blocked.choices[0].message.content
    assert is_blocked_response_content(text)
    assert "代码：CG-SCANNER-ERROR" in text
    assert "CG-CONFIG-UNAVAILABLE" not in text
    assert "variant_fault_decoy_e2_001" not in text
    assert "variant construction exploded" not in text


def test_s8_post_isolation_scanner_error_not_residual(monkeypatch):
    """S8: after quarantine, re-scan still abnormal → CG-SCANNER-ERROR (not residual)."""
    from credential_guard.sensitive_paths import (
        EncodedPrivateKeyScanError,
        contains_private_key_material as real_scan,
    )

    markers = {
        mw.QUARANTINED_SCANNER_HISTORY_FIELD,
        mw.QUARANTINED_SCANNER_HISTORY_MESSAGE,
    }

    def selective(text):
        if text in markers:
            raise EncodedPrivateKeyScanError("post-isolation still broken")
        return real_scan(text)

    monkeypatch.setattr(mw, "contains_private_key_material", selective)
    monkeypatch.setattr(
        "credential_guard.middleware.contains_private_key_material", selective
    )
    huge = _oversized_plain("s8_scan_")
    out = on_llm_request(
        request={
            "model": "m",
            "messages": [
                {"role": "user", "content": "start"},
                {"role": "tool", "content": huge, "tool_call_id": "t"},
                {"role": "user", "content": "继续"},
            ],
        }
    )
    assert isinstance(out["request"], LocalBlockRequest)
    assert out["request"].block_detail.code == "CG-SCANNER-ERROR"


def test_s8_post_isolation_true_residual_is_residual_code(monkeypatch):
    """S8: re-scan completes and finds real residual → CG-RESIDUAL-SECRET."""
    secret = "scanner_s8_residual_decoy_001"
    get_registry().register("db", "password", secret)
    huge = _oversized_plain("s8_resid_")

    real_quarantine = mw._quarantine_residual_path

    def plant_on_current_user(payload, path, finding):
        out = real_quarantine(payload, path, finding)
        out = deepcopy(out)
        # Plant on current last user — unrecoverable residual after scanner isolation.
        out["messages"][-1]["content"] = f"继续 {secret}"
        return out

    monkeypatch.setattr(mw, "_quarantine_residual_path", plant_on_current_user)
    out = on_llm_request(
        request={
            "model": "m",
            "messages": [
                {"role": "user", "content": "early-keep"},
                {"role": "tool", "content": huge, "tool_call_id": "t"},
                {"role": "user", "content": "继续"},
            ],
        }
    )
    assert isinstance(out["request"], LocalBlockRequest)
    assert out["request"].block_detail.code == "CG-RESIDUAL-SECRET"
    prompt = on_llm_execution(
        request=out["request"], next_call=lambda req: {"ok": True}
    ).choices[0].message.content
    assert "代码：CG-RESIDUAL-SECRET" in prompt
    assert secret not in prompt


def test_s8_mutation_skip_final_gate_allows_leak_evidence(monkeypatch):
    """S8 mutation evidence: skip final gate after plant → secret escapes (gate load-bearing)."""
    secret = "scanner_s8_mut_gate_002"
    get_registry().register("db", "password", secret)
    huge = _oversized_plain("s8_mut_")
    real_quarantine = mw._quarantine_residual_path
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "early"},
            {"role": "tool", "content": huge, "tool_call_id": "t"},
            {"role": "user", "content": "继续"},
        ],
    }

    def quarantine_plant(payload, path, finding):
        out = real_quarantine(payload, path, finding)
        out = deepcopy(out)
        out["messages"][0]["content"] = f"leaked {secret}"
        return out

    # Production still blocks via recovery loop / final gate on planted residual.
    monkeypatch.setattr(mw, "_quarantine_residual_path", quarantine_plant)
    out_prod = on_llm_request(request=deepcopy(request))
    assert isinstance(out_prod["request"], LocalBlockRequest)
    assert out_prod["request"].block_detail.code == "CG-RESIDUAL-SECRET"

    def recover_stop_after_quarantine(payload, registry, root):
        findings = mw._scan_residuals(payload, registry, root)
        if not findings:
            return payload
        finding = findings[0]
        return quarantine_plant(payload, finding.path, finding)

    monkeypatch.setattr(mw, "_recover_residuals", recover_stop_after_quarantine)
    monkeypatch.setattr(mw, "_final_residual_gate", lambda *a, **k: None)
    out = on_llm_request(request=deepcopy(request))
    assert not isinstance(out["request"], LocalBlockRequest)
    wire = json.dumps(out["request"], ensure_ascii=False)
    assert secret in wire


def test_s9_prompt_and_logs_zero_leak(monkeypatch, caplog):
    """S9: exception body / decoy / dynamic key / host must not appear in prompt/logs."""
    from credential_guard.sensitive_paths import EncodedPrivateKeyScanError

    decoy = "scanner_s9_decoy_secret_SHOULD_NOT_LEAK"
    host = "evil.example.internal"
    dyn = "dyn_leak_key_zzz"
    path_hint = "/tmp/credential-guard/internal/path.pem"

    def boom(text):
        raise EncodedPrivateKeyScanError(
            f"scan failed decoy={decoy} host={host} key={dyn} path={path_hint} text={text[:20]}"
        )

    monkeypatch.setattr(mw, "contains_private_key_material", boom)
    monkeypatch.setattr(
        "credential_guard.middleware.contains_private_key_material", boom
    )
    monkeypatch.setattr(
        "credential_guard.middleware.redact_private_keys",
        lambda text: (_ for _ in ()).throw(
            EncodedPrivateKeyScanError(f"redact boom {decoy} {host}")
        ),
    )

    with caplog.at_level(logging.DEBUG, logger="credential_guard"):
        blocked = on_llm_execution(
            request={
                "model": "m",
                "messages": [
                    {"role": "user", "content": "start"},
                    {
                        "role": "assistant",
                        "content": "ok",
                        "metadata": {dyn: "value-with-" + decoy},
                    },
                    {"role": "user", "content": "继续"},
                ],
            },
            next_call=lambda req: {"ok": True},
        )
    text = blocked.choices[0].message.content
    assert is_blocked_response_content(text)
    assert "代码：CG-SCANNER-ERROR" in text
    for leak in (decoy, host, dyn, path_hint, "scan failed", "redact boom"):
        assert leak not in text
        assert leak not in caplog.text
    assert hashlib.sha256(decoy.encode()).hexdigest() not in text
    assert hashlib.sha256(decoy.encode()).hexdigest() not in caplog.text


# --- mutation load-bearing -------------------------------------------------


def test_mutation_disable_scanner_quarantine_historical_reds(monkeypatch):
    huge = _oversized_plain("mut_no_q_")
    monkeypatch.setattr(
        mw, "_quarantine_residual_path", lambda payload, path, finding: payload
    )
    out = on_llm_request(
        request={
            "model": "m",
            "messages": [
                {"role": "user", "content": "h"},
                {"role": "tool", "content": huge, "tool_call_id": "t"},
                {"role": "user", "content": "继续"},
            ],
        }
    )
    if not isinstance(out["request"], LocalBlockRequest):
        wire = json.dumps(out["request"], ensure_ascii=False)
        assert huge not in wire
        pytest.fail("quarantine disabled must not Provider-continue with oversize field")


def test_mutation_skip_rescan_after_quarantine_reds(monkeypatch):
    """Skip root re-scan after quarantine → systemic/marker failure would be missed."""
    from credential_guard.sensitive_paths import (
        EncodedPrivateKeyScanError,
        contains_private_key_material as real_scan,
    )

    markers = {
        mw.QUARANTINED_SCANNER_HISTORY_FIELD,
        mw.QUARANTINED_SCANNER_HISTORY_MESSAGE,
    }

    def selective(text):
        if text in markers or len(text.encode("utf-8")) > MAX_PRIVATE_KEY_SCAN_BYTES:
            raise EncodedPrivateKeyScanError("marker/oversize")
        return real_scan(text)

    monkeypatch.setattr(mw, "contains_private_key_material", selective)
    monkeypatch.setattr(
        "credential_guard.middleware.contains_private_key_material", selective
    )

    def recover_no_rescan(payload, registry, root):
        # Quarantine once then return without proving cleanliness.
        findings = mw._scan_residuals(payload, registry, root)
        if not findings:
            return payload
        finding = findings[0]
        return mw._quarantine_residual_path(payload, finding.path, finding)

    huge = _oversized_plain("mut_no_rescan_")
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "start"},
            {"role": "tool", "content": huge, "tool_call_id": "t"},
            {"role": "user", "content": "继续"},
        ],
    }
    # Production blocks (marker unscannable).
    out_prod = on_llm_request(request=deepcopy(request))
    assert isinstance(out_prod["request"], LocalBlockRequest)
    assert out_prod["request"].block_detail.code == "CG-SCANNER-ERROR"

    monkeypatch.setattr(mw, "_recover_residuals", recover_no_rescan)
    monkeypatch.setattr(mw, "_final_residual_gate", lambda *a, **k: None)
    out = on_llm_request(request=deepcopy(request))
    # Mutation evidence: Provider continues without re-proving marker safety.
    assert not isinstance(out["request"], LocalBlockRequest)


def test_mutation_global_map_couples_sessions(monkeypatch):
    huge = _oversized_plain("mut_map_")
    real_quarantine = mw._quarantine_residual_path
    counter = {"n": 0}

    def mapped_quarantine(payload, path, finding):
        out = real_quarantine(payload, path, finding)
        counter["n"] += 1
        out = deepcopy(out)
        # Stamp global counter into quarantined tool content.
        if (
            isinstance(out, dict)
            and isinstance(out.get("messages"), list)
            and len(out["messages"]) > 1
            and isinstance(out["messages"][1], dict)
        ):
            out["messages"][1]["content"] = (
                f"{mw.QUARANTINED_SCANNER_HISTORY_MESSAGE}#{counter['n']}"
            )
        return out

    monkeypatch.setattr(mw, "_quarantine_residual_path", mapped_quarantine)
    req = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "a"},
            {"role": "tool", "content": huge, "tool_call_id": "t"},
            {"role": "user", "content": "继续"},
        ],
    }
    pb_a, _ = _provider_once(deepcopy(req))
    pb_b, _ = _provider_once(deepcopy(req))
    # Global counter couples sessions — markers differ (mutation evidence).
    assert pb_a["messages"][1]["content"] != pb_b["messages"][1]["content"]


def test_mutation_no_budget_infinite_progress_guard(monkeypatch):
    """Budget=0 must fail closed (off-by-one / unbounded loop guard)."""
    monkeypatch.setattr(mw, "MAX_RESIDUAL_RECOVERY_ITERATIONS", 0)
    huge = _oversized_plain("mut_budget0_")
    out = on_llm_request(
        request={
            "model": "m",
            "messages": [
                {"role": "user", "content": "start"},
                {"role": "tool", "content": huge, "tool_call_id": "t"},
                {"role": "user", "content": "继续"},
            ],
        }
    )
    assert isinstance(out["request"], LocalBlockRequest)
    assert out["request"].block_detail.code == "CG-SCANNER-ERROR"


def test_e3_budget_cap_load_bearing_mutation_reds(monkeypatch):
    """E3: three recoverable fields — cap=2 blocks, cap=3 allows; bypass → RED evidence."""
    h1 = _oversized_plain("e3_a_")
    h2 = _oversized_plain("e3_b_")
    h3 = _oversized_plain("e3_c_")
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "start-keep"},
            {"role": "tool", "content": h1, "tool_call_id": "t1"},
            {"role": "assistant", "content": h2},
            {"role": "tool", "content": h3, "tool_call_id": "t2"},
            {"role": "user", "content": "继续"},
        ],
    }

    monkeypatch.setattr(mw, "MAX_RESIDUAL_RECOVERY_ITERATIONS", 2)
    out_cap2 = on_llm_request(request=deepcopy(request))
    assert isinstance(out_cap2["request"], LocalBlockRequest)
    assert out_cap2["request"].block_detail.code == "CG-SCANNER-ERROR"

    monkeypatch.setattr(mw, "MAX_RESIDUAL_RECOVERY_ITERATIONS", 3)
    pb3, sent3 = _provider_once(deepcopy(request))
    assert pb3["messages"][0]["content"] == "start-keep"
    assert pb3["messages"][4]["content"] == "继续"
    wire3 = json.dumps(sent3, ensure_ascii=False)
    for huge in (h1, h2, h3):
        assert huge not in wire3

    # Mutation: ignore advertised cap=2 by unbounded recover — must wrongly allow.
    real_recover = mw._recover_residuals

    def recover_bypass_budget(payload, registry, root):
        saved = mw.MAX_RESIDUAL_RECOVERY_ITERATIONS
        mw.MAX_RESIDUAL_RECOVERY_ITERATIONS = 10**9
        try:
            return real_recover(payload, registry, root)
        finally:
            mw.MAX_RESIDUAL_RECOVERY_ITERATIONS = saved

    monkeypatch.setattr(mw, "MAX_RESIDUAL_RECOVERY_ITERATIONS", 2)
    monkeypatch.setattr(mw, "_recover_residuals", recover_bypass_budget)
    out_mut = on_llm_request(request=deepcopy(request))
    assert not isinstance(out_mut["request"], LocalBlockRequest), (
        "budget bypass mutation must wrongly Provider-continue under cap=2"
    )


def test_mutation_misclassify_scanner_as_residual_reds(monkeypatch):
    """Error-code confusion: scanner findings must not become CG-RESIDUAL-SECRET."""
    real_block = mw._block_for_finding

    def confuse(root, finding):
        detail = real_block(root, finding)
        if finding.kind == "scanner-error":
            return mw._detail_residual(detail.location, action_kind="unrecoverable")
        return detail

    monkeypatch.setattr(mw, "_block_for_finding", confuse)
    huge = _oversized_plain("mut_code_")
    # Current user oversize → should be scanner; mutation makes residual.
    out = on_llm_request(
        request={
            "model": "m",
            "messages": [{"role": "user", "content": huge}],
        }
    )
    assert isinstance(out["request"], LocalBlockRequest)
    assert out["request"].block_detail.code == "CG-RESIDUAL-SECRET"


def test_mutation_allowlist_default_allow_reds(monkeypatch):
    """Allowlist → default-allow: current-user metadata wrongly Provider-continues."""
    monkeypatch.setattr(mw, "_is_approved_scanner_recovery_path", lambda *_a, **_k: True)
    huge = _oversized_plain("mut_al_meta_")
    out = on_llm_request(
        request={
            "model": "m",
            "messages": [
                {"role": "user", "content": "earlier"},
                {
                    "role": "user",
                    "content": "继续",
                    "metadata": {"dyn_mut_al": huge},
                },
            ],
        }
    )
    assert not isinstance(out["request"], LocalBlockRequest)


def test_mutation_current_user_index_array_tail_only_reds(monkeypatch):
    """Round3 mutation: restore array-tail-only current-user → trailing trail wrongly Provider=1."""

    def old_array_tail_only_current_user(root):
        if not isinstance(root, dict):
            return None
        messages = root.get("messages")
        if not isinstance(messages, (list, tuple)) or not messages:
            return None
        last = len(messages) - 1
        msg = messages[last]
        if isinstance(msg, dict) and msg.get("role") == "user":
            return last
        return None

    monkeypatch.setattr(mw, "_current_user_input_index", old_array_tail_only_current_user)
    huge = _oversized_plain("mut_r3_tail_")
    out = on_llm_request(
        request={
            "model": "m",
            "messages": [
                {"role": "user", "content": "early"},
                {"role": "user", "content": huge},
                {"role": "assistant", "content": "ack"},
                {
                    "role": "tool",
                    "name": "search_files",
                    "tool_call_id": "call_mut_r3_1",
                    "content": "tool-ack",
                },
            ],
        }
    )
    # Under Round2 tail-only semantics this wrongly continues; product gate must RED.
    assert not isinstance(out["request"], LocalBlockRequest)


def test_mutation_allowlist_name_and_top_metadata_reds(monkeypatch):
    """Allowlist → blacklist invert: name + top-level metadata wrongly recover."""
    from credential_guard.sensitive_paths import EncodedPrivateKeyScanError

    def old_blacklist_allow(payload, path):
        # Round-1 style: exclude few cores; default recover (incl. name / top metadata).
        if not path:
            return False
        if path[0] == "model":
            return False
        if path[0] == "metadata":
            return True
        if path[0] != "messages" or len(path) < 2 or not isinstance(path[1], int):
            return False
        if len(path) >= 3 and path[2] in {"role", "tool_call_id"}:
            return False
        if len(path) >= 3 and path[2] == "tool_calls" and "arguments" not in path:
            return False
        cur = mw._current_user_input_index(payload)
        if (
            cur is not None
            and len(path) >= 3
            and path[1] == cur
            and path[2] == "content"
        ):
            return False
        return True

    monkeypatch.setattr(mw, "_is_approved_scanner_recovery_path", old_blacklist_allow)

    boom_name = "mut_name_scan_fail"
    real = mw.contains_private_key_material

    def name_boom(text):
        if text == boom_name:
            raise EncodedPrivateKeyScanError("mut name boom")
        return real(text)

    monkeypatch.setattr(mw, "contains_private_key_material", name_boom)
    monkeypatch.setattr(
        "credential_guard.middleware.contains_private_key_material", name_boom
    )
    out_name = on_llm_request(
        request={
            "model": "m",
            "messages": [
                {"role": "user", "content": "start"},
                {"role": "assistant", "name": boom_name, "content": "ok"},
                {"role": "user", "content": "继续"},
            ],
        }
    )
    assert not isinstance(out_name["request"], LocalBlockRequest)

    huge = _oversized_plain("mut_top_meta_")
    # Restore real scanner for oversize top-level metadata value.
    monkeypatch.setattr(mw, "contains_private_key_material", real)
    monkeypatch.setattr(
        "credential_guard.middleware.contains_private_key_material", real
    )
    out_top = on_llm_request(
        request={
            "model": "m",
            "metadata": {"dyn_mut_top": huge},
            "messages": [{"role": "user", "content": "继续"}],
        }
    )
    assert not isinstance(out_top["request"], LocalBlockRequest)


def test_mutation_variant_fault_misclassified_as_config_reds(monkeypatch):
    """E2 mutation: variant seam fault reported as config → code confusion RED evidence."""
    from credential_guard.redactor import VariantBuildError

    get_registry().register("db", "password", "mut_variant_cfg_decoy")

    def boom_variants(*_a, **_k):
        raise VariantBuildError("mut variant boom")

    monkeypatch.setattr(mw, "collect_protected_replacements", boom_variants)
    monkeypatch.setattr(
        "credential_guard.redactor.collect_protected_replacements", boom_variants
    )
    real_prepare = mw._prepare_provider_bound

    def prepare_confuse(request):
        try:
            return real_prepare(request)
        except mw.RequestBlock as rb:
            if rb.detail.code == "CG-SCANNER-ERROR":
                raise mw.RequestBlock(mw._config_unavailable_detail()) from None
            raise

    monkeypatch.setattr(mw, "_prepare_provider_bound", prepare_confuse)
    out = on_llm_request(
        request={"model": "m", "messages": [{"role": "user", "content": "x"}]}
    )
    assert isinstance(out["request"], LocalBlockRequest)
    assert out["request"].block_detail.code == "CG-CONFIG-UNAVAILABLE"


def test_old_scanner_semantics_immediate_block_mutation_evidence(tmp_path):
    """单因素旧语义 mutation：字段 scanner-error 立即 RequestBlock（非精确历史 revision 回放）。"""
    plugin = tmp_path / "old_scanner_semantics_plugin.py"
    plugin.write_text(
        "import credential_guard.middleware as mw\n"
        "from credential_guard.middleware import RequestBlock\n"
        "from credential_guard.sensitive_paths import (\n"
        "    EncodedPrivateKeyScanError,\n"
        "    contains_private_key_material,\n"
        ")\n"
        "\n"
        "def pytest_configure(config):\n"
        "    def old_redact(payload):\n"
        "        def walk(node, path=()):\n"
        "            if isinstance(node, str):\n"
        "                try:\n"
        "                    contains_private_key_material(node)\n"
        "                except EncodedPrivateKeyScanError:\n"
        "                    raise RequestBlock(\n"
        "                        mw._detail_scanner_error(\n"
        "                            mw.humanize_location(payload, path)\n"
        "                        )\n"
        "                    ) from None\n"
        "                return node\n"
        "            if isinstance(node, dict):\n"
        "                return {\n"
        "                    k: walk(v, path + (mw._path_segment(k),))\n"
        "                    for k, v in node.items()\n"
        "                }\n"
        "            if isinstance(node, list):\n"
        "                return [walk(v, path + (i,)) for i, v in enumerate(node)]\n"
        "            if isinstance(node, tuple):\n"
        "                return tuple(\n"
        "                    walk(v, path + (i,)) for i, v in enumerate(node)\n"
        "                )\n"
        "            return node\n"
        "        return walk(payload, ())\n"
        "\n"
        "    def old_recover(payload, registry, root):\n"
        "        findings = mw._scan_residuals(payload, registry, root)\n"
        "        if findings:\n"
        "            finding = findings[0]\n"
        "            if finding.kind == 'scanner-error':\n"
        "                raise RequestBlock(finding.detail)\n"
        "            raise RequestBlock(mw._block_for_finding(root, finding))\n"
        "        return payload\n"
        "\n"
        "    mw._redact_locatable_private_keys = old_redact\n"
        "    mw._recover_residuals = old_recover\n",
        encoding="utf-8",
    )

    must_red = [
        "test_s1_historical_oversized_tool_content_recovers",
        "test_s1_historical_oversized_assistant_content_recovers",
        "test_s2_historical_metadata_dynamic_key_value_recovers",
        "test_s2_historical_extension_dynamic_key_value_recovers",
        "test_s3_historical_tool_call_arguments_recovers",
        "test_s5_same_session_two_rounds_and_cross_session",
    ]
    must_green = [
        # Fail-closed positives that remain Provider=0 under immediate-block semantics.
        # (Current-user action text differs under old pre-redact raise; covered by S7 product.)
        "test_s6_systemic_scanner_failure_stays_blocked",
        "test_s7_system_content_stays_blocked",
        "test_s7_unlocated_request_level_scanner_error",
    ]
    node_ids = [
        f"tests/test_scanner_error_session_recovery.py::{name}"
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
            "old_scanner_semantics_plugin",
            *node_ids,
        ],
        cwd=str(repo_root),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    failed_nodes = set(re.findall(r"FAILED .*::(test_[\w]+)", output))
    failed_count = int(m.group(1)) if (m := re.search(r"(\d+)\s+failed", output)) else 0
    passed_count = int(m.group(1)) if (m := re.search(r"(\d+)\s+passed", output)) else 0

    for name in must_red:
        assert name in failed_nodes, (
            f"old-scanner mutation must RED {name}; "
            f"failed={sorted(failed_nodes)}\n{output}"
        )
    for name in must_green:
        assert name not in failed_nodes, (
            f"fail-closed positive {name} must stay GREEN; "
            f"failed={sorted(failed_nodes)}\n{output}"
        )
    assert failed_count >= len(must_red)
    assert passed_count >= len(must_green)
