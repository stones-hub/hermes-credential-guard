"""Ordinary dynamic key collision → unique safe keys → continue (narrow TDD)."""

from __future__ import annotations

import hashlib
import json
import os
import re
from copy import deepcopy
from typing import Any, List, Set
from urllib.parse import quote

import pytest

from credential_guard.middleware import (
    LocalBlockRequest,
    on_llm_execution,
    on_llm_request,
)
from credential_guard.redactor import RedactionCollisionError, redact_payload
from credential_guard.registry import CredentialRegistry
from credential_guard.state import get_registry

SAFE_KEY_RE = re.compile(r"^<REDACTED_SENSITIVE_KEY_(\d+)>$")
FIXED_SAFE_KEY_1 = "<REDACTED_SENSITIVE_KEY_1>"
FIXED_SAFE_KEY_2 = "<REDACTED_SENSITIVE_KEY_2>"
FIXED_SAFE_KEY_3 = "<REDACTED_SENSITIVE_KEY_3>"


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
    assert not isinstance(out["request"], LocalBlockRequest)
    calls: list = []
    result = on_llm_execution(
        request=out["request"],
        next_call=lambda req: calls.append(deepcopy(req)) or {"ok": True},
    )
    assert result == {"ok": True}
    assert len(calls) == 1
    return out["request"], calls[0]


def _assert_unique_safe_keys(obj: dict, *, values: list) -> list[str]:
    keys = list(obj.keys())
    assert len(keys) == len(values)
    assert len(set(keys)) == len(keys)
    for key in keys:
        assert SAFE_KEY_RE.fullmatch(key), key
    for key, expected in zip(keys, values):
        assert obj[key] == expected
    return keys


def _assert_surface_anonymous_keys(keys: list[str], *, secret: str, token: str) -> None:
    """Old surface checks — insufficient alone against hash-derived keys."""
    for key in keys:
        assert SAFE_KEY_RE.fullmatch(key), key
        assert secret not in key
        assert token not in key
        assert "cg_" not in key
        assert str(len(secret)) not in key
        assert str(len(token)) not in key


def _collision_pair_keys(secret: str, *, occupied_prefix: dict | None = None):
    """Register secret, collide plain+token keys, return (keys, values, token)."""
    registry = CredentialRegistry()
    item = registry.register("db", "password", secret)
    payload: dict = {}
    if occupied_prefix:
        payload.update(occupied_prefix)
    payload[secret] = "value-A"
    payload[item.token] = "value-B"
    out = redact_payload(payload, registry)
    dynamic = {k: v for k, v in out.items() if k not in (occupied_prefix or {})}
    keys = list(dynamic.keys())
    values = list(dynamic.values())
    return keys, values, item.token, out


def _sha256_mutation_safe_key(original_key: Any, occupied: Set[str], forbid: Set[str]) -> str:
    """Single-factor mutation: derive placeholder solely from SHA-256(original).

    Skips candidates that accidentally embed forbid substrings (e.g. raw lengths)
    so old length assertions stay green and do not steal the RED signal.
    """
    raw = (
        original_key.encode("utf-8")
        if isinstance(original_key, str)
        else str(original_key).encode("utf-8")
    )
    digest = hashlib.sha256(raw).hexdigest()
    for width in range(8, 18):
        for start in range(0, 64 - width):
            base = int(digest[start : start + width], 16)
            for delta in range(0, 500):
                candidate = f"<REDACTED_SENSITIVE_KEY_{base + delta}>"
                if candidate in occupied:
                    continue
                if any(frag in candidate for frag in forbid):
                    continue
                if SAFE_KEY_RE.fullmatch(candidate) is None:
                    continue
                occupied.add(candidate)
                return candidate
    raise RuntimeError("sha256 mutation could not allocate a single-factor key")


def _install_sha256_derived_safe_key_mutation(monkeypatch):
    """Replace upper collision rename path — allocator has no original keys."""
    import credential_guard.redactor as redactor

    def mutated_redact_payload(payload, registry, *, _path=()):
        if isinstance(payload, str):
            return redactor.redact_text(payload, registry)
        if isinstance(payload, dict):
            prepared: List = []
            for key, value in payload.items():
                if isinstance(key, str):
                    new_key = redactor.redact_text(key, registry)
                    if key in redactor._CORE_PROTOCOL_KEYS and new_key != key:
                        raise RedactionCollisionError(
                            "dict key collision after redaction",
                            path=_path + ("<key>",),
                        )
                else:
                    new_key = key
                child_path = _path + (redactor._path_segment(key),)
                prepared.append(
                    (
                        key,
                        new_key,
                        mutated_redact_payload(value, registry, _path=child_path),
                    )
                )

            groups: dict = {}
            for idx, (_orig_key, new_key, _value) in enumerate(prepared):
                groups.setdefault(new_key, []).append(idx)

            final_keys: List = [None] * len(prepared)
            rename_indices: List[int] = []
            for _new_key, indices in groups.items():
                if len(indices) == 1:
                    final_keys[indices[0]] = prepared[indices[0]][1]
                    continue
                core_idxs = [
                    i
                    for i in indices
                    if isinstance(prepared[i][0], str)
                    and prepared[i][0] in redactor._CORE_PROTOCOL_KEYS
                ]
                non_core_idxs = [i for i in indices if i not in set(core_idxs)]
                if len(core_idxs) > 1:
                    raise RedactionCollisionError(
                        "dict key collision after redaction",
                        path=_path + ("<key>",),
                    )
                if core_idxs:
                    ci = core_idxs[0]
                    orig_core, new_core, _val = prepared[ci]
                    if new_core != orig_core:
                        raise RedactionCollisionError(
                            "dict key collision after redaction",
                            path=_path + ("<key>",),
                        )
                    final_keys[ci] = orig_core
                    rename_indices.extend(non_core_idxs)
                else:
                    rename_indices.extend(indices)

            occupied = {key for key in final_keys if key is not None}
            rename_indices.sort()
            # MUTATION: content-hash keys (not sequential allocate).
            forbid = {
                str(len(prepared[i][0]))
                for i in rename_indices
                if isinstance(prepared[i][0], str)
            }
            for idx in rename_indices:
                final_keys[idx] = _sha256_mutation_safe_key(
                    prepared[idx][0], occupied, forbid
                )

            out: dict = {}
            for idx, (_orig_key, _new_key, value) in enumerate(prepared):
                final_key = final_keys[idx]
                if final_key in out:
                    raise RedactionCollisionError(
                        "dict key collision after redaction",
                        path=_path + ("<key>",),
                    )
                out[final_key] = value
            return out
        if isinstance(payload, list):
            return [
                mutated_redact_payload(item, registry, _path=_path + (idx,))
                for idx, item in enumerate(payload)
            ]
        if isinstance(payload, tuple):
            return tuple(
                mutated_redact_payload(item, registry, _path=_path + (idx,))
                for idx, item in enumerate(payload)
            )
        return payload

    monkeypatch.setattr(redactor, "redact_payload", mutated_redact_payload)
    monkeypatch.setattr(
        "credential_guard.middleware.redact_payload", mutated_redact_payload
    )
    return mutated_redact_payload


def test_plain_and_token_key_collision_continues_with_unique_safe_keys():
    """已登记凭证明文键 + token 键碰撞 → Provider=1，两值保留，全匿名。"""
    secret = "COLLIDE_PLAIN_TOKEN_SECRET_001"
    item = get_registry().register("db", "password", secret)
    request = {
        "model": "m",
        "messages": [
            {"role": "system", "content": "sys-keep"},
            {"role": "user", "content": "long-task-keep"},
            {
                "role": "assistant",
                "content": "progress-keep",
                "metadata": {secret: "value-A", item.token: "value-B"},
            },
        ],
    }
    original = deepcopy(request)
    provider_bound, sent = _provider_once(request)

    meta = provider_bound["messages"][2]["metadata"]
    keys = _assert_unique_safe_keys(meta, values=["value-A", "value-B"])
    assert keys == ["<REDACTED_SENSITIVE_KEY_1>", "<REDACTED_SENSITIVE_KEY_2>"]

    blob = json.dumps(sent, ensure_ascii=False)
    assert secret not in blob
    assert item.token not in blob
    assert secret not in json.dumps(list(meta.keys()), ensure_ascii=False)
    assert item.token not in json.dumps(list(meta.keys()), ensure_ascii=False)
    assert provider_bound["messages"][0]["content"] == "sys-keep"
    assert provider_bound["messages"][1]["content"] == "long-task-keep"
    assert provider_bound["messages"][2]["content"] == "progress-keep"
    assert request == original
    assert secret in request["messages"][2]["metadata"]
    assert item.token in request["messages"][2]["metadata"]


def test_two_variant_keys_normalize_then_continue():
    """两种同一凭证变体键归一后碰撞 → 继续，值全保留。"""
    secret = "collide_var_secret_AAA/+"
    item = get_registry().register("db", "password", secret)
    encoded = quote(secret, safe="")
    assert encoded != secret
    assert redact_payload({encoded: "x"}, get_registry())[item.token] == "x"

    payload = {secret: "keep-plain", encoded: "keep-encoded", "other": "ctx"}
    original = deepcopy(payload)
    out = redact_payload(payload, get_registry())
    assert payload == original
    assert out["other"] == "ctx"
    dynamic = {k: v for k, v in out.items() if k != "other"}
    _assert_unique_safe_keys(dynamic, values=["keep-plain", "keep-encoded"])
    flat = json.dumps(out, ensure_ascii=False)
    assert secret not in flat
    assert encoded not in flat
    assert item.token not in flat


def test_metadata_collision_preserves_other_messages():
    secret = "META_COLLIDE_SECRET_002"
    item = get_registry().register("db", "password", secret)
    request = {
        "model": "m",
        "messages": [
            {"role": "user", "content": "context-before"},
            {"role": "assistant", "content": "assistant-keep"},
            {"role": "user", "content": "context-after"},
        ],
        "metadata": {secret: "m-a", item.token: "m-b", "trace": "keep-trace"},
    }
    provider_bound, _sent = _provider_once(request)
    assert provider_bound["messages"][0]["content"] == "context-before"
    assert provider_bound["messages"][1]["content"] == "assistant-keep"
    assert provider_bound["messages"][2]["content"] == "context-after"
    assert provider_bound["metadata"]["trace"] == "keep-trace"
    dynamic = {
        k: v for k, v in provider_bound["metadata"].items() if k != "trace"
    }
    _assert_unique_safe_keys(dynamic, values=["m-a", "m-b"])


def test_nested_tool_result_object_collision_same_session_continues():
    """历史工具结果嵌套普通对象碰撞 → 同 Session 继续。"""
    secret = "TOOL_NEST_COLLIDE_SECRET_003"
    item = get_registry().register("db", "password", secret)
    request = {
        "model": "m",
        "messages": [
            {"role": "system", "content": "sys-ctx"},
            {"role": "user", "content": "do long job"},
            {"role": "assistant", "content": "calling tool"},
            {
                "role": "tool",
                "name": "fetch_api",
                "tool_call_id": "call_1",
                "content": {
                    "ok": True,
                    "payload": {secret: "nest-A", item.token: "nest-B"},
                    "note": "history-keep",
                },
            },
            {"role": "user", "content": "continue please"},
        ],
    }
    original = deepcopy(request)
    provider_bound, sent = _provider_once(request)
    nested = provider_bound["messages"][3]["content"]["payload"]
    _assert_unique_safe_keys(nested, values=["nest-A", "nest-B"])
    assert provider_bound["messages"][3]["content"]["note"] == "history-keep"
    assert provider_bound["messages"][3]["content"]["ok"] is True
    assert provider_bound["messages"][4]["content"] == "continue please"
    assert provider_bound["messages"][0]["content"] == "sys-ctx"
    blob = json.dumps(sent, ensure_ascii=False)
    assert secret not in blob
    assert item.token not in blob
    assert request == original


def test_same_session_twice_stable_provider_bound():
    secret = "STABLE_COLLIDE_SECRET_004"
    item = get_registry().register("db", "password", secret)
    request = {
        "model": "m",
        "messages": [
            {
                "role": "user",
                "content": "turn",
                "metadata": {secret: "A", item.token: "B"},
            }
        ],
    }
    original = deepcopy(request)
    pb1, sent1 = _provider_once(request)
    assert request == original
    pb2, sent2 = _provider_once(request)
    assert request == original
    assert pb1 == pb2
    assert sent1 == sent2
    keys = list(pb1["messages"][0]["metadata"].keys())
    assert keys == ["<REDACTED_SENSITIVE_KEY_1>", "<REDACTED_SENSITIVE_KEY_2>"]


def test_preexisting_safe_key_skips_occupied_number():
    secret = "SKIP_NUM_COLLIDE_SECRET_005"
    item = get_registry().register("db", "password", secret)
    payload = {
        "<REDACTED_SENSITIVE_KEY_1>": "occupied",
        secret: "A",
        item.token: "B",
    }
    original = deepcopy(payload)
    out = redact_payload(payload, get_registry())
    assert payload == original
    assert out["<REDACTED_SENSITIVE_KEY_1>"] == "occupied"
    assigned = [k for k in out if k != "<REDACTED_SENSITIVE_KEY_1>"]
    assert assigned == [
        "<REDACTED_SENSITIVE_KEY_2>",
        "<REDACTED_SENSITIVE_KEY_3>",
    ]
    assert out["<REDACTED_SENSITIVE_KEY_2>"] == "A"
    assert out["<REDACTED_SENSITIVE_KEY_3>"] == "B"


def test_collision_group_must_not_keep_token_key():
    """仅改第二个键、保留第一个 token 键 → 必须 RED。"""
    secret = "NO_KEEP_TOKEN_SECRET_006"
    item = get_registry().register("db", "password", secret)
    out = redact_payload({secret: "A", item.token: "B"}, get_registry())
    for key in out:
        assert key != item.token
        assert secret not in key
        assert SAFE_KEY_RE.fullmatch(key)


def test_collision_keys_must_be_distinct():
    secret = "DISTINCT_SAFE_KEY_SECRET_007"
    item = get_registry().register("db", "password", secret)
    out = redact_payload({secret: "A", item.token: "B"}, get_registry())
    assert len(out) == 2
    assert len(set(out.keys())) == 2
    assert list(out.values()) == ["A", "B"]


def test_safe_key_must_not_embed_secret_token_hash_or_length():
    secret = "META_LEAK_COLLIDE_SECRET_008"
    item = get_registry().register("db", "password", secret)
    out = redact_payload({secret: "A", item.token: "B"}, get_registry())
    for key in out:
        assert SAFE_KEY_RE.fullmatch(key)
        assert secret not in key
        assert item.token not in key
        assert "cg_" not in key
        assert str(len(secret)) not in key
        assert str(len(item.token)) not in key


def test_safe_keys_are_content_independent_fixed_sequence():
    """占位键严格顺序编号，与敏感键内容无关（机械门禁，非宽泛 regex）。"""
    secret_a = "HASHGATE_PLAIN_ALPHA_ONE"
    secret_b = "HASHGATE_PLAIN_BETA_TWO_DIFFERENT_CHARS_ZZ"
    assert secret_a != secret_b
    assert len(secret_a) != len(secret_b)

    keys_a, values_a, token_a, _ = _collision_pair_keys(secret_a)
    keys_b, values_b, token_b, _ = _collision_pair_keys(secret_b)

    assert keys_a == [FIXED_SAFE_KEY_1, FIXED_SAFE_KEY_2]
    assert keys_b == [FIXED_SAFE_KEY_1, FIXED_SAFE_KEY_2]
    assert keys_a == keys_b
    assert values_a == ["value-A", "value-B"]
    assert values_b == ["value-A", "value-B"]
    assert token_a != secret_a and token_b != secret_b
    _assert_surface_anonymous_keys(keys_a, secret=secret_a, token=token_a)
    _assert_surface_anonymous_keys(keys_b, secret=secret_b, token=token_b)


def test_safe_keys_stable_across_length_charset_and_encoding():
    """不同长度/字符/编码变体 → 键集合与值顺序仍为固定顺序编号。"""
    samples = [
        "LEN8key!",  # min length
        "unicode短密钥内容甲乙丙丁戊己",
        "ENCODED_VARIANT_BASE_SECRET_QQQ/+",
    ]
    encoded = quote(samples[2], safe="")
    assert encoded != samples[2]
    samples.append(encoded)

    expected_keys = [FIXED_SAFE_KEY_1, FIXED_SAFE_KEY_2]
    for secret in samples:
        keys, values, token, _ = _collision_pair_keys(secret)
        assert keys == expected_keys
        assert values == ["value-A", "value-B"]
        _assert_surface_anonymous_keys(keys, secret=secret, token=token)


def test_occupied_skip_depends_only_on_numbers_not_secret_content():
    """已有占位符时，避让只由占用编号决定，与敏感键内容无关。"""
    occupied = {FIXED_SAFE_KEY_1: "occupied"}
    secret_a = "OCCUPY_SKIP_CONTENT_AAA_001"
    secret_b = "OCCUPY_SKIP_CONTENT_BBB_VERY_DIFFERENT_999"
    keys_a, values_a, token_a, out_a = _collision_pair_keys(
        secret_a, occupied_prefix=occupied
    )
    keys_b, values_b, token_b, out_b = _collision_pair_keys(
        secret_b, occupied_prefix=occupied
    )
    assert out_a[FIXED_SAFE_KEY_1] == "occupied"
    assert out_b[FIXED_SAFE_KEY_1] == "occupied"
    assert keys_a == [FIXED_SAFE_KEY_2, FIXED_SAFE_KEY_3]
    assert keys_b == [FIXED_SAFE_KEY_2, FIXED_SAFE_KEY_3]
    assert keys_a == keys_b
    assert values_a == ["value-A", "value-B"]
    assert values_b == ["value-A", "value-B"]
    _assert_surface_anonymous_keys(keys_a, secret=secret_a, token=token_a)
    _assert_surface_anonymous_keys(keys_b, secret=secret_b, token=token_b)


def test_mutation_sha256_derived_safe_keys_must_red(monkeypatch):
    """仅把上层碰撞分配改成原文 SHA-256 派生 → 内容无关顺序门禁必须 RED。

    单因素：mutation 不泄漏长度，旧表面断言在 mutation 下仍绿。
    """
    mutated = _install_sha256_derived_safe_key_mutation(monkeypatch)

    secret_a = "HASHGATE_PLAIN_ALPHA_ONE"
    secret_b = "HASHGATE_PLAIN_BETA_TWO_DIFFERENT_CHARS_ZZ"
    reg_a, reg_b = CredentialRegistry(), CredentialRegistry()
    item_a = reg_a.register("db", "password", secret_a)
    item_b = reg_b.register("db", "password", secret_b)

    out_a = mutated({secret_a: "value-A", item_a.token: "value-B"}, reg_a)
    out_b = mutated({secret_b: "value-A", item_b.token: "value-B"}, reg_b)
    keys_a = list(out_a.keys())
    keys_b = list(out_b.keys())

    # Old surface checks stay green under this mutation (single-factor).
    _assert_surface_anonymous_keys(keys_a, secret=secret_a, token=item_a.token)
    _assert_surface_anonymous_keys(keys_b, secret=secret_b, token=item_b.token)
    assert list(out_a.values()) == ["value-A", "value-B"]
    assert list(out_b.values()) == ["value-A", "value-B"]

    # Content-independent fixed-sequence gate must RED.
    with pytest.raises(AssertionError):
        assert keys_a == [FIXED_SAFE_KEY_1, FIXED_SAFE_KEY_2]
    with pytest.raises(AssertionError):
        assert keys_b == [FIXED_SAFE_KEY_1, FIXED_SAFE_KEY_2]
    with pytest.raises(AssertionError):
        assert keys_a == keys_b


def test_core_protocol_key_sensitive_rewrite_still_blocks():
    """核心协议键被敏感改写 → Provider=0 + CG-REDACTION-COLLISION。"""
    # Exact core key name registered as secret → redaction would rename "messages".
    secret = "messages"
    get_registry().register("db", "password", secret)
    request = {
        "model": "m",
        "messages": [{"role": "user", "content": "hello-safe"}],
    }
    original = deepcopy(request)
    out = on_llm_request(request=request)
    assert request == original
    assert isinstance(out["request"], LocalBlockRequest)
    assert out["request"].block_detail.code == "CG-REDACTION-COLLISION"
    calls: list = []
    blocked = on_llm_execution(
        request=out["request"],
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []
    assert "代码：CG-REDACTION-COLLISION" in blocked.choices[0].message.content


def test_redaction_collision_error_still_maps_to_local_block(monkeypatch):
    """核心协议无法安全构造时：RedactionCollisionError → Provider=0。"""
    import credential_guard.redactor as redactor

    secret = "CORE_COLLIDE_SECRET_009"
    item = get_registry().register("db", "password", secret)

    def always_collide(payload, registry, *, _path=()):
        raise RedactionCollisionError(
            "dict key collision after redaction",
            path=_path + ("<key>",),
        )

    monkeypatch.setattr(redactor, "redact_payload", always_collide)
    monkeypatch.setattr(
        "credential_guard.middleware.redact_payload", always_collide
    )
    out = on_llm_request(
        request={
            "model": "m",
            "messages": [
                {
                    "role": "user",
                    "content": "core-keep",
                    "metadata": {secret: "A", item.token: "B"},
                }
            ],
        }
    )
    assert isinstance(out["request"], LocalBlockRequest)
    assert out["request"].block_detail.code == "CG-REDACTION-COLLISION"


def test_ordinary_collision_preserves_sibling_core_keys():
    """普通动态键碰撞时，同级核心协议键不得被改成占位符。"""
    registry = CredentialRegistry()
    secret = "SIBLING_CORE_COLLIDE_013"
    item = registry.register("db", "password", secret)
    nested = {
        "role": "tool",
        "name": "fetch_api",
        "content": "body-keep",
        secret: "A",
        item.token: "B",
    }
    out = redact_payload(nested, registry)
    assert out["role"] == "tool"
    assert out["name"] == "fetch_api"
    assert out["content"] == "body-keep"
    dynamic = {
        k: v for k, v in out.items() if k not in {"role", "name", "content"}
    }
    keys = _assert_unique_safe_keys(dynamic, values=["A", "B"])
    assert keys == ["<REDACTED_SENSITIVE_KEY_1>", "<REDACTED_SENSITIVE_KEY_2>"]
    assert item.token not in out
    assert secret not in out


def test_mutation_force_residual_after_safe_rename_blocks(monkeypatch):
    import credential_guard.middleware as mw

    secret = "RESIDUAL_AFTER_RENAME_010"
    item = get_registry().register("db", "password", secret)

    def force_residual(payload, registry, root, path=()):
        if path == ():
            return mw._detail_residual("request")
        return None

    monkeypatch.setattr(mw, "_find_residual_plain_secret", force_residual)
    out = on_llm_request(
        request={
            "model": "m",
            "messages": [
                {
                    "role": "user",
                    "content": "x",
                    "metadata": {secret: "A", item.token: "B"},
                }
            ],
        }
    )
    assert isinstance(out["request"], LocalBlockRequest)
    assert out["request"].block_detail.code == "CG-RESIDUAL-SECRET"
    calls: list = []
    on_llm_execution(
        request=out["request"],
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []


def test_scanner_error_and_config_unavailable_still_provider_zero(monkeypatch):
    import credential_guard.middleware as mw
    from credential_guard.runtime_config import RuntimeConfigError
    from credential_guard.sensitive_paths import EncodedPrivateKeyScanError

    def boom_scan(text: str) -> str:
        raise EncodedPrivateKeyScanError("synthetic scanner failure")

    monkeypatch.setattr(mw, "redact_private_keys", boom_scan)
    out = on_llm_request(
        request={"model": "m", "messages": [{"role": "user", "content": "hello"}]}
    )
    assert isinstance(out["request"], LocalBlockRequest)
    assert out["request"].block_detail.code == "CG-SCANNER-ERROR"

    monkeypatch.setattr(mw, "redact_private_keys", lambda text: text)

    def boom_cfg():
        raise RuntimeConfigError("RUNTIME_CONFIG_UNAVAILABLE")

    monkeypatch.setattr(mw, "get_egress_registry_snapshot", boom_cfg)
    out2 = on_llm_request(
        request={"model": "m", "messages": [{"role": "user", "content": "hello"}]}
    )
    assert isinstance(out2["request"], LocalBlockRequest)
    assert out2["request"].block_detail.code == "CG-CONFIG-UNAVAILABLE"


def test_mutation_remove_unique_key_allocation_must_red(monkeypatch):
    """删除唯一键分配逻辑 → 原碰撞用例回到阻断/异常。"""
    import credential_guard.redactor as redactor

    secret = "MUT_REMOVE_ALLOC_SECRET_011"
    item = get_registry().register("db", "password", secret)

    def legacy_collide(payload, registry, *, _path=()):
        if isinstance(payload, str):
            return redactor.redact_text(payload, registry)
        if isinstance(payload, dict):
            out = {}
            for key, value in payload.items():
                new_key = (
                    redactor.redact_text(key, registry)
                    if isinstance(key, str)
                    else key
                )
                if new_key in out:
                    raise RedactionCollisionError(
                        "dict key collision after redaction",
                        path=_path + ("<key>",),
                    )
                out[new_key] = legacy_collide(
                    value, registry, _path=_path + (redactor._path_segment(key),)
                )
            return out
        if isinstance(payload, list):
            return [
                legacy_collide(v, registry, _path=_path + (i,))
                for i, v in enumerate(payload)
            ]
        if isinstance(payload, tuple):
            return tuple(
                legacy_collide(v, registry, _path=_path + (i,))
                for i, v in enumerate(payload)
            )
        return payload

    monkeypatch.setattr(redactor, "redact_payload", legacy_collide)
    monkeypatch.setattr(
        "credential_guard.middleware.redact_payload", legacy_collide
    )
    request = {
        "model": "m",
        "messages": [
            {
                "role": "user",
                "content": "x",
                "metadata": {secret: "A", item.token: "B"},
            }
        ],
    }
    out = on_llm_request(request=request)
    assert isinstance(out["request"], LocalBlockRequest)
    assert out["request"].block_detail.code == "CG-REDACTION-COLLISION"


def test_synthetic_probe_historical_tool_collision_shape():
    """合成真实形态：历史工具结果含碰撞动态对象，同 Session Provider=1。"""
    secret = "PROBE_HIST_TOOL_COLLIDE_012"
    item = get_registry().register("api", "token", secret)
    request = {
        "model": "m",
        "messages": [
            {"role": "system", "content": "you are helper"},
            {"role": "user", "content": "fetch status then continue deploy"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "http_credential_request",
                            "arguments": '{"ref":"<CREDENTIAL:api.token>"}',
                        },
                    }
                ],
            },
            {
                "role": "tool",
                "name": "http_credential_request",
                "tool_call_id": "call_1",
                "content": {
                    "status": 200,
                    "body": {
                        secret: "alpha",
                        item.token: "beta",
                        "deploy_id": "d-9",
                    },
                },
            },
            {"role": "user", "content": "continue with deploy_id"},
        ],
    }
    original = deepcopy(request)
    pb1, sent1 = _provider_once(request)
    pb2, sent2 = _provider_once(request)
    assert pb1 == pb2
    assert sent1 == sent2
    assert request == original
    body = pb1["messages"][3]["content"]["body"]
    assert body["deploy_id"] == "d-9"
    dynamic = {k: v for k, v in body.items() if k != "deploy_id"}
    keys = _assert_unique_safe_keys(dynamic, values=["alpha", "beta"])
    assert keys == ["<REDACTED_SENSITIVE_KEY_1>", "<REDACTED_SENSITIVE_KEY_2>"]
    blob = json.dumps(sent1, ensure_ascii=False)
    assert secret not in blob
    assert item.token not in blob
    assert pb1["messages"][1]["content"] == "fetch status then continue deploy"
    assert pb1["messages"][4]["content"] == "continue with deploy_id"
    assert pb1["messages"][2]["tool_calls"][0]["function"]["name"] == (
        "http_credential_request"
    )
