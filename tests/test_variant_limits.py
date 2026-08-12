"""T6: resource limits and fault injection must fail closed without echoing input."""

from __future__ import annotations

import json
import os

import pytest

from credential_guard.hooks import on_transform_tool_result
from credential_guard.middleware import SAFE_BLOCK_MESSAGE, on_llm_execution, on_llm_request
from credential_guard.redactor import (
    MAX_REGISTRY_ITEMS,
    MAX_SECRET_LENGTH,
    MAX_TOTAL_VARIANT_CHARS,
    VariantBuildError,
    build_secret_variants,
    collect_protected_replacements,
)
from credential_guard.registry import CredentialRegistry
from credential_guard.result_guard import RESULT_GUARD_FAIL_TEXT
from credential_guard.sensitive_paths import (
    EncodedPrivateKeyScanError,
    MAX_PRIVATE_KEY_SCAN_BYTES,
    contains_private_key_material,
)
from credential_guard.state import get_registry


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


def _assert_exec_blocked(secret: str) -> None:
    calls = []
    blocked = on_llm_execution(
        request={"messages": [{"content": secret}]},
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []
    assert getattr(blocked, "model", "") == "credential-guard-blocked"
    assert blocked.choices[0].message.content == SAFE_BLOCK_MESSAGE
    assert secret not in str(blocked)


def _assert_request_safe(secret: str) -> None:
    out = on_llm_request(request={"messages": [{"content": secret}]})
    blob = json.dumps(out)
    assert secret not in blob
    assert out["request"]["messages"][0]["content"] == SAFE_BLOCK_MESSAGE


def _assert_tool_safe(secret: str) -> None:
    out = on_transform_tool_result(
        result=f"leak {secret}", tool_name="dummy", arguments={}
    )
    assert secret not in out
    assert out == RESULT_GUARD_FAIL_TEXT
    assert out.count(secret) == 0
    # R4: never parse fail-closed tool results as JSON.
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


def test_t6_secret_too_long_fail_closed():
    secret = "S" * (MAX_SECRET_LENGTH + 1)
    with pytest.raises(VariantBuildError):
        build_secret_variants(secret)
    # Bypass registry min-length via direct register of long secret.
    get_registry().register("db", "password", secret)
    _assert_exec_blocked(secret)
    _assert_request_safe(secret)
    _assert_tool_safe(secret)


def test_t6_registry_item_count_limit_fail_closed(monkeypatch):
    monkeypatch.setattr("credential_guard.redactor.MAX_REGISTRY_ITEMS", 2)
    reg = get_registry()
    reg.register("a", "password", "secret_aaa_01")
    reg.register("b", "password", "secret_bbb_02")
    reg.register("c", "password", "secret_ccc_03")
    with pytest.raises(VariantBuildError):
        collect_protected_replacements(reg)
    # Provider egress still fail-closed via collect_protected_replacements.
    _assert_exec_blocked("secret_aaa_01")
    _assert_request_safe("secret_bbb_02")
    # R4 result_guard shares the same MAX_REGISTRY_ITEMS aggregate gate.
    _assert_tool_safe("secret_ccc_03")


def test_t6_total_variant_chars_limit_fail_closed(monkeypatch):
    monkeypatch.setattr("credential_guard.redactor.MAX_TOTAL_VARIANT_CHARS", 40)
    secret = "variant_limit_secret_001"
    get_registry().register("db", "password", secret)
    with pytest.raises(VariantBuildError):
        collect_protected_replacements(get_registry())
    _assert_exec_blocked(secret)
    _assert_request_safe(secret)
    # R4 result_guard shares the same MAX_TOTAL_VARIANT_CHARS aggregate gate.
    _assert_tool_safe(secret)


def test_t6_result_guard_merged_session_registry_count_fail_closed(monkeypatch):
    """session_materials + registry merged identity count must share MAX_REGISTRY_ITEMS."""
    monkeypatch.setattr("credential_guard.redactor.MAX_REGISTRY_ITEMS", 2)
    get_registry().register("a", "password", "secret_aaa_01")
    get_registry().register("b", "password", "secret_bbb_02")
    from credential_guard.result_guard import guard_tool_result
    from credential_guard.state import get_egress_registry_snapshot

    sess_secret = "secret_sess_03"
    out = guard_tool_result(
        f"leak {sess_secret}",
        get_egress_registry_snapshot(),
        session_materials=[("sess", sess_secret)],
    )
    assert out == RESULT_GUARD_FAIL_TEXT
    assert sess_secret not in out


def test_t6_result_guard_merged_session_registry_chars_fail_closed(monkeypatch):
    """Merged unique variants across session + registry must share MAX_TOTAL_VARIANT_CHARS."""
    monkeypatch.setattr("credential_guard.redactor.MAX_TOTAL_VARIANT_CHARS", 40)
    # Each secret alone is under 40 variant-chars; together they exceed.
    get_registry().register("a", "password", "sec_aaa_01")
    from credential_guard.result_guard import guard_tool_result
    from credential_guard.state import get_egress_registry_snapshot

    sess_secret = "sec_bbb_02"
    out = guard_tool_result(
        f"leak {sess_secret}",
        get_egress_registry_snapshot(),
        session_materials=[("sess", sess_secret)],
    )
    assert out == RESULT_GUARD_FAIL_TEXT
    assert sess_secret not in out


def test_t6_mutation_remove_result_guard_count_gate_is_red(monkeypatch):
    """Mutation: deleting the identity-count gate must break tool fail-closed."""
    import credential_guard.result_guard as rg

    monkeypatch.setattr("credential_guard.redactor.MAX_REGISTRY_ITEMS", 2)
    get_registry().register("a", "password", "secret_aaa_01")
    get_registry().register("b", "password", "secret_bbb_02")
    get_registry().register("c", "password", "secret_ccc_03")
    _assert_tool_safe("secret_ccc_03")

    def merge_without_count(registry, session_materials=None):
        identities = rg._merged_identities(registry, session_materials)
        # Intentionally skip: len(identities) > MAX_REGISTRY_ITEMS
        variant_owner: dict = {}
        pairs = []
        total_chars = 0
        for token, secret in identities:
            for variant in build_secret_variants(secret, token=token):
                owner = variant_owner.get(variant)
                if owner is not None and owner != token:
                    raise VariantBuildError("variant collision across identities")
                if owner is None:
                    variant_owner[variant] = token
                    pairs.append((variant, token))
                    total_chars += len(variant)
                    if total_chars > MAX_TOTAL_VARIANT_CHARS:
                        raise VariantBuildError("total variant chars exceed limit")
        pairs.sort(key=lambda p: len(p[0]), reverse=True)
        return pairs

    monkeypatch.setattr(rg, "_merge_replacement_pairs", merge_without_count)
    out = on_transform_tool_result(
        result="leak secret_ccc_03", tool_name="dummy", arguments={}
    )
    # Gate removed → over-limit path redacts instead of fail-closed (mutation RED signal).
    assert out != RESULT_GUARD_FAIL_TEXT
    assert "<CREDENTIAL:c>" in out
    assert "secret_ccc_03" not in out


def test_t6_mutation_remove_result_guard_total_chars_gate_is_red(monkeypatch):
    """Mutation: deleting the total-chars gate must break tool fail-closed."""
    import credential_guard.result_guard as rg
    import credential_guard.redactor as redactor_mod

    monkeypatch.setattr(redactor_mod, "MAX_TOTAL_VARIANT_CHARS", 40)
    secret = "variant_limit_secret_001"
    get_registry().register("db", "password", secret)
    _assert_tool_safe(secret)

    def merge_without_chars(registry, session_materials=None):
        identities = rg._merged_identities(registry, session_materials)
        if len(identities) > redactor_mod.MAX_REGISTRY_ITEMS:
            raise VariantBuildError("registry item count exceeds limit")
        variant_owner: dict = {}
        pairs = []
        for token, secret_v in identities:
            for variant in build_secret_variants(secret_v, token=token):
                owner = variant_owner.get(variant)
                if owner is not None and owner != token:
                    raise VariantBuildError("variant collision across identities")
                if owner is None:
                    variant_owner[variant] = token
                    pairs.append((variant, token))
                    # Intentionally skip total_chars / MAX_TOTAL_VARIANT_CHARS gate.
        pairs.sort(key=lambda p: len(p[0]), reverse=True)
        return pairs

    monkeypatch.setattr(rg, "_merge_replacement_pairs", merge_without_chars)
    out = on_transform_tool_result(
        result=f"leak {secret}", tool_name="dummy", arguments={}
    )
    assert out != RESULT_GUARD_FAIL_TEXT
    assert "<CREDENTIAL:db>" in out
    assert secret not in out


def test_t6_variant_builder_exception_fail_closed(monkeypatch, caplog):
    import logging

    secret = "variant_boom_secret_01"
    get_registry().register("db", "password", secret)
    caplog.set_level(logging.WARNING, logger="credential_guard")

    def boom(*_a, **_k):
        raise RuntimeError(f"builder exploded {secret}")

    monkeypatch.setattr("credential_guard.redactor.build_secret_variants", boom)
    monkeypatch.setattr("credential_guard.result_guard.build_secret_variants", boom)
    _assert_exec_blocked(secret)
    _assert_request_safe(secret)
    _assert_tool_safe(secret)
    joined = "\n".join(r.message for r in caplog.records)
    assert secret not in joined


def test_t6_encoded_private_key_scanner_overlimit_fail_closed():
    huge = "A" * (MAX_PRIVATE_KEY_SCAN_BYTES + 10)
    with pytest.raises(EncodedPrivateKeyScanError):
        contains_private_key_material(huge)
    # Full oversized payload must block downstream without echoing body.
    calls = []
    blocked = on_llm_execution(
        request={"messages": [{"content": huge}]},
        next_call=lambda req: calls.append(req) or {"ok": True},
    )
    assert calls == []
    assert SAFE_BLOCK_MESSAGE in str(blocked.choices[0].message.content)
    assert huge not in str(blocked)

    out = on_llm_request(request={"messages": [{"content": huge}]})
    assert huge not in json.dumps(out)
    assert out["request"]["messages"][0]["content"] == SAFE_BLOCK_MESSAGE

    tool = on_transform_tool_result(result=huge, tool_name="dummy", arguments={})
    assert huge not in tool
    assert tool == RESULT_GUARD_FAIL_TEXT
    assert tool.count(huge) == 0


def test_t6_encoded_private_key_scanner_exception_fail_closed(monkeypatch, caplog):
    import logging

    secret = "scan_boom_secret_0001"
    get_registry().register("db", "password", secret)
    caplog.set_level(logging.WARNING, logger="credential_guard")

    def boom(_text):
        raise EncodedPrivateKeyScanError(f"scan failed {secret}")

    monkeypatch.setattr(
        "credential_guard.middleware.contains_private_key_material", boom
    )
    # R4 tool-result path: patch the production call site inside result_guard.
    monkeypatch.setattr(
        "credential_guard.result_guard.contains_private_key_material", boom
    )
    _assert_exec_blocked(secret)
    _assert_request_safe(secret)
    _assert_tool_safe(secret)
    joined = "\n".join(r.message for r in caplog.records)
    assert secret not in joined


def test_t6_tool_fail_closed_mutation_legacy_json_is_red():
    """Mutation: old SAFE JSON shape must not satisfy variant-limit tool fail-closed."""
    secret = "S" * (MAX_SECRET_LENGTH + 1)
    get_registry().register("db", "password", secret)
    out = on_transform_tool_result(
        result=f"leak {secret}", tool_name="dummy", arguments={}
    )
    assert out == RESULT_GUARD_FAIL_TEXT
    legacy = json.dumps(
        {"error": "tool result blocked by credential-guard"}, ensure_ascii=False
    )
    assert out != legacy


def test_t6_limit_constants_are_explicit():
    assert MAX_SECRET_LENGTH == 1_048_576
    assert MAX_REGISTRY_ITEMS == 256
    assert MAX_TOTAL_VARIANT_CHARS == 16_777_216
    assert MAX_PRIVATE_KEY_SCAN_BYTES == 512_000
