from __future__ import annotations

from credential_guard.models import make_token_id
from credential_guard.redactor import contains_plain_secret, redact_payload
from credential_guard.registry import CredentialRegistry, MIN_SECRET_LENGTH


def test_redacts_nested_payload_and_keeps_original_object_unchanged():
    registry = CredentialRegistry()
    item = registry.register("db", "password", "canary_password_123")
    payload = {"a": ["token canary_password_123"], "b": {"v": "canary_password_123"}}
    redacted = redact_payload(payload, registry)
    assert redacted["a"][0] == f"token {item.token}"
    assert redacted["b"]["v"] == item.token
    assert payload["a"][0] == "token canary_password_123"


def test_longer_secret_replaced_first_for_overlap():
    registry = CredentialRegistry()
    registry.register("short", "v", "abcd1234")
    long_item = registry.register("long", "v", "abcd1234XYZ")
    redacted = redact_payload("x abcd1234XYZ y", registry)
    assert redacted == f"x {long_item.token} y"


def test_rejects_short_or_empty_secret():
    registry = CredentialRegistry()
    for value in ("", "x" * (MIN_SECRET_LENGTH - 1)):
        try:
            registry.register("k", "f", value)
            assert False, "expected ValueError"
        except ValueError:
            pass


def test_detects_plain_secret_after_redaction_check():
    registry = CredentialRegistry()
    item = registry.register("api", "key", "decoy_api_key_456")
    assert contains_plain_secret({"msg": "decoy_api_key_456"}, registry) is True
    assert contains_plain_secret({"msg": item.token}, registry) is False


def test_authorization_header_and_dsn_redaction():
    registry = CredentialRegistry()
    item = registry.register("db", "password", "SuperSecret99")
    auth = redact_payload({"Authorization": "Bearer SuperSecret99"}, registry)
    assert auth["Authorization"] == f"Bearer {item.token}"
    dsn = redact_payload(
        "mysql://user:SuperSecret99@127.0.0.1:3306/db",
        registry,
    )
    assert "SuperSecret99" not in dsn
    assert item.token in dsn


def test_duplicate_values_and_tuple_redaction():
    registry = CredentialRegistry()
    item = registry.register("db", "password", "dup_secret_001")
    payload = ("dup_secret_001", ["dup_secret_001", {"k": "dup_secret_001"}])
    redacted = redact_payload(payload, registry)
    assert redacted[0] == item.token
    assert redacted[1][0] == item.token
    assert redacted[1][1]["k"] == item.token
    assert isinstance(redacted, tuple)


def test_token_id_stable_and_resolvable():
    registry = CredentialRegistry()
    a = registry.register("db", "password", "stable_secret_01")
    b_id = make_token_id("db", "password")
    assert a.token_id == b_id
    assert registry.resolve_by_token_id(b_id) is a or registry.resolve_by_token_id(
        b_id
    ).secret == "stable_secret_01"
