from __future__ import annotations

import pytest

from credential_guard.models import make_token_id
from credential_guard.redactor import redact_payload
from credential_guard.registry import CredentialRegistry, MIN_SECRET_LENGTH


def test_key_equals_secret_token_has_zero_secret_count():
    secret = "SecretValue123"
    registry = CredentialRegistry()
    item = registry.register(secret, "password", secret)
    assert item.secret not in item.token
    assert item.token.count(secret) == 0
    assert item.token == f"<SECRET:{make_token_id(secret, 'password')}>"


def test_field_equals_secret_token_has_zero_secret_count():
    secret = "SecretValue123"
    registry = CredentialRegistry()
    item = registry.register("db", secret, secret)
    assert item.token.count(secret) == 0


def test_key_contains_secret_rejected_or_token_clean():
    # key cannot embed arbitrary length; use key that is prefix of secret — still opaque.
    registry = CredentialRegistry()
    item = registry.register("Secret", "password", "SecretValue999")
    assert "SecretValue999" not in item.token
    assert item.token.count("SecretValue999") == 0


def test_secret_contains_key_token_clean():
    registry = CredentialRegistry()
    item = registry.register("db", "password", "dbpasswordXYZ")
    assert "dbpasswordXYZ" not in item.token
    redacted = redact_payload("use dbpasswordXYZ now", registry)
    assert "dbpasswordXYZ" not in redacted
    assert item.token in redacted


def test_pure_alphanumeric_secret_as_key_and_field():
    secret = "SecretValue123"
    registry = CredentialRegistry()
    item = registry.register(secret, secret, secret)
    assert item.token.count(secret) == 0
    body = redact_payload(f"key={secret} field={secret} secret={secret}", registry)
    assert body.count(secret) == 0
    assert body.count(item.token) >= 1


def test_cross_registration_second_secret_cannot_poison_first_token():
    registry = CredentialRegistry()
    first = registry.register("db", "password", "first_secret_AAA")
    # Second secret crafted to equal first token id / contain first token.
    with pytest.raises(ValueError):
        registry.register("other", "token", first.token_id + "xxxxxxxx")
    # Equal to full token string (may fail identifier rules); try secret == token.
    with pytest.raises(ValueError):
        registry.register("other", "field", first.token + "pad")


def test_token_original_secret_count_always_zero_after_redact():
    registry = CredentialRegistry()
    secrets = ["alphaSecret99", "betaSecret88", "gammaSecret77"]
    tokens = []
    for i, secret in enumerate(secrets):
        item = registry.register(f"k{i}x", f"f{i}x", secret)
        tokens.append(item.token)
        assert item.token.count(secret) == 0
    payload = " ".join(secrets)
    redacted = redact_payload(payload, registry)
    for secret in secrets:
        assert redacted.count(secret) == 0
    for token in tokens:
        assert token in redacted


def test_min_secret_length_boundary_8_ok_7_rejected():
    registry = CredentialRegistry()
    assert MIN_SECRET_LENGTH == 8
    ok = registry.register("db", "password", "a" * 8)
    assert len(ok.secret) == 8
    with pytest.raises(ValueError):
        registry.register("db", "other", "a" * 7)
