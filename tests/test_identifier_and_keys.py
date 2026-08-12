from __future__ import annotations

import pytest

from credential_guard.models import make_token_id
from credential_guard.redactor import RedactionCollisionError, redact_payload
from credential_guard.registry import (
    MAX_IDENTIFIER_LENGTH,
    CredentialRegistry,
    validate_identifier,
)


def test_rejects_empty_and_illegal_identifiers():
    registry = CredentialRegistry()
    for key, field in (
        ("", "password"),
        ("db", ""),
        ("db.password", "v"),
        ("db password", "v"),
        ("1db", "v"),
        ("db", "pass word"),
        ("db", "x" * (MAX_IDENTIFIER_LENGTH + 1)),
        ("db/secret", "v"),
    ):
        with pytest.raises(ValueError):
            registry.register(key, field, "decoy_secret_value_1")


def test_accepts_boundary_safe_identifiers():
    registry = CredentialRegistry()
    key = "A" + ("b" * 63)
    field = "Z" + ("9" * 63)
    assert len(key) == MAX_IDENTIFIER_LENGTH
    value = registry.register(key, field, "decoy_secret_value_2")
    assert value.token == f"<SECRET:{make_token_id(key, field)}>"
    assert "decoy_secret_value_2" not in value.token


def test_rejects_identifier_that_looks_like_secret_fragment():
    with pytest.raises(ValueError):
        validate_identifier("decoy_db_password_123!", "key")


def test_redacts_dict_string_keys_and_values():
    registry = CredentialRegistry()
    item = registry.register("db", "password", "decoy_key_secret_AAA")
    payload = {"prefix_decoy_key_secret_AAA_suffix": "decoy_key_secret_AAA"}
    redacted = redact_payload(payload, registry)
    assert list(redacted.keys()) == [f"prefix_{item.token}_suffix"]
    assert redacted[f"prefix_{item.token}_suffix"] == item.token


def test_dict_key_collision_after_redaction_fails_closed():
    registry = CredentialRegistry()
    item = registry.register("db", "password", "COLLIDE_SECRET_1")
    payload = {
        "COLLIDE_SECRET_1": "a",
        item.token: "b",
    }
    with pytest.raises(RedactionCollisionError):
        redact_payload(payload, registry)


def test_token_never_embeds_raw_secret_even_if_key_were_secretish():
    registry = CredentialRegistry()
    value = registry.register("canarydb", "password", "raw_secret_value_XYZ")
    assert "raw_secret_value_XYZ" not in value.token
    assert value.token.startswith("<SECRET:cg_")
    assert value.token == f"<SECRET:{make_token_id('canarydb', 'password')}>"
