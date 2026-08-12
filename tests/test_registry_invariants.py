from __future__ import annotations

import pytest

from credential_guard.models import CredentialValue, make_token_id
from credential_guard.redactor import redact_payload
from credential_guard.registry import CredentialRegistry


def test_same_identity_same_secret_is_idempotent():
    registry = CredentialRegistry()
    first = registry.register("db", "password", "same_secret_AA")
    second = registry.register("db", "password", "same_secret_AA")
    assert second is first
    assert len(registry.values()) == 1
    assert len(registry.metadata()) == 1


def test_same_identity_different_secret_rejected_no_partial_mutation():
    registry = CredentialRegistry()
    first = registry.register("db", "password", "first_secret_AA")
    before = registry.metadata()
    with pytest.raises(ValueError, match="implicit rotation|different secret"):
        registry.register("db", "password", "second_secret_BB")
    assert registry.metadata() == before
    assert registry.resolve_by_token_id(first.token_id) is first
    assert len(registry.values()) == 1


def test_same_secret_across_different_identities_rejected():
    registry = CredentialRegistry()
    registry.register("db", "password", "shared_secret_99")
    before_count = len(registry.values())
    with pytest.raises(ValueError, match="already registered|same secret"):
        registry.register("api", "token", "shared_secret_99")
    assert len(registry.values()) == before_count
    assert registry.resolve_by_token_id(make_token_id("api", "token")) is None


def test_token_id_collision_rejects_second_identity(monkeypatch):
    registry = CredentialRegistry()
    first = registry.register("db", "password", "first_secret_AA")

    def colliding_token_id(key: str, field: str) -> str:
        if (key, field) == ("other", "field"):
            return first.token_id
        return make_token_id(key, field)

    monkeypatch.setattr(
        "credential_guard.models.make_token_id",
        colliding_token_id,
    )
    monkeypatch.setattr(
        "credential_guard.registry.make_token_id",
        colliding_token_id,
    )
    # CredentialValue.build uses models.make_token_id
    monkeypatch.setattr(
        CredentialValue,
        "build",
        staticmethod(
            lambda key, field, secret: CredentialValue(
                key=key, field=field, secret=secret, token_id=colliding_token_id(key, field)
            )
        ),
    )

    before = registry.metadata()
    with pytest.raises(ValueError, match="token id"):
        registry.register("other", "field", "other_secret_BB")
    assert registry.metadata() == before
    assert len(registry.values()) == 1
    resolved = registry.resolve_by_token_id(first.token_id)
    assert resolved is first


def test_resolve_by_token_id_is_deterministic_single_or_none():
    registry = CredentialRegistry()
    item = registry.register("db", "password", "resolve_secret_01")
    assert registry.resolve_by_token_id(item.token_id) is item
    assert registry.resolve_by_token_id("cg_nonexistent0000") is None


def test_metadata_order_stable_independent_of_secret_length_sort():
    registry = CredentialRegistry()
    short = registry.register("short", "v", "abcdefgh")  # 8
    long = registry.register("longish", "v", "abcdefghijklmnop")  # 16
    mid = registry.register("mid", "v", "abcdefghi")  # 9
    # Redaction view is length-descending.
    values = registry.values()
    assert [v.key for v in values] == ["longish", "mid", "short"]
    # Metadata stays insertion order — not length sort.
    assert [m["key"] for m in registry.metadata()] == ["short", "longish", "mid"]
    assert short.token_id == registry.metadata()[0]["token_id"]
    assert long.token_id == registry.metadata()[1]["token_id"]
    assert mid.token_id == registry.metadata()[2]["token_id"]


def test_failed_register_does_not_partially_mutate_indexes():
    registry = CredentialRegistry()
    registry.register("db", "password", "anchor_secret_1")
    snap_meta = registry.metadata()
    snap_values = {(v.key, v.field, v.token_id) for v in registry.values()}
    with pytest.raises(ValueError):
        registry.register("db", "password", "rotated_secret_2")
    with pytest.raises(ValueError):
        registry.register("other", "token", "anchor_secret_1")
    assert registry.metadata() == snap_meta
    assert {(v.key, v.field, v.token_id) for v in registry.values()} == snap_values


def test_cross_identity_same_secret_would_break_redaction_so_rejected():
    """One plaintext must not map to multiple tokens."""
    registry = CredentialRegistry()
    a = registry.register("db", "password", "one_plain_secret")
    with pytest.raises(ValueError):
        registry.register("cache", "password", "one_plain_secret")
    body = redact_payload("use one_plain_secret here", registry)
    assert body.count(a.token) == 1
    assert "one_plain_secret" not in body
