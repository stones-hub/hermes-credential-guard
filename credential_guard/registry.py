from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from .models import CredentialValue, make_token_id

MIN_SECRET_LENGTH = 8
SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
MAX_IDENTIFIER_LENGTH = 64

Identity = Tuple[str, str]


def validate_identifier(value: str, kind: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"invalid credential {kind}")
    if len(value) > MAX_IDENTIFIER_LENGTH:
        raise ValueError(f"invalid credential {kind}")
    if SAFE_IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(f"invalid credential {kind}")
    return value


class CredentialRegistry:
    """In-memory credential registry with identity/token/secret indexes.

    Invariants (M1):
    - ``(key, field)`` is the unique logical identity.
    - Same identity + same secret is idempotent.
    - Same identity + different secret is rejected (no implicit rotation).
    - ``token_id`` is unique across identities.
    - A given secret maps to at most one identity (avoids multi-token replace).
    - Failed registration never partially mutates indexes.
    """

    def __init__(self, min_secret_length: int = MIN_SECRET_LENGTH) -> None:
        self._min_secret_length = min_secret_length
        self._by_identity: Dict[Identity, CredentialValue] = {}
        self._by_token_id: Dict[str, CredentialValue] = {}
        self._by_secret: Dict[str, CredentialValue] = {}
        self._order: List[Identity] = []

    @property
    def min_secret_length(self) -> int:
        return self._min_secret_length

    def clear(self) -> None:
        self._by_identity.clear()
        self._by_token_id.clear()
        self._by_secret.clear()
        self._order.clear()

    def register(self, key: str, field: str, secret: str) -> CredentialValue:
        safe_key = validate_identifier(key, "key")
        safe_field = validate_identifier(field, "field")
        secret_text = "" if secret is None else str(secret)
        if len(secret_text.strip()) < self._min_secret_length:
            raise ValueError("credential secret is too short")

        identity: Identity = (safe_key, safe_field)
        existing = self._by_identity.get(identity)
        if existing is not None:
            if existing.secret == secret_text:
                return existing
            raise ValueError(
                "same identity with different secret rejected "
                "(no implicit rotation; use explicit replace API in M2)"
            )

        # Build candidate without mutating indexes.
        value = CredentialValue.build(safe_key, safe_field, secret_text)
        self._assert_token_secret_invariant(value)

        secret_owner = self._by_secret.get(secret_text)
        if secret_owner is not None:
            raise ValueError(
                "same secret already registered under a different identity"
            )

        token_owner = self._by_token_id.get(value.token_id)
        if token_owner is not None:
            raise ValueError("token id collision with existing identity")

        # Commit atomically after all checks.
        self._by_identity[identity] = value
        self._by_token_id[value.token_id] = value
        self._by_secret[secret_text] = value
        self._order.append(identity)
        return value

    def values(self) -> list[CredentialValue]:
        """Length-descending redaction view (read-only list copy)."""
        items = [self._by_identity[identity] for identity in self._order]
        return sorted(items, key=lambda item: len(item.secret), reverse=True)

    def metadata(self) -> List[Dict[str, str]]:
        """Non-secret metadata in stable insertion order."""
        return [
            {
                "key": self._by_identity[identity].key,
                "field": self._by_identity[identity].field,
                "token_id": self._by_identity[identity].token_id,
            }
            for identity in self._order
        ]

    def resolve_by_token_id(self, token_id: str) -> Optional[CredentialValue]:
        return self._by_token_id.get(token_id)

    def _assert_token_secret_invariant(self, candidate: CredentialValue) -> None:
        """Invariant: no token/token_id may contain any registered secret (or vice versa)."""
        all_items = list(self._by_identity.values()) + [candidate]
        for item in all_items:
            secret = item.secret
            if not secret:
                continue
            for other in all_items:
                if secret in other.token or other.token in secret:
                    raise ValueError("token must not contain credential secret")
                if secret in other.token_id or other.token_id in secret:
                    raise ValueError("token id must not relate to credential secret")


# Re-export for tests that patch make_token_id via this module.
__all__ = [
    "CredentialRegistry",
    "MIN_SECRET_LENGTH",
    "MAX_IDENTIFIER_LENGTH",
    "validate_identifier",
    "make_token_id",
]
