from __future__ import annotations

import hashlib
from dataclasses import dataclass


def make_token_id(key: str, field: str) -> str:
    """Deterministic opaque id derived from key/field — never from the secret.

    Trade-off: tokens are not human-readable as key.field, but they stay stable,
    locally resolvable via the registry, and cannot embed secret material even
    when key/field equal or contain the secret (ASCII-safe identifiers).
    """
    digest = hashlib.sha256(f"{key}\0{field}".encode("utf-8")).hexdigest()[:16]
    return f"cg_{digest}"


@dataclass(frozen=True)
class CredentialValue:
    key: str
    field: str
    secret: str
    token_id: str

    @property
    def token(self) -> str:
        return f"<SECRET:{self.token_id}>"

    @staticmethod
    def build(key: str, field: str, secret: str) -> "CredentialValue":
        token_id = make_token_id(key, field)
        return CredentialValue(key=key, field=field, secret=secret, token_id=token_id)
