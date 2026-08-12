from __future__ import annotations

import base64
import json
from typing import Any, List, Tuple
from urllib.parse import quote, quote_plus

from .registry import CredentialRegistry

# Bounded variant construction limits (fail closed when exceeded).
# High but finite credential byte cap: supports large stdin tokens without
# unbounded config/redactor growth (R3B process inject).
MAX_SECRET_LENGTH = 1_048_576
MAX_REGISTRY_ITEMS = 256
MAX_VARIANTS_PER_ITEM = 32
MAX_TOTAL_VARIANT_CHARS = 16_777_216


class RedactionCollisionError(RuntimeError):
    """Raised when redacting dict keys would collide and silently overwrite."""


class VariantBuildError(RuntimeError):
    """Raised when protected-variant construction fails or exceeds bounds."""


def _json_escape_bodies(secret: str) -> List[str]:
    """JSON-string interiors for ascii and unicode dumps (no surrounding quotes)."""
    out: List[str] = []
    for ensure_ascii in (True, False):
        try:
            encoded = json.dumps(secret, ensure_ascii=ensure_ascii)
        except Exception as exc:
            raise VariantBuildError("json escape form unavailable") from exc
        if len(encoded) < 2 or encoded[0] != '"' or encoded[-1] != '"':
            raise VariantBuildError("json escape form unavailable")
        body = encoded[1:-1]
        if body and body != secret:
            out.append(body)
    return out


def build_secret_variants(secret: str, *, token: str = "") -> List[str]:
    """Deterministic bounded reversible encodings for one registered secret.

    Always includes the plain secret. Deduplicates. Never yields empty strings
    or the opaque token itself. Fail closed on length / count / collision issues
    at the single-secret construction layer.
    """
    if not isinstance(secret, str) or not secret:
        raise VariantBuildError("secret variant input invalid")
    if len(secret) > MAX_SECRET_LENGTH:
        raise VariantBuildError("secret exceeds max length")

    candidates: List[str] = [secret]
    try:
        candidates.append(quote(secret, safe=""))
        candidates.append(quote_plus(secret))
        raw = secret.encode("utf-8")
        candidates.append(base64.b64encode(raw).decode("ascii"))
        candidates.append(base64.urlsafe_b64encode(raw).decode("ascii"))
        candidates.extend(_json_escape_bodies(secret))
    except VariantBuildError:
        raise
    except Exception as exc:
        raise VariantBuildError("variant construction failed") from exc

    seen: set[str] = set()
    out: List[str] = []
    for item in candidates:
        if not item:
            continue
        if token and item == token:
            continue
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    if len(out) > MAX_VARIANTS_PER_ITEM:
        raise VariantBuildError("too many variants for secret")
    return out


def collect_protected_replacements(
    registry: CredentialRegistry,
) -> List[Tuple[str, str]]:
    """Authoritative (variant → token) pairs for redact + residue checks.

    Sorted by variant length descending. Same variant mapping to different
    identities, variant containing another token/secret, or resource limits
    raise VariantBuildError (fail closed).
    """
    items = list(registry.values())
    if len(items) > MAX_REGISTRY_ITEMS:
        raise VariantBuildError("registry item count exceeds limit")

    variant_owner: dict[str, str] = {}  # variant -> token
    pairs: List[Tuple[str, str]] = []
    total_chars = 0

    for item in items:
        try:
            variants = build_secret_variants(item.secret, token=item.token)
        except VariantBuildError:
            raise
        except Exception as exc:
            raise VariantBuildError("variant construction failed") from exc

        for variant in variants:
            owner = variant_owner.get(variant)
            if owner is not None and owner != item.token:
                raise VariantBuildError("variant collision across identities")
            if owner is None:
                variant_owner[variant] = item.token
                pairs.append((variant, item.token))
                total_chars += len(variant)
                if total_chars > MAX_TOTAL_VARIANT_CHARS:
                    raise VariantBuildError("total variant chars exceed limit")

            # Derived encodings must not embed another identity's opaque token.
            # Plain-secret / combo substring overlap uses length-descending replace.
            # Exact same variant under two identities is rejected via variant_owner.
            if variant == item.secret:
                continue
            for other in items:
                if other is item:
                    continue
                if other.token and other.token in variant:
                    raise VariantBuildError("variant contains other token")

    pairs.sort(key=lambda p: len(p[0]), reverse=True)
    return pairs


def redact_text(text: str, registry: CredentialRegistry) -> str:
    redacted = text
    for variant, token in collect_protected_replacements(registry):
        redacted = redacted.replace(variant, token)
    return redacted


def redact_payload(payload: Any, registry: CredentialRegistry) -> Any:
    if isinstance(payload, str):
        return redact_text(payload, registry)
    if isinstance(payload, dict):
        out: dict[Any, Any] = {}
        for key, value in payload.items():
            new_key = redact_text(key, registry) if isinstance(key, str) else key
            if new_key in out:
                raise RedactionCollisionError("dict key collision after redaction")
            out[new_key] = redact_payload(value, registry)
        return out
    if isinstance(payload, list):
        return [redact_payload(item, registry) for item in payload]
    if isinstance(payload, tuple):
        return tuple(redact_payload(item, registry) for item in payload)
    return payload


def contains_plain_secret(payload: Any, registry: CredentialRegistry) -> bool:
    try:
        flattened = json.dumps(payload, ensure_ascii=False, default=str)
    except Exception:
        flattened = str(payload)
    for variant, _token in collect_protected_replacements(registry):
        if variant in flattened:
            return True
    return False
