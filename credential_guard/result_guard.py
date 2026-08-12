"""R4 authoritative tool-result guard: one standard, format-preserving."""

from __future__ import annotations

import logging
import re
from typing import List, Optional, Sequence, Tuple

from . import redactor as redactor_mod
from .redactor import VariantBuildError, build_secret_variants
from .registry import CredentialRegistry
from .sensitive_paths import contains_private_key_material

logger = logging.getLogger("credential_guard")

RESULT_GUARD_FAIL_TEXT = (
    "工具可能已经执行，但返回内容未通过安全检查，原始结果未返回。"
    "请独立核验目标系统的真实状态。"
)
REDACTED_SECRET = "<REDACTED_SECRET>"

# Reason code only — never embed result body, secrets, or exception objects.
RESULT_GUARD_FAIL_REASON = "RESULT_GUARD_FAIL"

SessionMaterial = Tuple[str, str]  # (credential_name, secret)

_AUTH_HEADER_RE = re.compile(
    r"(?im)^(Authorization|Proxy-Authorization)([ \t]*:[ \t]*)(.+)$"
)
_COOKIE_HEADER_RE = re.compile(
    r"(?im)^((?:Set-)?Cookie)([ \t]*:[ \t]*)(.+)$"
)
_CREDENTIAL_PLACEHOLDER_RE = re.compile(r"<CREDENTIAL:([^>\n]+)>")

# Explicit high-confidence field names only (bounded; not a DLP engine).
_SENSITIVE_FIELD_NAMES = frozenset({"password", "token", "secret"})

# JSON-style: "password": "value" or "password":"value"
_JSON_SENSITIVE_FIELD_RE = re.compile(
    r'(?i)("(?:password|token|secret)")(\s*:\s*)("(?:\\.|[^"\\])*")'
)
# Log / form style: password=value or password: value (no spaces in value)
_LOG_SENSITIVE_FIELD_RE = re.compile(
    r"(?i)\b(password|token|secret)(\s*[=:]\s*)([^\s,;\"'}]+)"
)

_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN[^\n-]{0,80}PRIVATE KEY-----"
    r".*?"
    r"-----END[^\n-]{0,80}PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)


def _credential_placeholder(name: str) -> str:
    return f"<CREDENTIAL:{name}>"


def _merged_identities(
    registry: CredentialRegistry,
    session_materials: Optional[Sequence[SessionMaterial]],
) -> List[Tuple[str, str]]:
    """Unified (token, secret) identities: session materials first, then registry.

    Aggregation budgets (MAX_REGISTRY_ITEMS / MAX_TOTAL_VARIANT_CHARS) apply to
    this merged view — same constants as outbound redactor, no second budget set.
    """
    identities: List[Tuple[str, str]] = []
    if session_materials:
        for name, secret in session_materials:
            if not isinstance(name, str) or not name:
                raise VariantBuildError("session material name invalid")
            if not isinstance(secret, str) or not secret:
                raise VariantBuildError("session material secret invalid")
            identities.append((_credential_placeholder(name), secret))
    for item in registry.values():
        identities.append((_credential_placeholder(item.key), item.secret))
    return identities


def _merge_replacement_pairs(
    registry: CredentialRegistry,
    session_materials: Optional[Sequence[SessionMaterial]],
) -> List[Tuple[str, str]]:
    """Authoritative (variant → token) pairs with the same aggregate gates as egress."""
    identities = _merged_identities(registry, session_materials)
    if len(identities) > redactor_mod.MAX_REGISTRY_ITEMS:
        raise VariantBuildError("registry item count exceeds limit")

    variant_owner: dict[str, str] = {}
    pairs: List[Tuple[str, str]] = []
    total_chars = 0

    for token, secret in identities:
        try:
            variants = build_secret_variants(secret, token=token)
        except VariantBuildError:
            raise
        except Exception as exc:
            raise VariantBuildError("variant construction failed") from exc

        for variant in variants:
            owner = variant_owner.get(variant)
            if owner is not None and owner != token:
                raise VariantBuildError("variant collision across identities")
            if owner is None:
                variant_owner[variant] = token
                pairs.append((variant, token))
                total_chars += len(variant)
                if total_chars > redactor_mod.MAX_TOTAL_VARIANT_CHARS:
                    raise VariantBuildError("total variant chars exceed limit")

    pairs.sort(key=lambda p: len(p[0]), reverse=True)
    return pairs


def redact_registered(
    text: str,
    registry: CredentialRegistry,
    session_materials: Optional[Sequence[SessionMaterial]] = None,
) -> str:
    out = text
    for variant, token in _merge_replacement_pairs(registry, session_materials):
        if variant and variant in out:
            out = out.replace(variant, token)
    return out


def _auth_cookie_replacement_value(value: str) -> str:
    """Whole-value auth/cookie replacement after registered redaction.

    Unique registered identity → keep ``<CREDENTIAL:name>`` as the whole value.
    Unregistered or multiple distinct registered identities → ``<REDACTED_SECRET>``.
    """
    names: List[str] = []
    seen: set[str] = set()
    for name in _CREDENTIAL_PLACEHOLDER_RE.findall(value):
        if name not in seen:
            seen.add(name)
            names.append(name)
    if len(names) == 1:
        return _credential_placeholder(names[0])
    return REDACTED_SECRET


def _redact_auth_headers(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        return f"{match.group(1)}{match.group(2)}{_auth_cookie_replacement_value(match.group(3))}"

    return _AUTH_HEADER_RE.sub(repl, text)


def _redact_cookie_headers(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        return f"{match.group(1)}{match.group(2)}{_auth_cookie_replacement_value(match.group(3))}"

    return _COOKIE_HEADER_RE.sub(repl, text)


def _is_already_placeholder(value: str) -> bool:
    v = value.strip().strip('"')
    if v == REDACTED_SECRET:
        return True
    if v.startswith("<CREDENTIAL:") and v.endswith(">"):
        return True
    if v.startswith("<SECRET:") and v.endswith(">"):
        return True
    return False


def _redact_sensitive_fields(text: str) -> str:
    def json_repl(match: re.Match[str]) -> str:
        raw_val = match.group(3)
        inner = raw_val[1:-1] if len(raw_val) >= 2 else raw_val
        if _is_already_placeholder(inner):
            return match.group(0)
        return f'{match.group(1)}{match.group(2)}"{REDACTED_SECRET}"'

    out = _JSON_SENSITIVE_FIELD_RE.sub(json_repl, text)

    def log_repl(match: re.Match[str]) -> str:
        name = match.group(1)
        val = match.group(3)
        if _is_already_placeholder(val):
            return match.group(0)
        return f"{name}{match.group(2)}{REDACTED_SECRET}"

    out = _LOG_SENSITIVE_FIELD_RE.sub(log_repl, out)
    return out


def redact_unknown_high_confidence(text: str) -> str:
    out = _redact_auth_headers(text)
    out = _redact_cookie_headers(out)
    out = _redact_sensitive_fields(out)
    return out


def _private_key_present(text: str) -> bool:
    """Presence check; scan bound / scanner errors propagate for fail-closed.

    Must not catch ``EncodedPrivateKeyScanError`` and invent window/streaming
    semantics — that would bypass ``MAX_PRIVATE_KEY_SCAN_BYTES``.
    """
    return bool(contains_private_key_material(text))


def redact_private_keys(text: str) -> str:
    """Replace fully locatable PEM blocks; fail closed if material remains."""
    out = text
    if _PEM_BLOCK_RE.search(out):
        out = _PEM_BLOCK_RE.sub(REDACTED_SECRET, out)
    if _private_key_present(out):
        # Still looks like a key after PEM replacement — cannot safely localize.
        raise RuntimeError("private key material not fully localizable")
    return out


def assert_zero_residue(
    text: str,
    registry: CredentialRegistry,
    session_materials: Optional[Sequence[SessionMaterial]] = None,
) -> None:
    for variant, _token in _merge_replacement_pairs(registry, session_materials):
        if variant and variant in text:
            raise RuntimeError("registered secret residue remains")
    for match in _AUTH_HEADER_RE.finditer(text):
        value = match.group(3).strip()
        if not value or value == REDACTED_SECRET:
            continue
        if _CREDENTIAL_PLACEHOLDER_RE.fullmatch(value):
            continue
        if re.match(r"(?i)(Bearer|Basic)\s+\S+", value):
            raise RuntimeError("auth header residue remains")
    if _private_key_present(text):
        raise RuntimeError("private key residue remains")


def guard_tool_result(
    text: str,
    registry: CredentialRegistry,
    session_materials: Optional[Sequence[SessionMaterial]] = None,
) -> str:
    """Authoritative result guard. Never raises; returns text or fixed fail text."""
    if not isinstance(text, str):
        text = str(text)
    try:
        out = redact_registered(text, registry, session_materials)
        out = redact_unknown_high_confidence(out)
        out = redact_private_keys(out)
        assert_zero_residue(out, registry, session_materials)
        return out
    except Exception:
        # Fixed warning + reason code only — never log bodies or exception objects.
        logger.warning(
            "credential-guard result_guard failed closed reason=%s",
            RESULT_GUARD_FAIL_REASON,
        )
        return RESULT_GUARD_FAIL_TEXT


__all__ = [
    "RESULT_GUARD_FAIL_TEXT",
    "RESULT_GUARD_FAIL_REASON",
    "REDACTED_SECRET",
    "guard_tool_result",
    "redact_registered",
    "redact_unknown_high_confidence",
    "redact_private_keys",
    "assert_zero_residue",
]
