"""Detect redacted credential codes — no registry / token lookup."""

from __future__ import annotations

import json
import re
from typing import Any

# Exact whole-string match only; never guess or repair malformed markers.
_REDACTED_CREDENTIAL_CODE = re.compile(r"^<SECRET:cg_[0-9a-f]{16}>$")

_C6_PAYLOAD = {
    "error": "CREDENTIAL_CODE_NOT_USABLE",
    "message": (
        "提供的是脱敏代号，不是凭证引用。凭证不能通过对话传入；"
        "请使用工具描述中列出的 <CREDENTIAL:name>。"
    ),
    "ok": False,
    "source": "credential-guard",
}


def is_redacted_credential_code(value: Any) -> bool:
    """True only for a complete, case-sensitive redacted credential code."""
    if not isinstance(value, str):
        return False
    return _REDACTED_CREDENTIAL_CODE.fullmatch(value) is not None


def credential_code_not_usable_error() -> str:
    """Fixed JSON for credential-parameter misuse of a redacted code."""
    return json.dumps(_C6_PAYLOAD, separators=(",", ":"), sort_keys=True)


__all__ = [
    "credential_code_not_usable_error",
    "is_redacted_credential_code",
]
