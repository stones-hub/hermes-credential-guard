"""Strict logical credential reference analysis for tool args.

No restore/resolve API — references are identified only, never replaced with
secret values in this module.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any, Collection, Dict, List, Sequence, Tuple

from .config import NAME_RE

# Exact full-string reference only. No prefix/suffix, no case folding.
_REF_EXACT = re.compile(r"^<CREDENTIAL:([a-z][a-z0-9_-]{0,63})>$")
# Any credential-marker residue (case-insensitive) for fail-closed scanning.
_REF_TRACE = re.compile(r"<\s*CREDENTIAL\s*:", re.IGNORECASE)


class ReferenceError(Exception):
    """Fail-closed reference error. Never embed secrets or full args."""

    __slots__ = ("code",)

    def __init__(self, code: str, message: str = "invalid credential reference") -> None:
        object.__setattr__(self, "code", code)
        super().__init__(message)

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "code":
            raise AttributeError("code is immutable")
        super().__setattr__(name, value)


@dataclass(frozen=True)
class CredentialReference:
    credential_name: str
    arg_path: Tuple[object, ...]


@dataclass(frozen=True)
class ReferenceAnalysis:
    args: Dict[str, Any]
    references: Tuple[CredentialReference, ...]

    @property
    def has_reference(self) -> bool:
        return bool(self.references)


def analyze_references(
    args: dict,
    registered_names: Collection[str],
) -> ReferenceAnalysis:
    if not isinstance(args, dict):
        raise ReferenceError("ARGS_NOT_OBJECT")

    registered = frozenset(registered_names)
    cloned = copy.deepcopy(args)
    found: List[CredentialReference] = []

    def _reject(code: str) -> None:
        raise ReferenceError(code)

    def _scan(value: Any, path: Tuple[object, ...]) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(key, str) and _REF_TRACE.search(key):
                    _reject("REFERENCE_IN_KEY")
                if not isinstance(key, str):
                    # Non-string keys are not JSON tool args; fail closed if odd.
                    _reject("UNSUPPORTED_STRUCTURE")
                _scan(child, path + (key,))
            return
        if isinstance(value, list):
            for idx, child in enumerate(value):
                _scan(child, path + (idx,))
            return
        if isinstance(value, str):
            exact = _REF_EXACT.fullmatch(value)
            if exact:
                name = exact.group(1)
                if not NAME_RE.fullmatch(name):
                    _reject("INVALID_CREDENTIAL_NAME")
                if name not in registered:
                    _reject("UNREGISTERED_CREDENTIAL")
                found.append(
                    CredentialReference(credential_name=name, arg_path=path)
                )
                return
            if _REF_TRACE.search(value):
                _reject("MALFORMED_REFERENCE")
            # Also catch encoded / mixed-case variants without the marker regex.
            lowered = value.lower()
            if "<credential:" in lowered or "%3ccredential%3a" in lowered:
                _reject("MALFORMED_REFERENCE")
            return
        if value is None or isinstance(value, (bool, int, float)):
            return
        # bytes / set / custom objects are not valid tool-arg leaves with refs,
        # but may still carry residue if stringified — reject non-JSON leaves
        # that look like they could hide a reference channel.
        if isinstance(value, (bytes, bytearray, set, tuple)):
            _reject("UNSUPPORTED_STRUCTURE")
        # Other types (custom objects): fail closed.
        _reject("UNSUPPORTED_STRUCTURE")

    _scan(cloned, ())

    if len(found) > 1:
        raise ReferenceError("MULTIPLE_REFERENCES")

    return ReferenceAnalysis(args=cloned, references=tuple(found))


__all__ = [
    "CredentialReference",
    "ReferenceAnalysis",
    "ReferenceError",
    "analyze_references",
]
