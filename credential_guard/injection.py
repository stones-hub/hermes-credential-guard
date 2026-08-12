"""R3A injection kernel: one-shot SecretLease after plan consume.

Internal only — not a model-facing tool. Never logs or serializes secret material.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, Mapping, Optional

from .injection_plan import InjectionPlan, PlanState
from .runtime_config import RuntimeView, note_injection_secret_resolve


class InjectionError(Exception):
    """Fixed safe code only — never embed secrets, hosts, paths, or raw exceptions."""

    def __init__(self, code: str) -> None:
        self.code = str(code)
        super().__init__(self.code)

    def __repr__(self) -> str:
        return f"InjectionError({self.code!r})"


class SecretLease:
    """Single-credential lease. Adapter-scope read only; no safe serialization."""

    __slots__ = ("_material", "_closed")

    def __init__(self, material: Mapping[str, Any]) -> None:
        self._material: Optional[Dict[str, Any]] = dict(material)
        self._closed = False

    def read_for_adapter(self) -> Dict[str, Any]:
        if self._closed or self._material is None:
            raise InjectionError("INJECTION_LEASE_CLOSED")
        # Return a shallow copy so caller mutations do not alias lease storage
        # longer than the adapter scope; values remain short-lived strings.
        return dict(self._material)

    def close(self) -> None:
        self._material = None
        self._closed = True

    def __repr__(self) -> str:
        return "SecretLease(<redacted>)"

    def __str__(self) -> str:
        return "SecretLease(<redacted>)"

    def __copy__(self):
        raise InjectionError("INJECTION_LEASE_COPY_FORBIDDEN")

    def __deepcopy__(self, memo):
        raise InjectionError("INJECTION_LEASE_COPY_FORBIDDEN")

    def __getstate__(self):
        raise InjectionError("INJECTION_LEASE_SERIALIZE_FORBIDDEN")

    def __setstate__(self, state):
        raise InjectionError("INJECTION_LEASE_SERIALIZE_FORBIDDEN")


def _credential_from_view(view: RuntimeView, name: str) -> Mapping[str, Any]:
    try:
        canonical = view.to_canonical_dict()
        creds = canonical.get("credentials")
        if not isinstance(creds, dict) or name not in creds:
            raise InjectionError("INJECTION_RESOLVE_FAILED")
        entry = creds[name]
        if not isinstance(entry, dict):
            raise InjectionError("INJECTION_RESOLVE_FAILED")
        return entry
    except InjectionError:
        raise
    except Exception:
        raise InjectionError("INJECTION_RESOLVE_FAILED") from None


def resolve_one_for_execution(
    consumed_plan: InjectionPlan, verified_view: RuntimeView
) -> SecretLease:
    """Resolve exactly the consumed plan's credential from the verified view."""
    if not isinstance(consumed_plan, InjectionPlan):
        raise InjectionError("INJECTION_RESOLVE_FAILED")
    if consumed_plan.state is not PlanState.CONSUMED:
        raise InjectionError("INJECTION_RESOLVE_FAILED")
    if not isinstance(verified_view, RuntimeView):
        raise InjectionError("INJECTION_RESOLVE_FAILED")

    name = consumed_plan.credential_name
    if not isinstance(name, str) or not name:
        raise InjectionError("INJECTION_RESOLVE_FAILED")

    entry = _credential_from_view(verified_view, name)
    ctype = entry.get("type")
    try:
        if ctype == "token":
            value = entry.get("value")
            if not isinstance(value, str) or not value:
                raise InjectionError("INJECTION_RESOLVE_FAILED")
            material = {"kind": "token", "value": value}
        elif ctype == "username_password":
            username = entry.get("username")
            password = entry.get("password")
            if not isinstance(username, str) or not username:
                raise InjectionError("INJECTION_RESOLVE_FAILED")
            if not isinstance(password, str) or not password:
                raise InjectionError("INJECTION_RESOLVE_FAILED")
            material = {
                "kind": "username_password",
                "username": username,
                "password": password,
            }
        else:
            raise InjectionError("INJECTION_RESOLVE_FAILED")
    except InjectionError:
        raise
    except Exception:
        raise InjectionError("INJECTION_RESOLVE_FAILED") from None

    note_injection_secret_resolve(1)
    return SecretLease(material)


__all__ = [
    "InjectionError",
    "SecretLease",
    "resolve_one_for_execution",
]
