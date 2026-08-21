from __future__ import annotations

from .registry import CredentialRegistry

_registry = CredentialRegistry()


def get_registry() -> CredentialRegistry:
    """Process-local base registry (tests may register synthetic canaries)."""
    return _registry


def get_base_registry_snapshot() -> CredentialRegistry:
    """Fresh independent copy of the process-local base registry only.

    This is the C1 pass-through source. The unified config file is absent, so
    the file half of ``get_egress_registry_snapshot`` contributes nothing — but
    the credentials registered in this process are still load-bearing and must
    keep being replaced before egress. Returning an empty registry here would
    send them to the Provider in plaintext.

    Never returns the shared global instance and never mutates it (see
    ``get_registry``). Conflicts fail closed exactly as in the merged snapshot;
    a pass-through branch must never degrade a conflict into "send it anyway".
    """
    from .runtime_config import RuntimeConfigError

    merged = CredentialRegistry()
    try:
        for item in _registry.values():
            merged.register(item.key, item.field, item.secret)
    except Exception:
        raise RuntimeConfigError("RUNTIME_CONFIG_UNAVAILABLE") from None
    return merged


def get_egress_registry_snapshot() -> CredentialRegistry:
    """Fresh independent merge of base memory registry + v2 file secret store.

    Never mutates the shared global registry in place. Conflicts (same identity
    with different secret, or same secret under multiple identities) fail closed.
    Unified-config read/schema/permission failures also fail closed.
    Formal runtime loads only the Schema v2 unified config file.
    """
    from .runtime_config import RuntimeConfigError, ensure_published_from_disk

    try:
        view = ensure_published_from_disk()
        file_snap = view.egress_registry
    except RuntimeConfigError:
        raise
    except Exception:
        raise RuntimeConfigError("RUNTIME_CONFIG_UNAVAILABLE") from None

    merged = CredentialRegistry()
    try:
        for item in _registry.values():
            merged.register(item.key, item.field, item.secret)
        for item in file_snap.values():
            merged.register(item.key, item.field, item.secret)
    except ValueError:
        raise RuntimeConfigError("RUNTIME_CONFIG_UNAVAILABLE") from None
    except RuntimeConfigError:
        raise
    except Exception:
        raise RuntimeConfigError("RUNTIME_CONFIG_UNAVAILABLE") from None
    return merged
