from __future__ import annotations

from .registry import CredentialRegistry

_registry = CredentialRegistry()


def get_registry() -> CredentialRegistry:
    """Process-local base registry (tests may register synthetic canaries)."""
    return _registry


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
