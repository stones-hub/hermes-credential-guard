try:
    from .credential_guard import register
except ImportError:  # pragma: no cover - flat import path for local tooling
    from credential_guard import register

__all__ = ["register"]
