"""Formal runtime adapter: credential-guard.json → egress registry + binding view.

R1B: sole production config source for hooks/middleware/state. Does not read
credentials.json / targets.json (migration-only). Does not execute adapters.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Tuple, Union

from .bindings import PROCESS_REFERENCE_ARG_PATH, PROCESS_REFERENCE_TOOL
from .config import CONFIG_FILENAME, ConfigError, CredentialGuardConfig
from .config_lock import ConfigLockError, shared_config_lock
from .registry import CredentialRegistry

PathLike = Union[str, Path]

# R2 product convention for HTTP logical-reference tool (adapter lands in R3).
HTTP_REFERENCE_TOOL = "http_credential_request"
HTTP_REFERENCE_ARG_PATH: Tuple[str, ...] = ("credential",)

_RUNTIME_LOCK = threading.RLock()
# R2/R3 shared critical section: final lstat → compare → consume (→ R3 resolve).
# Callers must not re-read config outside this lock after consume.
_EXECUTION_RECHECK_LOCK = threading.RLock()
_PUBLISHED: Optional["RuntimeView"] = None
_UNAVAILABLE = False
# R1B egress publish-event counter. Observational only — not an R2 security
# binding. R2 plans bind config_file_identity + config/binding/target digest + lstat.
_GENERATION = 0
# Test-observable seam: increments when execution-bound secret material is resolved.
# R1B egress registry build counts (secrets enter redaction registry).
# Default production callers never reset.
_EXECUTION_SECRET_RESOLVE_COUNT = 0
# R3A injection-time resolve observer — distinct from egress registry build counts.
_INJECTION_SECRET_RESOLVE_COUNT = 0


def note_execution_secret_resolve(n: int = 1) -> None:
    """Record that secret material was resolved for registry/injection use."""
    global _EXECUTION_SECRET_RESOLVE_COUNT
    with _RUNTIME_LOCK:
        _EXECUTION_SECRET_RESOLVE_COUNT += int(n)


def get_execution_secret_resolve_count() -> int:
    with _RUNTIME_LOCK:
        return int(_EXECUTION_SECRET_RESOLVE_COUNT)


def reset_execution_secret_resolve_count_for_tests() -> None:
    global _EXECUTION_SECRET_RESOLVE_COUNT
    with _RUNTIME_LOCK:
        _EXECUTION_SECRET_RESOLVE_COUNT = 0


def note_injection_secret_resolve(n: int = 1) -> None:
    """Record an approval-bound, execution-time credential resolve (R3A)."""
    global _INJECTION_SECRET_RESOLVE_COUNT
    with _RUNTIME_LOCK:
        _INJECTION_SECRET_RESOLVE_COUNT += int(n)


def get_injection_secret_resolve_count() -> int:
    with _RUNTIME_LOCK:
        return int(_INJECTION_SECRET_RESOLVE_COUNT)


def reset_injection_secret_resolve_count_for_tests() -> None:
    global _INJECTION_SECRET_RESOLVE_COUNT
    with _RUNTIME_LOCK:
        _INJECTION_SECRET_RESOLVE_COUNT = 0


class RuntimeConfigError(Exception):
    """Fail-closed runtime config error. Never embed secrets, hosts, or paths."""

    __slots__ = ("code",)

    def __init__(self, code: str, message: str = "configuration error") -> None:
        object.__setattr__(self, "code", code)
        super().__init__(message)

    def __repr__(self) -> str:
        return f"RuntimeConfigError(code={self.code!r})"


def _store_dir() -> Path:
    hermes = os.environ.get("HERMES_HOME", "").strip()
    if hermes:
        return Path(hermes) / "credential-guard"
    return Path.home() / ".hermes" / "credential-guard"


def default_config_path() -> Path:
    return _store_dir() / CONFIG_FILENAME


def _map_config_error(exc: ConfigError) -> RuntimeConfigError:
    code = getattr(exc, "code", "") or ""
    if code == "CONFIG_NOT_FOUND":
        return RuntimeConfigError("RUNTIME_CONFIG_NOT_FOUND")
    if code in {
        "CONFIG_SCHEMA",
        "CONFIG_INVALID_JSON",
        "CONFIG_INVALID_UTF8",
        "CONFIG_DUPLICATE_KEY",
        "CONFIG_TOO_LARGE",
        "CONFIG_NOT_FILE",
    }:
        return RuntimeConfigError("RUNTIME_CONFIG_INVALID")
    return RuntimeConfigError("RUNTIME_CONFIG_UNAVAILABLE")


def _stable_digest(payload: Mapping[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _freeze_binding_meta(bindings: Mapping[str, Any]) -> Mapping[str, Any]:
    """Immutable binding metadata view — match fields only, no secret/host."""

    def scrub(name: str, entry: Mapping[str, Any]) -> Dict[str, Any]:
        btype = entry.get("type")
        out: Dict[str, Any] = {
            "type": btype,
            "credential_ref": entry.get("credential_ref"),
            "approval": entry.get("approval"),
        }
        # Safe structural metadata only (no host/url/alias/secret/program path).
        if btype in {"process_env", "stdin"}:
            out["allowed_tools"] = (PROCESS_REFERENCE_TOOL,)
            out["reference_arg_path"] = PROCESS_REFERENCE_ARG_PATH
            out["inject_mode"] = btype
            # Approval-safe summary: logical mode only — never program/env/argv.
            out["operation_summary"] = f"fixed local program:{btype}"
            out["process_summary"] = "fixed local program"
        if btype == "http" and isinstance(entry.get("inject"), Mapping):
            inj = entry["inject"]
            out["inject_type"] = inj.get("type")
            if inj.get("type") == "api_key_header":
                out["inject_header_name"] = inj.get("header_name")
            out["reference_arg_path"] = HTTP_REFERENCE_ARG_PATH
            out["allowed_tools"] = (HTTP_REFERENCE_TOOL,)
            loc = inj.get("location") or inj.get("header_name") or ""
            raw_target = entry.get("target")
            # Safe scheme only — never host/port in scrubbed approval meta.
            scheme = (
                raw_target.get("scheme")
                if isinstance(raw_target, Mapping)
                else None
            )
            if scheme in {"http", "https"}:
                out["scheme"] = scheme
            else:
                scheme = "https"
            out["operation_summary"] = f"{scheme}:{inj.get('type')}:{loc}"
            req = entry.get("request")
            if isinstance(req, Mapping):
                methods = req.get("allowed_methods") or ()
                paths = req.get("allowed_paths") or ()
                out["allowed_methods"] = tuple(methods)
                out["allowed_paths"] = tuple(paths)
                out["connect_timeout_seconds"] = req.get("connect_timeout_seconds")
                out["total_timeout_seconds"] = req.get("total_timeout_seconds")
                out["max_response_body_bytes"] = req.get("max_response_body_bytes")
        # Digests bind all execution-affecting fields. Real host/port/program enter
        # digest bytes only — never the scrubbed meta exposed to model/approval.
        digest_src: Dict[str, Any] = {
            "name": name,
            "type": out.get("type"),
            "credential_ref": out.get("credential_ref"),
            "approval": out.get("approval"),
            "allowed_tools": list(out.get("allowed_tools") or ()),
            "reference_arg_path": list(out.get("reference_arg_path") or ()),
            "inject_type": out.get("inject_type"),
            "inject_header_name": out.get("inject_header_name"),
            "inject_mode": out.get("inject_mode"),
            "scheme": out.get("scheme"),
            "allowed_methods": list(out.get("allowed_methods") or ()),
            "allowed_paths": list(out.get("allowed_paths") or ()),
            "connect_timeout_seconds": out.get("connect_timeout_seconds"),
            "total_timeout_seconds": out.get("total_timeout_seconds"),
            "max_response_body_bytes": out.get("max_response_body_bytes"),
        }
        # Process fields: bind real program/argv/env/limits into digest only.
        if btype in {"process_env", "stdin"}:
            digest_src["program"] = entry.get("program")
            digest_src["argv"] = list(entry.get("argv") or ())
            digest_src["env_name"] = entry.get("env_name")
            digest_src["stdin_format"] = entry.get("stdin_format")
            digest_src["timeout_seconds"] = entry.get("timeout_seconds")
            digest_src["max_stdout_bytes"] = entry.get("max_stdout_bytes")
            digest_src["max_stderr_bytes"] = entry.get("max_stderr_bytes")
        out["binding_digest"] = _stable_digest(digest_src)

        target_src: Dict[str, Any] = {
            "name": name,
            "credential_ref": out.get("credential_ref"),
            "type": btype,
        }
        raw_target = entry.get("target")
        if isinstance(raw_target, Mapping):
            # Include real target identity in digest only.
            target_src["scheme"] = raw_target.get("scheme")
            target_src["host"] = raw_target.get("host")
            target_src["port"] = raw_target.get("port")
        if btype in {"process_env", "stdin"}:
            # Program absolute path is the process target identity (digest only).
            target_src["program"] = entry.get("program")
            target_src["argv"] = list(entry.get("argv") or ())
            target_src["inject_mode"] = btype
        out["target_digest"] = _stable_digest(target_src)
        return out

    cleaned = {name: scrub(name, bindings[name]) for name in bindings}
    return MappingProxyType({k: MappingProxyType(v) for k, v in cleaned.items()})


def build_file_egress_registry(cfg: CredentialGuardConfig) -> CredentialRegistry:
    """Build a complete egress registry from an immutable config snapshot.

    Registers token.value and username_password.password (+ basic_auth combo per
    existing approved egress rules).
    """
    registry = CredentialRegistry()
    for name in sorted(cfg.credentials):
        entry = cfg.credentials[name]
        ctype = entry["type"]
        try:
            if ctype == "token":
                note_execution_secret_resolve()
                registry.register(name, "value", entry["value"])
            elif ctype == "username_password":
                password = entry["password"]
                username = entry["username"]
                note_execution_secret_resolve()
                registry.register(name, "password", password)
                # Existing approved Basic Auth combination redaction (not username alone).
                note_execution_secret_resolve()
                registry.register(name, "basic_auth", f"{username}:{password}")
            else:
                raise RuntimeConfigError("RUNTIME_CONFIG_INVALID")
        except RuntimeConfigError:
            raise
        except ValueError:
            raise RuntimeConfigError("RUNTIME_CONFIG_INVALID") from None
        except Exception:
            raise RuntimeConfigError("RUNTIME_CONFIG_UNAVAILABLE") from None
    return registry


def _file_identity(path: Path) -> Mapping[str, Any]:
    st = path.lstat()
    return MappingProxyType(
        {
            "mtime_ns": int(st.st_mtime_ns),
            "size": int(st.st_size),
            "inode": int(st.st_ino),
            "device": int(st.st_dev),
        }
    )


def get_current_config_file_identity(
    path: Optional[PathLike] = None,
) -> Mapping[str, Any]:
    """lstat-only identity of the default single-file config. Never open/read body."""
    target = Path(path) if path is not None else default_config_path()
    try:
        return _file_identity(target)
    except OSError as exc:
        raise RuntimeConfigError("RUNTIME_CONFIG_UNAVAILABLE") from exc


def execution_recheck_lock() -> threading.RLock:
    """Process-local lock for final lstat → compare → consume (+ R3 resolve)."""
    return _EXECUTION_RECHECK_LOCK


def _build_view(
    cfg: CredentialGuardConfig,
    generation: int,
    *,
    config_path: Optional[Path] = None,
) -> "RuntimeView":
    registry = build_file_egress_registry(cfg)
    bindings = _freeze_binding_meta(cfg.bindings)
    digest = cfg.config_digest
    names = tuple(sorted(bindings))
    refs = tuple(
        sorted(
            {
                str(bindings[n].get("credential_ref") or "")
                for n in bindings
                if bindings[n].get("credential_ref")
            }
        )
    )
    credential_names = tuple(sorted(cfg.credentials))
    identity: Mapping[str, Any] = MappingProxyType({})
    if config_path is not None:
        try:
            identity = _file_identity(Path(config_path))
        except OSError:
            identity = MappingProxyType({})
    canonical = cfg.to_canonical_dict()
    return RuntimeView(
        generation=generation,
        config_digest=digest,
        binding_view_digest=digest,
        egress_registry_digest_marker=digest,
        binding_names=names,
        binding_credential_refs=refs,
        credential_names=credential_names,
        bindings=bindings,
        config_file_identity=identity,
        egress_registry=registry,
        _canonical=canonical,
    )


@dataclass(frozen=True)
class RuntimeView:
    generation: int
    config_digest: str
    binding_view_digest: str
    egress_registry_digest_marker: str
    binding_names: Tuple[str, ...]
    binding_credential_refs: Tuple[str, ...]
    credential_names: Tuple[str, ...]
    bindings: Mapping[str, Any]
    config_file_identity: Mapping[str, Any]
    egress_registry: CredentialRegistry
    _canonical: Dict[str, Any]

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Deep copy — caller mutations must not affect runtime."""
        return _deep_copy(self._canonical)


def _deep_copy(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _deep_copy(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deep_copy(v) for v in obj]
    if isinstance(obj, tuple):
        return [_deep_copy(v) for v in obj]
    return obj


def load_config(path: Optional[PathLike] = None) -> CredentialGuardConfig:
    target: PathLike = path if path is not None else default_config_path()
    try:
        return CredentialGuardConfig.load(target)
    except ConfigError as exc:
        raise _map_config_error(exc) from None
    except RuntimeConfigError:
        raise
    except Exception:
        raise RuntimeConfigError("RUNTIME_CONFIG_UNAVAILABLE") from None


def _publish(view: RuntimeView) -> RuntimeView:
    global _PUBLISHED, _UNAVAILABLE, _GENERATION
    with _RUNTIME_LOCK:
        _PUBLISHED = view
        _UNAVAILABLE = False
        _GENERATION = view.generation
        return view


def mark_runtime_unavailable() -> None:
    global _PUBLISHED, _UNAVAILABLE
    with _RUNTIME_LOCK:
        _PUBLISHED = None
        _UNAVAILABLE = True


def reset_runtime_for_tests() -> None:
    global _PUBLISHED, _UNAVAILABLE, _GENERATION
    with _RUNTIME_LOCK:
        _PUBLISHED = None
        _UNAVAILABLE = False
        _GENERATION = 0
    reset_execution_secret_resolve_count_for_tests()
    reset_injection_secret_resolve_count_for_tests()

def load_and_publish_runtime(path=None) -> RuntimeView:
    """Load credential-guard.json, build complete snapshot, publish atomically.

    Holds the cross-process *shared* config lock for the full read→build→publish
    critical section (not merely the in-process publish). Lock order:
    config lock → ``_RUNTIME_LOCK``.

    On failure: mark runtime unavailable (do not leave partial publish) and
    always release the config lock.
    """
    global _GENERATION
    target = Path(path) if path is not None else default_config_path()
    store = target.parent
    try:
        # Shared lock covers body read + view build + atomic publish.
        with shared_config_lock(store):
            cfg = load_config(target)
            with _RUNTIME_LOCK:
                next_gen = _GENERATION + 1
            view = _build_view(cfg, next_gen, config_path=target)
            return _publish(view)
    except ConfigLockError as exc:
        mark_runtime_unavailable()
        raise RuntimeConfigError("RUNTIME_CONFIG_UNAVAILABLE") from exc
    except RuntimeConfigError:
        mark_runtime_unavailable()
        raise
    except Exception:
        mark_runtime_unavailable()
        raise RuntimeConfigError("RUNTIME_CONFIG_UNAVAILABLE") from None


def reload_runtime(path=None) -> RuntimeView:
    """Reload from disk. Failure marks runtime unavailable (fail closed)."""
    return load_and_publish_runtime(path)


def get_runtime_view() -> RuntimeView:
    with _RUNTIME_LOCK:
        if _UNAVAILABLE or _PUBLISHED is None:
            raise RuntimeConfigError("RUNTIME_CONFIG_UNAVAILABLE")
        return _PUBLISHED


def ensure_published_from_disk(path=None) -> RuntimeView:
    """Fresh load + atomic publish for each formal egress request."""
    return load_and_publish_runtime(path)


def require_runtime_adapter(binding_name: str) -> None:
    """R1B: adapters are metadata-only; execution paths fail closed."""
    view = get_runtime_view()
    if binding_name not in view.bindings:
        raise RuntimeConfigError("RUNTIME_CONFIG_UNAVAILABLE")
    # http / process_env / stdin injection not implemented until R3+.
    raise RuntimeConfigError("RUNTIME_ADAPTER_NOT_READY")


__all__ = [
    "HTTP_REFERENCE_ARG_PATH",
    "HTTP_REFERENCE_TOOL",
    "RuntimeConfigError",
    "RuntimeView",
    "build_file_egress_registry",
    "default_config_path",
    "ensure_published_from_disk",
    "execution_recheck_lock",
    "get_current_config_file_identity",
    "get_execution_secret_resolve_count",
    "get_injection_secret_resolve_count",
    "get_runtime_view",
    "load_and_publish_runtime",
    "load_config",
    "mark_runtime_unavailable",
    "note_execution_secret_resolve",
    "note_injection_secret_resolve",
    "reload_runtime",
    "require_runtime_adapter",
    "reset_execution_secret_resolve_count_for_tests",
    "reset_injection_secret_resolve_count_for_tests",
    "reset_runtime_for_tests",
]
