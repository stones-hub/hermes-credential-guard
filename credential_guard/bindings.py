"""Binding schema validation for credential-guard.json (v2)."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Mapping

# Legacy shell-tool names — rejected for process bindings (R3B).
ALLOWED_TOOLS = frozenset({"terminal", "execute_code"})

# Formal model tool for fixed local program env/stdin injection (R3B).
PROCESS_REFERENCE_TOOL = "credential_process_run"
PROCESS_REFERENCE_ARG_PATH = ("credential",)

ALLOWED_BINDING_TYPES = frozenset({"http", "process_env", "stdin"})

ALLOWED_CREDENTIAL_TYPES = frozenset({"token", "username_password"})

# Env names that must never be overwritten via process_env injection.
FORBIDDEN_ENV_NAMES = frozenset(
    {
        "PATH",
        "HOME",
        "HERMES_HOME",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONEXECUTABLE",
        "PYTHONUSERBASE",
        "VIRTUAL_ENV",
        "CONDA_PREFIX",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PERL5LIB",
        "RUBYLIB",
        "RUBYOPT",
        "BASH_ENV",
        "ENV",
        "SHELLOPTS",
        "PS4",
        "PROMPT_COMMAND",
        "IFS",
        "CDPATH",
        "SHELL",
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "TEMP",
        "TMP",
        "TMPDIR",
    }
)

# Basename denylist: shells and common language interpreters (R3B).
_FORBIDDEN_PROGRAM_BASENAMES = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "fish",
        "dash",
        "ksh",
        "csh",
        "tcsh",
        "python",
        "python3",
        "python2",
        "perl",
        "ruby",
        "node",
        "nodejs",
        "osascript",
        "env",
    }
)

# Argv tokens that open secondary interpretation surfaces.
_FORBIDDEN_ARGV_FLAGS = frozenset(
    {
        "-c",
        "-e",
        "-ec",
        "--command",
        "--eval",
        "--execute",
    }
)

_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_DNS_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_FORBIDDEN_HEADERS = frozenset({"authorization", "cookie", "host"})

_HTTP_FIELDS = frozenset(
    {"type", "credential_ref", "target", "request", "inject", "approval"}
)
_PROCESS_ENV_FIELDS = frozenset(
    {
        "type",
        "credential_ref",
        "program",
        "argv",
        "env_name",
        "timeout_seconds",
        "max_stdout_bytes",
        "max_stderr_bytes",
        "approval",
    }
)
_STDIN_FIELDS = frozenset(
    {
        "type",
        "credential_ref",
        "program",
        "argv",
        "stdin_format",
        "timeout_seconds",
        "max_stdout_bytes",
        "max_stderr_bytes",
        "approval",
    }
)
_TARGET_FIELDS = frozenset({"scheme", "host", "port"})
_REQUEST_REQUIRED_FIELDS = frozenset({"allowed_methods", "allowed_paths"})
_REQUEST_OPTIONAL_FIELDS = frozenset(
    {
        "connect_timeout_seconds",
        "total_timeout_seconds",
        "max_response_body_bytes",
    }
)
_REQUEST_FIELDS = _REQUEST_REQUIRED_FIELDS | _REQUEST_OPTIONAL_FIELDS
_BEARER_FIELDS = frozenset({"type", "location"})
_BASIC_FIELDS = frozenset({"type", "location"})
_API_KEY_FIELDS = frozenset({"type", "header_name"})
_STDIN_FORMATS = frozenset({"raw", "line"})

_ALLOWED_HTTP_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
)
_UNSAFE_PATH_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\\\u0085\u2028\u2029]")
_CTRL_OR_NUL = re.compile(r"[\x00-\x1f\x7f]")

# Safe finite defaults / caps for process adapter limits (R3B).
_DEFAULT_CONNECT_TIMEOUT = 5
_DEFAULT_TOTAL_TIMEOUT = 30
_DEFAULT_MAX_BODY_BYTES = 65536
_MIN_PROCESS_TIMEOUT = 1
_MAX_PROCESS_TIMEOUT = 120
_MIN_PROCESS_OUTPUT = 256
_MAX_PROCESS_OUTPUT = 8_388_608
_MAX_ARGV_LEN = 32
_MAX_ARGV_ELEM_BYTES = 4096


def validate_dns_host(host: Any) -> str:
    from .config import ConfigError

    if not isinstance(host, str) or not host:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if any(ord(ch) < 32 for ch in host):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    # Reject URL shape, userinfo, path, trailing dot, wildcards, uppercase, IP.
    if "://" in host or "/" in host or "@" in host or "*" in host or "?" in host:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if host.endswith("."):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if any(ch.isupper() for ch in host):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if _looks_like_ip(host):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    labels = host.split(".")
    if len(labels) < 2:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if len(host) > 253:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    for label in labels:
        if not _DNS_LABEL_RE.fullmatch(label):
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    return host


def _looks_like_ip(host: str) -> bool:
    # IPv4
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    # IPv6 (coarse)
    if ":" in host:
        return True
    return False


def validate_env_name(name: Any) -> str:
    from .config import ConfigError

    if not isinstance(name, str) or not name:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if name in FORBIDDEN_ENV_NAMES:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if not _ENV_NAME_RE.fullmatch(name):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    return name


def validate_tool(tool: Any) -> str:
    """Legacy helper — process bindings no longer accept terminal/execute_code."""
    from .config import ConfigError

    if not isinstance(tool, str) or not tool:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if tool not in ALLOWED_TOOLS:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    return tool


def validate_program_path(program: Any) -> str:
    """Absolute pathname string for a fixed local program (existence checked in B2)."""
    from .config import ConfigError

    if not isinstance(program, str) or not program:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if _CTRL_OR_NUL.search(program):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if program.startswith("~") or "$" in program:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if not os.path.isabs(program):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    # Reject dot-segment traversal even in absolute form.
    parts = program.split("/")
    if ".." in parts or any(p == "." or p == "" for p in parts[1:]):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    base = os.path.basename(program)
    if not base or base in _FORBIDDEN_PROGRAM_BASENAMES:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    # Also reject common interpreter versioned names: python3.11, nodejs, etc.
    lowered = base.lower()
    for banned in _FORBIDDEN_PROGRAM_BASENAMES:
        if lowered == banned or lowered.startswith(banned + "."):
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if len(program) > 1024:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    return program


def validate_fixed_argv(argv: Any, program: str) -> List[str]:
    from .config import ConfigError

    if not isinstance(argv, list) or not argv:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if len(argv) > _MAX_ARGV_LEN:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    out: List[str] = []
    for item in argv:
        if not isinstance(item, str) or not item:
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        if _CTRL_OR_NUL.search(item):
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        if len(item.encode("utf-8")) > _MAX_ARGV_ELEM_BYTES:
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        if item in _FORBIDDEN_ARGV_FLAGS:
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        out.append(item)
    # argv[0] must equal the configured absolute program (no model placeholders).
    if out[0] != program:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    return out


def validate_header_name(name: Any) -> str:
    from .config import ConfigError

    if not isinstance(name, str) or not name:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if "\n" in name or "\r" in name or "\x00" in name:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if name.lower() in _FORBIDDEN_HEADERS:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if not _HEADER_NAME_RE.fullmatch(name):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    return name


def validate_binding(
    name: str,
    entry: Mapping[str, Any],
    credentials: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Any]:
    from .config import ConfigError

    if not isinstance(entry, dict):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    btype = entry.get("type")
    if btype not in ALLOWED_BINDING_TYPES:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if btype == "http":
        return _validate_http(name, entry, credentials)
    if btype == "process_env":
        return _validate_process_env(name, entry, credentials)
    if btype == "stdin":
        return _validate_stdin(name, entry, credentials)
    raise ConfigError("CONFIG_SCHEMA", "invalid configuration")


def _require_fields(entry: Mapping[str, Any], allowed: frozenset) -> None:
    from .config import ConfigError

    if set(entry) - allowed:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if allowed - set(entry):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")


def _require_approval(entry: Mapping[str, Any]) -> None:
    from .config import ConfigError

    if entry.get("approval") != "required":
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")


def _resolve_cred(
    ref: Any, credentials: Mapping[str, Mapping[str, Any]]
) -> Mapping[str, Any]:
    from .config import ConfigError

    if not isinstance(ref, str) or ref not in credentials:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    return credentials[ref]


def validate_exact_http_path(path: Any) -> str:
    """Exact allowlist path: relative origin path, no regex/wildcards."""
    from .config import ConfigError

    if not isinstance(path, str) or not path:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if not path.startswith("/") or path.startswith("//"):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if any(ch in path for ch in ("*", "?", "(", ")", "[", "]", "{", "}", "|", "^", "$", "+")):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if "://" in path or "@" in path or "#" in path or "?" in path:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if _UNSAFE_PATH_CHARS.search(path):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if ".." in path or "/./" in path or path.endswith("/.") or path.endswith("/.."):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if len(path) > 512:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    return path


def _validate_int_in_range(value: Any, lo: int, hi: int) -> int:
    from .config import ConfigError

    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if value < lo or value > hi:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    return value


def _validate_http_request(request: Any) -> Dict[str, Any]:
    from .config import ConfigError

    if not isinstance(request, dict):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    unknown = set(request) - _REQUEST_FIELDS
    missing = _REQUEST_REQUIRED_FIELDS - set(request)
    if unknown or missing:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")

    methods_raw = request["allowed_methods"]
    if not isinstance(methods_raw, list) or not methods_raw:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    methods: list[str] = []
    seen_m: set[str] = set()
    for item in methods_raw:
        if not isinstance(item, str) or item not in _ALLOWED_HTTP_METHODS:
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        if item in seen_m:
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        seen_m.add(item)
        methods.append(item)

    paths_raw = request["allowed_paths"]
    if not isinstance(paths_raw, list) or not paths_raw:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    if len(paths_raw) > 64:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    paths: list[str] = []
    seen_p: set[str] = set()
    for item in paths_raw:
        path = validate_exact_http_path(item)
        if path in seen_p:
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        seen_p.add(path)
        paths.append(path)

    connect = (
        _validate_int_in_range(request["connect_timeout_seconds"], 1, 60)
        if "connect_timeout_seconds" in request
        else _DEFAULT_CONNECT_TIMEOUT
    )
    total = (
        _validate_int_in_range(request["total_timeout_seconds"], 1, 120)
        if "total_timeout_seconds" in request
        else _DEFAULT_TOTAL_TIMEOUT
    )
    if total < connect:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    max_body = (
        _validate_int_in_range(request["max_response_body_bytes"], 256, 8_388_608)
        if "max_response_body_bytes" in request
        else _DEFAULT_MAX_BODY_BYTES
    )
    return {
        "allowed_methods": methods,
        "allowed_paths": paths,
        "connect_timeout_seconds": connect,
        "total_timeout_seconds": total,
        "max_response_body_bytes": max_body,
    }


def _validate_http(
    name: str,
    entry: Mapping[str, Any],
    credentials: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Any]:
    from .config import ConfigError

    _require_fields(entry, _HTTP_FIELDS)
    _require_approval(entry)
    cred = _resolve_cred(entry["credential_ref"], credentials)
    target = entry["target"]
    if not isinstance(target, dict):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    _require_fields(target, _TARGET_FIELDS)
    if target["scheme"] != "https":
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    host = validate_dns_host(target["host"])
    port = target["port"]
    if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    request_out = _validate_http_request(entry["request"])
    inject = entry["inject"]
    if not isinstance(inject, dict):
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    itype = inject.get("type")
    if itype == "bearer":
        _require_fields(inject, _BEARER_FIELDS)
        if inject["location"] != "authorization_header":
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        if cred.get("type") != "token":
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        inject_out = {"type": "bearer", "location": "authorization_header"}
    elif itype == "basic":
        _require_fields(inject, _BASIC_FIELDS)
        if inject["location"] != "authorization_header":
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        if cred.get("type") != "username_password":
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        inject_out = {"type": "basic", "location": "authorization_header"}
    elif itype == "api_key_header":
        _require_fields(inject, _API_KEY_FIELDS)
        header_name = validate_header_name(inject["header_name"])
        if cred.get("type") != "token":
            raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
        inject_out = {"type": "api_key_header", "header_name": header_name}
    else:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    return {
        "type": "http",
        "credential_ref": entry["credential_ref"],
        "target": {"scheme": "https", "host": host, "port": port},
        "request": request_out,
        "inject": inject_out,
        "approval": "required",
    }


def _validate_process_limits(entry: Mapping[str, Any]) -> Dict[str, int]:
    timeout = _validate_int_in_range(
        entry["timeout_seconds"], _MIN_PROCESS_TIMEOUT, _MAX_PROCESS_TIMEOUT
    )
    max_out = _validate_int_in_range(
        entry["max_stdout_bytes"], _MIN_PROCESS_OUTPUT, _MAX_PROCESS_OUTPUT
    )
    max_err = _validate_int_in_range(
        entry["max_stderr_bytes"], _MIN_PROCESS_OUTPUT, _MAX_PROCESS_OUTPUT
    )
    return {
        "timeout_seconds": timeout,
        "max_stdout_bytes": max_out,
        "max_stderr_bytes": max_err,
    }


def _validate_process_env(
    name: str,
    entry: Mapping[str, Any],
    credentials: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Any]:
    from .config import ConfigError

    _require_fields(entry, _PROCESS_ENV_FIELDS)
    _require_approval(entry)
    cred = _resolve_cred(entry["credential_ref"], credentials)
    # Env inject first edition: token only.
    if cred.get("type") != "token":
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    program = validate_program_path(entry["program"])
    argv = validate_fixed_argv(entry["argv"], program)
    env_name = validate_env_name(entry["env_name"])
    limits = _validate_process_limits(entry)
    return {
        "type": "process_env",
        "credential_ref": entry["credential_ref"],
        "program": program,
        "argv": argv,
        "env_name": env_name,
        "timeout_seconds": limits["timeout_seconds"],
        "max_stdout_bytes": limits["max_stdout_bytes"],
        "max_stderr_bytes": limits["max_stderr_bytes"],
        "approval": "required",
    }


def _validate_stdin(
    name: str,
    entry: Mapping[str, Any],
    credentials: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Any]:
    from .config import ConfigError

    _require_fields(entry, _STDIN_FIELDS)
    _require_approval(entry)
    cred = _resolve_cred(entry["credential_ref"], credentials)
    # First edition: token value only — avoid implied username_password formats.
    if cred.get("type") != "token":
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    program = validate_program_path(entry["program"])
    argv = validate_fixed_argv(entry["argv"], program)
    stdin_format = entry["stdin_format"]
    if stdin_format not in _STDIN_FORMATS:
        raise ConfigError("CONFIG_SCHEMA", "invalid configuration")
    limits = _validate_process_limits(entry)
    return {
        "type": "stdin",
        "credential_ref": entry["credential_ref"],
        "program": program,
        "argv": argv,
        "stdin_format": stdin_format,
        "timeout_seconds": limits["timeout_seconds"],
        "max_stdout_bytes": limits["max_stdout_bytes"],
        "max_stderr_bytes": limits["max_stderr_bytes"],
        "approval": "required",
    }


__all__ = [
    "ALLOWED_BINDING_TYPES",
    "ALLOWED_CREDENTIAL_TYPES",
    "ALLOWED_TOOLS",
    "FORBIDDEN_ENV_NAMES",
    "PROCESS_REFERENCE_ARG_PATH",
    "PROCESS_REFERENCE_TOOL",
    "validate_binding",
    "validate_dns_host",
    "validate_env_name",
    "validate_exact_http_path",
    "validate_fixed_argv",
    "validate_header_name",
    "validate_program_path",
    "validate_tool",
]
