from __future__ import annotations

from typing import Any, Callable, Optional

from .state import get_egress_registry_snapshot, get_registry

INTERCEPT_POINTS = (
    "llm_request",
    "llm_execution",
    "tool_request",
    "tool_execution",
    "transform_tool_result",
    "pre_tool_call",
)
PLUGIN_NAME = "credential-guard"
HTTP_TOOL_NAME = "http_credential_request"
PROCESS_TOOL_NAME = "credential_process_run"
TOOL_NAMES = (HTTP_TOOL_NAME, PROCESS_TOOL_NAME)

# Product coverage boundary (plugin-only; no Hermes source changes / monkey patches).
# These strings are load-bearing for docs/CLI contract tests — do not claim global
# coverage of every Hermes model call.
COVERAGE_BOUNDARY_MAIN = (
    "coverage: protects Hermes main-chat conversation loop model requests "
    "and main-chain tool results"
)
COVERAGE_BOUNDARY_AUXILIARY = (
    "coverage: does not cover auxiliary_client.call_llm "
    "(title_generation/compression/vision/oneshot/session_search/…); "
    "current Hermes plugin interfaces do not wrap those host paths"
)
COVERAGE_BOUNDARY_NOTE = (
    "note: closing auxiliary.title_generation only removes one exposure path; "
    "it is not equivalent to full outbound coverage"
)
CHECK_HELP = (
    "Check registration; main-chat conversation loop + main-chain tool results "
    "are covered; Hermes auxiliary_client paths are out of current plugin scope"
)

# Expected leaf callback names inside the loaded plugin package.
_EXPECTED_CALLBACKS = {
    "llm_request": "on_llm_request",
    "llm_execution": "on_llm_execution",
    "tool_request": "on_tool_request",
    "tool_execution": "on_tool_execution",
    "transform_tool_result": "on_transform_tool_result",
    "pre_tool_call": "on_pre_tool_call",
}


VALIDATE_HELP = (
    "Offline read-only validation of credential-guard.json "
    "(no RuntimeView publish, no sidecar write, no Provider/adapter)"
)


def setup_parser(subparser: Any) -> None:
    subs = subparser.add_subparsers(dest="credential_guard_command")
    check = subs.add_parser("check", help=CHECK_HELP)
    check.set_defaults(func=handle_command)
    refresh = subs.add_parser(
        "refresh-targets",
        help="Regenerate credential-guard.targets.json from credential-guard.json",
    )
    refresh.set_defaults(func=handle_command)
    validate = subs.add_parser("validate", help=VALIDATE_HELP)
    validate.add_argument(
        "file",
        nargs="?",
        default=None,
        help="Config file to validate (default: Profile credential-guard.json)",
    )
    validate.set_defaults(func=handle_command)


def handle_command(args: Any) -> int:
    cmd = getattr(args, "credential_guard_command", "")
    if cmd == "check":
        return run_check()
    if cmd == "refresh-targets":
        from .target_catalog import run_refresh_targets

        return run_refresh_targets()
    if cmd == "validate":
        return run_validate(getattr(args, "file", None))
    print(
        "usage: hermes credential-guard "
        "check|refresh-targets|validate"
    )
    return 1


def _safe_location(name: Any) -> str:
    """Return a NAME_RE-safe identifier, else the fail-closed fallback."""
    from .config import NAME_RE

    if isinstance(name, str) and NAME_RE.fullmatch(name):
        return name
    return "configuration"


def run_validate(path: Any = None) -> int:
    """Offline read-only Schema v2 validation. Never publishes or writes.

    Explicit ``path`` reads only that file; ``None`` uses ``default_config_path()``.
    Does not require a live RuntimeView, does not generate the target catalog
    sidecar, and does not call Provider/adapters. stdout carries only PASS/FAIL
    lines with fixed codes and safe locations — never secrets, hosts, programs,
    paths, JSON bodies, or exception text.
    """
    from pathlib import Path

    from .config import ConfigError, CredentialGuardConfig
    from .runtime_config import default_config_path

    target = Path(path) if path is not None else default_config_path()
    try:
        cfg = CredentialGuardConfig.load(target)
    except ConfigError as exc:
        code = getattr(exc, "code", None) or "CONFIG_UNAVAILABLE"
        if not isinstance(code, str) or not code:
            code = "CONFIG_UNAVAILABLE"
        print(f"FAIL {code} configuration")
        return 1
    except Exception:
        print("FAIL CONFIG_UNAVAILABLE configuration")
        return 1

    # Names only from the successfully parsed canonical structure.
    for name in cfg.credentials:
        safe = _safe_location(name)
        if safe == "configuration":
            print("FAIL CONFIG_SCHEMA configuration")
            return 1
        print(f"PASS credential {safe}")
    for name in cfg.bindings:
        safe = _safe_location(name)
        if safe == "configuration":
            print("FAIL CONFIG_SCHEMA configuration")
            return 1
        print(f"PASS binding {safe}")
    print("VALID")
    return 0


def run_check() -> int:
    """Query the live PluginManager for intercept registration + registry health."""
    missing: list[str] = []
    try:
        from hermes_cli.plugins import get_plugin_manager

        mgr = get_plugin_manager()
    except Exception:
        print("credential-guard: check failed: PluginManager unavailable")
        return 1

    loaded = getattr(mgr, "_plugins", {}).get(PLUGIN_NAME)
    if loaded is None or not getattr(loaded, "enabled", False):
        missing.append("plugin_loaded_enabled")

    plugin_ns = _plugin_namespace(loaded)
    if loaded is not None and getattr(loaded, "enabled", False) and not plugin_ns:
        missing.append("plugin_module_namespace")

    middleware = getattr(mgr, "_middleware", {})
    hooks = getattr(mgr, "_hooks", {})

    req_cbs = list(middleware.get("llm_request", []) or [])
    exec_cbs = list(middleware.get("llm_execution", []) or [])
    tool_req_cbs = list(middleware.get("tool_request", []) or [])
    tool_exec_cbs = list(middleware.get("tool_execution", []) or [])
    tool_cbs = list(hooks.get("transform_tool_result", []) or [])
    pre_tool_cbs = list(hooks.get("pre_tool_call", []) or [])

    if not _has_our_callback(req_cbs, "llm_request", plugin_ns, loaded):
        missing.append("llm_request")
    if not _has_our_callback(exec_cbs, "llm_execution", plugin_ns, loaded):
        missing.append("llm_execution")
    if not _has_our_callback(tool_req_cbs, "tool_request", plugin_ns, loaded):
        missing.append("tool_request")
    if not _has_our_callback(tool_exec_cbs, "tool_execution", plugin_ns, loaded):
        missing.append("tool_execution")
    if not _has_our_callback(tool_cbs, "transform_tool_result", plugin_ns, loaded):
        missing.append("transform_tool_result")
    if not _has_our_callback(pre_tool_cbs, "pre_tool_call", plugin_ns, loaded):
        missing.append("pre_tool_call")
    if not _has_our_tool(
        mgr,
        loaded,
        HTTP_TOOL_NAME,
        "handle_http_credential_request",
        (".credential_guard.reference_tools", ".reference_tools"),
    ):
        missing.append(HTTP_TOOL_NAME)
    if not _has_our_tool(
        mgr,
        loaded,
        PROCESS_TOOL_NAME,
        "handle_credential_process_run",
        (".credential_guard.process_tools", ".process_tools"),
    ):
        missing.append(PROCESS_TOOL_NAME)

    try:
        registry = get_registry()
        meta = registry.metadata()
        entry_count = len(meta)
    except Exception:
        missing.append("registry")
        entry_count = -1
        meta = []

    egress_status = "unavailable"
    egress_opaque_count = 0
    try:
        egress = get_egress_registry_snapshot()
        egress_opaque_count = len(egress.metadata())
        egress_status = "ready"
    except Exception:
        egress_status = "unavailable"
        egress_opaque_count = 0
        missing.append("egress_registry")

    if missing:
        print("credential-guard: check failed")
        print(f"missing: {', '.join(missing)}")
        print(f"egress_registry={egress_status}")
        print(f"egress_opaque_count={egress_opaque_count}")
        return 1

    print("credential-guard: enabled")
    print(f"intercepts: {', '.join(INTERCEPT_POINTS)}")
    print(f"tools: {', '.join(TOOL_NAMES)}")
    print(f"registry_entries: {entry_count}")
    print(f"egress_registry={egress_status}")
    print(f"egress_opaque_count={egress_opaque_count}")
    for item in meta:
        # key/field/token_id only — never secrets
        print(f"registry_meta: {item['key']}.{item['field']} -> {item['token_id']}")
    print(COVERAGE_BOUNDARY_MAIN)
    print(COVERAGE_BOUNDARY_AUXILIARY)
    print(COVERAGE_BOUNDARY_NOTE)
    print(
        "optional temp mitigate: auxiliary.title_generation.enabled=false "
        "(reduces one path only). See docs/R7-Hermes当前版本真实外发兼容性修复方案.md"
    )
    return 0


def _plugin_namespace(loaded: Any) -> str:
    if loaded is None:
        return ""
    module = getattr(loaded, "module", None)
    if module is None:
        return ""
    name = getattr(module, "__name__", "") or ""
    return name


def _expected_callable(loaded: Any, intercept: str) -> Optional[Callable[..., Any]]:
    """Resolve the live plugin's expected callback identity when importable."""
    import importlib
    import sys

    expected_name = _EXPECTED_CALLBACKS.get(intercept)
    if not expected_name or loaded is None:
        return None
    plugin_ns = _plugin_namespace(loaded)
    if not plugin_ns:
        return None
    if intercept == "transform_tool_result":
        rels = (".credential_guard.hooks", ".hooks")
    elif intercept == "pre_tool_call":
        rels = (".credential_guard.approval", ".approval")
    elif intercept == "tool_request":
        rels = (".credential_guard.tool_request", ".tool_request")
    elif intercept == "tool_execution":
        rels = (".credential_guard.tool_execution", ".tool_execution")
    else:
        rels = (".credential_guard.middleware", ".middleware")
    for rel in rels:
        mod_name = plugin_ns + rel
        mod = sys.modules.get(mod_name)
        if mod is None:
            try:
                mod = importlib.import_module(mod_name)
            except Exception:
                continue
        cb = getattr(mod, expected_name, None)
        if callable(cb):
            return cb
    return None


def _has_our_callback(
    callbacks: list[Any],
    intercept: str,
    plugin_ns: str,
    loaded: Any,
) -> bool:
    """Accept only the production callback object directly registered in the manager.

    Does not match by bare function name or ``credential_guard`` substring.
    Does not trust arbitrary ``__wrapped__`` forgeries — the exact production
    callable identity must appear in the PluginManager callback list.
    """
    if not plugin_ns:
        return False
    expected_cb = _expected_callable(loaded, intercept)
    if expected_cb is None:
        return False
    for cb in callbacks:
        if cb is expected_cb:
            return True
    return False


def _resolve_handler(
    loaded: Any, handler_name: str, rels: tuple
) -> Optional[Callable[..., Any]]:
    import importlib
    import sys

    plugin_ns = _plugin_namespace(loaded)
    if not plugin_ns:
        return None
    for rel in rels:
        mod_name = plugin_ns + rel
        mod = sys.modules.get(mod_name)
        if mod is None:
            try:
                mod = importlib.import_module(mod_name)
            except Exception:
                continue
        candidate = getattr(mod, handler_name, None)
        if callable(candidate):
            return candidate
    return None


def has_all_generic_credential_tools(mgr: Any, loaded: Any) -> bool:
    """True when both generic reference tools use production handlers."""
    return (
        _has_our_tool(
            mgr,
            loaded,
            HTTP_TOOL_NAME,
            "handle_http_credential_request",
            (".credential_guard.reference_tools", ".reference_tools"),
        )
        and _has_our_tool(
            mgr,
            loaded,
            PROCESS_TOOL_NAME,
            "handle_credential_process_run",
            (".credential_guard.process_tools", ".process_tools"),
        )
    )


def _has_our_tool(
    mgr: Any,
    loaded: Any,
    tool_name: str,
    handler_name: str,
    rels: tuple,
) -> bool:
    """Require tool registered with the exact production handler callable."""
    expected_handler = _resolve_handler(loaded, handler_name, rels)
    if expected_handler is None:
        return False

    plugin_tools = getattr(mgr, "_plugin_tool_names", None)
    if isinstance(plugin_tools, set) and tool_name not in plugin_tools:
        return False

    try:
        from tools.registry import registry

        entry = registry.get_entry(tool_name)
    except Exception:
        entry = None
    if entry is None:
        # Unit-test FakeMgr without tools.registry: accept explicit attribute.
        tools = getattr(mgr, "_tools", {}) or {}
        handler = tools.get(tool_name)
        return handler is expected_handler
    return getattr(entry, "handler", None) is expected_handler
