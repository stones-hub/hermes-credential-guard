from __future__ import annotations

"""Test-only companion plugin (never shipped in the production package).

Optionally loads decoy credentials into the production base registry when
explicitly enabled (legacy). M3.1-A production egress reads credentials.json
directly — companion must not be the production secret source for canary E2E.

Fault injection uses companion-owned pre/post middleware (or outermost
execution wrapper) that monkeypatches production module internals around
the production callback without changing manager callback identity.
"""

import json
import os
from pathlib import Path
from typing import Any, Callable, List, Optional, Tuple

_RESTORE_STACK: List[List[Tuple[Any, str, Any]]] = []


def register(ctx) -> None:
    _load_fixture_into_production_registry()
    _install_approval_driver()
    _register_inject_middleware(ctx)


def _install_approval_driver() -> None:
    """Install Hermes formal approval_callback driven by test harness.

    Goes through the real host gate (``request_tool_approval`` →
    ``prompt_dangerous_approval`` → callback). Does not skip the gate, does
    not set YOLO, and does not touch command_allowlist.

    Records actual scripted choice + returned value for gate accounting.
    Evidence level: harness-driven formal callback seam — not human PTY clicks.
    """
    replies_raw = os.environ.get("CREDENTIAL_GUARD_TEST_APPROVAL_REPLIES", "").strip()
    log_path = os.environ.get("CREDENTIAL_GUARD_TEST_APPROVAL_LOG", "").strip()
    if not replies_raw:
        return
    replies = [part.strip().lower() for part in replies_raw.split(",") if part.strip()]
    if not replies:
        return
    state = {"index": 0, "replies": replies}

    def _map_choice(raw: str) -> str:
        if raw in {"o", "once"}:
            return "once"
        if raw in {"s", "session"}:
            return "session"
        if raw in {"a", "always"}:
            return "always"
        if raw in {"d", "deny"}:
            return "deny"
        return "deny"

    def _driver(command: str, description: str, **kwargs: Any) -> str:
        idx = state["index"]
        if idx >= len(state["replies"]):
            scripted = "deny"
            returned = "deny"
        else:
            scripted = state["replies"][idx]
            state["index"] = idx + 1
            returned = _map_choice(scripted)
        # rule_key may appear inside synthetic command/description; capture
        # both plus sequence for reconciliation when tool_call_id is absent.
        entry = {
            "seq": idx,
            "command": command if isinstance(command, str) else str(command),
            "description": description if isinstance(description, str) else str(description),
            "scripted_choice": scripted,
            "returned_choice": returned,
            "callback_kwargs_keys": sorted(str(k) for k in kwargs.keys()),
        }
        if log_path:
            try:
                path = Path(log_path)
                existing: List[Any] = []
                if path.is_file():
                    try:
                        existing = json.loads(path.read_text(encoding="utf-8"))
                    except Exception:
                        existing = []
                if not isinstance(existing, list):
                    existing = []
                existing.append(entry)
                path.write_text(json.dumps(existing, ensure_ascii=False), encoding="utf-8")
            except OSError:
                pass
        return returned

    try:
        from tools.terminal_tool import set_approval_callback
        from tools import approval as hermes_approval

        set_approval_callback(_driver)

        # Re-bind on the calling thread whenever the host gate is entered so
        # thread-local callback storage cannot miss quiet/agent worker threads.
        orig_request = hermes_approval.request_tool_approval

        def _request_with_driver(*args: Any, **kwargs: Any):
            set_approval_callback(_driver)
            return orig_request(*args, **kwargs)

        hermes_approval.request_tool_approval = _request_with_driver  # type: ignore
    except Exception:
        return


def _load_fixture_into_production_registry() -> None:
    if os.environ.get("CREDENTIAL_GUARD_TEST_FIXTURE_ENABLE", "").strip() != "1":
        return
    raw_path = os.environ.get("CREDENTIAL_GUARD_TEST_FIXTURE_PATH", "").strip()
    if not raw_path:
        return
    path = Path(raw_path).resolve()
    if not _path_allowed(path) or not path.is_file():
        return
    registry = _production_registry()
    if registry is None:
        return
    entries = _parse_simple_yaml_list(path.read_text(encoding="utf-8"))
    registry.clear()
    for entry in entries:
        registry.register(
            str(entry.get("key", "")),
            str(entry.get("field", "")),
            str(entry.get("secret", "")),
        )


def _register_inject_middleware(ctx) -> None:
    """Register companion-owned inject helpers; keep production cbs untouched."""
    mgr = getattr(ctx, "_manager", None)
    if mgr is None:
        return

    # llm_request: pre patches → production runs → post restores
    ctx.register_middleware("llm_request", _pre_llm_request)
    ctx.register_middleware("llm_request", _post_llm_request)
    # llm_execution: outermost wrapper patches around next_call (production)
    ctx.register_middleware("llm_execution", _wrap_llm_execution)
    # hooks: pre/post around production hook
    ctx.register_hook("transform_tool_result", _pre_transform_tool_result)
    ctx.register_hook("transform_tool_result", _post_transform_tool_result)

    _reorder_production_surrounded(mgr)


def _is_production_cb(cb: Callable[..., Any]) -> bool:
    mod = (getattr(cb, "__module__", "") or "").replace("\\", "/")
    name = getattr(cb, "__name__", "") or ""
    if "credential_guard_test" in mod:
        return False
    if "credential_guard" not in mod:
        return False
    return name in {
        "on_llm_request",
        "on_llm_execution",
        "on_transform_tool_result",
    }


def _reorder_production_surrounded(mgr: Any) -> None:
    """Ensure order: companion_pre → production → companion_post (request/hooks).

    For llm_execution: companion wrapper first, then production (and any others).
    """
    middleware = getattr(mgr, "_middleware", {})
    hooks = getattr(mgr, "_hooks", {})

    req = list(middleware.get("llm_request", []) or [])
    production_req = [cb for cb in req if _is_production_cb(cb)]
    middleware["llm_request"] = (
        [_pre_llm_request] + production_req + [_post_llm_request]
    )

    exe = list(middleware.get("llm_execution", []) or [])
    production_exe = [cb for cb in exe if _is_production_cb(cb)]
    others_exe = [
        cb
        for cb in exe
        if cb is not _wrap_llm_execution and not _is_production_cb(cb)
    ]
    middleware["llm_execution"] = [_wrap_llm_execution] + production_exe + others_exe

    hook_cbs = list(hooks.get("transform_tool_result", []) or [])
    production_hooks = [cb for cb in hook_cbs if _is_production_cb(cb)]
    hooks["transform_tool_result"] = (
        [_pre_transform_tool_result] + production_hooks + [_post_transform_tool_result]
    )


def _pre_llm_request(**_kwargs: Any) -> None:
    _RESTORE_STACK.append(_install_inject_patches("llm_request"))
    return None


def _post_llm_request(**_kwargs: Any) -> None:
    if _RESTORE_STACK:
        _restore_patches(_RESTORE_STACK.pop())
    return None


def _wrap_llm_execution(**kwargs: Any) -> Any:
    next_call = kwargs.get("next_call")
    request = kwargs.get("request")
    patches = _install_inject_patches("llm_execution")
    try:
        if not callable(next_call):
            return None
        return next_call(request)
    finally:
        _restore_patches(patches)


def _pre_transform_tool_result(**_kwargs: Any) -> None:
    _RESTORE_STACK.append(_install_inject_patches("transform_tool_result"))
    return None


def _post_transform_tool_result(**_kwargs: Any) -> None:
    if _RESTORE_STACK:
        _restore_patches(_RESTORE_STACK.pop())
    return None


def _install_inject_patches(stage: str) -> List[Tuple[Any, str, Any]]:
    wanted = os.environ.get("CREDENTIAL_GUARD_TEST_INJECT_FAILURE", "").strip()
    if not wanted:
        return []

    def boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("credential-guard test injected failure")

    patches: List[Tuple[Any, str, Any]] = []

    try:
        import hermes_plugins.credential_guard.credential_guard.middleware as mw
        import hermes_plugins.credential_guard.credential_guard.hooks as hooks
    except Exception:
        return []

    if stage == "llm_request":
        if wanted in {"llm_request", "get_registry", "egress_snapshot"}:
            patches.append((mw, "get_egress_registry_snapshot", boom))
        elif wanted in {"redact", "values"}:
            patches.append((mw, "redact_payload", boom))
        elif wanted in {"serialize", "contains"}:
            patches.append((mw, "redact_payload", boom))
    elif stage == "llm_execution":
        if wanted in {"llm_execution", "get_registry", "egress_snapshot"}:
            patches.append((mw, "get_egress_registry_snapshot", boom))
        elif wanted in {"redact", "values"}:
            patches.append((mw, "redact_payload", boom))
        elif wanted in {"contains", "serialize"}:
            patches.append((mw, "contains_plain_secret", boom))
        elif wanted in {"file_backend", "credentials_store"}:
            patches.append((mw, "get_egress_registry_snapshot", boom))
    elif stage == "transform_tool_result":
        if wanted in {"transform_tool_result", "get_registry", "egress_snapshot"}:
            patches.append((hooks, "get_egress_registry_snapshot", boom))
        elif wanted in {"json_parse", "redact"}:
            patches.append((hooks, "redact_payload", boom))
            patches.append((hooks, "redact_text", boom))

    applied: List[Tuple[Any, str, Any]] = []
    for obj, attr, repl in patches:
        applied.append((obj, attr, getattr(obj, attr)))
        setattr(obj, attr, repl)
    return applied


def _restore_patches(patches: List[Tuple[Any, str, Any]]) -> None:
    for obj, attr, orig in patches:
        setattr(obj, attr, orig)


def _production_registry() -> Any:
    try:
        from hermes_plugins.credential_guard.credential_guard.state import get_registry

        return get_registry()
    except Exception:
        return None


def _path_allowed(path: Path) -> bool:
    allowed_roots = []
    for key in ("HERMES_HOME", "TMPDIR", "HOME"):
        root = os.environ.get(key, "").strip()
        if root:
            allowed_roots.append(Path(root).resolve())
    for root in allowed_roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _parse_simple_yaml_list(text: str) -> List[dict]:
    entries: List[dict] = []
    current: Optional[dict] = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("- "):
            if current:
                entries.append(current)
            current = {}
            rest = line[2:].strip()
            if rest and ":" in rest:
                k, v = rest.split(":", 1)
                current[k.strip()] = _strip_quotes(v.strip())
            continue
        if current is not None and ":" in line:
            k, v = line.split(":", 1)
            current[k.strip()] = _strip_quotes(v.strip())
    if current:
        entries.append(current)
    return entries


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value
