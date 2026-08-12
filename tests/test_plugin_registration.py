from __future__ import annotations

import importlib
import sys
import types
from argparse import Namespace
from pathlib import Path

import pytest

from credential_guard import register
from credential_guard.approval import on_pre_tool_call
from credential_guard.cli import handle_command, run_check
from credential_guard.hooks import on_transform_tool_result
from credential_guard.middleware import on_llm_execution, on_llm_request
from credential_guard.state import get_registry
from credential_guard.reference_tools import handle_http_credential_request
from credential_guard.process_tools import handle_credential_process_run
from credential_guard.runtime_config import HTTP_REFERENCE_TOOL
from credential_guard.bindings import PROCESS_REFERENCE_TOOL
from credential_guard.tool_execution import on_tool_execution
from credential_guard.tool_request import on_tool_request

_REPO_ROOT = Path(__file__).resolve().parents[1]


class _BlockToolsFinder:
    """Meta path finder that refuses to resolve blocked *.tools module names."""

    def __init__(self, blocked: frozenset[str]) -> None:
        self._blocked = blocked

    def find_spec(self, fullname, path, target=None):  # noqa: ANN001
        if fullname in self._blocked:
            raise ImportError(f"{fullname} is blocked for isolation test")
        return None


def _reimport_generic_tools_with_tools_blocked():
    """Re-execute live reference/process tool modules while tools.py is unusable.

    Uses static import statements (not import_module/exec) so the no-build
    corpus scanner does not fail-closed on unresolved dynamic sinks.
    """
    saved_ref = sys.modules.pop("credential_guard.reference_tools", None)
    saved_proc = sys.modules.pop("credential_guard.process_tools", None)
    saved_tools = sys.modules.pop("credential_guard.tools", None)
    finder = _BlockToolsFinder(frozenset({"credential_guard.tools"}))
    sys.meta_path.insert(0, finder)
    try:
        import credential_guard.reference_tools as ref
        import credential_guard.process_tools as proc

        return ref, proc
    finally:
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
        if saved_tools is None:
            sys.modules.pop("credential_guard.tools", None)
        else:
            sys.modules["credential_guard.tools"] = saved_tools
        if saved_ref is None:
            sys.modules.pop("credential_guard.reference_tools", None)
        else:
            sys.modules["credential_guard.reference_tools"] = saved_ref
        if saved_proc is None:
            sys.modules.pop("credential_guard.process_tools", None)
        else:
            sys.modules["credential_guard.process_tools"] = saved_proc
        # Point package attrs back at restored objects — never re-import
        # (re-import would mint new function objects and poison identity checks).
        import credential_guard as _cg_pkg

        if saved_ref is not None:
            setattr(_cg_pkg, "reference_tools", saved_ref)
        elif hasattr(_cg_pkg, "reference_tools"):
            delattr(_cg_pkg, "reference_tools")
        if saved_proc is not None:
            setattr(_cg_pkg, "process_tools", saved_proc)
        elif hasattr(_cg_pkg, "process_tools"):
            delattr(_cg_pkg, "process_tools")


@pytest.fixture(autouse=True)
def _restore_base_registry():
    """Isolate base registry mutations — prevent cross-module pollution."""
    reg = get_registry()
    snapshot = [(item.key, item.field, item.secret) for item in reg.values()]
    try:
        yield
    finally:
        reg.clear()
        for key, field, secret in snapshot:
            reg.register(key, field, secret)


class FakeCtx:
    def __init__(self) -> None:
        self.middlewares = []
        self.hooks = []
        self.cli = []
        self.tools = []

    def register_middleware(self, kind, callback):
        self.middlewares.append((kind, callback))

    def register_hook(self, name, callback):
        self.hooks.append((name, callback))

    def register_cli_command(self, **kwargs):
        self.cli.append(kwargs)

    def register_tool(self, **kwargs):
        self.tools.append(kwargs)


def _install_fake_mgr(monkeypatch, mgr):
    import sys

    plugins_mod = types.ModuleType("hermes_cli.plugins")
    plugins_mod.get_plugin_manager = lambda: mgr
    hermes_cli = types.ModuleType("hermes_cli")
    hermes_cli.plugins = plugins_mod
    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.plugins", plugins_mod)


def _plugin_module():
    """Simulate LoadedPlugin.module as the directory plugin package root."""
    import credential_guard as cg_pkg

    mod = types.ModuleType("credential_guard")
    # Namespace root used by CLI check; callbacks live under credential_guard.*
    mod.__name__ = "credential_guard"
    mod.credential_guard = cg_pkg
    return mod


def _complete_mgr(
    *,
    llm_request=None,
    llm_execution=None,
    transform_tool_result=None,
    pre_tool_call=None,
    tool_handler=None,
):
    class FakeLoaded:
        enabled = True
        module = _plugin_module()

    class FakeMgr:
        _plugins = {"credential-guard": FakeLoaded()}
        _middleware = {
            "llm_request": [llm_request or on_llm_request],
            "llm_execution": [llm_execution or on_llm_execution],
            "tool_request": [on_tool_request],
            "tool_execution": [on_tool_execution],
        }
        _hooks = {
            "transform_tool_result": [
                transform_tool_result or on_transform_tool_result
            ],
            "pre_tool_call": [pre_tool_call or on_pre_tool_call],
        }
        _plugin_tool_names = {
            HTTP_REFERENCE_TOOL,
            PROCESS_REFERENCE_TOOL,
        }
        _tools = {
            HTTP_REFERENCE_TOOL: handle_http_credential_request
            if tool_handler is None
            else tool_handler,
            PROCESS_REFERENCE_TOOL: handle_credential_process_run
            if tool_handler is None
            else tool_handler,
        }

    return FakeMgr()


def test_registers_all_required_intercepts():
    ctx = FakeCtx()
    register(ctx)
    assert {name for name, _ in ctx.middlewares} == {
        "llm_request",
        "llm_execution",
        "tool_request",
        "tool_execution",
    }
    assert {name for name, _ in ctx.hooks} == {
        "transform_tool_result",
        "pre_tool_call",
    }
    assert len(ctx.cli) == 1
    assert ctx.cli[0]["name"] == "credential-guard"
    assert len(ctx.tools) == 2
    names = {t["name"] for t in ctx.tools}
    assert names == {
        HTTP_REFERENCE_TOOL,
        "credential_process_run",
    }


def test_check_fails_when_plugin_manager_unavailable(capsys):
    code = handle_command(Namespace(credential_guard_command="check"))
    out = capsys.readouterr().out
    assert code != 0
    assert "SECRET_" not in out
    assert "check failed" in out or "unavailable" in out


def test_check_detects_missing_callbacks(monkeypatch, capsys):
    class FakeLoaded:
        enabled = True
        module = _plugin_module()

    class FakeMgr:
        _plugins = {"credential-guard": FakeLoaded()}
        _middleware = {"llm_request": [], "llm_execution": []}
        _hooks = {"transform_tool_result": [], "pre_tool_call": []}
        _plugin_tool_names = set()
        _tools = {}

    _install_fake_mgr(monkeypatch, FakeMgr())
    code = run_check()
    out = capsys.readouterr().out
    assert code == 1
    assert "missing:" in out
    assert "llm_request" in out


def test_check_green_when_callbacks_present(monkeypatch, capsys, tmp_path):
    import json
    import os

    hermes = tmp_path / "hermes_home"
    store = hermes / "credential-guard"
    store.mkdir(parents=True)
    os.chmod(store, 0o700)
    cfg = store / "credential-guard.json"
    cfg.write_text(
        json.dumps({"version": 2, "credentials": {}, "bindings": {}}),
        encoding="utf-8",
    )
    os.chmod(cfg, 0o600)
    monkeypatch.setenv("HERMES_HOME", str(hermes))

    _install_fake_mgr(monkeypatch, _complete_mgr())
    get_registry().clear()
    get_registry().register("db", "password", "check_meta_secret_1")
    try:
        code = run_check()
        out = capsys.readouterr().out
        assert code == 0
        assert "credential-guard: enabled" in out
        assert "llm_request" in out
        assert "pre_tool_call" in out
        assert HTTP_REFERENCE_TOOL in out
        assert PROCESS_REFERENCE_TOOL in out
        assert "check_meta_secret_1" not in out
        assert "cg_" in out
        assert "egress_registry=ready" in out
        assert "egress_opaque_count=1" in out  # base db/password only
    finally:
        get_registry().clear()


def test_check_rejects_totally_unrelated_on_llm_request(monkeypatch, capsys):
    unrelated = types.ModuleType("totally_unrelated")

    def on_llm_request(**kwargs):
        return kwargs

    on_llm_request.__module__ = "totally_unrelated"
    unrelated.on_llm_request = on_llm_request

    _install_fake_mgr(monkeypatch, _complete_mgr(llm_request=on_llm_request))
    code = run_check()
    out = capsys.readouterr().out
    assert code == 1
    assert "llm_request" in out


def test_check_rejects_evil_credential_guardian_substring(monkeypatch, capsys):
    def innocent(**kwargs):
        return kwargs

    innocent.__module__ = "evil_credential_guardian"
    innocent.__name__ = "innocent"

    _install_fake_mgr(monkeypatch, _complete_mgr(llm_request=innocent))
    code = run_check()
    assert code == 1
    assert "llm_request" in capsys.readouterr().out


def test_check_rejects_same_name_lambda(monkeypatch, capsys):
    impostor = eval("lambda **kwargs: kwargs")
    impostor.__name__ = "on_llm_request"
    impostor.__module__ = "dynamic_fake_module"

    _install_fake_mgr(monkeypatch, _complete_mgr(llm_request=impostor))
    code = run_check()
    assert code == 1
    assert "llm_request" in capsys.readouterr().out


def test_check_rejects_other_plugin_only_callbacks(monkeypatch, capsys):
    def other_plugin_cb(**kwargs):
        return kwargs

    other_plugin_cb.__module__ = "hermes_plugins.other_plugin"
    other_plugin_cb.__name__ = "on_llm_request"

    _install_fake_mgr(
        monkeypatch,
        _complete_mgr(
            llm_request=other_plugin_cb,
            llm_execution=other_plugin_cb,
            transform_tool_result=other_plugin_cb,
            pre_tool_call=other_plugin_cb,
            tool_handler=other_plugin_cb,
        ),
    )
    code = run_check()
    out = capsys.readouterr().out
    assert code == 1
    assert "llm_request" in out
    assert "llm_execution" in out
    assert "transform_tool_result" in out


def test_check_rejects_forged_wrapped_pointing_to_production(monkeypatch, capsys):
    """Evil callback with __wrapped__ = real callback must NOT fake-green check.

    Production check only accepts the production callable directly present in
    the manager list — forged __wrapped__ chains are ignored.
    """

    def evil(**kwargs):
        # Never calls production — only forges the attribute.
        return kwargs

    evil.__wrapped__ = on_llm_request  # type: ignore[attr-defined]
    evil.__name__ = "on_llm_request"
    evil.__module__ = "evil_forged_wrapper"

    _install_fake_mgr(monkeypatch, _complete_mgr(llm_request=evil))
    code = run_check()
    out = capsys.readouterr().out
    assert code == 1
    assert "llm_request" in out


def test_check_rejects_functools_wrapped_even_when_chain_is_real(monkeypatch, capsys):
    """Wrappers are not accepted — only direct production identity."""
    import functools

    @functools.wraps(on_llm_request)
    def wrapped(**kwargs):
        return on_llm_request(**kwargs)

    _install_fake_mgr(monkeypatch, _complete_mgr(llm_request=wrapped))
    code = run_check()
    assert code == 1
    assert "llm_request" in capsys.readouterr().out


@pytest.mark.parametrize(
    "missing_kind",
    [
        "llm_request",
        "llm_execution",
        "tool_request",
        "tool_execution",
        "transform_tool_result",
        "pre_tool_call",
        "http_credential_request",
        "credential_process_run",
    ],
)
def test_check_fails_when_any_one_intercept_removed(monkeypatch, capsys, missing_kind):
    mgr = _complete_mgr()
    if missing_kind == "llm_request":
        mgr._middleware["llm_request"] = []
    elif missing_kind == "llm_execution":
        mgr._middleware["llm_execution"] = []
    elif missing_kind == "tool_request":
        mgr._middleware["tool_request"] = []
    elif missing_kind == "tool_execution":
        mgr._middleware["tool_execution"] = []
    elif missing_kind == "transform_tool_result":
        mgr._hooks["transform_tool_result"] = []
    elif missing_kind == "pre_tool_call":
        mgr._hooks["pre_tool_call"] = []
    elif missing_kind == "http_credential_request":
        mgr._plugin_tool_names = {PROCESS_REFERENCE_TOOL}
        mgr._tools.pop(HTTP_REFERENCE_TOOL, None)
    else:
        mgr._plugin_tool_names = {HTTP_REFERENCE_TOOL}
        mgr._tools.pop(PROCESS_REFERENCE_TOOL, None)

    _install_fake_mgr(monkeypatch, mgr)
    code = run_check()
    out = capsys.readouterr().out
    assert code == 1
    assert missing_kind in out


def test_p4_registry_isolation_leaves_empty_for_subsequent_empty_assumption(
    monkeypatch, capsys, tmp_path
):
    """Order regression: after check_green pollution, empty-registry assumption holds."""
    import json
    import os

    from credential_guard.runtime_config import (
        load_and_publish_runtime,
        reset_runtime_for_tests,
    )
    from credential_guard.state import get_egress_registry_snapshot

    hermes = tmp_path / "hermes_home"
    store = hermes / "credential-guard"
    store.mkdir(parents=True)
    os.chmod(store, 0o700)
    cfg = store / "credential-guard.json"
    cfg.write_text(
        json.dumps({"version": 2, "credentials": {}, "bindings": {}}),
        encoding="utf-8",
    )
    os.chmod(cfg, 0o600)
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()

    _install_fake_mgr(monkeypatch, _complete_mgr())
    get_registry().clear()
    get_registry().register("db", "password", "check_meta_secret_1")
    assert run_check() == 0
    # Autouse fixture must restore; simulate end-of-test by clearing to snapshot
    # (fixture runs after this test). Explicitly clear pollution here then assert
    # empty merge after publish — same assumption as execute_code empty view.
    get_registry().clear()
    reset_runtime_for_tests()
    load_and_publish_runtime()
    assert list(get_egress_registry_snapshot().values()) == []


def test_generic_tools_import_without_legacy_tools_module():
    """http/process shells must not need credential_guard.tools for TOOLSET_NAME."""
    ref, proc = _reimport_generic_tools_with_tools_blocked()
    assert ref.TOOLSET_NAME == "credential_guard"
    assert proc.TOOLSET_NAME == "credential_guard"


def test_reimport_helper_preserves_live_module_and_handler_identity():
    """Isolation helper must leave live module/handler object identities intact."""
    import credential_guard as cg_pkg

    ref_before = sys.modules["credential_guard.reference_tools"]
    proc_before = sys.modules["credential_guard.process_tools"]
    http_before = ref_before.handle_http_credential_request
    proc_handler_before = proc_before.handle_credential_process_run

    _reimport_generic_tools_with_tools_blocked()

    assert sys.modules["credential_guard.reference_tools"] is ref_before
    assert sys.modules["credential_guard.process_tools"] is proc_before
    assert cg_pkg.reference_tools is ref_before
    assert cg_pkg.process_tools is proc_before
    assert (
        sys.modules["credential_guard.reference_tools"].handle_http_credential_request
        is http_before
    )
    assert (
        sys.modules["credential_guard.process_tools"].handle_credential_process_run
        is proc_handler_before
    )


@pytest.mark.parametrize(
    ("victim_rel", "mut_pkg"),
    [
        ("credential_guard/reference_tools.py", "cg_slice_b_mut_ref"),
        ("credential_guard/process_tools.py", "cg_slice_b_mut_proc"),
    ],
)
def test_mutation_reverting_toolset_import_to_tools_is_red(
    victim_rel, mut_pkg, tmp_path
):
    """Temp-tree copy with TOOLSET_NAME import reverted to tools.py must fail import.

    Does not touch the live tree. Loads via literal import_module name so the
    no-build scanner can fold the argument; tools submodule is meta-path blocked.
    """
    original = (_REPO_ROOT / victim_rel).read_text(encoding="utf-8")
    assert "from .constants import TOOLSET_NAME" in original
    mutated = original.replace(
        "from .constants import TOOLSET_NAME",
        "from .tools import TOOLSET_NAME",
        1,
    )
    assert mutated != original
    assert "from .tools import TOOLSET_NAME" in mutated

    pkg = tmp_path / mut_pkg
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "constants.py").write_text(
        'TOOLSET_NAME = "credential_guard"\n',
        encoding="utf-8",
    )
    # Sibling stubs so the full mutated module body can execute until .tools.
    (pkg / "runtime_config.py").write_text(
        'HTTP_REFERENCE_TOOL = "http_credential_request"\n',
        encoding="utf-8",
    )
    (pkg / "bindings.py").write_text(
        'PROCESS_REFERENCE_TOOL = "credential_process_run"\n'
        'PROCESS_REFERENCE_ARG_PATH = "credential"\n',
        encoding="utf-8",
    )
    (pkg / "tool_execution.py").write_text(
        "def finalize_reference_execution(*a, **k):\n    return ''\n",
        encoding="utf-8",
    )
    (pkg / Path(victim_rel).name).write_text(mutated, encoding="utf-8")

    tools_fullname = f"{mut_pkg}.tools"
    mod_fullname = f"{mut_pkg}.{Path(victim_rel).stem}"
    finder = _BlockToolsFinder(frozenset({tools_fullname}))
    sys.meta_path.insert(0, finder)
    sys.path.insert(0, str(tmp_path))
    try:
        sys.modules.pop(mod_fullname, None)
        sys.modules.pop(tools_fullname, None)
        sys.modules.pop(mut_pkg, None)
        with pytest.raises(ImportError, match="blocked for isolation test"):
            # Literal module names only — one branch per parametrize value.
            if mut_pkg == "cg_slice_b_mut_ref":
                importlib.import_module("cg_slice_b_mut_ref.reference_tools")
            else:
                importlib.import_module("cg_slice_b_mut_proc.process_tools")
    finally:
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
        if sys.path and sys.path[0] == str(tmp_path):
            sys.path.pop(0)
        for key in list(sys.modules):
            if key == mut_pkg or key.startswith(mut_pkg + "."):
                sys.modules.pop(key, None)
