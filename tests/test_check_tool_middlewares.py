"""T2: credential-guard check must verify tool_request/tool_execution identities."""

from __future__ import annotations

import types
from argparse import Namespace

import pytest

from credential_guard.approval import on_pre_tool_call
from credential_guard.cli import run_check
from credential_guard.hooks import on_transform_tool_result
from credential_guard.middleware import on_llm_execution, on_llm_request
from credential_guard.reference_tools import handle_http_credential_request
from credential_guard.process_tools import handle_credential_process_run
from credential_guard.runtime_config import HTTP_REFERENCE_TOOL
from credential_guard.bindings import PROCESS_REFERENCE_TOOL
from credential_guard.state import get_registry
from credential_guard.tool_execution import on_tool_execution
from credential_guard.tool_request import on_tool_request


def _plugin_module():
    import credential_guard as cg_pkg

    mod = types.ModuleType("credential_guard")
    mod.__name__ = "credential_guard"
    mod.credential_guard = cg_pkg
    return mod


def _install_fake_mgr(monkeypatch, mgr):
    import sys

    plugins_mod = types.ModuleType("hermes_cli.plugins")
    plugins_mod.get_plugin_manager = lambda: mgr
    hermes_cli = types.ModuleType("hermes_cli")
    hermes_cli.plugins = plugins_mod
    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.plugins", plugins_mod)


def _complete_mgr(**overrides):
    class FakeLoaded:
        enabled = True
        module = _plugin_module()

    mw = {
        "llm_request": [on_llm_request],
        "llm_execution": [on_llm_execution],
        "tool_request": [on_tool_request],
        "tool_execution": [on_tool_execution],
    }
    hooks = {
        "transform_tool_result": [on_transform_tool_result],
        "pre_tool_call": [on_pre_tool_call],
    }
    tools = {
        HTTP_REFERENCE_TOOL: handle_http_credential_request,
        PROCESS_REFERENCE_TOOL: handle_credential_process_run,
    }
    for k, v in overrides.items():
        if k in mw:
            mw[k] = v
        elif k in hooks:
            hooks[k] = v
        elif k in tools:
            tools[k] = v

    class FakeMgr:
        _plugins = {"credential-guard": FakeLoaded()}
        _middleware = mw
        _hooks = hooks
        _plugin_tool_names = set(tools)
        _tools = tools

    return FakeMgr()


@pytest.fixture(autouse=True)
def _registry_iso():
    reg = get_registry()
    snap = [(i.key, i.field, i.secret) for i in reg.values()]
    try:
        yield
    finally:
        reg.clear()
        for k, f, s in snap:
            reg.register(k, f, s)


def test_check_requires_tool_request_middleware(monkeypatch, capsys, tmp_path):
    import json
    import os

    hermes = tmp_path / "h"
    store = hermes / "credential-guard"
    store.mkdir(parents=True)
    os.chmod(store, 0o700)
    cfg = store / "credential-guard.json"
    cfg.write_text(json.dumps({"version": 2, "credentials": {}, "bindings": {}}))
    os.chmod(cfg, 0o600)
    monkeypatch.setenv("HERMES_HOME", str(hermes))

    mgr = _complete_mgr()
    mgr._middleware["tool_request"] = []
    _install_fake_mgr(monkeypatch, mgr)
    assert run_check() == 1
    assert "tool_request" in capsys.readouterr().out


def test_check_requires_tool_execution_middleware(monkeypatch, capsys, tmp_path):
    import json
    import os

    hermes = tmp_path / "h"
    store = hermes / "credential-guard"
    store.mkdir(parents=True)
    os.chmod(store, 0o700)
    cfg = store / "credential-guard.json"
    cfg.write_text(json.dumps({"version": 2, "credentials": {}, "bindings": {}}))
    os.chmod(cfg, 0o600)
    monkeypatch.setenv("HERMES_HOME", str(hermes))

    mgr = _complete_mgr()
    mgr._middleware["tool_execution"] = []
    _install_fake_mgr(monkeypatch, mgr)
    assert run_check() == 1
    assert "tool_execution" in capsys.readouterr().out


def test_check_rejects_replaced_tool_request_identity(monkeypatch, capsys, tmp_path):
    import json
    import os

    hermes = tmp_path / "h"
    store = hermes / "credential-guard"
    store.mkdir(parents=True)
    os.chmod(store, 0o700)
    cfg = store / "credential-guard.json"
    cfg.write_text(json.dumps({"version": 2, "credentials": {}, "bindings": {}}))
    os.chmod(cfg, 0o600)
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    get_registry().clear()
    get_registry().register("db", "password", "meta_only")

    def impostor(**kwargs):
        return kwargs

    impostor.__name__ = "on_tool_request"
    impostor.__module__ = "evil"
    mgr = _complete_mgr(tool_request=[impostor])
    _install_fake_mgr(monkeypatch, mgr)
    try:
        assert run_check() == 1
        assert "tool_request" in capsys.readouterr().out
    finally:
        get_registry().clear()


def test_check_green_with_tool_middlewares(monkeypatch, capsys, tmp_path):
    import json
    import os

    hermes = tmp_path / "h"
    store = hermes / "credential-guard"
    store.mkdir(parents=True)
    os.chmod(store, 0o700)
    cfg = store / "credential-guard.json"
    cfg.write_text(json.dumps({"version": 2, "credentials": {}, "bindings": {}}))
    os.chmod(cfg, 0o600)
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    get_registry().clear()
    get_registry().register("db", "password", "meta_only")
    try:
        _install_fake_mgr(monkeypatch, _complete_mgr())
        code = run_check()
        out = capsys.readouterr().out
        assert code == 0
        assert "tool_request" in out
        assert "tool_execution" in out
        assert "pre_tool_call" in out
        assert HTTP_REFERENCE_TOOL in out
    finally:
        get_registry().clear()
