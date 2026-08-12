from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from credential_guard import register
from credential_guard.state import get_registry


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


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


def test_production_package_has_no_test_fixture_module(tmp_path):
    dest = tmp_path / "credential-guard"
    shutil.copytree(
        PLUGIN_ROOT,
        dest,
        ignore=shutil.ignore_patterns(
            ".venv",
            ".pytest_cache",
            "__pycache__",
            "tests",
            "scripts",
            "docs",
            "*.md",
            ".m0-m1-*",
            ".m2-*",
        ),
    )
    assert not (dest / "credential_guard" / "test_fixture.py").exists()
    banned = (
        "CREDENTIAL_GUARD_TEST_FIXTURE",
        "CREDENTIAL_GUARD_TEST_INJECT",
        "CREDENTIAL_GUARD_TEST_COUNT",
        "maybe_load_test_fixture",
        "maybe_raise_injected_failure",
        "decoy_db_password_123",
    )
    for path in dest.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for token in banned:
            assert token not in text, f"{path} contains {token}"


def test_production_register_ignores_old_test_env_vars(monkeypatch, tmp_path):
    import json

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

    get_registry().clear()
    monkeypatch.setenv("CREDENTIAL_GUARD_TEST_FIXTURE_ENABLE", "1")
    monkeypatch.setenv("CREDENTIAL_GUARD_TEST_FIXTURE_PATH", "/tmp/should-not-load.yaml")
    monkeypatch.setenv("CREDENTIAL_GUARD_TEST_INJECT_FAILURE", "redact")
    ctx = FakeCtx()
    register(ctx)
    assert get_registry().values() == []
    # Production middleware must not raise from env inject switch.
    from credential_guard.middleware import on_llm_request

    out = on_llm_request(request={"messages": [{"content": "hello"}]})
    assert out["source"] == "credential-guard"
    assert out["request"]["messages"][0]["content"] == "hello"


def test_production_init_does_not_import_test_only_modules():
    init_text = (PLUGIN_ROOT / "credential_guard" / "__init__.py").read_text(
        encoding="utf-8"
    )
    assert "test_fixture" not in init_text
    mw = (PLUGIN_ROOT / "credential_guard" / "middleware.py").read_text(encoding="utf-8")
    hooks = (PLUGIN_ROOT / "credential_guard" / "hooks.py").read_text(encoding="utf-8")
    assert "test_fixture" not in mw
    assert "test_fixture" not in hooks
