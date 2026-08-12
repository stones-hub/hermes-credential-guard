"""R1A: prove new config/migration modules never touch real Hermes profiles."""

from __future__ import annotations

import ast
import inspect
import os
import subprocess
from pathlib import Path

import pytest

import credential_guard.bindings as bindings_mod
import credential_guard.config as config_mod
import credential_guard.migration as migration_mod
from credential_guard.config import CONFIG_FILENAME, CredentialGuardConfig
from credential_guard.migration import migrate_config, resolve_config_dir


REPO = Path(__file__).resolve().parents[1]
NEW_MODULES = (
    REPO / "credential_guard" / "config.py",
    REPO / "credential_guard" / "bindings.py",
    REPO / "credential_guard" / "migration.py",
)

FORBIDDEN_LITERALS = (
    "~/.hermes/profiles/worker",
    "/Users/yelei/.hermes/profiles/worker",
    "profiles/worker",
    "profiles/default",
)


def test_new_modules_have_no_hardcoded_real_profile_paths():
    for path in NEW_MODULES:
        text = path.read_text(encoding="utf-8")
        for lit in FORBIDDEN_LITERALS:
            assert lit not in text, f"{path.name} contains forbidden path {lit!r}"
        tree = ast.parse(text, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for lit in FORBIDDEN_LITERALS:
                    assert lit not in node.value


def test_monkeypatch_home_and_hermes_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    resolved = resolve_config_dir()
    assert resolved == hermes / "credential-guard"
    assert str(tmp_path) in str(resolved)
    assert "profiles/worker" not in str(resolved)


def test_no_subprocess_hermes_profile_invocation_in_new_modules():
    for path in NEW_MODULES:
        text = path.read_text(encoding="utf-8")
        assert "hermes -p worker" not in text
        assert "hermes -p default" not in text
        assert "subprocess" not in text or "subprocess" not in text.split("import")[0]
        tree = ast.parse(text, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = ""
                if isinstance(func, ast.Attribute):
                    name = func.attr
                elif isinstance(func, ast.Name):
                    name = func.id
                if name in {"run", "Popen", "call", "check_call", "check_output"}:
                    # Ensure not invoking hermes with -p worker/default via constants.
                    for arg in node.args:
                        if isinstance(arg, (ast.List, ast.Tuple)):
                            joined = " ".join(
                                a.value
                                for a in arg.elts
                                if isinstance(a, ast.Constant) and isinstance(a.value, str)
                            )
                            assert "-p worker" not in joined
                            assert "-p default" not in joined


def test_production_api_requires_explicit_dir_or_temp_hermes_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    # Explicit directory wins.
    explicit = tmp_path / "explicit-store"
    explicit.mkdir()
    assert resolve_config_dir(explicit) == explicit.resolve()

    home = tmp_path / "home"
    hermes = tmp_path / "hermes-home"
    home.mkdir()
    hermes.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    assert resolve_config_dir(None) == (hermes / "credential-guard").resolve()

    # Without HERMES_HOME, must not silently target a real worker profile.
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.setenv("HOME", str(home))
    resolved = resolve_config_dir(None)
    assert "profiles/worker" not in str(resolved)
    assert "profiles/default" not in str(resolved)
    # Falls back to temporary HOME/.hermes/credential-guard — still under tmp.
    assert str(home) in str(resolved)


def test_dynamic_load_uses_only_tmp_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Must not read real profile config.yaml body during this test."""
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))

    real_worker = Path.home() / ".hermes" / "profiles" / "worker" / "config.yaml"
    # Do not read real config body; only ensure our load path never opens it.
    opened: list[str] = []
    real_open = os.open

    def tracking_open(path, flags, *args, **kwargs):
        opened.append(str(path))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", tracking_open)

    store = hermes / "credential-guard"
    store.mkdir()
    os.chmod(store, 0o700)
    cfg_path = store / CONFIG_FILENAME
    cfg_path.write_text(
        '{"version":2,"credentials":{},"bindings":{}}',
        encoding="utf-8",
    )
    os.chmod(cfg_path, 0o600)
    CredentialGuardConfig.load(cfg_path)

    for p in opened:
        assert "profiles/worker" not in p
        assert "profiles/default" not in p
        if str(real_worker) == p or p.endswith("profiles/worker/config.yaml"):
            pytest.fail("must not open real worker config.yaml")


def test_migrate_config_signature_accepts_explicit_dir():
    sig = inspect.signature(migrate_config)
    params = list(sig.parameters)
    assert params, "migrate_config must accept an explicit config directory"
    # First positional parameter is the store/config directory.
    assert params[0] in {"store_dir", "config_dir", "path", "directory"}


def test_modules_export_expected_symbols():
    assert hasattr(config_mod, "CredentialGuardConfig")
    assert hasattr(config_mod, "ConfigError")
    assert hasattr(bindings_mod, "ALLOWED_BINDING_TYPES") or hasattr(
        bindings_mod, "validate_binding"
    )
    assert hasattr(migration_mod, "migrate_config")
    assert hasattr(migration_mod, "resolve_config_dir")


def test_load_and_migrate_reject_insecure_parent_without_path_leak(
    tmp_path: Path,
):
    """Boundary: store parent/dir mode gates must not leak absolute paths."""
    decoy = "CG_BOUND_" + "a" * 24
    store = tmp_path / "credential-guard"
    store.mkdir()
    os.chmod(store, 0o755)
    cfg_path = store / CONFIG_FILENAME
    cfg_path.write_text(
        '{"version":2,"credentials":{},"bindings":{}}',
        encoding="utf-8",
    )
    os.chmod(cfg_path, 0o600)

    with pytest.raises(Exception) as ei_load:
        CredentialGuardConfig.load(cfg_path)
    blob = f"{ei_load.value!s}{ei_load.value!r}"
    assert str(cfg_path) not in blob
    assert str(store) not in blob
    assert decoy not in blob
    assert getattr(ei_load.value, "__context__", "missing") is None

    # Migrate also requires secure store directory.
    from credential_guard.migration import MigrationError

    (store / "credentials.json").write_text(
        '{"version":1,"credentials":{}}', encoding="utf-8"
    )
    (store / "targets.json").write_text(
        '{"version":1,"targets":{}}', encoding="utf-8"
    )
    os.chmod(store / "credentials.json", 0o600)
    os.chmod(store / "targets.json", 0o600)
    with pytest.raises(MigrationError) as ei_mig:
        migrate_config(store)
    blob2 = f"{ei_mig.value!s}{ei_mig.value!r}"
    assert str(store) not in blob2
    assert ei_mig.value.__context__ is None
    assert ei_mig.value.__cause__ is None
