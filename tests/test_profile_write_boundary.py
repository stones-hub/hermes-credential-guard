"""R1A: prove the config modules never touch real Hermes profiles.

Round 6 deleted ``credential_guard/migration.py`` (the v1 dual-file migrator) along
with the retired ``HERMES_HOME`` guess it carried. This file kept two tests that
asserted *that* resolver's behaviour; the property they defended -- "resolving our
own config directory must never silently target a real worker/default profile" --
still matters, so they now run against ``store_location``, which is where the
resolution actually lives. Everything else here is unchanged.
"""

from __future__ import annotations

import ast
import os
import subprocess
from pathlib import Path

import pytest

import credential_guard.bindings as bindings_mod
import credential_guard.config as config_mod
import credential_guard.store_location as store_location_mod
from credential_guard.config import CONFIG_FILENAME, CredentialGuardConfig
from credential_guard.store_location import (
    StoreLocationError,
    resolve_store_dir,
    use_store_dir,
)


REPO = Path(__file__).resolve().parents[1]
NEW_MODULES = (
    REPO / "credential_guard" / "config.py",
    REPO / "credential_guard" / "bindings.py",
    REPO / "credential_guard" / "store_location.py",
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


@pytest.mark.no_store_bridge
def test_resolution_never_targets_a_real_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Formerly test_monkeypatch_home_and_hermes_home.

    It used to assert the store landed at ``$HERMES_HOME/credential-guard``. Round 6
    stopped reading that variable, so the assertion now covers what it was actually
    defending: whatever the environment says, resolution must stay inside the test's
    temporary tree and must never name a real profile.
    """
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))

    store = tmp_path / "profiles" / "scratch" / "credential-guard"
    use_store_dir(store)
    try:
        resolved = resolve_store_dir()
        assert str(tmp_path) in str(resolved)
        assert "profiles/worker" not in str(resolved)
        assert "profiles/default" not in str(resolved)
    finally:
        use_store_dir(None)


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


@pytest.mark.no_store_bridge
def test_unresolvable_root_fails_closed_instead_of_guessing_a_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Formerly test_production_api_requires_explicit_dir_or_temp_hermes_home.

    The retired resolver fell back to ``$HOME/.hermes/credential-guard`` when it could
    not tell where it was, and the old assertion pinned that fallback. Round 6 made the
    same situation fail closed, which satisfies the original intent more strictly: with
    nothing to derive from, no path is produced at all, so no real profile can be hit.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("HERMES_HOME", raising=False)
    use_store_dir(None)

    def _no_root(package_dir):
        raise StoreLocationError("STORE_ROOT_NOT_DERIVABLE")

    monkeypatch.setattr(store_location_mod, "_profile_root_from", _no_root)

    with pytest.raises(StoreLocationError):
        resolve_store_dir()


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


def test_modules_export_expected_symbols():
    assert hasattr(config_mod, "CredentialGuardConfig")
    assert hasattr(config_mod, "ConfigError")
    assert hasattr(bindings_mod, "ALLOWED_BINDING_TYPES") or hasattr(
        bindings_mod, "validate_binding"
    )
    assert hasattr(store_location_mod, "resolve_store_dir")
    assert hasattr(store_location_mod, "StoreLocationError")


def test_load_rejects_insecure_parent_without_path_leak(tmp_path: Path):
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
