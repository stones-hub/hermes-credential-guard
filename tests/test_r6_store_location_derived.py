"""Round 6: the store location is DERIVED, never guessed from the environment.

Three earlier rounds each patched a different symptom of one root cause: the
plugin located its own config directory by reading ``$HERMES_HOME`` and, when
that lookup landed somewhere without a config file, C1 declared the user "brand
new" and let the request through un-redacted.  A configured operator whose
environment variable was wrong, stale, or simply absent therefore lost
redaction silently.

The fix removes the guess.  The plugin is installed at
``<profile>/plugins/credential-guard/`` so it can derive the profile root from
its own location on disk -- no environment variable, nothing an operator can
point elsewhere, nothing to spoof.  If the root cannot be derived the plugin
fails closed rather than assuming "unconfigured".

This module pins that contract.  ``resolve_store_dir`` is the single source of
truth; ``runtime_config``/``target_catalog``/``sensitive_paths`` must all defer
to it rather than carrying private copies of the old five-line guess.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

from credential_guard import runtime_config as _runtime_config_mod
from credential_guard import sensitive_paths as _sensitive_paths_mod
from credential_guard import store_location
from credential_guard import target_catalog as _target_catalog_mod

_STORE_DIR_MODULES = {
    "runtime_config": _runtime_config_mod,
    "target_catalog": _target_catalog_mod,
    "sensitive_paths": _sensitive_paths_mod,
}


DECOY = "sk-ROUND6-decoy-abcdefgh12345678"

# This module tests the derivation itself, so it must bypass the conftest
# bridge that maps a test-set HERMES_HOME onto the explicit override.
pytestmark = pytest.mark.no_store_bridge


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _install_tree(root: Path) -> Path:
    """Build a realistic ``<profile>/plugins/credential-guard/`` layout.

    Returns the directory that stands in for the installed package (the
    equivalent of ``credential_guard/`` inside the plugin directory).
    """
    pkg = root / "plugins" / "credential-guard" / "credential_guard"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    return pkg


def _write_config(store_dir: Path) -> Path:
    store_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    cfg = store_dir / "credential-guard.json"
    cfg.write_text(
        json.dumps(
            {
                "version": 2,
                "credentials": {"a": {"type": "token", "value": DECOY}},
                "bindings": {},
            }
        ),
        encoding="utf-8",
    )
    os.chmod(cfg, 0o600)
    return cfg


# --------------------------------------------------------------------------
# the derivation itself
# --------------------------------------------------------------------------


def test_store_dir_derived_from_installed_package_location(tmp_path):
    """The profile root comes from where the plugin actually sits on disk."""
    profile = tmp_path / "profiles" / "worker"
    pkg = _install_tree(profile)

    resolved = store_location.resolve_store_dir(package_dir=pkg)

    assert resolved == profile / "credential-guard"


def test_derivation_ignores_hermes_home_entirely(tmp_path, monkeypatch):
    """HERMES_HOME is not consulted -- it was the root cause of three rounds."""
    profile = tmp_path / "profiles" / "worker"
    pkg = _install_tree(profile)

    for bogus in (
        str(tmp_path / "somewhere-else"),
        str(tmp_path),
        "/tmp",
        "",
        "   ",
    ):
        monkeypatch.setenv("HERMES_HOME", bogus)
        assert store_location.resolve_store_dir(package_dir=pkg) == (
            profile / "credential-guard"
        ), f"HERMES_HOME={bogus!r} must not move the store"

    monkeypatch.delenv("HERMES_HOME", raising=False)
    assert store_location.resolve_store_dir(package_dir=pkg) == (
        profile / "credential-guard"
    )


def test_each_profile_gets_its_own_store(tmp_path):
    """Two installs under two profiles resolve to two different stores."""
    a = tmp_path / "profiles" / "alpha"
    b = tmp_path / "profiles" / "beta"
    pkg_a = _install_tree(a)
    pkg_b = _install_tree(b)

    resolved_a = store_location.resolve_store_dir(package_dir=pkg_a)
    resolved_b = store_location.resolve_store_dir(package_dir=pkg_b)

    assert resolved_a == a / "credential-guard"
    assert resolved_b == b / "credential-guard"
    assert resolved_a != resolved_b


def test_deepest_plugins_ancestor_wins(tmp_path):
    """A profile nested under an unrelated 'plugins' dir still resolves right."""
    outer = tmp_path / "plugins" / "decoy"
    profile = outer / "profiles" / "worker"
    pkg = _install_tree(profile)

    assert store_location.resolve_store_dir(package_dir=pkg) == (
        profile / "credential-guard"
    )


# --------------------------------------------------------------------------
# fail-closed when the layout is not an install tree
# --------------------------------------------------------------------------


def test_source_tree_has_no_derivable_root(tmp_path):
    """Running from a checkout (no plugins/ ancestor) must not invent a root."""
    pkg = tmp_path / "repo" / "credential_guard"
    pkg.mkdir(parents=True)

    with pytest.raises(store_location.StoreLocationError) as ei:
        store_location.resolve_store_dir(package_dir=pkg)

    assert ei.value.code == store_location.STORE_ROOT_UNDERIVABLE


def test_undate_root_does_not_fall_back_to_home(tmp_path, monkeypatch):
    """No silent fallback to ~/.hermes -- that fallback caused the S7 leak."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    pkg = tmp_path / "repo" / "credential_guard"
    pkg.mkdir(parents=True)

    with pytest.raises(store_location.StoreLocationError):
        store_location.resolve_store_dir(package_dir=pkg)


# --------------------------------------------------------------------------
# the test seam: explicit, not environmental
# --------------------------------------------------------------------------


def test_override_seam_is_explicit_and_scoped(tmp_path):
    """Tests pin the store by explicit argument, never by env var."""
    store = tmp_path / "custom-store"
    assert store_location.resolve_store_dir(store_dir=store) == store


def test_override_seam_beats_derivation(tmp_path):
    """An explicit store_dir wins over whatever the layout would derive."""
    profile = tmp_path / "profiles" / "worker"
    pkg = _install_tree(profile)
    store = tmp_path / "explicit"

    assert store_location.resolve_store_dir(package_dir=pkg, store_dir=store) == store


# --------------------------------------------------------------------------
# no configuration means blocked, not "brand new user"
# --------------------------------------------------------------------------


def test_missing_config_is_an_error_not_a_pass_through(tmp_path):
    """C1's 'absent means unconfigured, let it through' premise is withdrawn."""
    profile = tmp_path / "profiles" / "worker"
    pkg = _install_tree(profile)

    resolved = store_location.resolve_store_dir(package_dir=pkg)
    assert not (resolved / "credential-guard.json").exists()

    assert store_location.config_is_present(resolved) is False


def test_present_config_is_detected(tmp_path):
    profile = tmp_path / "profiles" / "worker"
    pkg = _install_tree(profile)
    resolved = store_location.resolve_store_dir(package_dir=pkg)
    _write_config(resolved)

    assert store_location.config_is_present(resolved) is True


# --------------------------------------------------------------------------
# the three former copies now defer to one implementation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "module_name",
    ["runtime_config", "target_catalog", "sensitive_paths"],
)
def test_no_module_derives_the_store_from_hermes_home(module_name):
    """No module may locate its OWN store by reading the environment.

    Scoped deliberately: ``sensitive_paths`` still expands ``$HERMES_HOME``
    inside paths *the model wrote* -- a different feature (deciding which files
    a model may read), not the store lookup. Prose mentioning the retired guess
    is fine too. What must not come back is an environment read that yields
    this plugin's own configuration directory.
    """
    mod = _STORE_DIR_MODULES[module_name]
    src = Path(mod.__file__).read_text(encoding="utf-8")

    lines = src.splitlines()
    for idx, line in enumerate(lines):
        if "HERMES_HOME" not in line or "environ" not in line:
            continue
        window = "\n".join(lines[idx : idx + 4])
        assert store_location.STORE_DIRNAME not in window, (
            f"{module_name}:{idx + 1} derives the store directory from "
            f"HERMES_HOME; it must call store_location.resolve_store_dir(). "
            f"Offending block:\n{window}"
        )


@pytest.mark.parametrize(
    "module_name",
    ["runtime_config", "target_catalog", "sensitive_paths"],
)
def test_no_module_keeps_a_private_home_fallback(module_name):
    """The silent ``~/.hermes`` fallback is what leaked in round 6."""
    mod = _STORE_DIR_MODULES[module_name]
    src = Path(mod.__file__).read_text(encoding="utf-8")

    assert '".hermes"' not in src, (
        f"{module_name} still contains a hard-coded ~/.hermes fallback; the "
        "store location must come from credential_guard.store_location"
    )


@pytest.mark.parametrize(
    "module_name",
    ["runtime_config", "target_catalog", "sensitive_paths"],
)
def test_modules_agree_on_one_store_dir(module_name, tmp_path, monkeypatch):
    """All three former copies resolve to the identical directory."""
    profile = tmp_path / "profiles" / "worker"
    pkg = _install_tree(profile)
    monkeypatch.setattr(
        store_location, "_installed_package_dir", lambda: pkg, raising=False
    )

    mod = _STORE_DIR_MODULES[module_name]
    getter = getattr(mod, "_store_dir")

    assert getter() == store_location.resolve_store_dir(package_dir=pkg)
