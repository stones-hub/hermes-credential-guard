"""Test-wide bridge from the retired ``HERMES_HOME`` seam to the explicit one.

Background
----------
The plugin used to locate its own configuration by reading ``$HERMES_HOME``.
Three separate credential leaks traced back to that habit, so the lookup was
replaced by :mod:`credential_guard.store_location`, which derives the profile
root from where the plugin is actually installed and fails closed when it
cannot. Production code no longer consults the environment at all.

The suite, however, pins the store location in ~164 places by setting
``HERMES_HOME`` to a ``tmp_path``. Those tests are still exercising real
behaviour -- only the *mechanism* for pointing at a temporary store changed.
Rather than rewrite every call site (and risk quietly altering assertions in
the process), this fixture watches for the environment variable the tests set
and forwards it to the explicit override.

This bridge lives in the test tree only. It is not importable by the plugin,
so it cannot reintroduce the production behaviour it replaces. New tests should
prefer :func:`credential_guard.store_location.store_dir_override` directly.
"""

from __future__ import annotations

import os

import pytest

from credential_guard import store_location


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "no_store_bridge: opt out of the HERMES_HOME->explicit-store bridge",
    )


#: ``HERMES_HOME`` as it stood when pytest started. Hermes exports this for its
#: own runtime, so the variable is normally *already set* to the live profile
#: when the suite runs inside an agent session. The bridge below must forward
#: only values a test sets for itself; forwarding this one pointed the store at
#: the operator's real profile and let tests overwrite a real config file.
_AMBIENT_HERMES_HOME = os.environ.get("HERMES_HOME", "").strip()


def _forbidden_store_roots() -> tuple[str, ...]:
    """Profile roots that a test must never be able to target."""
    roots = []
    if _AMBIENT_HERMES_HOME:
        roots.append(os.path.realpath(_AMBIENT_HERMES_HOME))
    real_home = os.environ.get("HERMES_REAL_HOME") or os.path.expanduser("~")
    roots.append(os.path.realpath(os.path.join(real_home, ".hermes")))
    return tuple(roots)


def _assert_not_a_live_profile(candidate: str) -> None:
    """Fail loudly rather than let a test write into a live profile."""
    resolved = os.path.realpath(candidate)
    for root in _forbidden_store_roots():
        if resolved == root or resolved.startswith(root + os.sep):
            raise AssertionError(
                "test tried to point the credential store at a live Hermes "
                f"profile ({resolved!r} is under {root!r}). Tests must use "
                "tmp_path; see tests/conftest.py."
            )


@pytest.fixture(autouse=True)
def _bridge_hermes_home_to_explicit_store(request, monkeypatch):
    """Mirror a test-set ``HERMES_HOME`` onto the explicit store override.

    Re-evaluated before every test and torn down after, so a value set by one
    test cannot leak into the next. When the variable is absent the override
    stays clear and the plugin's real derivation (or its fail-closed error)
    applies -- which is exactly what the store-location tests need.

    Only values a test sets are forwarded. A ``HERMES_HOME`` inherited from the
    surrounding process is ignored: Hermes sets it to the running profile, and
    treating that as a test fixture made the suite write to the operator's real
    credential store. Any attempt to resolve into a live profile is a hard
    failure, not a silent redirect.
    """
    original = store_location._OVERRIDE_STORE_DIR

    if request.node.get_closest_marker("no_store_bridge"):
        # Tests that exercise the derivation itself must see the real thing.
        try:
            yield
        finally:
            store_location._OVERRIDE_STORE_DIR = original
        return

    def _sync() -> None:
        raw = os.environ.get("HERMES_HOME", "").strip()
        # Inherited value -> not a test's choice -> do not honour it.
        if raw and raw != _AMBIENT_HERMES_HOME:
            candidate = os.path.join(raw, store_location.STORE_DIRNAME)
            _assert_not_a_live_profile(candidate)
            store_location.use_store_dir(candidate)
        else:
            store_location.use_store_dir(None)

    _sync()

    # Tests set HERMES_HOME *inside* the test body far more often than in a
    # fixture, so keep the override in step with any later mutation.
    real_setenv = monkeypatch.setenv
    real_delenv = monkeypatch.delenv

    def setenv(name, value, *a, **kw):
        real_setenv(name, value, *a, **kw)
        if name in ("HERMES_HOME", "HOME"):
            _sync()

    def delenv(name, *a, **kw):
        real_delenv(name, *a, **kw)
        if name in ("HERMES_HOME", "HOME"):
            _sync()

    monkeypatch.setattr(monkeypatch, "setenv", setenv, raising=False)
    monkeypatch.setattr(monkeypatch, "delenv", delenv, raising=False)

    try:
        yield
    finally:
        store_location._OVERRIDE_STORE_DIR = original
