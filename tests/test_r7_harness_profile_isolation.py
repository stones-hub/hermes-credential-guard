"""Regression: the test harness must never write into a live Hermes profile.

Incident (round 7). ``tests/conftest.py`` bridges a test-set ``HERMES_HOME`` onto
the explicit store override so ~164 existing call sites keep working after the
production code stopped reading that variable. The first version of the bridge
forwarded *any* value it saw -- including the one Hermes itself exports for the
running profile. Inside an agent session ``HERMES_HOME`` is therefore already
set to the live profile before pytest starts, so the bridge pointed the store at
``~/.hermes/profiles/worker/credential-guard`` and tests overwrote the real
config file there.

Nothing was lost that time (the file held a decoy), but the same bug with a real
credential in place would have destroyed it. These tests pin the two properties
that keep it from recurring:

* an *inherited* ``HERMES_HOME`` is ignored -- only a value a test sets counts;
* any attempt to resolve the store into a live profile is a hard failure rather
  than a silent redirect.

Both assertions target ``tests/conftest.py`` itself, which is why they poke at
its private helpers directly.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import conftest as harness
from credential_guard import store_location


def test_ambient_hermes_home_is_captured_at_import():
    """The bridge needs a record of what it inherited to be able to ignore it."""
    assert hasattr(harness, "_AMBIENT_HERMES_HOME")
    assert isinstance(harness._AMBIENT_HERMES_HOME, str)


def test_live_profile_roots_are_refused(tmp_path: Path):
    """The incident path: a store dir inside the live profile must raise."""
    roots = harness._forbidden_store_roots()
    assert roots, "there is always at least ~/.hermes to protect"

    for root in roots:
        victim = os.path.join(root, store_location.STORE_DIRNAME)
        with pytest.raises(AssertionError) as excinfo:
            harness._assert_not_a_live_profile(victim)
        assert "live Hermes" in str(excinfo.value)

        # Nested paths are refused too, not just the exact root.
        deeper = os.path.join(root, "profiles", "worker", store_location.STORE_DIRNAME)
        with pytest.raises(AssertionError):
            harness._assert_not_a_live_profile(deeper)


def test_temporary_stores_are_still_allowed(tmp_path: Path):
    """The guard must not be so broad that ordinary tmp_path stores trip it."""
    harness._assert_not_a_live_profile(
        str(tmp_path / "profiles" / "worker" / store_location.STORE_DIRNAME)
    )


def test_sibling_named_directory_is_not_confused_for_the_profile(tmp_path: Path):
    """Prefix matching must respect separators: ``/x/.hermes-copy`` is not ``/x/.hermes``.

    Built from a tmp_path so the lookalike sits outside every protected root --
    appending ``-copy`` to a real root (e.g. ``~/.hermes/profiles/worker-copy``)
    would still be *inside* ``~/.hermes`` and is refused on purpose.
    """
    lookalike = str(tmp_path / ".hermes-copy")
    harness._assert_not_a_live_profile(os.path.join(lookalike, "credential-guard"))


def test_inherited_value_does_not_point_the_store_at_the_live_profile():
    """End-to-end: a test that never touches ``HERMES_HOME`` gets no override.

    This is the incident itself. The autouse bridge runs for this test (no
    ``no_store_bridge`` marker -- an earlier draft carried one, which made the
    fixture bail out early and the assertion vacuous). With an inherited
    ``HERMES_HOME`` present and nothing set locally, the bridge must leave the
    override clear. The pre-fix bridge forwarded the inherited value here and
    aimed the store at the operator's real profile.
    """
    ambient = harness._AMBIENT_HERMES_HOME
    if not ambient:
        pytest.skip("no ambient HERMES_HOME in this environment")

    # The bridge saw the inherited value and must have declined to use it.
    assert store_location._OVERRIDE_STORE_DIR is None, (
        "inherited HERMES_HOME leaked into the store override: "
        f"{store_location._OVERRIDE_STORE_DIR!r}"
    )


def test_bridge_still_honours_a_value_the_test_sets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The fix must not break the bridge's actual job.

    ~164 existing tests point the store at a temporary directory by setting
    ``HERMES_HOME``. That must keep working -- only the *inherited* value is
    ignored.
    """
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    expected = os.path.join(str(tmp_path), store_location.STORE_DIRNAME)
    assert str(store_location._OVERRIDE_STORE_DIR) == expected
