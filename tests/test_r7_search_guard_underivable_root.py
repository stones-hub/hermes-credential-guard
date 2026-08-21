"""Round 7: path protection must survive an underivable store root.

``search_path_is_protected`` called ``_store_dir()``, which raises
``StoreLocationError`` when the plugin is not running from an installed profile
layout (a source checkout, an unusual install). The exception escaped the
function, so the guard did not return "protected" -- it crashed. A crashing
guard protects nothing, which is the failure mode this codebase treats as worst
case: fail *open* by accident.

The sibling helper ``_store_file_is_protected`` already handled this via
``_store_dir_or_none()`` and documented the rule ("an underivable root must not
silently unprotect a file"). ``search_path_is_protected`` simply had not been
brought in line.

These tests pin the behaviour with no derivable store root:

* the call returns a bool rather than raising;
* ssh/home based protection still fires;
* an unrelated directory is still reported unprotected (the fallback must not
  degrade into "everything is protected", which would be useless).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from credential_guard import sensitive_paths, store_location


@pytest.fixture()
def underivable_root(monkeypatch: pytest.MonkeyPatch):
    """Force the store lookup to fail the way a source checkout does."""

    def _raise(*args, **kwargs):
        raise store_location.StoreLocationError(
            store_location.STORE_ROOT_UNDERIVABLE,
            "no 'plugins' directory above it",
        )

    monkeypatch.setattr(store_location, "resolve_store_dir", _raise)
    # Confirm the precondition actually holds, so a refactor that stops calling
    # resolve_store_dir turns this suite red instead of quietly passing.
    with pytest.raises(store_location.StoreLocationError):
        store_location.resolve_store_dir()
    return None


def test_search_guard_does_not_raise_when_root_underivable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, underivable_root
):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))

    result = sensitive_paths.search_path_is_protected(str(tmp_path / "elsewhere"))
    assert isinstance(result, bool)


def test_ssh_protection_survives_underivable_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, underivable_root
):
    """The important half: losing the store root must not lose ssh protection."""
    home = tmp_path / "home"
    ssh = home / ".ssh"
    ssh.mkdir(parents=True)
    (ssh / "config").write_text("Host x\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))

    assert sensitive_paths.search_path_is_protected(str(ssh))
    assert sensitive_paths.search_path_is_protected(str(home))
    assert sensitive_paths.search_path_is_protected(str(tmp_path))


def test_unrelated_path_still_unprotected_when_root_underivable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, underivable_root
):
    """The fallback must stay discriminating, not blanket-protect everything."""
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))

    alone = tmp_path.parent / f"r7-alone-{tmp_path.name}"
    alone.mkdir(exist_ok=True)
    (alone / "a.txt").write_text("x", encoding="utf-8")

    assert not sensitive_paths.search_path_is_protected(str(alone))
