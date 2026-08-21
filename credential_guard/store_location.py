"""Single source of truth for where this plugin's configuration lives.

Rationale
---------
Three consecutive rounds of leaks all traced back to one habit: the plugin
located its own config directory by reading ``$HERMES_HOME``::

    hermes = os.environ.get("HERMES_HOME", "").strip()
    if hermes:
        return Path(hermes) / "credential-guard"
    return Path.home() / ".hermes" / "credential-guard"

Five lines, copied verbatim into three modules.  Whenever that lookup landed
somewhere without a config file, the caller concluded "this user has never
configured anything" and let the request through un-redacted.  An operator who
*had* configured credentials therefore lost protection silently whenever the
variable was wrong (round 4), pointed at an unrelated existing directory
(round 5), or simply absent because a new shell / cron job / service unit never
exported it (round 6).

The guess is now gone.  The plugin is installed at
``<profile>/plugins/credential-guard/``, so it can derive the profile root from
its own location on disk.  There is no environment variable to get wrong, no
fallback path to drift onto, and nothing for a caller to point elsewhere.  When
the root cannot be derived the plugin fails closed instead of assuming the user
is new.

Every module that needs the store directory calls :func:`resolve_store_dir`.
No module keeps a private copy of the lookup.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, Union

__all__ = [
    "STORE_DIRNAME",
    "CONFIG_FILENAME",
    "STORE_ROOT_UNDERIVABLE",
    "StoreLocationError",
    "use_store_dir",
    "store_dir_override",
    "resolve_store_dir",
    "resolve_config_path",
    "config_is_present",
]

PathLike = Union[str, "os.PathLike[str]"]

#: Directory, relative to the profile root, holding this plugin's config.
STORE_DIRNAME = "credential-guard"

#: The one configuration file. There is no secondary location.
CONFIG_FILENAME = "credential-guard.json"

#: Raised when the profile root cannot be derived from the install layout.
STORE_ROOT_UNDERIVABLE = "STORE_ROOT_UNDERIVABLE"

#: The directory name Hermes installs plugins into, i.e. the anchor we look for
#: when walking up from this file: ``<profile>/plugins/<plugin>/...``.
_PLUGINS_DIRNAME = "plugins"


class StoreLocationError(Exception):
    """The configuration directory could not be located.

    Callers must treat this as fail-closed. It explicitly does NOT mean "the
    user has not configured anything yet" -- that conflation is what leaked
    credentials in three previous rounds.
    """

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


#: Process-wide explicit override, installed by :func:`use_store_dir`.
#:
#: This is the seam tests use to point the plugin at a temporary directory.
#: It is a module-level value set by an explicit call -- deliberately NOT an
#: environment variable, so that no ambient state inherited from a shell, a
#: cron job, or a service manager can move the store. Production code never
#: sets it.
_OVERRIDE_STORE_DIR = None  # type: Optional[Path]


def use_store_dir(store_dir: Optional[PathLike]) -> None:
    """Pin the store directory explicitly (test/CLI seam).

    Pass ``None`` to clear. Prefer the :func:`store_dir_override` context
    manager, which restores the previous value even when a test fails.
    """
    global _OVERRIDE_STORE_DIR
    _OVERRIDE_STORE_DIR = None if store_dir is None else Path(store_dir)


@contextmanager
def store_dir_override(store_dir: PathLike):
    """Scope an explicit store directory to a block, restoring on exit."""
    global _OVERRIDE_STORE_DIR
    previous = _OVERRIDE_STORE_DIR
    _OVERRIDE_STORE_DIR = Path(store_dir)
    try:
        yield Path(store_dir)
    finally:
        _OVERRIDE_STORE_DIR = previous


def _installed_package_dir() -> Path:
    """Directory of the installed ``credential_guard`` package."""
    return Path(__file__).resolve().parent


def _profile_root_from(package_dir: PathLike) -> Path:
    """Walk up from the package to the profile root.

    Layout::

        <profile>/plugins/credential-guard/credential_guard/store_location.py
        ^^^^^^^^^ what we want          ^^^^^^^^^^^^^^^^^^ package_dir

    The nearest ``plugins`` ancestor wins, so a profile that itself happens to
    live underneath some unrelated ``plugins`` directory still resolves to its
    own root rather than to the outer one.
    """
    try:
        resolved = Path(package_dir).resolve()
    except (OSError, TypeError, ValueError) as exc:
        raise StoreLocationError(
            STORE_ROOT_UNDERIVABLE,
            "cannot resolve the plugin package directory",
        ) from exc

    for ancestor in resolved.parents:
        if ancestor.name == _PLUGINS_DIRNAME:
            return ancestor.parent

    raise StoreLocationError(
        STORE_ROOT_UNDERIVABLE,
        "the plugin is not running from an installed profile layout "
        "(no 'plugins' directory above it)",
    )


def resolve_store_dir(
    *,
    package_dir: Optional[PathLike] = None,
    store_dir: Optional[PathLike] = None,
) -> Path:
    """Return the directory holding this profile's credential-guard config.

    :param store_dir: explicit override. This is the seam tests and the CLI's
        ``--config`` use; it is an argument rather than an environment
        variable precisely so that no ambient state can redirect the lookup.
    :param package_dir: where the installed package sits. Defaults to this
        file's own directory.
    :raises StoreLocationError: when no override is given and the profile root
        cannot be derived from the install layout. Fail closed; never guess.
    """
    if store_dir is not None:
        return Path(store_dir)
    if _OVERRIDE_STORE_DIR is not None:
        return _OVERRIDE_STORE_DIR

    root = _profile_root_from(
        package_dir if package_dir is not None else _installed_package_dir()
    )
    return root / STORE_DIRNAME


def resolve_config_path(
    *,
    package_dir: Optional[PathLike] = None,
    store_dir: Optional[PathLike] = None,
) -> Path:
    """Full path to the single configuration file."""
    return (
        resolve_store_dir(package_dir=package_dir, store_dir=store_dir)
        / CONFIG_FILENAME
    )


def config_is_present(store_dir: PathLike) -> bool:
    """Whether a configuration file exists in ``store_dir``.

    A ``False`` here means "no configuration" and nothing more. It is not a
    licence to skip redaction: callers block. Errors resolve to ``False`` so a
    stat failure cannot be mistaken for a healthy configured install.
    """
    try:
        return (Path(store_dir) / CONFIG_FILENAME).is_file()
    except OSError:
        return False
