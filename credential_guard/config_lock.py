"""Cross-process cooperative config lock for Credential Guard.

Lock file: ``.credential-guard.runtime.lock`` inside the secure store directory.
macOS/Linux: ``fcntl.flock``.

Modes
-----
* **shared** — R1B ``load_and_publish_runtime`` (read body → build → publish),
  R2 final recheck+consume, and (future R3) resolve+inject+downstream start.
* **exclusive** — Credential Guard formal writers (migration publish/replace/
  recovery) and the production ``exclusive_atomic_replace_config`` helper.

Timeout contract
----------------
Public ``timeout_seconds`` must be exact ``int``/``float`` (not ``bool``),
finite, strictly positive, and ``<= MAX_LOCK_TIMEOUT_SECONDS`` (300s).
Invalid values raise ``ConfigLockError("CONFIG_LOCK_TIMEOUT")`` before any
lock-file open/create or formal-config write (bounded wait / fail-closed).

Threat model (frozen)
---------------------
Protects only cooperative Credential Guard publish/write/consume paths.
Does **not** claim protection against malicious same-UID processes that bypass
this protocol and mutate files via raw syscalls.

Lock order (must not invert)
----------------------------
::

    cross-process config lock
      → runtime in-process lock / execution-recheck lock
        → plan store lock

Never acquire this config lock while already holding the plan store lock.
Migration retains its own ``.cg-migrate.lock`` *outside* this lock; migration
then takes exclusive config lock for unified-file write phases. Readers never
take the migrate lock, so ordering is:

    migrate lock (writers only) → exclusive config lock → (no plan store)

Nested same-thread acquire is rejected fail-loud (avoids same-process flock
deadlock on upgrade / second open).
"""

from __future__ import annotations

import errno
import fcntl
import math
import os
import stat
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Iterator, Optional, Union

from .config import CONFIG_FILENAME

PathLike = Union[str, Path]

RUNTIME_LOCK_NAME = ".credential-guard.runtime.lock"
DEFAULT_LOCK_TIMEOUT_SECONDS = 5.0
# Explicit safety cap for public lock APIs (bounded wait / fail-closed).
# Keeps cooperative acquire from accepting NaN/Inf/unbounded caller values.
MAX_LOCK_TIMEOUT_SECONDS = 300
_POLL_INTERVAL_SECONDS = 0.05


class ConfigLockError(Exception):
    """Fail-closed config lock error. Never embed secrets or absolute paths."""

    __slots__ = ("code",)

    def __init__(self, code: str, message: str = "configuration lock error") -> None:
        object.__setattr__(self, "code", code)
        super().__init__(message)

    def __repr__(self) -> str:
        return f"ConfigLockError(code={self.code!r})"


def _mode_bits(mode: int) -> int:
    return stat.S_IMODE(mode)


def _assert_secure_store_dir(store_dir: Path) -> None:
    try:
        lst = os.lstat(store_dir)
    except OSError as exc:
        raise ConfigLockError("CONFIG_LOCK_FS") from exc
    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISDIR(lst.st_mode):
        raise ConfigLockError("CONFIG_LOCK_FS")
    if lst.st_uid != os.geteuid():
        raise ConfigLockError("CONFIG_LOCK_FS")
    if _mode_bits(lst.st_mode) != 0o700:
        raise ConfigLockError("CONFIG_LOCK_FS")


class _LockHeld:
    __slots__ = ("fd", "exclusive")

    def __init__(self, fd: int, exclusive: bool) -> None:
        self.fd = fd
        self.exclusive = exclusive


_thread_state = threading.local()


def _thread_depth() -> int:
    return int(getattr(_thread_state, "depth", 0) or 0)


def _open_lock_fd(store_dir: Path) -> int:
    path = store_dir / RUNTIME_LOCK_NAME
    cloexec = getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    created = False

    create_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | cloexec | nofollow
    try:
        fd = os.open(path, create_flags, 0o600)
        created = True
    except FileExistsError:
        created = False
    except OSError as exc:
        en = getattr(exc, "errno", None)
        if en == errno.EEXIST:
            created = False
        elif en in {getattr(os, "ELOOP", -1), getattr(errno, "ELOOP", -1)}:
            raise ConfigLockError("CONFIG_LOCK_SYMLINK") from exc
        else:
            raise ConfigLockError("CONFIG_LOCK_FS") from exc

    if not created:
        exist_flags = os.O_RDWR | cloexec | nofollow
        try:
            fd = os.open(path, exist_flags)
        except OSError as exc:
            en = getattr(exc, "errno", None)
            if en in {getattr(os, "ELOOP", -1), getattr(errno, "ELOOP", -1)}:
                raise ConfigLockError("CONFIG_LOCK_SYMLINK") from exc
            raise ConfigLockError("CONFIG_LOCK_FS") from exc

    if created:
        try:
            os.fchmod(fd, 0o600)
        except OSError as exc:
            try:
                os.close(fd)
            except OSError:
                pass
            raise ConfigLockError("CONFIG_LOCK_FS") from exc

    try:
        st = os.fstat(fd)
        lst = os.lstat(path)
    except OSError as exc:
        try:
            os.close(fd)
        except OSError:
            pass
        raise ConfigLockError("CONFIG_LOCK_FS") from exc

    if (
        stat.S_ISLNK(lst.st_mode)
        or not stat.S_ISREG(st.st_mode)
        or not stat.S_ISREG(lst.st_mode)
        or st.st_ino != lst.st_ino
        or st.st_dev != lst.st_dev
        or st.st_uid != os.geteuid()
        or lst.st_uid != os.geteuid()
        or _mode_bits(st.st_mode) != 0o600
        or _mode_bits(lst.st_mode) != 0o600
    ):
        try:
            os.close(fd)
        except OSError:
            pass
        if stat.S_ISLNK(lst.st_mode):
            raise ConfigLockError("CONFIG_LOCK_SYMLINK")
        if _mode_bits(st.st_mode) != 0o600 or _mode_bits(lst.st_mode) != 0o600:
            raise ConfigLockError("CONFIG_LOCK_MODE")
        raise ConfigLockError("CONFIG_LOCK_FS")

    return fd


def _validate_timeout_seconds(timeout_seconds: object) -> float:
    """Accept only exact int/float, finite, strictly positive, and <= max.

    Rejects bool (int subclass), NaN/Inf, zero/negative, and values above
    ``MAX_LOCK_TIMEOUT_SECONDS``. Must run before any lock-file or formal-config
    side effect so invalid inputs fail closed with a bounded-wait contract.
    """
    if type(timeout_seconds) not in (int, float):
        raise ConfigLockError("CONFIG_LOCK_TIMEOUT")
    value = float(timeout_seconds)
    if (
        not math.isfinite(value)
        or value <= 0.0
        or value > float(MAX_LOCK_TIMEOUT_SECONDS)
    ):
        raise ConfigLockError("CONFIG_LOCK_TIMEOUT")
    return value


def _acquire_flock(fd: int, *, exclusive: bool, timeout_seconds: float) -> None:
    flag = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            fcntl.flock(fd, flag | fcntl.LOCK_NB)
            return
        except (BlockingIOError, OSError):
            if time.monotonic() >= deadline:
                raise ConfigLockError("CONFIG_LOCK_TIMEOUT")
            time.sleep(_POLL_INTERVAL_SECONDS)


def _release_fd(fd: int) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(fd)
    except OSError:
        pass


def _verify_lock_path_after_acquire(store_dir: Path, fd: int) -> None:
    path = store_dir / RUNTIME_LOCK_NAME
    try:
        st = os.fstat(fd)
        lst = os.lstat(path)
    except OSError as exc:
        raise ConfigLockError("CONFIG_LOCK_FS") from exc
    if (
        stat.S_ISLNK(lst.st_mode)
        or st.st_ino != lst.st_ino
        or st.st_dev != lst.st_dev
        or _mode_bits(lst.st_mode) != 0o600
        or lst.st_uid != os.geteuid()
    ):
        raise ConfigLockError("CONFIG_LOCK_FS")


@contextmanager
def _hold_config_lock(
    store_dir: PathLike,
    *,
    exclusive: bool,
    timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
) -> Iterator[_LockHeld]:
    # Validate before any lock-file open/create or formal-config write.
    timeout_seconds = _validate_timeout_seconds(timeout_seconds)
    root = Path(store_dir)
    _assert_secure_store_dir(root)

    if _thread_depth() != 0:
        raise ConfigLockError("CONFIG_LOCK_REENTRANT")

    fd = -1
    acquired = False
    _thread_state.depth = 1
    _thread_state.exclusive = exclusive
    try:
        fd = _open_lock_fd(root)
        _acquire_flock(fd, exclusive=exclusive, timeout_seconds=timeout_seconds)
        acquired = True
        _verify_lock_path_after_acquire(root, fd)
        yield _LockHeld(fd=fd, exclusive=exclusive)
    finally:
        if acquired and fd >= 0:
            _release_fd(fd)
        elif fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        _thread_state.depth = 0
        _thread_state.exclusive = False


@contextmanager
def shared_config_lock(
    store_dir: PathLike,
    *,
    timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
) -> Generator[None, None, None]:
    """Shared flock covering load/build/publish or final recheck+consume (+ R3)."""
    with _hold_config_lock(
        store_dir, exclusive=False, timeout_seconds=timeout_seconds
    ):
        yield


@contextmanager
def exclusive_config_lock(
    store_dir: PathLike,
    *,
    timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
) -> Generator[None, None, None]:
    """Exclusive flock covering formal unified-config write transactions."""
    with _hold_config_lock(
        store_dir, exclusive=True, timeout_seconds=timeout_seconds
    ):
        yield


def exclusive_atomic_replace_config(
    store_dir: PathLike,
    new_text: str,
    *,
    timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
) -> None:
    """Replace ``credential-guard.json`` under exclusive lock (full write txn).

    Temp file is written in the store directory, chmod 0600, fsynced, then
    ``os.replace`` onto the formal name. Failures release the lock and must not
    leave a half-written formal file (temp cleaned best-effort).
    """
    root = Path(store_dir)
    formal = root / CONFIG_FILENAME
    tmp_path: Optional[Path] = None
    with exclusive_config_lock(root, timeout_seconds=timeout_seconds):
        try:
            fd, tmp_name = tempfile.mkstemp(
                prefix=".cg-cfg-write-",
                suffix=".tmp",
                dir=str(root),
            )
            tmp_path = Path(tmp_name)
            try:
                os.fchmod(fd, 0o600)
                data = new_text.encode("utf-8")
                view = memoryview(data)
                while len(view) > 0:
                    n = os.write(fd, view)
                    if n <= 0:
                        raise OSError("short write")
                    view = view[n:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(str(tmp_path), str(formal))
            tmp_path = None
            try:
                dir_fd = os.open(str(root), os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
        finally:
            if tmp_path is not None:
                try:
                    tmp_path.unlink()
                except OSError:
                    pass


__all__ = [
    "CONFIG_LOCK_ORDER_COMMENT",
    "ConfigLockError",
    "DEFAULT_LOCK_TIMEOUT_SECONDS",
    "MAX_LOCK_TIMEOUT_SECONDS",
    "RUNTIME_LOCK_NAME",
    "exclusive_atomic_replace_config",
    "exclusive_config_lock",
    "shared_config_lock",
]

# Exported for audits / docs sync — lock order is also in the module docstring.
CONFIG_LOCK_ORDER_COMMENT = (
    "cross-process config lock → runtime/execution in-process lock → plan store lock"
)
