"""Program identity capture and TOCTOU-resistant verified executable prep (R3B).

Binds device/inode/mode/uid/size/mtime_ns + content SHA-256. Execution must use
a privately copied, re-verified immutable binary — never ``Popen`` the live
pathname after a check-then-use window.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class ProgramIdentityError(Exception):
    __slots__ = ("code",)

    def __init__(self, code: str = "PROGRAM_IDENTITY_REJECTED") -> None:
        self.code = str(code)
        super().__init__(self.code)

    def __repr__(self) -> str:
        return f"ProgramIdentityError({self.code!r})"


@dataclass(frozen=True)
class ProgramIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    size: int
    mtime_ns: int
    content_sha256: str


@dataclass(frozen=True)
class VerifiedExecutable:
    """Path to an immutable private copy ready for shell=False exec."""

    executable_path: str
    identity: ProgramIdentity
    work_dir: str


def _sha256_fd(fd: int) -> str:
    h = hashlib.sha256()
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        h.update(chunk)
    return h.hexdigest()


def _require_safe_lstat(path: str) -> os.stat_result:
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise ProgramIdentityError("PROGRAM_IDENTITY_REJECTED") from exc
    if stat.S_ISLNK(st.st_mode):
        raise ProgramIdentityError("PROGRAM_IDENTITY_REJECTED")
    if not stat.S_ISREG(st.st_mode):
        raise ProgramIdentityError("PROGRAM_IDENTITY_REJECTED")
    if st.st_uid != os.geteuid():
        raise ProgramIdentityError("PROGRAM_IDENTITY_REJECTED")
    mode = stat.S_IMODE(st.st_mode)
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ProgramIdentityError("PROGRAM_IDENTITY_REJECTED")
    if not (mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
        raise ProgramIdentityError("PROGRAM_IDENTITY_REJECTED")
    return st


def _open_nofollow(path: str) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(path, flags)
    except OSError as exc:
        raise ProgramIdentityError("PROGRAM_IDENTITY_REJECTED") from exc


def _identity_from_fd(path: str, st_lstat: os.stat_result, fd: int) -> ProgramIdentity:
    try:
        st_f = os.fstat(fd)
    except OSError as exc:
        raise ProgramIdentityError("PROGRAM_IDENTITY_REJECTED") from exc
    if (
        st_f.st_dev != st_lstat.st_dev
        or st_f.st_ino != st_lstat.st_ino
        or st_f.st_size != st_lstat.st_size
        or int(st_f.st_mtime_ns) != int(st_lstat.st_mtime_ns)
        or st_f.st_uid != st_lstat.st_uid
        or stat.S_IMODE(st_f.st_mode) != stat.S_IMODE(st_lstat.st_mode)
    ):
        raise ProgramIdentityError("PROGRAM_IDENTITY_CHANGED")
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        digest = _sha256_fd(fd)
        os.lseek(fd, 0, os.SEEK_SET)
    except OSError as exc:
        raise ProgramIdentityError("PROGRAM_IDENTITY_REJECTED") from exc
    return ProgramIdentity(
        device=int(st_f.st_dev),
        inode=int(st_f.st_ino),
        mode=int(stat.S_IMODE(st_f.st_mode)),
        uid=int(st_f.st_uid),
        size=int(st_f.st_size),
        mtime_ns=int(st_f.st_mtime_ns),
        content_sha256=digest,
    )


def capture_program_identity(path: str) -> ProgramIdentity:
    """lstat → O_NOFOLLOW open → fstat → content hash. Rejects symlink/unsafe mode."""
    if not isinstance(path, str) or not path:
        raise ProgramIdentityError("PROGRAM_IDENTITY_REJECTED")
    st = _require_safe_lstat(path)
    fd = _open_nofollow(path)
    try:
        return _identity_from_fd(path, st, fd)
    finally:
        os.close(fd)


def verify_same_identity(path: str, expected: ProgramIdentity) -> ProgramIdentity:
    """Re-capture and require exact identity match (content hash included)."""
    if not isinstance(expected, ProgramIdentity):
        raise ProgramIdentityError("PROGRAM_IDENTITY_REJECTED")
    current = capture_program_identity(path)
    if (
        current.device != expected.device
        or current.inode != expected.inode
        or current.mode != expected.mode
        or current.uid != expected.uid
        or current.size != expected.size
        or current.mtime_ns != expected.mtime_ns
        or current.content_sha256 != expected.content_sha256
    ):
        raise ProgramIdentityError("PROGRAM_IDENTITY_CHANGED")
    return current


def prepare_verified_executable(
    path: str,
    expected: ProgramIdentity,
    *,
    work_dir: Optional[str] = None,
) -> VerifiedExecutable:
    """Copy program into a private 0700 dir after identity recheck; exec the copy.

    macOS/Python cannot reliably fexecve from an fd. A private immutable copy
    closes the pathname TOCTOU window between verify and Popen.
    """
    verify_same_identity(path, expected)
    base = Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="cg-proc-"))
    try:
        if work_dir:
            base.mkdir(parents=True, exist_ok=True)
        os.chmod(base, 0o700)
    except OSError as exc:
        raise ProgramIdentityError("PROGRAM_IDENTITY_REJECTED") from exc

    # Re-open source with O_NOFOLLOW and stream into the private copy.
    st = _require_safe_lstat(path)
    src_fd = _open_nofollow(path)
    try:
        src_ident = _identity_from_fd(path, st, src_fd)
        if src_ident.content_sha256 != expected.content_sha256:
            raise ProgramIdentityError("PROGRAM_IDENTITY_CHANGED")
        if (
            src_ident.device != expected.device
            or src_ident.inode != expected.inode
            or src_ident.mode != expected.mode
            or src_ident.uid != expected.uid
            or src_ident.size != expected.size
            or src_ident.mtime_ns != expected.mtime_ns
        ):
            raise ProgramIdentityError("PROGRAM_IDENTITY_CHANGED")

        dest = base / "program"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        dest_fd = os.open(str(dest), flags, 0o700)
        try:
            os.lseek(src_fd, 0, os.SEEK_SET)
            while True:
                chunk = os.read(src_fd, 1024 * 1024)
                if not chunk:
                    break
                os.write(dest_fd, chunk)
            os.fsync(dest_fd)
        finally:
            os.close(dest_fd)
        os.chmod(dest, 0o700)
    finally:
        os.close(src_fd)

    # Bind identity of the *copy* (new inode); content hash must match expected.
    copy_ident = capture_program_identity(str(dest))
    if copy_ident.content_sha256 != expected.content_sha256:
        try:
            dest.unlink()
        except OSError:
            pass
        raise ProgramIdentityError("PROGRAM_IDENTITY_CHANGED")
    return VerifiedExecutable(
        executable_path=str(dest),
        identity=copy_ident,
        work_dir=str(base),
    )


def cleanup_verified_executable(verified: VerifiedExecutable) -> None:
    """Best-effort removal of private work dir after process exit."""
    try:
        shutil.rmtree(verified.work_dir, ignore_errors=True)
    except Exception:
        return


__all__ = [
    "ProgramIdentity",
    "ProgramIdentityError",
    "VerifiedExecutable",
    "capture_program_identity",
    "cleanup_verified_executable",
    "prepare_verified_executable",
    "verify_same_identity",
]
