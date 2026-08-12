"""R3B fixed local program adapter — single-shot env or stdin credential inject."""

from __future__ import annotations

import errno
import os
import select
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

from ..injection import InjectionError, SecretLease
from ..process_identity import (
    VerifiedExecutable,
    cleanup_verified_executable,
)
from ..registry import CredentialRegistry
from ..result_guard import RESULT_GUARD_FAIL_TEXT, guard_tool_result

# Minimal child env allowlist — never copy full os.environ.
_BASE_ENV_KEYS = frozenset(
    {
        "PATH",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "TERM",
    }
)

_START_LOCK = threading.Lock()
_PROCESS_START_COUNT = 0

# Bounded wait after SIGTERM before escalating to SIGKILL on the process group.
_GROUP_TERM_WAIT_S = 1.0
_GROUP_KILL_WAIT_S = 1.0
_GROUP_POLL_S = 0.05


class ProcessAdapterError(Exception):
    def __init__(self, code: str = "PROCESS_ADAPTER_FAILED") -> None:
        self.code = str(code)
        super().__init__(self.code)

    def __repr__(self) -> str:
        return f"ProcessAdapterError({self.code!r})"


def process_start_count() -> int:
    with _START_LOCK:
        return int(_PROCESS_START_COUNT)


def reset_process_start_count_for_tests() -> None:
    global _PROCESS_START_COUNT
    with _START_LOCK:
        _PROCESS_START_COUNT = 0


def _note_process_start() -> None:
    global _PROCESS_START_COUNT
    with _START_LOCK:
        _PROCESS_START_COUNT += 1


def _safe_fail(code: str = "PROCESS_ADAPTER_FAILED") -> Dict[str, Any]:
    return {"ok": False, "error": code, "source": "credential-guard"}


def _token_value(lease: SecretLease) -> str:
    try:
        material = lease.read_for_adapter()
    except InjectionError as exc:
        raise ProcessAdapterError("PROCESS_ADAPTER_FAILED") from exc
    if material.get("kind") != "token":
        raise ProcessAdapterError("PROCESS_INJECT_MISMATCH")
    value = material.get("value")
    if not isinstance(value, str) or not value:
        raise ProcessAdapterError("PROCESS_INJECT_MISMATCH")
    if "\x00" in value:
        raise ProcessAdapterError("PROCESS_INJECT_MISMATCH")
    return value


def _build_base_env() -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key in _BASE_ENV_KEYS:
        val = os.environ.get(key)
        if isinstance(val, str) and val and "\x00" not in val:
            out[key] = val
    # Always provide a minimal PATH if host PATH missing/empty.
    if "PATH" not in out:
        out["PATH"] = "/usr/bin:/bin"
    return out


def _build_argv(binding: Mapping[str, Any], verified: VerifiedExecutable) -> List[str]:
    raw = binding.get("argv")
    if not isinstance(raw, (list, tuple)) or not raw:
        raise ProcessAdapterError("PROCESS_ADAPTER_FAILED")
    argv = [str(x) for x in raw]
    # Remap argv[0] to the verified private copy; remaining argv stay binding-fixed.
    return [verified.executable_path, *argv[1:]]


def _guard_output(text: str, credential_name: str, secret: str) -> str:
    """Apply the unified result guard; preserve business output, replace secrets."""
    materials: List[Tuple[str, str]] = []
    if isinstance(credential_name, str) and credential_name and secret:
        materials.append((credential_name, secret))
    return guard_tool_result(text, CredentialRegistry(), session_materials=materials)

class NonblockingSetupError(ProcessAdapterError):
    """Internal: selector-loop fd could not be set non-blocking. No OS details."""

    def __init__(self) -> None:
        super().__init__("PROCESS_ADAPTER_FAILED")


@dataclass(frozen=True)
class ProcessExecutionHandle:
    """Immutable per-execution handle.

    ``pgid`` is the *expected* process-group id from the start_new_session
    launch contract (equal to child pid). It is established on Popen return and
    does not require the leader to still be alive.
    """

    proc: subprocess.Popen
    pgid: int
    used_new_session: bool


def _establish_execution_handle(proc: subprocess.Popen) -> ProcessExecutionHandle:
    """First production statement after Popen(start_new_session=True).

    ``start_new_session=True`` is this adapter's immutable launch contract: on
    successful Popen return the child's session/process-group id equals its pid.
    Establish ``expected_pgid = child_pid`` immediately — do not require a live
    leader before knowing the PGID.

    Optional ``getpgid(pid)`` is only a liveness consistency check:
    - returns pid → normal
    - ESRCH → leader already gone; retain contract expected_pgid for group cleanup
    - returns non-pid → fail-closed (``used_new_session=False``); never killpg a
      foreign group; still allow direct-child reap
    Unexpected getpgid OSError raises ProcessAdapterError *after* the contract
    handle exists in the caller only if this helper is used carefully — prefer
    calling this as the sole post-Popen establishment step; on unexpected errors
    the returned path still surfaces via raise from ``_consistency_check_pgid``.
    Never embeds pid/pgid in errors.
    """
    pid = getattr(proc, "pid", None)
    if not isinstance(pid, int) or pid <= 0:
        raise ProcessAdapterError("PROCESS_ADAPTER_FAILED")
    expected_pgid = int(pid)
    # Contract handle FIRST — before any optional consistency query.
    handle = ProcessExecutionHandle(
        proc=proc, pgid=expected_pgid, used_new_session=True
    )
    return _consistency_check_pgid(handle)


def _consistency_check_pgid(handle: ProcessExecutionHandle) -> ProcessExecutionHandle:
    """Optional live getpgid check; never drops the contract expected_pgid."""
    pid = handle.pgid
    try:
        observed = os.getpgid(handle.proc.pid)
    except OSError as exc:
        err_no = getattr(exc, "errno", None)
        if err_no == errno.ESRCH or isinstance(exc, ProcessLookupError):
            return handle
        raise ProcessAdapterError("PROCESS_ADAPTER_FAILED") from exc
    if observed != pid:
        return ProcessExecutionHandle(
            proc=handle.proc, pgid=pid, used_new_session=False
        )
    return handle


def _capture_session_pgid(proc: subprocess.Popen) -> int:
    """Compatibility helper: establish handle and return expected_pgid.

    Raises ProcessAdapterError when the consistency check fail-closes
    (observed pgid != child pid) or on unexpected getpgid errors. ESRCH keeps
    the contract pgid.
    """
    handle = _establish_execution_handle(proc)
    if not handle.used_new_session:
        raise ProcessAdapterError("PROCESS_ADAPTER_FAILED")
    return int(handle.pgid)


def _set_nonblocking(fd: int) -> None:
    """Set fd non-blocking; fail-closed on any OSError (no swallow)."""
    try:
        os.set_blocking(fd, False)
    except OSError as exc:
        raise NonblockingSetupError() from exc


def _pgid_present(pgid: int) -> bool:
    """True if at least one process in the group still exists (incl. zombies briefly)."""
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.ESRCH:
            return False
        return True


def _wait_pgid_gone(pgid: int, deadline: float) -> None:
    while time.monotonic() < deadline:
        if not _pgid_present(pgid):
            return
        time.sleep(_GROUP_POLL_S)


def _kill_process_group(
    proc: subprocess.Popen,
    *,
    captured_pgid: Optional[int],
    used_new_session: bool,
) -> None:
    """Terminate the child session/process group using the *captured* PGID.

    Never re-discovers PGID via getpgid(leader) at cleanup time — leader may
    already be gone while descendants still hold injected env. killpg only when
    start_new_session was used and captured_pgid == original child pid.
    Never embeds PID/PGID/paths into raised errors (caller maps to safe codes).
    """
    pid = getattr(proc, "pid", None)
    allow_killpg = (
        used_new_session
        and isinstance(pid, int)
        and pid > 0
        and isinstance(captured_pgid, int)
        and captured_pgid == pid
    )
    pgid = captured_pgid if allow_killpg else None

    if allow_killpg and pgid is not None:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except OSError:
            pass
        term_deadline = time.monotonic() + _GROUP_TERM_WAIT_S
        while time.monotonic() < term_deadline:
            if proc.poll() is not None and not _pgid_present(pgid):
                break
            time.sleep(_GROUP_POLL_S)
        if proc.poll() is None or _pgid_present(pgid):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass
            _wait_pgid_gone(pgid, time.monotonic() + _GROUP_KILL_WAIT_S)
    else:
        # Fail-closed: do not kill foreign groups; still reap direct child.
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=_GROUP_TERM_WAIT_S)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    try:
        if proc.poll() is None:
            try:
                proc.wait(timeout=_GROUP_KILL_WAIT_S)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=_GROUP_KILL_WAIT_S)
                except Exception:
                    pass
        else:
            try:
                proc.wait(timeout=0.01)
            except Exception:
                pass
    except Exception:
        pass


def _kill_and_reap(
    proc: subprocess.Popen,
    *,
    captured_pgid: Optional[int] = None,
    used_new_session: bool = True,
) -> None:
    _kill_process_group(
        proc, captured_pgid=captured_pgid, used_new_session=used_new_session
    )


def _cleanup_handle(handle: Optional[ProcessExecutionHandle]) -> None:
    if handle is None:
        return
    _kill_and_reap(
        handle.proc,
        captured_pgid=handle.pgid,
        used_new_session=handle.used_new_session,
    )


def _bounded_io(
    proc: subprocess.Popen,
    *,
    stdin_data: Optional[bytes],
    max_stdout: int,
    max_stderr: int,
    deadline: float,
) -> Tuple[bytes, bytes, bool, bool, bool]:
    """Selector-driven stdin write + stdout/stderr read under one monotonic deadline.

    Never uses communicate(). stdin is non-blocking; env mode passes stdin_data=None
    after the caller has already closed stdin.
    """
    stdout_chunks: List[bytes] = []
    stderr_chunks: List[bytes] = []
    out_len = 0
    err_len = 0
    out_trunc = False
    err_trunc = False
    timed_out = False

    def _fileno_or_none(stream) -> Optional[int]:
        if stream is None:
            return None
        try:
            if getattr(stream, "closed", False):
                return None
            return stream.fileno()
        except (ValueError, OSError):
            return None

    stdout_fd = _fileno_or_none(proc.stdout)
    stderr_fd = _fileno_or_none(proc.stderr)
    # Only touch stdin when we still have bytes to write (env mode already closed it).
    stdin_fd = _fileno_or_none(proc.stdin) if stdin_data is not None else None

    for fd in (stdout_fd, stderr_fd, stdin_fd):
        if fd is not None:
            _set_nonblocking(fd)

    read_fds = {fd for fd in (stdout_fd, stderr_fd) if fd is not None}
    stdin_view: Optional[memoryview] = None
    stdin_offset = 0
    stdin_open = False
    if stdin_data is not None and stdin_fd is not None:
        stdin_view = memoryview(stdin_data)
        stdin_open = True
        if len(stdin_data) == 0:
            try:
                proc.stdin.close()
            except Exception:
                pass
            stdin_open = False
            stdin_view = None

    while read_fds or stdin_open:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break

        want_read = list(read_fds)
        want_write: List[int] = []
        if stdin_open and stdin_fd is not None and stdin_view is not None:
            want_write = [stdin_fd]

        try:
            ready_r, ready_w, _ = select.select(
                want_read, want_write, [], min(remaining, 0.25)
            )
        except (InterruptedError, select.error):
            continue

        if not ready_r and not ready_w:
            if proc.poll() is not None and not stdin_open:
                # Drain any remaining briefly.
                try:
                    ready_r, _, _ = select.select(list(read_fds), [], [], 0)
                except Exception:
                    ready_r = []
                if not ready_r:
                    break
            continue

        if stdin_open and stdin_fd is not None and stdin_fd in ready_w and stdin_view is not None:
            try:
                n = os.write(stdin_fd, stdin_view[stdin_offset:])
            except BrokenPipeError:
                n = -1
            except OSError as exc:
                if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    n = 0
                elif exc.errno in (errno.EPIPE, errno.EINVAL):
                    n = -1
                else:
                    n = -1
            if n < 0:
                try:
                    proc.stdin.close()
                except Exception:
                    pass
                stdin_open = False
                stdin_view = None
            elif n > 0:
                stdin_offset += n
                if stdin_offset >= len(stdin_view):
                    try:
                        proc.stdin.close()
                    except Exception:
                        pass
                    stdin_open = False
                    stdin_view = None

        for fd in ready_r:
            try:
                chunk = os.read(fd, 4096)
            except OSError as exc:
                if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    continue
                read_fds.discard(fd)
                continue
            if not chunk:
                read_fds.discard(fd)
                continue
            if fd == stdout_fd:
                if out_len >= max_stdout:
                    out_trunc = True
                    continue
                take = chunk[: max_stdout - out_len]
                stdout_chunks.append(take)
                out_len += len(take)
                if len(take) < len(chunk) or out_len >= max_stdout:
                    out_trunc = True
            elif fd == stderr_fd:
                if err_len >= max_stderr:
                    err_trunc = True
                    continue
                take = chunk[: max_stderr - err_len]
                stderr_chunks.append(take)
                err_len += len(take)
                if len(take) < len(chunk) or err_len >= max_stderr:
                    err_trunc = True

        if out_trunc or err_trunc:
            break

    return (
        b"".join(stdout_chunks),
        b"".join(stderr_chunks),
        out_trunc,
        err_trunc,
        timed_out,
    )


def execute_process(
    *,
    binding: Mapping[str, Any],
    lease: SecretLease,
    verified: VerifiedExecutable,
) -> Dict[str, Any]:
    """Run verified program once with env or stdin inject. Never mutates os.environ."""
    btype = binding.get("type")
    if btype not in {"process_env", "stdin"}:
        return _safe_fail("PROCESS_ADAPTER_FAILED")

    try:
        timeout = int(binding["timeout_seconds"])
        max_out = int(binding["max_stdout_bytes"])
        max_err = int(binding["max_stderr_bytes"])
        if timeout <= 0 or max_out <= 0 or max_err <= 0:
            return _safe_fail("PROCESS_ADAPTER_FAILED")
    except Exception:
        return _safe_fail("PROCESS_ADAPTER_FAILED")

    handle: Optional[ProcessExecutionHandle] = None
    secret = ""
    stdin_data: Optional[bytes] = None
    deadline = 0.0
    try:
        secret = _token_value(lease)
        argv = _build_argv(binding, verified)
        env = _build_base_env()

        if btype == "process_env":
            env_name = binding.get("env_name")
            if not isinstance(env_name, str) or not env_name:
                return _safe_fail("PROCESS_ADAPTER_FAILED")
            if env_name in env and env_name not in {
                "PATH",
                "LANG",
                "LC_ALL",
                "LC_CTYPE",
                "TZ",
                "TERM",
            }:
                return _safe_fail("PROCESS_ADAPTER_FAILED")
            env[env_name] = secret
            stdin_data = None
        else:
            fmt = binding.get("stdin_format")
            if fmt not in {"raw", "line"}:
                return _safe_fail("PROCESS_ADAPTER_FAILED")
            payload = secret if fmt == "raw" else secret + "\n"
            stdin_data = payload.encode("utf-8")

        deadline = time.monotonic() + float(timeout)
        _note_process_start()
        proc = subprocess.Popen(
            argv,
            shell=False,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            cwd=None,
            start_new_session=True,
        )
        # First production statement after Popen: expected_pgid = child_pid
        # from the start_new_session contract (leader need not still be alive).
        pid = getattr(proc, "pid", None)
        if not isinstance(pid, int) or pid <= 0:
            try:
                proc.kill()
            except Exception:
                pass
            try:
                proc.wait(timeout=_GROUP_KILL_WAIT_S)
            except Exception:
                pass
            return _safe_fail("PROCESS_ADAPTER_FAILED")
        handle = ProcessExecutionHandle(
            proc=proc, pgid=int(pid), used_new_session=True
        )
        try:
            handle = _consistency_check_pgid(handle)
        except ProcessAdapterError:
            _cleanup_handle(handle)
            return _safe_fail("PROCESS_ADAPTER_FAILED")
        if not handle.used_new_session:
            # Consistency check saw a foreign pgid — fail-closed, no killpg.
            _cleanup_handle(handle)
            return _safe_fail("PROCESS_ADAPTER_FAILED")
    except ProcessAdapterError:
        _cleanup_handle(handle)
        return _safe_fail("PROCESS_ADAPTER_FAILED")
    except Exception:
        _cleanup_handle(handle)
        return _safe_fail("PROCESS_ADAPTER_FAILED")

    timed_out = False
    truncated = False
    try:
        proc = handle.proc
        # Env mode: close stdin immediately, then share the same read/timeout loop.
        if stdin_data is None and proc.stdin is not None:
            try:
                proc.stdin.close()
            except Exception:
                pass
            io_stdin: Optional[bytes] = None
        else:
            io_stdin = stdin_data

        out_b, err_b, out_trunc, err_trunc, read_timeout = _bounded_io(
            proc,
            stdin_data=io_stdin,
            max_stdout=max_out,
            max_stderr=max_err,
            deadline=deadline,
        )
        truncated = out_trunc or err_trunc
        timed_out = read_timeout
        if truncated or timed_out:
            _cleanup_handle(handle)
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _cleanup_handle(handle)
            else:
                try:
                    proc.wait(timeout=max(remaining, 0.001))
                except subprocess.TimeoutExpired:
                    timed_out = True
                    _cleanup_handle(handle)

        # Always reap group via captured PGID — leader may already be gone.
        _cleanup_handle(handle)

        exit_code = proc.poll()
        if exit_code is None:
            exit_code = -1

        try:
            out_s = out_b.decode("utf-8", errors="replace")
            err_s = err_b.decode("utf-8", errors="replace")
        except Exception:
            return _safe_fail("PROCESS_ADAPTER_FAILED")

        cred_name = binding.get("credential_ref")
        if not isinstance(cred_name, str) or not cred_name:
            return _safe_fail("PROCESS_ADAPTER_FAILED")
        out_s = _guard_output(out_s, cred_name, secret)
        err_s = _guard_output(err_s, cred_name, secret)
        if out_s == RESULT_GUARD_FAIL_TEXT or err_s == RESULT_GUARD_FAIL_TEXT:
            return _safe_fail("PROCESS_ADAPTER_FAILED")
        # Belt: plaintext secret must not remain after the unified guard.
        if (secret and secret in out_s) or (secret and secret in err_s):
            return _safe_fail("PROCESS_ADAPTER_FAILED")

        if timed_out:
            return {
                "ok": False,
                "error": "PROCESS_TIMEOUT",
                "source": "credential-guard",
                "timeout": True,
                "truncated": truncated,
            }
        if truncated:
            return {
                "ok": False,
                "error": "PROCESS_OUTPUT_LIMIT",
                "source": "credential-guard",
                "timeout": False,
                "truncated": True,
            }

        return {
            "ok": True,
            "exit_code": int(exit_code),
            "stdout": out_s,
            "stderr": err_s,
            "timeout": False,
            "truncated": False,
            "source": "credential-guard",
        }
    except NonblockingSetupError:
        _cleanup_handle(handle)
        return _safe_fail("PROCESS_ADAPTER_FAILED")
    except Exception:
        _cleanup_handle(handle)
        return _safe_fail("PROCESS_ADAPTER_FAILED")
    finally:
        # Parent env must remain untouched (we never assigned into os.environ).
        # Final group reap is idempotent if already cleaned above.
        _cleanup_handle(handle)


__all__ = [
    "NonblockingSetupError",
    "ProcessAdapterError",
    "ProcessExecutionHandle",
    "cleanup_verified_executable",
    "execute_process",
    "process_start_count",
    "reset_process_start_count_for_tests",
]
