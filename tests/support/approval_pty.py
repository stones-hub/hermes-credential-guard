"""PTY-driven Hermes approval interaction for M2 E2E (does not bypass the gate)."""

from __future__ import annotations

import errno
import os
import select
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional, Sequence


# Markers that indicate Hermes is waiting for an approval choice.
_CHOICE_MARKERS = (
    "Choice [o/s/a/D]:",
    "Choice [o/s/D]:",
    "选择 [o/s/a/D]:",
    "選擇 [o/s/a/D]:",
)

# Broader evidence that an approval panel was shown (for counting / leakage scan).
_APPROVAL_EVIDENCE = (
    "credential-guard requires approval",
    "DANGEROUS COMMAND",
    "危险命令",
    "[o]nce",
    "[o]仅此一次",
)


@dataclass
class PtyRunResult:
    returncode: int
    output: str
    approval_prompt_count: int = 0
    approvals_submitted: int = 0
    argv_samples: List[str] = field(default_factory=list)
    argv_sample_ok: bool = False
    argv_plain_password_count: int = 0
    pid: Optional[int] = None


def _count_needle(blob: str, needle: str) -> int:
    if not needle:
        return 0
    return blob.count(needle)


def _ps_command_lines(pids: Sequence[int]) -> List[str]:
    lines: List[str] = []
    for pid in pids:
        if pid <= 0:
            continue
        try:
            proc = subprocess.run(
                ["/bin/ps", "-ww", "-o", "command=", "-p", str(pid)],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except Exception:
            continue
        text = (proc.stdout or "").strip()
        if text:
            lines.append(text)
    return lines


def _descendant_pids(root_pid: int) -> List[int]:
    try:
        proc = subprocess.run(
            ["/bin/ps", "-ax", "-o", "pid=,ppid="],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:
        return [root_pid]
    children: dict[int, List[int]] = {}
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
        except ValueError:
            continue
        children.setdefault(ppid, []).append(pid)
    out: List[int] = []
    stack = [root_pid]
    seen = set()
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        out.append(cur)
        stack.extend(children.get(cur, []))
    return out


def _answer_terminal_queries(master_fd: int, chunk: str) -> None:
    """Reply to OSC/DSR queries so libraries waiting on terminal info do not hang."""
    # OSC 11 (background color) / OSC 10 (foreground): ]11;? or ]10;?
    if "\x1b]11;?" in chunk or "\x1b]10;?" in chunk:
        try:
            # Valid OSC color reply; content is arbitrary for our purposes.
            os.write(master_fd, b"\x1b]11;rgb:0000/0000/0000\x1b\\")
            os.write(master_fd, b"\x1b]10;rgb:ffff/ffff/ffff\x1b\\")
        except OSError:
            pass
    # Cursor position report request CSI 6 n
    if "\x1b[6n" in chunk:
        try:
            os.write(master_fd, b"\x1b[1;1R")
        except OSError:
            pass


def run_with_approval_pty(
    cmd: List[str],
    *,
    cwd: str,
    env: dict,
    approval_replies: Sequence[str],
    decoy: str = "",
    timeout: float = 180.0,
    argv_sample_interval: float = 0.05,
    write_pty_choices: bool = True,
    short_lived_argv_probe: Optional[str] = None,
) -> PtyRunResult:
    """Run ``cmd`` under a PTY; optionally answer approval prompts; sample argv.

    When ``write_pty_choices`` is False (callback-driven harness), PTY is only
    used to host the process for argv sampling — choices are not written.
    ``argv_sample_interval`` defaults to 50ms so short-lived decoy argv probes
    are deterministically captured.
    """
    master_fd, slave_fd = os.openpty()
    popen_env = dict(env)
    popen_env["HERMES_INTERACTIVE"] = "1"
    popen_env.pop("HERMES_YOLO_MODE", None)
    popen_env["TERM"] = "xterm-256color"
    # Keep English approval markers stable for the harness matcher.
    popen_env.setdefault("LANG", "en_US.UTF-8")
    popen_env.setdefault("LC_ALL", "en_US.UTF-8")
    if popen_env.get("CREDENTIAL_GUARD_TEST_DISABLE_PTY_CHOICE", "").strip() == "1":
        write_pty_choices = False

    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=popen_env,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        start_new_session=True,
    )
    os.close(slave_fd)

    output_chunks: List[str] = []
    approval_prompt_count = 0
    approvals_submitted = 0
    reply_index = 0
    argv_samples: List[str] = []
    argv_hits = 0
    sample_ok = False
    stop_sample = threading.Event()
    # Track already-answered offsets so split reads still work.
    answered_up_to = 0
    probe_seen = False

    def _sampler() -> None:
        nonlocal sample_ok, argv_hits, probe_seen
        while not stop_sample.is_set():
            try:
                pids = _descendant_pids(proc.pid)
                lines = _ps_command_lines(pids)
                if lines:
                    sample_ok = True
                    argv_samples.extend(lines)
                    if decoy:
                        for line in lines:
                            argv_hits += _count_needle(line, decoy)
                    if short_lived_argv_probe:
                        for line in lines:
                            if short_lived_argv_probe in line:
                                probe_seen = True
            except Exception:
                pass
            stop_sample.wait(argv_sample_interval)

    sampler = threading.Thread(target=_sampler, daemon=True)
    sampler.start()

    # Optional short-lived child carrying a recognizable argv token.
    probe_proc = None
    if short_lived_argv_probe:
        try:
            probe_proc = subprocess.Popen(
                ["/bin/sh", "-c", f"echo {short_lived_argv_probe}; sleep 0.3"],
                start_new_session=False,
            )
            # Re-parent under the hermes process group is not portable; instead
            # sample the probe pid explicitly in the sampler via /bin/ps tree
            # from proc.pid — so spawn as child of this process and also scan
            # our own descendants of the sampler root. Attach by making the
            # probe a child of proc via a helper is hard; instead include
            # probe_proc.pid in sampling.
        except Exception:
            probe_proc = None

    def _sampler_with_probe() -> None:
        nonlocal sample_ok, argv_hits, probe_seen
        while not stop_sample.is_set():
            try:
                pids = _descendant_pids(proc.pid)
                if probe_proc is not None and probe_proc.pid:
                    pids = list(pids) + [probe_proc.pid]
                    pids.extend(_descendant_pids(probe_proc.pid))
                lines = _ps_command_lines(pids)
                if lines:
                    sample_ok = True
                    argv_samples.extend(lines)
                    if decoy:
                        for line in lines:
                            argv_hits += _count_needle(line, decoy)
                    if short_lived_argv_probe:
                        for line in lines:
                            if short_lived_argv_probe in line:
                                probe_seen = True
            except Exception:
                pass
            stop_sample.wait(argv_sample_interval)

    # Replace sampler if probe requested.
    if short_lived_argv_probe:
        stop_sample.set()
        sampler.join(timeout=1)
        stop_sample.clear()
        sampler = threading.Thread(target=_sampler_with_probe, daemon=True)
        sampler.start()

    deadline = time.time() + timeout
    try:
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    proc.kill()
                break
            ready, _, _ = select.select([master_fd], [], [], min(0.2, remaining))
            if ready:
                try:
                    data = os.read(master_fd, 8192)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                if not data:
                    if proc.poll() is not None:
                        break
                else:
                    text = data.decode("utf-8", "replace")
                    output_chunks.append(text)
                    _answer_terminal_queries(master_fd, text)
                    if write_pty_choices:
                        joined = "".join(output_chunks)
                        # Search only the not-yet-answered suffix for new prompts.
                        search_region = joined[answered_up_to:]
                        earliest = None
                        earliest_marker = ""
                        for marker in _CHOICE_MARKERS:
                            pos = search_region.find(marker)
                            if pos >= 0 and (earliest is None or pos < earliest):
                                earliest = pos
                                earliest_marker = marker
                        if earliest is not None:
                            approval_prompt_count += 1
                            answered_up_to += earliest + len(earliest_marker)
                            if reply_index < len(approval_replies):
                                reply = approval_replies[reply_index]
                                reply_index += 1
                                try:
                                    os.write(
                                        master_fd,
                                        (reply.strip() + "\n").encode("utf-8"),
                                    )
                                    approvals_submitted += 1
                                except OSError:
                                    pass
            if proc.poll() is not None:
                # Drain residual output briefly.
                drain_deadline = time.time() + 0.5
                while time.time() < drain_deadline:
                    ready2, _, _ = select.select([master_fd], [], [], 0.05)
                    if not ready2:
                        break
                    try:
                        data = os.read(master_fd, 8192)
                    except OSError:
                        break
                    if not data:
                        break
                    output_chunks.append(data.decode("utf-8", "replace"))
                break
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                proc.kill()
            proc.wait(timeout=5)
    finally:
        stop_sample.set()
        sampler.join(timeout=2)
        if probe_proc is not None:
            try:
                probe_proc.wait(timeout=1)
            except Exception:
                try:
                    probe_proc.kill()
                except Exception:
                    pass
        try:
            os.close(master_fd)
        except OSError:
            pass

    joined = "".join(output_chunks)
    if write_pty_choices:
        # Prefer Choice-line count; fall back to evidence markers if Choice text
        # was localized differently but approval panels clearly appeared.
        choice_count = sum(joined.count(m) for m in _CHOICE_MARKERS)
        if choice_count > approval_prompt_count:
            approval_prompt_count = choice_count
        if approval_prompt_count == 0:
            evidence = sum(1 for m in _APPROVAL_EVIDENCE if m in joined)
            if evidence:
                approval_prompt_count = max(
                    1, joined.count("credential-guard requires approval")
                )

    if short_lived_argv_probe and not probe_seen:
        sample_ok = False

    return PtyRunResult(
        returncode=int(proc.returncode if proc.returncode is not None else -1),
        output=joined,
        approval_prompt_count=approval_prompt_count,
        approvals_submitted=approvals_submitted,
        argv_samples=argv_samples,
        argv_sample_ok=sample_ok,
        argv_plain_password_count=argv_hits,
        pid=proc.pid,
    )
