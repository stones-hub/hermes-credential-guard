"""R3B Slice B3: process adapter — single-shot env/stdin inject, bounded I/O."""

from __future__ import annotations

import errno
import hashlib
import os
import re
import secrets
import signal
import stat
import subprocess
import textwrap
import time
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from credential_guard.injection import SecretLease
from credential_guard.process_identity import (
    capture_program_identity,
    cleanup_verified_executable,
    prepare_verified_executable,
)
from credential_guard.redactor import MAX_SECRET_LENGTH

# LibreSSL prints bare 64-hex; OpenSSL 3 prints "ALG(stdin)= HEX". Never awk '{print $2}'.
_OPENSSL_HEX_MARK = (
    "printf '%s' \"$VAL\" | openssl dgst -sha256 -hex | "
    "awk '{last=\"\"; for(i=1;i<=NF;i++) if($i~/^[0-9a-fA-F]{64}$/) last=$i; "
    "if(last!=\"\") print last}' > \"$MARK\""
)


def _decoy(n: int = 16) -> str:
    return "CG_SYNTHETIC_DECOY_" + secrets.token_hex(n)


def _normalize_openssl_sha256_hex(line: str) -> str:
    """Tests-only: last [0-9a-fA-F]{64} token from openssl/LibreSSL dgst -hex."""
    tokens = re.findall(r"[0-9a-fA-F]{64}", line)
    if not tokens:
        raise AssertionError("openssl dgst -hex produced no 64-hex digest token")
    return tokens[-1]


def _legacy_awk_field2(line: str) -> str:
    """Broken helper parse: awk '{print $2}' — empty on LibreSSL bare hex."""
    parts = line.strip().split()
    return parts[1] if len(parts) > 1 else ""


def _make_env_probe(tmp_path: Path) -> Path:
    """Helper: hash $CG_PROBE_ENV into marker file; never print secret."""
    path = tmp_path / "cg-env-probe"
    path.write_text(
        textwrap.dedent(
            f"""\
            #!/bin/sh
            MARK="$1"
            VAL="${{CG_PROBE_ENV-}}"
            if [ -z "$VAL" ]; then
              printf 'absent' > "$MARK"
            else
              {_OPENSSL_HEX_MARK}
            fi
            printf 'ok\\n'
            """
        ),
        encoding="utf-8",
    )
    os.chmod(path, 0o700)
    return path


def _make_stdin_probe(tmp_path: Path) -> Path:
    path = tmp_path / "cg-stdin-probe"
    path.write_text(
        textwrap.dedent(
            f"""\
            #!/bin/sh
            MARK="$1"
            VAL=$(cat)
            if [ -z "$VAL" ]; then
              printf 'absent' > "$MARK"
            else
              {_OPENSSL_HEX_MARK}
            fi
            # Prove argv/env did not receive the secret: echo env/argv markers only.
            printf 'argv0=%s\\n' "$0"
            printf 'env_probe=%s\\n' "${{CG_PROBE_ENV-ABSENT}}"
            """
        ),
        encoding="utf-8",
    )
    os.chmod(path, 0o700)
    return path


def _make_echo_decoy(tmp_path: Path) -> Path:
    path = tmp_path / "cg-echo-decoy"
    path.write_text(
        textwrap.dedent(
            """\
            #!/bin/sh
            printf 'STATUS=0\\nECHO=%s\\n' "$CG_PROBE_ENV"
            """
        ),
        encoding="utf-8",
    )
    os.chmod(path, 0o700)
    return path


def _lease(token: str) -> SecretLease:
    return SecretLease({"kind": "token", "value": token})


def _binding_env(program: str, marker: str, **over: Any) -> Dict[str, Any]:
    b: Dict[str, Any] = {
        "type": "process_env",
        "credential_ref": "cli_token",
        "program": program,
        "argv": [program, marker],
        "env_name": "CG_PROBE_ENV",
        "timeout_seconds": 10,
        "max_stdout_bytes": 4096,
        "max_stderr_bytes": 4096,
        "approval": "required",
    }
    b.update(over)
    return b


def test_b3_env_inject_once_parent_and_followup_child_zero(tmp_path: Path):
    from credential_guard.adapters import process as proc

    decoy = _decoy()
    helper = _make_env_probe(tmp_path)
    marker = str(tmp_path / "mark.env")
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    try:
        # argv must use verified copy path as argv[0] semantics for exec;
        # binding argv[1:] stay fixed; adapter remaps argv[0] to verified path.
        binding = _binding_env(program, marker)
        parent_before = os.environ.get("CG_PROBE_ENV")
        assert parent_before is None or parent_before != decoy

        starts_before = proc.process_start_count()
        result = proc.execute_process(
            binding=binding,
            lease=_lease(decoy),
            verified=verified,
        )
        assert result["ok"] is True
        assert result["exit_code"] == 0
        assert proc.process_start_count() == starts_before + 1
        assert os.environ.get("CG_PROBE_ENV") != decoy
        assert parent_before == os.environ.get("CG_PROBE_ENV")

        expected = hashlib.sha256(decoy.encode("utf-8")).hexdigest()
        assert Path(marker).read_text(encoding="utf-8").strip() == expected

        # Follow-up child without inject must not see decoy.
        follow = subprocess.run(
            ["/bin/sh", "-c", 'printf "%s" "${CG_PROBE_ENV-ABSENT}"'],
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        assert follow.stdout == "ABSENT"
        assert decoy not in follow.stdout
        assert decoy not in str(result)
    finally:
        cleanup_verified_executable(verified)


def test_b3_stdin_inject_once_argv_env_zero(tmp_path: Path):
    from credential_guard.adapters import process as proc

    decoy = _decoy()
    helper = _make_stdin_probe(tmp_path)
    marker = str(tmp_path / "mark.stdin")
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    try:
        binding = {
            "type": "stdin",
            "credential_ref": "cli_token",
            "program": program,
            "argv": [program, marker],
            "stdin_format": "raw",
            "timeout_seconds": 10,
            "max_stdout_bytes": 4096,
            "max_stderr_bytes": 4096,
            "approval": "required",
        }
        result = proc.execute_process(
            binding=binding, lease=_lease(decoy), verified=verified
        )
        assert result["ok"] is True
        expected = hashlib.sha256(decoy.encode("utf-8")).hexdigest()
        assert Path(marker).read_text(encoding="utf-8").strip() == expected
        assert decoy not in result.get("stdout", "")
        assert decoy not in result.get("stderr", "")
        assert "ABSENT" in result.get("stdout", "") or "env_probe=ABSENT" in result.get(
            "stdout", ""
        )
        # argv must not contain decoy
        assert decoy not in str(binding["argv"])
    finally:
        cleanup_verified_executable(verified)


def test_b3_stdout_echo_decoy_fail_closed(tmp_path: Path):
    from credential_guard.adapters import process as proc

    decoy = _decoy()
    helper = _make_echo_decoy(tmp_path)
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    try:
        binding = _binding_env(program, "unused")
        binding["argv"] = [program]
        result = proc.execute_process(
            binding=binding, lease=_lease(decoy), verified=verified
        )
        assert result["ok"] is True
        assert "STATUS=0" in result.get("stdout", "")
        assert decoy not in str(result)
        assert decoy not in result.get("stdout", "")
        from credential_guard.models import make_token_id

        assert f"<SECRET:{make_token_id('cli_token', 'value')}>" in result.get(
            "stdout", ""
        )
        assert "<CREDENTIAL:cli_token>" not in result.get("stdout", "")
        assert result.get("error") != "PROCESS_OUTPUT_LEAK"
        assert "PROCESS_OUTPUT_LEAK" not in str(result)
        assert "***" not in result.get("stdout", "")
        assert "***" not in str(result)
    finally:
        cleanup_verified_executable(verified)


def test_b3_stdout_echo_mutation_process_output_leak_is_red(tmp_path: Path):
    """Mutation: legacy PROCESS_OUTPUT_LEAK / ok=False must not satisfy R4 echo guard."""
    from credential_guard.adapters import process as proc

    decoy = _decoy()
    helper = _make_echo_decoy(tmp_path)
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work-mut"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    try:
        binding = _binding_env(program, "unused")
        binding["argv"] = [program]
        result = proc.execute_process(
            binding=binding, lease=_lease(decoy), verified=verified
        )
        assert not (
            result.get("ok") is False and result.get("error") == "PROCESS_OUTPUT_LEAK"
        )
        assert result["ok"] is True
        from credential_guard.models import make_token_id

        assert f"<SECRET:{make_token_id('cli_token', 'value')}>" in result["stdout"]
        assert "<CREDENTIAL:cli_token>" not in result["stdout"]
    finally:
        cleanup_verified_executable(verified)


def test_b3_timeout_kills_and_reaps(tmp_path: Path):
    from credential_guard.adapters import process as proc

    decoy = _decoy()
    helper = tmp_path / "cg-sleep-helper"
    helper.write_text("#!/bin/sh\nsleep 30\n", encoding="utf-8")
    os.chmod(helper, 0o700)
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    try:
        binding = _binding_env(program, "x", timeout_seconds=1, argv=[program])
        result = proc.execute_process(
            binding=binding, lease=_lease(decoy), verified=verified
        )
        assert result["ok"] is False
        assert result.get("timeout") is True
        assert result["error"] == "PROCESS_TIMEOUT"
        assert decoy not in str(result)
    finally:
        cleanup_verified_executable(verified)


def test_b3_output_flood_terminates(tmp_path: Path):
    from credential_guard.adapters import process as proc

    decoy = _decoy()
    helper = tmp_path / "cg-flood-helper"
    helper.write_text(
        "#!/bin/sh\nwhile true; do printf 'xxxxxxxx'; done\n",
        encoding="utf-8",
    )
    os.chmod(helper, 0o700)
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    try:
        binding = _binding_env(
            program, "x", max_stdout_bytes=512, timeout_seconds=5, argv=[program]
        )
        result = proc.execute_process(
            binding=binding, lease=_lease(decoy), verified=verified
        )
        assert result["ok"] is False
        assert result["error"] in {"PROCESS_OUTPUT_LIMIT", "PROCESS_TIMEOUT"}
        assert decoy not in str(result)
    finally:
        cleanup_verified_executable(verified)


def test_b3_result_omits_program_path_env_argv(tmp_path: Path):
    from credential_guard.adapters import process as proc

    decoy = _decoy()
    helper = _make_env_probe(tmp_path)
    marker = str(tmp_path / "mark2.env")
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    try:
        result = proc.execute_process(
            binding=_binding_env(program, marker),
            lease=_lease(decoy),
            verified=verified,
        )
        blob = str(result)
        assert program not in blob
        assert verified.executable_path not in blob
        assert "CG_PROBE_ENV" not in blob
        assert decoy not in blob
    finally:
        cleanup_verified_executable(verified)


def test_r3b_openssl_hex_marker_parse_mutation():
    """Old awk $2 RED on LibreSSL bare hex; last-64 normalize GREEN on both formats."""
    decoy = "CG_SYNTHETIC_DECOY_openssl_fmt_probe"
    expected = hashlib.sha256(decoy.encode("utf-8")).hexdigest()
    bare = expected + "\n"
    prefixed = f"SHA2-256(stdin)= {expected}\n"

    assert _legacy_awk_field2(bare) == ""
    assert _normalize_openssl_sha256_hex(bare) == expected
    assert _normalize_openssl_sha256_hex(prefixed) == expected
    assert _legacy_awk_field2(prefixed) == expected

    # Live LibreSSL (/usr/bin) and PATH openssl must both normalize to hashlib.
    for openssl_bin in ("/usr/bin/openssl", "openssl"):
        proc = subprocess.run(
            [openssl_bin, "dgst", "-sha256", "-hex"],
            input=decoy.encode("utf-8"),
            capture_output=True,
            timeout=5,
            check=False,
        )
        if proc.returncode != 0:
            if openssl_bin == "/usr/bin/openssl":
                continue
            pytest.fail(f"{openssl_bin} dgst failed: {proc.stderr!r}")
        line = proc.stdout.decode("utf-8", errors="replace")
        assert _normalize_openssl_sha256_hex(line) == expected
        if openssl_bin == "/usr/bin/openssl" and line.strip() == expected:
            assert _legacy_awk_field2(line) == ""


# ---------------------------------------------------------------------------
# Round3 Blocker A — process-group cleanup on timeout / output-limit
# ---------------------------------------------------------------------------


def _pgid_present(pgid: int) -> bool:
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


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _wait_until(pred, *, timeout: float = 2.0, interval: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(interval)
    return bool(pred())


def _make_descendant_sleeper(tmp_path: Path) -> Path:
    """Leader spawns long-lived descendant (PID via $!), then sleeps."""
    path = tmp_path / "cg-group-sleeper"
    path.write_text(
        textwrap.dedent(
            """\
            #!/bin/sh
            MARK=$1
            /bin/sleep 3600 &
            printf '%s\\n' "$!" > "$MARK"
            # Synthetic env presence marker only — never echo the token.
            if [ -n "${CG_PROBE_ENV-}" ]; then
              printf 'env_present\\n' > "${MARK}.env"
            fi
            sleep 3600
            """
        ),
        encoding="utf-8",
    )
    os.chmod(path, 0o700)
    return path


def _make_descendant_flooder(tmp_path: Path) -> Path:
    path = tmp_path / "cg-group-flooder"
    path.write_text(
        textwrap.dedent(
            """\
            #!/bin/sh
            MARK=$1
            /bin/sleep 3600 &
            printf '%s\\n' "$!" > "$MARK"
            while true; do printf 'xxxxxxxx'; done
            """
        ),
        encoding="utf-8",
    )
    os.chmod(path, 0o700)
    return path


def _run_and_capture_group(
    *,
    tmp_path: Path,
    helper: Path,
    decoy: str,
    binding_over: Dict[str, Any],
):
    from credential_guard.adapters import process as proc

    marker = tmp_path / "desc.pid"
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work"
    work.mkdir(mode=0o700, exist_ok=True)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    recorded: Dict[str, Any] = {}

    real_popen = subprocess.Popen

    def _spy_popen(*args, **kwargs):
        p = real_popen(*args, **kwargs)
        recorded["pid"] = p.pid
        try:
            recorded["pgid"] = os.getpgid(p.pid)
        except OSError:
            recorded["pgid"] = None
        return p

    try:
        binding = _binding_env(program, str(marker), **binding_over)
        binding["argv"] = [program, str(marker)]
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(subprocess, "Popen", _spy_popen)
            result = proc.execute_process(
                binding=binding, lease=_lease(decoy), verified=verified
            )
        desc_pid: Optional[int] = None
        if marker.is_file():
            raw = marker.read_text(encoding="utf-8").strip()
            if raw.isdigit():
                desc_pid = int(raw)
        return result, recorded, desc_pid, marker
    finally:
        cleanup_verified_executable(verified)
        pgid = recorded.get("pgid")
        if isinstance(pgid, int):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass


def test_b3_timeout_kills_entire_process_group(tmp_path: Path):
    decoy = _decoy()
    helper = _make_descendant_sleeper(tmp_path)
    t0 = time.monotonic()
    result, recorded, desc_pid, marker = _run_and_capture_group(
        tmp_path=tmp_path,
        helper=helper,
        decoy=decoy,
        binding_over={"timeout_seconds": 1},
    )
    elapsed = time.monotonic() - t0
    assert result["ok"] is False
    assert result["error"] == "PROCESS_TIMEOUT"
    assert elapsed < 8.0
    assert decoy not in str(result)
    leader = recorded.get("pid")
    pgid = recorded.get("pgid")
    assert isinstance(leader, int) and isinstance(pgid, int)
    assert pgid == leader
    assert not _pid_alive(leader)
    assert desc_pid is not None and desc_pid != leader
    assert _wait_until(lambda: not _pid_alive(desc_pid), timeout=2.0)
    assert _wait_until(lambda: not _pgid_present(pgid), timeout=2.0)
    blob = str(result) + marker.read_text(encoding="utf-8") if marker.is_file() else str(result)
    assert decoy not in blob
    assert str(leader) not in str(result)
    assert str(pgid) not in str(result)


def test_b3_output_limit_kills_entire_process_group(tmp_path: Path):
    decoy = _decoy()
    helper = _make_descendant_flooder(tmp_path)
    result, recorded, desc_pid, marker = _run_and_capture_group(
        tmp_path=tmp_path,
        helper=helper,
        decoy=decoy,
        binding_over={"timeout_seconds": 5, "max_stdout_bytes": 512},
    )
    assert result["ok"] is False
    assert result["error"] in {"PROCESS_OUTPUT_LIMIT", "PROCESS_TIMEOUT"}
    assert decoy not in str(result)
    leader = recorded.get("pid")
    pgid = recorded.get("pgid")
    assert isinstance(leader, int) and isinstance(pgid, int)
    assert not _pid_alive(leader)
    assert desc_pid is not None
    assert _wait_until(lambda: not _pid_alive(desc_pid), timeout=2.0)
    assert _wait_until(lambda: not _pgid_present(pgid), timeout=2.0)


def test_b3_mutation_leader_only_kill_leaves_descendant(tmp_path: Path):
    """Mutation: replace group cleanup with leader-only kill → descendant survives."""
    from credential_guard.adapters import process as proc

    decoy = _decoy()
    helper = _make_descendant_sleeper(tmp_path)
    marker = tmp_path / "mut.desc.pid"
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work-mut"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    recorded: Dict[str, Any] = {}
    real_popen = subprocess.Popen

    def _spy_popen(*args, **kwargs):
        p = real_popen(*args, **kwargs)
        recorded["pid"] = p.pid
        recorded["pgid"] = os.getpgid(p.pid)
        return p

    def _leader_only_kill(p, *, used_new_session=True, captured_pgid=None):
        try:
            if p.poll() is None:
                p.kill()
                try:
                    p.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass
        except Exception:
            pass

    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(subprocess, "Popen", _spy_popen)
            mp.setattr(proc, "_kill_and_reap", _leader_only_kill)
            result = proc.execute_process(
                binding=_binding_env(
                    program, str(marker), timeout_seconds=1, argv=[program, str(marker)]
                ),
                lease=_lease(decoy),
                verified=verified,
            )
        assert result["error"] == "PROCESS_TIMEOUT"
        assert _wait_until(
            lambda: marker.is_file() and marker.read_text(encoding="utf-8").strip().isdigit(),
            timeout=2.0,
        )
        desc_pid = int(marker.read_text(encoding="utf-8").strip())
        pgid = recorded["pgid"]
        # RED under mutation: descendant still alive / pgid still present.
        assert _pid_alive(desc_pid)
        assert _pgid_present(pgid)
    finally:
        cleanup_verified_executable(verified)
        pgid = recorded.get("pgid")
        if isinstance(pgid, int):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Round3 Blocker B — non-blocking stdin under shared deadline
# ---------------------------------------------------------------------------


def _make_stdin_ignore_helper(tmp_path: Path) -> Path:
    """Never reads stdin; sleeps so a blocking write would hang past timeout."""
    path = tmp_path / "cg-stdin-ignore"
    path.write_text("#!/bin/sh\nsleep 30\n", encoding="utf-8")
    os.chmod(path, 0o700)
    return path


def _make_stdin_ignore_flood_helper(tmp_path: Path) -> Path:
    path = tmp_path / "cg-stdin-ignore-flood"
    path.write_text(
        textwrap.dedent(
            """\
            #!/bin/sh
            # Do not read stdin; flood both streams.
            while true; do
              printf 'YYYYYYYY' >&1
              printf 'ZZZZZZZZ' >&2
            done
            """
        ),
        encoding="utf-8",
    )
    os.chmod(path, 0o700)
    return path


def _make_stdin_sha_helper(tmp_path: Path) -> Path:
    path = tmp_path / "cg-stdin-sha-once"
    path.write_text(
        textwrap.dedent(
            f"""\
            #!/bin/sh
            MARK="$1"
            VAL=$(cat)
            if [ -z "$VAL" ]; then
              printf 'absent' > "$MARK"
            else
              {_OPENSSL_HEX_MARK}
            fi
            printf 'ok\\n'
            """
        ),
        encoding="utf-8",
    )
    os.chmod(path, 0o700)
    return path


def test_b3_large_stdin_unread_times_out_bounded(tmp_path: Path):
    from credential_guard.adapters import process as proc

    # ~900KiB synthetic token — within raised schema cap, large enough to fill pipes.
    nbytes = min(900 * 1024, MAX_SECRET_LENGTH)
    decoy = "CG_SYNTHETIC_DECOY_" + ("a" * (nbytes - len("CG_SYNTHETIC_DECOY_")))
    assert len(decoy) <= MAX_SECRET_LENGTH
    helper = _make_stdin_ignore_helper(tmp_path)
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    try:
        binding = {
            "type": "stdin",
            "credential_ref": "cli_token",
            "program": program,
            "argv": [program],
            "stdin_format": "raw",
            "timeout_seconds": 1,
            "max_stdout_bytes": 4096,
            "max_stderr_bytes": 4096,
            "approval": "required",
        }
        t0 = time.monotonic()
        result = proc.execute_process(
            binding=binding, lease=_lease(decoy), verified=verified
        )
        elapsed = time.monotonic() - t0
        assert result["ok"] is False
        assert result["error"] == "PROCESS_TIMEOUT"
        assert elapsed < 5.0
        # Never log/print the full decoy — only length + hash fingerprint.
        assert decoy not in str(result)
        assert len(decoy) == nbytes
    finally:
        cleanup_verified_executable(verified)


def test_b3_stdin_unread_with_flood_group_gone(tmp_path: Path):
    from credential_guard.adapters import process as proc

    nbytes = min(256 * 1024, MAX_SECRET_LENGTH)
    decoy = "CG_SYNTHETIC_DECOY_" + ("b" * (nbytes - len("CG_SYNTHETIC_DECOY_")))
    helper = _make_stdin_ignore_flood_helper(tmp_path)
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    recorded: Dict[str, Any] = {}
    real_popen = subprocess.Popen

    def _spy(*a, **k):
        p = real_popen(*a, **k)
        recorded["pid"] = p.pid
        recorded["pgid"] = os.getpgid(p.pid)
        return p

    try:
        binding = {
            "type": "stdin",
            "credential_ref": "cli_token",
            "program": program,
            "argv": [program],
            "stdin_format": "raw",
            "timeout_seconds": 2,
            "max_stdout_bytes": 512,
            "max_stderr_bytes": 512,
            "approval": "required",
        }
        t0 = time.monotonic()
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(subprocess, "Popen", _spy)
            result = proc.execute_process(
                binding=binding, lease=_lease(decoy), verified=verified
            )
        elapsed = time.monotonic() - t0
        assert result["ok"] is False
        assert result["error"] in {"PROCESS_OUTPUT_LIMIT", "PROCESS_TIMEOUT"}
        assert elapsed < 8.0
        assert decoy not in str(result)
        pgid = recorded["pgid"]
        leader = recorded["pid"]
        assert _wait_until(lambda: not _pid_alive(leader), timeout=2.0)
        assert _wait_until(lambda: not _pgid_present(pgid), timeout=2.0)
    finally:
        cleanup_verified_executable(verified)
        pgid = recorded.get("pgid")
        if isinstance(pgid, int):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass


def test_b3_stdin_partial_write_receives_exact_once(tmp_path: Path):
    from credential_guard.adapters import process as proc

    # Mid-size token exercises partial writes without huge fixtures.
    decoy = "CG_SYNTHETIC_DECOY_" + secrets.token_hex(8) + ("c" * 64_000)
    helper = _make_stdin_sha_helper(tmp_path)
    marker = tmp_path / "mark.partial"
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    try:
        binding = {
            "type": "stdin",
            "credential_ref": "cli_token",
            "program": program,
            "argv": [program, str(marker)],
            "stdin_format": "raw",
            "timeout_seconds": 10,
            "max_stdout_bytes": 4096,
            "max_stderr_bytes": 4096,
            "approval": "required",
        }
        result = proc.execute_process(
            binding=binding, lease=_lease(decoy), verified=verified
        )
        assert result["ok"] is True
        expected = hashlib.sha256(decoy.encode("utf-8")).hexdigest()
        assert marker.read_text(encoding="utf-8").strip() == expected
        assert decoy not in str(result)
    finally:
        cleanup_verified_executable(verified)


def test_b3_mutation_sync_stdin_write_hangs_past_deadline(tmp_path: Path):
    """Mutation: restore blocking stdin.write → must miss the 1s timeout bound."""
    from credential_guard.adapters import process as proc

    nbytes = min(900 * 1024, MAX_SECRET_LENGTH)
    decoy = "CG_SYNTHETIC_DECOY_" + ("d" * (nbytes - len("CG_SYNTHETIC_DECOY_")))
    helper = _make_stdin_ignore_helper(tmp_path)
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work-mut-stdin"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))

    def _blocking_io(p, *, stdin_data, max_stdout, max_stderr, deadline):
        # Legacy: synchronous full write before any deadline-aware read loop.
        if stdin_data is not None and p.stdin is not None:
            p.stdin.write(stdin_data)
            p.stdin.close()
        # Never reach deadline handling if write blocks.
        out = p.stdout.read() if p.stdout else b""
        err = p.stderr.read() if p.stderr else b""
        return out, err, False, False, False

    try:
        binding = {
            "type": "stdin",
            "credential_ref": "cli_token",
            "program": program,
            "argv": [program],
            "stdin_format": "raw",
            "timeout_seconds": 1,
            "max_stdout_bytes": 4096,
            "max_stderr_bytes": 4096,
            "approval": "required",
        }
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(proc, "_bounded_io", _blocking_io)
            t0 = time.monotonic()
            # Hard wall so the mutation RED cannot hang the suite forever.
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(
                    proc.execute_process,
                    binding=binding,
                    lease=_lease(decoy),
                    verified=verified,
                )
                try:
                    result = fut.result(timeout=3.0)
                    elapsed = time.monotonic() - t0
                    # If it somehow returned, it must NOT be a clean bounded timeout.
                    healthy_bounded = (
                        result.get("error") == "PROCESS_TIMEOUT" and elapsed < 2.5
                    )
                    assert healthy_bounded is False
                except concurrent.futures.TimeoutError:
                    # Expected RED: sync write blocked past the adapter deadline.
                    elapsed = time.monotonic() - t0
                    assert elapsed >= 2.5
    finally:
        cleanup_verified_executable(verified)


def test_b3_schema_allows_large_but_bounded_token():
    assert MAX_SECRET_LENGTH >= 900 * 1024
    assert MAX_SECRET_LENGTH <= 2_097_152


# ---------------------------------------------------------------------------
# Round4 Blocker A — capture immutable PGID at Popen; cleanup never getpgid(leader)
# ---------------------------------------------------------------------------


def _make_leader_exit_first(tmp_path: Path) -> Path:
    """Leader forks long-lived descendant inheriting env, then exits immediately."""
    path = tmp_path / "cg-leader-exit-first"
    path.write_text(
        textwrap.dedent(
            """\
            #!/bin/sh
            MARK=$1
            /bin/sleep 3600 &
            printf '%s\\n' "$!" > "$MARK"
            if [ -n "${CG_PROBE_ENV-}" ]; then
              printf 'env_present\\n' > "${MARK}.env"
            fi
            exit 0
            """
        ),
        encoding="utf-8",
    )
    os.chmod(path, 0o700)
    return path


def _make_term_ignore_descendant(tmp_path: Path) -> Path:
    """Leader + descendant; descendant ignores SIGTERM (requires SIGKILL)."""
    path = tmp_path / "cg-term-ignore-desc"
    path.write_text(
        textwrap.dedent(
            """\
            #!/bin/sh
            MARK=$1
            # Descendant ignores TERM so group cleanup must escalate to KILL.
            ( trap '' TERM; /bin/sleep 3600 ) &
            printf '%s\\n' "$!" > "$MARK"
            if [ -n "${CG_PROBE_ENV-}" ]; then
              printf 'env_present\\n' > "${MARK}.env"
            fi
            /bin/sleep 3600
            """
        ),
        encoding="utf-8",
    )
    os.chmod(path, 0o700)
    return path


def test_r4_leader_exits_first_cleanup_kills_group_via_captured_pgid(tmp_path: Path):
    """Leader forks then exits; cleanup must still clear PGID/descendant via saved PGID."""
    from credential_guard.adapters import process as proc

    decoy = _decoy()
    helper = _make_leader_exit_first(tmp_path)
    marker = tmp_path / "r4.leader-exit.pid"
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work-r4-a1"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    recorded: Dict[str, Any] = {}
    real_popen = subprocess.Popen
    captured_handles: list = []

    def _spy_popen(*args, **kwargs):
        p = real_popen(*args, **kwargs)
        recorded["pid"] = p.pid
        recorded["pgid"] = os.getpgid(p.pid)
        return p

    real_handle_ctor = proc.ProcessExecutionHandle

    def _track_handle(*, proc: subprocess.Popen, pgid: int, used_new_session: bool):
        h = real_handle_ctor(proc=proc, pgid=pgid, used_new_session=used_new_session)
        captured_handles.append(h)
        return h

    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(subprocess, "Popen", _spy_popen)
            mp.setattr(proc, "ProcessExecutionHandle", _track_handle)
            result = proc.execute_process(
                binding=_binding_env(
                    program, str(marker), timeout_seconds=5, argv=[program, str(marker)]
                ),
                lease=_lease(decoy),
                verified=verified,
            )
        assert decoy not in str(result)
        assert captured_handles, "PGID handle must be captured at Popen"
        h = captured_handles[0]
        assert h.pgid == recorded["pid"] == recorded["pgid"]
        assert _wait_until(
            lambda: marker.is_file()
            and marker.read_text(encoding="utf-8").strip().isdigit(),
            timeout=2.0,
        )
        desc_pid = int(marker.read_text(encoding="utf-8").strip())
        assert desc_pid != recorded["pid"]
        # Leader already exited; group/descendant must still be cleared.
        assert not _pid_alive(recorded["pid"])
        assert _wait_until(lambda: not _pid_alive(desc_pid), timeout=2.0)
        assert _wait_until(lambda: not _pgid_present(h.pgid), timeout=2.0)
        assert str(recorded["pid"]) not in str(result)
        assert str(h.pgid) not in str(result)
        env_mark = Path(str(marker) + ".env")
        if env_mark.is_file():
            assert decoy not in env_mark.read_text(encoding="utf-8")
    finally:
        cleanup_verified_executable(verified)
        pgid = recorded.get("pgid")
        if isinstance(pgid, int):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass


def test_r4_term_ignore_descendant_escalates_to_kill(tmp_path: Path):
    from credential_guard.adapters import process as proc

    decoy = _decoy()
    helper = _make_term_ignore_descendant(tmp_path)
    result, recorded, desc_pid, marker = _run_and_capture_group(
        tmp_path=tmp_path,
        helper=helper,
        decoy=decoy,
        binding_over={"timeout_seconds": 1},
    )
    assert result["ok"] is False
    assert result["error"] == "PROCESS_TIMEOUT"
    assert decoy not in str(result)
    leader = recorded["pid"]
    pgid = recorded["pgid"]
    assert isinstance(desc_pid, int) and desc_pid != leader
    assert not _pid_alive(leader)
    assert _wait_until(lambda: not _pid_alive(desc_pid), timeout=3.0)
    assert _wait_until(lambda: not _pgid_present(pgid), timeout=2.0)
    assert str(leader) not in str(result)
    assert str(pgid) not in str(result)


def test_r4_mutation_cleanup_getpgid_leaves_orphan_when_leader_gone(tmp_path: Path):
    """Mutation: restore cleanup-time getpgid(leader) → orphan survives after leader exit."""
    from credential_guard.adapters import process as proc

    decoy = _decoy()
    helper = _make_leader_exit_first(tmp_path)
    marker = tmp_path / "r4.mut-getpgid.pid"
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work-r4-mut-a"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    recorded: Dict[str, Any] = {}
    real_popen = subprocess.Popen

    def _spy_popen(*args, **kwargs):
        p = real_popen(*args, **kwargs)
        recorded["pid"] = p.pid
        recorded["pgid"] = os.getpgid(p.pid)
        return p

    def _legacy_kill_via_getpgid(p, *, captured_pgid=None, used_new_session=True):
        # Old bug: rediscover PGID from (possibly dead) leader.
        pid = getattr(p, "pid", None)
        pgid = None
        if used_new_session and isinstance(pid, int) and pid > 0:
            try:
                pgid = os.getpgid(pid)
            except OSError:
                pgid = None
            if pgid is not None and pgid == pid:
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except OSError:
                    pass
        try:
            if p.poll() is None:
                p.kill()
                p.wait(timeout=1.0)
            else:
                p.wait(timeout=0.01)
        except Exception:
            pass

    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(subprocess, "Popen", _spy_popen)
            mp.setattr(proc, "_kill_and_reap", _legacy_kill_via_getpgid)
            result = proc.execute_process(
                binding=_binding_env(
                    program, str(marker), timeout_seconds=5, argv=[program, str(marker)]
                ),
                lease=_lease(decoy),
                verified=verified,
            )
        assert decoy not in str(result)
        assert _wait_until(
            lambda: marker.is_file()
            and marker.read_text(encoding="utf-8").strip().isdigit(),
            timeout=2.0,
        )
        desc_pid = int(marker.read_text(encoding="utf-8").strip())
        pgid = recorded["pgid"]
        # RED under mutation: leader gone so getpgid failed; descendant still alive.
        assert not _pid_alive(recorded["pid"])
        assert _pid_alive(desc_pid)
        assert _pgid_present(pgid)
    finally:
        cleanup_verified_executable(verified)
        pgid = recorded.get("pgid")
        if isinstance(pgid, int):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass


def test_r4_mutation_leader_only_kill_leaves_term_ignore_descendant(tmp_path: Path):
    """Mutation: kill leader only → TERM-ignore descendant survives (RED)."""
    from credential_guard.adapters import process as proc

    decoy = _decoy()
    helper = _make_term_ignore_descendant(tmp_path)
    marker = tmp_path / "r4.mut-leader.pid"
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work-r4-mut-leader"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    recorded: Dict[str, Any] = {}
    real_popen = subprocess.Popen

    def _spy_popen(*a, **k):
        p = real_popen(*a, **k)
        recorded["pid"] = p.pid
        recorded["pgid"] = os.getpgid(p.pid)
        return p

    def _leader_only(p, *, used_new_session=True, captured_pgid=None):
        try:
            if p.poll() is None:
                p.kill()
                try:
                    p.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass
        except Exception:
            pass

    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(subprocess, "Popen", _spy_popen)
            mp.setattr(proc, "_kill_and_reap", _leader_only)
            result = proc.execute_process(
                binding=_binding_env(
                    program, str(marker), timeout_seconds=1, argv=[program, str(marker)]
                ),
                lease=_lease(decoy),
                verified=verified,
            )
        assert result["error"] == "PROCESS_TIMEOUT"
        assert _wait_until(
            lambda: marker.is_file()
            and marker.read_text(encoding="utf-8").strip().isdigit(),
            timeout=2.0,
        )
        desc_pid = int(marker.read_text(encoding="utf-8").strip())
        assert _pid_alive(desc_pid)
        assert _pgid_present(recorded["pgid"])
    finally:
        cleanup_verified_executable(verified)
        pgid = recorded.get("pgid")
        if isinstance(pgid, int):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Round4 Blocker B — nonblocking setup failure must fail-closed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("which", ["stdin", "stdout", "stderr"])
def test_r4_nonblocking_setup_failure_fail_closed(tmp_path: Path, which: str, monkeypatch):
    from credential_guard.adapters import process as proc

    decoy = _decoy()
    if which == "stdin":
        helper = _make_stdin_ignore_helper(tmp_path)
        btype = "stdin"
    else:
        helper = _make_term_ignore_descendant(tmp_path)
        btype = "process_env"
    marker = tmp_path / f"r4.nb.{which}.pid"
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / f"work-nb-{which}"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    recorded: Dict[str, Any] = {}
    real_popen = subprocess.Popen
    write_count: Dict[str, int] = {"n": 0}
    real_write = os.write
    real_set_blocking = os.set_blocking
    fail_fd: Dict[str, Optional[int]] = {"fd": None}
    real_bounded = proc._bounded_io

    def _spy(*a, **k):
        p = real_popen(*a, **k)
        recorded["pid"] = p.pid
        recorded["pgid"] = os.getpgid(p.pid)
        return p

    def _bounded_with_fault(p, **kwargs):
        stream = getattr(p, which, None)
        if stream is not None and not getattr(stream, "closed", False):
            try:
                fail_fd["fd"] = stream.fileno()
            except Exception:
                fail_fd["fd"] = None
        return real_bounded(p, **kwargs)

    def _faulty_set_blocking(fd, blocking):
        if fail_fd["fd"] is not None and fd == fail_fd["fd"]:
            raise OSError(errno.EINVAL, "synthetic")
        return real_set_blocking(fd, blocking)

    def _count_write(fd, data):
        write_count["n"] += 1
        return real_write(fd, data)

    try:
        monkeypatch.setattr(subprocess, "Popen", _spy)
        monkeypatch.setattr(os, "set_blocking", _faulty_set_blocking)
        monkeypatch.setattr(os, "write", _count_write)
        monkeypatch.setattr(proc, "_bounded_io", _bounded_with_fault)
        t0 = time.monotonic()
        if btype == "stdin":
            payload = "CG_SYNTHETIC_DECOY_" + ("n" * 64_000)
            binding = {
                "type": "stdin",
                "credential_ref": "cli_token",
                "program": program,
                "argv": [program],
                "stdin_format": "raw",
                "timeout_seconds": 5,
                "max_stdout_bytes": 4096,
                "max_stderr_bytes": 4096,
                "approval": "required",
            }
            result = proc.execute_process(
                binding=binding, lease=_lease(payload), verified=verified
            )
            decoy = payload
        else:
            binding = _binding_env(
                program, str(marker), timeout_seconds=5, argv=[program, str(marker)]
            )
            result = proc.execute_process(
                binding=binding, lease=_lease(decoy), verified=verified
            )
        elapsed = time.monotonic() - t0
        assert result["ok"] is False
        assert result["error"] == "PROCESS_ADAPTER_FAILED"
        assert elapsed < 5.0
        assert write_count["n"] == 0
        assert decoy not in str(result)
        assert "synthetic" not in str(result)
        assert "EINVAL" not in str(result)
        leader = recorded.get("pid")
        pgid = recorded.get("pgid")
        assert isinstance(leader, int) and isinstance(pgid, int)
        assert str(leader) not in str(result)
        assert str(pgid) not in str(result)
        assert _wait_until(lambda: not _pid_alive(leader), timeout=2.0)
        assert _wait_until(lambda: not _pgid_present(pgid), timeout=2.0)
        if marker.is_file():
            raw = marker.read_text(encoding="utf-8").strip()
            if raw.isdigit():
                assert _wait_until(lambda: not _pid_alive(int(raw)), timeout=2.0)
    finally:
        cleanup_verified_executable(verified)
        pgid = recorded.get("pgid")
        if isinstance(pgid, int):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass


def test_r4_mutation_swallow_oserror_on_set_nonblocking_is_red(tmp_path: Path, monkeypatch):
    """Mutation: restore swallow-OSError set_nonblocking → must not pass fail-closed contract."""
    from credential_guard.adapters import process as proc

    decoy = "CG_SYNTHETIC_DECOY_" + ("m" * 64_000)
    helper = _make_stdin_ignore_helper(tmp_path)
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work-r4-mut-nb"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    recorded: Dict[str, Any] = {}
    real_popen = subprocess.Popen
    real_set_blocking = os.set_blocking
    write_count = {"n": 0}
    real_write = os.write
    fail_fd: Dict[str, Optional[int]] = {"fd": None}
    real_bounded = proc._bounded_io

    def _spy(*a, **k):
        p = real_popen(*a, **k)
        recorded["pid"] = p.pid
        recorded["pgid"] = os.getpgid(p.pid)
        return p

    def _bounded_capture(p, **kwargs):
        if p.stdin is not None and not getattr(p.stdin, "closed", False):
            try:
                fail_fd["fd"] = p.stdin.fileno()
            except Exception:
                fail_fd["fd"] = None
        return real_bounded(p, **kwargs)

    def _faulty_set_blocking(fd, blocking):
        if fail_fd["fd"] is not None and fd == fail_fd["fd"]:
            raise OSError(errno.EINVAL, "synthetic")
        return real_set_blocking(fd, blocking)

    def _swallow_set_nonblocking(fd: int) -> None:
        try:
            os.set_blocking(fd, False)
        except OSError:
            pass

    def _count_write(fd, data):
        write_count["n"] += 1
        return real_write(fd, data)

    try:
        monkeypatch.setattr(subprocess, "Popen", _spy)
        monkeypatch.setattr(os, "set_blocking", _faulty_set_blocking)
        monkeypatch.setattr(os, "write", _count_write)
        monkeypatch.setattr(proc, "_bounded_io", _bounded_capture)
        monkeypatch.setattr(proc, "_set_nonblocking", _swallow_set_nonblocking)
        binding = {
            "type": "stdin",
            "credential_ref": "cli_token",
            "program": program,
            "argv": [program],
            "stdin_format": "raw",
            "timeout_seconds": 2,
            "max_stdout_bytes": 4096,
            "max_stderr_bytes": 4096,
            "approval": "required",
        }
        result = proc.execute_process(
            binding=binding, lease=_lease(decoy), verified=verified
        )
        # Healthy fail-closed would be PROCESS_ADAPTER_FAILED with write_count==0.
        healthy = (
            result.get("error") == "PROCESS_ADAPTER_FAILED" and write_count["n"] == 0
        )
        assert healthy is False
    finally:
        cleanup_verified_executable(verified)
        pgid = recorded.get("pgid")
        if isinstance(pgid, int):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Round5 Blocker A — close Popen→first-getpgid leader-exit window
# ---------------------------------------------------------------------------


def _make_pre_getpgid_term_ignore_exit(tmp_path: Path) -> Path:
    """Leader forks TERM-ignore descendant, writes marker, exits immediately."""
    path = tmp_path / "cg-pre-getpgid-term-ignore"
    path.write_text(
        textwrap.dedent(
            """\
            #!/bin/sh
            MARK=$1
            ( trap '' TERM; /bin/sleep 3600 ) &
            printf '%s\\n' "$!" > "$MARK"
            if [ -n "${CG_PROBE_ENV-}" ]; then
              printf 'env_present\\n' > "${MARK}.env"
            fi
            exit 0
            """
        ),
        encoding="utf-8",
    )
    os.chmod(path, 0o700)
    return path


def _barrier_getpgid_esrch_after_leader_exit(
    *,
    recorded: Dict[str, Any],
    marker: Path,
):
    """Deterministic fault seam: after leader exits + descendant marked, first getpgid → ESRCH.

    A zombie still answers getpgid; the Round5 window is fully-reaped leader (ESRCH).
    This seam waits for proc.poll()!=None and marker, then raises ESRCH without syscall.
    """
    _real = os.getpgid

    def _gated(pid: int) -> int:
        if recorded.get("pid") == pid:
            proc_obj = recorded.get("proc")
            assert proc_obj is not None
            assert _wait_until(
                lambda: marker.is_file()
                and marker.read_text(encoding="utf-8").strip().isdigit()
                and proc_obj.poll() is not None,
                timeout=3.0,
            ), "barrier: leader must exit with descendant marked before first getpgid"
            desc = int(marker.read_text(encoding="utf-8").strip())
            assert _pid_alive(desc)
            recorded["barrier_fired"] = True
            recorded["desc_pid"] = desc
            raise OSError(errno.ESRCH, "No such process")
        return _real(pid)

    return _gated


def test_r5_pre_getpgid_leader_exit_clears_group_via_expected_pgid(tmp_path: Path):
    """GREEN: even if leader exits before first getpgid, expected_pgid=pid clears group."""
    from credential_guard.adapters import process as proc

    decoy = _decoy()
    helper = _make_pre_getpgid_term_ignore_exit(tmp_path)
    marker = tmp_path / "r5.pre-getpgid.pid"
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work-r5-a"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    recorded: Dict[str, Any] = {}
    real_popen = subprocess.Popen
    captured_handles: list = []
    real_handle_ctor = proc.ProcessExecutionHandle

    def _spy_popen(*args, **kwargs):
        assert kwargs.get("start_new_session") is True
        p = real_popen(*args, **kwargs)
        recorded["pid"] = p.pid
        recorded["proc"] = p
        recorded["expected_pgid"] = p.pid
        return p

    def _track_handle(*, proc: subprocess.Popen, pgid: int, used_new_session: bool):
        h = real_handle_ctor(proc=proc, pgid=pgid, used_new_session=used_new_session)
        captured_handles.append(h)
        return h

    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(subprocess, "Popen", _spy_popen)
            mp.setattr(
                os,
                "getpgid",
                _barrier_getpgid_esrch_after_leader_exit(
                    recorded=recorded, marker=marker
                ),
            )
            mp.setattr(proc, "ProcessExecutionHandle", _track_handle)
            result = proc.execute_process(
                binding=_binding_env(
                    program, str(marker), timeout_seconds=5, argv=[program, str(marker)]
                ),
                lease=_lease(decoy),
                verified=verified,
            )
        assert decoy not in str(result)
        assert recorded.get("barrier_fired") is True
        assert captured_handles, "handle must be established from launch contract"
        h = captured_handles[0]
        assert h.pgid == recorded["expected_pgid"] == recorded["pid"]
        assert h.used_new_session is True
        desc_pid = int(recorded["desc_pid"])
        assert recorded["proc"].poll() is not None
        assert _wait_until(lambda: not _pid_alive(desc_pid), timeout=3.0)
        assert _wait_until(lambda: not _pgid_present(h.pgid), timeout=2.0)
        assert str(recorded["pid"]) not in str(result)
        assert str(h.pgid) not in str(result)
        assert decoy not in str(result)
    finally:
        cleanup_verified_executable(verified)
        pgid = recorded.get("expected_pgid")
        if isinstance(pgid, int):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass


def test_r5_mutation_getpgid_success_only_saves_pgid_leaves_orphan(tmp_path: Path):
    """Mutation: only persist PGID when getpgid succeeds → orphan after ESRCH (RED)."""
    from credential_guard.adapters import process as proc

    decoy = _decoy()
    helper = _make_pre_getpgid_term_ignore_exit(tmp_path)
    marker = tmp_path / "r5.mut-getpgid-only.pid"
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work-r5-mut-a1"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    recorded: Dict[str, Any] = {}
    real_popen = subprocess.Popen
    real_ctor = proc.ProcessExecutionHandle
    adapter_err = proc.ProcessAdapterError

    def _spy_popen(*args, **kwargs):
        p = real_popen(*args, **kwargs)
        recorded["pid"] = p.pid
        recorded["proc"] = p
        recorded["expected_pgid"] = p.pid
        return p

    def _legacy_ctor(*, proc, pgid, used_new_session):  # noqa: A002 — match dataclass fields
        """Old bug: refuse to keep expected_pgid unless live getpgid succeeds."""
        pid = getattr(proc, "pid", None)
        if not isinstance(pid, int) or pid <= 0:
            raise adapter_err("PROCESS_ADAPTER_FAILED")
        try:
            live = os.getpgid(pid)
        except OSError as exc:
            raise adapter_err("PROCESS_ADAPTER_FAILED") from exc
        if live != pid:
            raise adapter_err("PROCESS_ADAPTER_FAILED")
        return real_ctor(proc=proc, pgid=live, used_new_session=used_new_session)

    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(subprocess, "Popen", _spy_popen)
            mp.setattr(
                os,
                "getpgid",
                _barrier_getpgid_esrch_after_leader_exit(
                    recorded=recorded, marker=marker
                ),
            )
            mp.setattr(proc, "ProcessExecutionHandle", _legacy_ctor)
            result = proc.execute_process(
                binding=_binding_env(
                    program, str(marker), timeout_seconds=5, argv=[program, str(marker)]
                ),
                lease=_lease(decoy),
                verified=verified,
            )
        assert result["ok"] is False
        assert recorded.get("barrier_fired") is True
        desc_pid = int(recorded["desc_pid"])
        assert recorded["proc"].poll() is not None
        assert _pid_alive(desc_pid)
        assert _pgid_present(recorded["expected_pgid"])
        assert decoy not in str(result)
    finally:
        cleanup_verified_executable(verified)
        pgid = recorded.get("expected_pgid")
        if isinstance(pgid, int):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass


def test_r5_mutation_capture_fail_only_kill_wait_leaves_orphan(tmp_path: Path):
    """Mutation: cleanup ignores expected_pgid and only proc.kill/wait → orphan (RED)."""
    from credential_guard.adapters import process as proc

    decoy = _decoy()
    helper = _make_pre_getpgid_term_ignore_exit(tmp_path)
    marker = tmp_path / "r5.mut-kill-wait.pid"
    program = str(helper)
    ident = capture_program_identity(program)
    work = tmp_path / "work-r5-mut-a2"
    work.mkdir(mode=0o700)
    verified = prepare_verified_executable(program, ident, work_dir=str(work))
    recorded: Dict[str, Any] = {}
    real_popen = subprocess.Popen

    def _spy_popen(*args, **kwargs):
        p = real_popen(*args, **kwargs)
        recorded["pid"] = p.pid
        recorded["proc"] = p
        recorded["expected_pgid"] = p.pid
        return p

    def _legacy_kill_wait_only(p, *, captured_pgid=None, used_new_session=True):
        # Old capture-fail / cleanup path: never killpg via expected_pgid.
        try:
            if p.poll() is None:
                p.kill()
                try:
                    p.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass
            else:
                try:
                    p.wait(timeout=0.01)
                except Exception:
                    pass
        except Exception:
            pass

    def _legacy_cleanup(handle):
        if handle is None:
            return
        _legacy_kill_wait_only(
            handle.proc,
            captured_pgid=handle.pgid,
            used_new_session=handle.used_new_session,
        )

    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(subprocess, "Popen", _spy_popen)
            mp.setattr(
                os,
                "getpgid",
                _barrier_getpgid_esrch_after_leader_exit(
                    recorded=recorded, marker=marker
                ),
            )
            mp.setattr(proc, "_kill_and_reap", _legacy_kill_wait_only)
            mp.setattr(proc, "_cleanup_handle", _legacy_cleanup)
            result = proc.execute_process(
                binding=_binding_env(
                    program, str(marker), timeout_seconds=5, argv=[program, str(marker)]
                ),
                lease=_lease(decoy),
                verified=verified,
            )
        assert decoy not in str(result)
        assert recorded.get("barrier_fired") is True
        desc_pid = int(recorded["desc_pid"])
        assert recorded["proc"].poll() is not None
        # RED under mutation: expected_pgid known but unused → descendant/PGID remain.
        assert _pid_alive(desc_pid)
        assert _pgid_present(recorded["expected_pgid"])
    finally:
        cleanup_verified_executable(verified)
        pgid = recorded.get("expected_pgid")
        if isinstance(pgid, int):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass
