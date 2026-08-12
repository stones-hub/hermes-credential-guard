"""R3B Slice B2: fixed local program identity + TOCTOU-resistant verification."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from credential_guard import process_identity as pi


def _write_helper(path: Path, body: str = "#!/bin/sh\necho ok\n", mode: int = 0o700) -> Path:
    path.write_text(body, encoding="utf-8")
    os.chmod(path, mode)
    return path


def test_b2_capture_rejects_symlink(tmp_path: Path):
    target = _write_helper(tmp_path / "real-helper")
    link = tmp_path / "link-helper"
    link.symlink_to(target)
    with pytest.raises(pi.ProgramIdentityError) as ei:
        pi.capture_program_identity(str(link))
    assert ei.value.code == "PROGRAM_IDENTITY_REJECTED"


def test_b2_capture_rejects_group_writable(tmp_path: Path):
    helper = _write_helper(tmp_path / "helper", mode=0o770)
    with pytest.raises(pi.ProgramIdentityError) as ei:
        pi.capture_program_identity(str(helper))
    assert ei.value.code == "PROGRAM_IDENTITY_REJECTED"


def test_b2_capture_rejects_other_writable(tmp_path: Path):
    helper = _write_helper(tmp_path / "helper", mode=0o702)
    with pytest.raises(pi.ProgramIdentityError) as ei:
        pi.capture_program_identity(str(helper))
    assert ei.value.code == "PROGRAM_IDENTITY_REJECTED"


def test_b2_capture_rejects_non_executable(tmp_path: Path):
    helper = _write_helper(tmp_path / "helper", mode=0o600)
    with pytest.raises(pi.ProgramIdentityError) as ei:
        pi.capture_program_identity(str(helper))
    assert ei.value.code == "PROGRAM_IDENTITY_REJECTED"


def test_b2_capture_accepts_owner_only_executable(tmp_path: Path):
    helper = _write_helper(tmp_path / "helper", mode=0o700)
    ident = pi.capture_program_identity(str(helper))
    assert ident.uid == os.geteuid()
    assert ident.mode & 0o111  # executable bit
    assert not (ident.mode & stat.S_IWGRP)
    assert not (ident.mode & stat.S_IWOTH)
    assert len(ident.content_sha256) == 64
    assert ident.size > 0


def test_b2_recheck_detects_content_change(tmp_path: Path):
    helper = _write_helper(tmp_path / "helper", body="#!/bin/sh\necho one\n")
    ident = pi.capture_program_identity(str(helper))
    helper.write_text("#!/bin/sh\necho two\n", encoding="utf-8")
    os.chmod(helper, 0o700)
    with pytest.raises(pi.ProgramIdentityError) as ei:
        pi.verify_same_identity(str(helper), ident)
    assert ei.value.code == "PROGRAM_IDENTITY_CHANGED"


def test_b2_prepare_executes_from_verified_copy_not_live_pathname(tmp_path: Path):
    """Must not Popen the original pathname after verify (TOCTOU)."""
    helper = _write_helper(
        tmp_path / "helper",
        body="#!/bin/sh\nprintf 'from-helper\\n'\n",
        mode=0o700,
    )
    ident = pi.capture_program_identity(str(helper))
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    verified = pi.prepare_verified_executable(str(helper), ident, work_dir=str(work))
    assert verified.executable_path != str(helper)
    assert Path(verified.executable_path).is_file()
    # Replace original after prepare — verified copy must remain the captured content.
    helper.write_text("#!/bin/sh\nprintf 'TAMPERED\\n'\n", encoding="utf-8")
    os.chmod(helper, 0o700)
    import subprocess

    proc = subprocess.run(
        [verified.executable_path],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert proc.returncode == 0
    assert "from-helper" in proc.stdout
    assert "TAMPERED" not in proc.stdout


def test_b2_mutation_skip_symlink_check_turns_red(tmp_path: Path, monkeypatch):
    target = _write_helper(tmp_path / "real-helper")
    link = tmp_path / "link-helper"
    link.symlink_to(target)
    real = pi.capture_program_identity

    def weak_capture(path: str):
        # Mutation: follow symlink via stat/open instead of rejecting lstat S_ISLNK.
        st = os.stat(path)  # follows
        return real(str(Path(path).resolve()))

    monkeypatch.setattr(pi, "capture_program_identity", weak_capture)
    # Under weak capture, symlink is accepted — RED vs contract.
    ident = pi.capture_program_identity(str(link))
    assert ident is not None
    monkeypatch.undo()
    with pytest.raises(pi.ProgramIdentityError):
        pi.capture_program_identity(str(link))


def test_b2_mutation_skip_final_identity_check_turns_red(tmp_path: Path, monkeypatch):
    helper = _write_helper(tmp_path / "helper", body="#!/bin/sh\necho one\n")
    ident = pi.capture_program_identity(str(helper))
    helper.write_text("#!/bin/sh\necho two\n", encoding="utf-8")
    os.chmod(helper, 0o700)

    def weak_verify(path, expected):
        return expected  # Mutation: skip recheck

    monkeypatch.setattr(pi, "verify_same_identity", weak_verify)
    # Weak verify falsely accepts changed content.
    assert pi.verify_same_identity(str(helper), ident) is ident
    monkeypatch.undo()
    with pytest.raises(pi.ProgramIdentityError) as ei:
        pi.verify_same_identity(str(helper), ident)
    assert ei.value.code == "PROGRAM_IDENTITY_CHANGED"
