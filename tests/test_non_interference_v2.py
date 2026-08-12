"""R4 non-interference matrix — clean results must pass through unchanged."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from credential_guard.hooks import on_transform_tool_result
from credential_guard.result_guard import guard_tool_result
from credential_guard.state import get_registry

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _isolated_empty_store(tmp_path, monkeypatch):
    hermes = tmp_path / "hermes_home"
    store = hermes / "credential-guard"
    store.mkdir(parents=True)
    os.chmod(store, 0o700)
    cfg = store / "credential-guard.json"
    cfg.write_text(
        json.dumps({"version": 2, "credentials": {}, "bindings": {}}),
        encoding="utf-8",
    )
    os.chmod(cfg, 0o600)
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(exist_ok=True)
    get_registry().clear()


def _through(result: str, tool_name: str = "terminal", **args) -> str:
    return on_transform_tool_result(
        result=result, tool_name=tool_name, arguments=args or {"command": "true"}
    )


def test_ordinary_chat_and_tool_text_unchanged():
    raw = "普通聊天回复：一切正常，无需凭证。"
    assert _through(raw, tool_name="chat") == raw


def test_temp_file_read_write_search_outputs_unchanged(tmp_path):
    # Keep file tree outside HERMES_HOME (fixture places store under tmp_path/hermes_home).
    work = tmp_path / "workdir"
    work.mkdir()
    f = work / "note.txt"
    f.write_text("file body 中文\n", encoding="utf-8")
    read_out = f"path={f}\ncontent:\n{f.read_text(encoding='utf-8')}"
    search_out = f"matches:\n{f}:1:file body 中文"
    assert _through(read_out, tool_name="read_file", path=str(f)) == read_out
    assert _through(search_out, tool_name="search_files", path=str(work)) == search_out


def test_temp_git_status_diff_log_unchanged(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "r4@example.test"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "r4"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    subprocess.run(["git", "add", "a.txt"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    status = subprocess.check_output(["git", "status"], cwd=repo, text=True)
    diff = subprocess.check_output(["git", "diff", "HEAD"], cwd=repo, text=True)
    log = subprocess.check_output(
        ["git", "log", "--oneline", "-1"], cwd=repo, text=True
    )
    assert _through(status) == status
    assert _through(diff) == diff
    assert _through(log) == log
    # Git SHA must not be treated as a secret.
    sha = log.split()[0]
    assert len(sha) >= 7
    assert _through(f"commit {sha}") == f"commit {sha}"


def test_pytest_and_memory_compile_outputs_unchanged(tmp_path):
    mod = tmp_path / "sample_mod.py"
    mod.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    compile_out = f"compiled {mod.name} ok"
    assert _through(compile_out) == compile_out
    # In-memory compile side effect stays local; output text unchanged.
    compile(mod.read_text(encoding="utf-8"), str(mod), "exec")
    digest = hashlib.sha256(mod.read_bytes()).hexdigest()
    assert _through(f"sha256={digest}") == f"sha256={digest}"


def test_terminal_execute_code_synthetic_unchanged():
    term = "exit_code=0\nstdout:\nok\n"
    code = ">>> print(1+1)\n2\n"
    assert _through(term, tool_name="terminal", command="echo ok") == term
    assert _through(code, tool_name="execute_code", code="print(1+1)") == code


def test_temp_ssh_config_and_loopback_fake_ssh_unchanged(tmp_path):
    ssh_dir = tmp_path / "home" / ".ssh"
    ssh_dir.mkdir(parents=True)
    cfg = ssh_dir / "config"
    body = "Host loopback\n  HostName 127.0.0.1\n  User decoy\n  Port 22\n"
    cfg.write_text(body, encoding="utf-8")
    # Reading SSH config via tool args targeting protected paths is blocked by
    # the pre-check (not R4 format guard). Non-protected synthetic output:
    fake_ssh = "ssh: connected to 127.0.0.1:22 banner=OpenSSH_fake"
    assert _through(fake_ssh, tool_name="terminal", command="echo fake") == fake_ssh
    assert cfg.read_text(encoding="utf-8") == body


def test_docker_systemd_synthetic_params_only():
    docker = "docker ps --format '{{.ID}}' → abcdef012345"
    systemd = "systemctl is-active → inactive (dead) unit=cg-fake.service"
    assert _through(docker) == docker
    assert _through(systemd) == systemd


def test_json_markdown_table_ids_base64_uuid_unchanged():
    raw = (
        '{\n  "request_id": "req-abc-123",\n'
        '  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",\n'
        '  "uuid": "550e8400-e29b-41d4-a716-446655440000"\n}'
    )
    md = "| a | b |\n|---|---|\n| 中文 | 1 |\n"
    b64 = base64.b64encode(b"not-a-secret-payload").decode("ascii")
    assert _through(raw) == raw
    assert _through(md) == md
    assert _through(f"data={b64}") == f"data={b64}"


def test_plugin_vs_direct_guard_identical_on_clean():
    raw = "clean line\n"
    via_hook = _through(raw)
    via_guard = guard_tool_result(raw, get_registry())
    assert via_hook == via_guard == raw


def test_no_approval_side_effect_on_clean_guard():
    # Guarding a clean result must not touch plan/approval stores.
    from credential_guard.tool_request import get_plan_store

    store = get_plan_store()
    before = len(getattr(store, "_plans", {}) or getattr(store, "_by_key", {}) or {})
    assert _through("ok") == "ok"
    after = len(getattr(store, "_plans", {}) or getattr(store, "_by_key", {}) or {})
    assert after == before
