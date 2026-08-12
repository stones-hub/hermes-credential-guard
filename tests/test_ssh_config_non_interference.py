"""Ordinary SSH / SSH Config non-interference + private-key path protection.

Uses temporary HOME only — never reads the developer's real ~/.ssh.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from credential_guard.approval import on_pre_tool_call
from credential_guard.config import CONFIG_FILENAME


@pytest.fixture
def ssh_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    home.mkdir()
    hermes.mkdir()
    store = hermes / "credential-guard"
    store.mkdir(mode=0o700)
    cfg = store / CONFIG_FILENAME
    cfg.write_text(
        json.dumps({"version": 2, "credentials": {}, "bindings": {}}),
        encoding="utf-8",
    )
    os.chmod(cfg, 0o600)
    ssh = home / ".ssh"
    ssh.mkdir(mode=0o700)
    alias = "cg-r5-ni-alias"
    config = ssh / "config"
    config.write_text(
        f"Host {alias}\n"
        f"  HostName 127.0.0.1\n"
        f"  User cgni\n"
        f"  IdentityFile {ssh / 'id_ed25519'}\n"
        f"  Port 22\n",
        encoding="utf-8",
    )
    os.chmod(config, 0o600)
    key = ssh / "id_ed25519"
    key.write_text("DECOY_PRIVATE_KEY_MATERIAL_NOT_REAL\n", encoding="utf-8")
    os.chmod(key, 0o600)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    return {
        "home": home,
        "hermes": hermes,
        "ssh": ssh,
        "config": config,
        "key": key,
        "alias": alias,
        "cfg": cfg,
    }


def _ssh_g(alias: str, *, home: Path, config: Path) -> subprocess.CompletedProcess:
    ssh_bin = shutil.which("ssh")
    assert ssh_bin, "ssh binary required for non-interference evidence"
    env = {
        "HOME": str(home),
        "PATH": os.environ.get("PATH") or "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
    }
    # -F pins the temp config; -G resolves only (no network).
    return subprocess.run(
        [ssh_bin, "-F", str(config), "-G", alias],
        capture_output=True,
        text=True,
        env=env,
        timeout=5,
        check=False,
    )


def test_ssh_g_resolves_alias_without_network(ssh_home):
    proc = _ssh_g(
        ssh_home["alias"], home=ssh_home["home"], config=ssh_home["config"]
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout.lower()
    assert "hostname 127.0.0.1" in out
    assert "user cgni" in out
    assert "identityfile" in out


def test_ssh_g_stable_with_plugin_pre_tool_call_idle(ssh_home):
    """Calling on_pre_tool_call for an ordinary terminal must not alter ssh -G."""
    before = _ssh_g(
        ssh_home["alias"], home=ssh_home["home"], config=ssh_home["config"]
    )
    assert before.returncode == 0
    # Ordinary non-sensitive terminal: plugin must not interfere.
    directive = on_pre_tool_call(
        tool_name="terminal",
        args={"command": f"ssh -G {ssh_home['alias']}"},
    )
    assert directive is None
    after = _ssh_g(
        ssh_home["alias"], home=ssh_home["home"], config=ssh_home["config"]
    )
    assert after.returncode == 0
    assert after.stdout == before.stdout


def test_private_key_and_ssh_config_reads_still_blocked(ssh_home):
    key = str(ssh_home["key"])
    cfg = str(ssh_home["config"])
    for path in (key, cfg):
        blocked = on_pre_tool_call(
            tool_name="read_file",
            args={"path": path},
        )
        assert blocked is not None
        assert blocked["action"] == "block"

    term = on_pre_tool_call(
        tool_name="terminal",
        args={"command": f"cat {key}"},
    )
    assert term is not None
    assert term["action"] == "block"


def test_credential_guard_config_still_protected(ssh_home):
    blocked = on_pre_tool_call(
        tool_name="read_file",
        args={"path": str(ssh_home["cfg"])},
    )
    assert blocked is not None
    assert blocked["action"] == "block"
