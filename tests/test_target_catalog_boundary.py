"""M3.1 B: targets.json catalog boundary + env-path / result secondary guards."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from credential_guard.approval import on_pre_tool_call
from credential_guard.hooks import on_transform_tool_result
from credential_guard.middleware import on_llm_execution
from credential_guard.sensitive_paths import (
    args_target_protected,
    extract_path_candidates,
    path_is_protected,
    search_path_is_protected,
    terminal_command_reads_protected,
)

_SAFE_ERROR = "tool result blocked by credential-guard"


def _make_store(tmp_path: Path, monkeypatch, *, alias: str = "cg-b-ssh-alias"):
    hermes = tmp_path / "hermes"
    home = tmp_path / "home"
    store = hermes / "credential-guard"
    store.mkdir(parents=True)
    home.mkdir(parents=True)
    os.chmod(store, 0o700)
    targets = {
        "version": 1,
        "targets": {
            "ops-box": {
                "type": "ssh_config",
                "ssh_alias": alias,
            },
            "analytics-ro": {
                "type": "mysql",
                "host": "127.0.0.1",
                "port": 3306,
                "database": "cg_b_canary_db",
                "credential_ref": "cg-b-cred-ref",
            },
        },
    }
    cred = store / "credentials.json"
    tgt = store / "targets.json"
    cfg = store / "credential-guard.json"
    cred.write_text(json.dumps({"version": 1, "credentials": {}}), encoding="utf-8")
    tgt.write_text(json.dumps(targets), encoding="utf-8")
    cfg.write_text(
        json.dumps({"version": 2, "credentials": {}, "bindings": {}}),
        encoding="utf-8",
    )
    os.chmod(cred, 0o600)
    os.chmod(tgt, 0o600)
    os.chmod(cfg, 0o600)
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    monkeypatch.setenv("HOME", str(home))
    return {
        "hermes": hermes,
        "home": home,
        "store": store,
        "targets": tgt,
        "credentials": cred,
        "config": cfg,
        "alias": alias,
        "host": "127.0.0.1",
        "database": "cg_b_canary_db",
        "credential_ref": "cg-b-cred-ref",
    }


def _assert_safe_block(result):
    assert result is not None
    assert result["action"] == "block"
    blob = json.dumps(result)
    assert "targets.json" not in blob
    assert "credentials.json" not in blob
    assert "ssh_alias" not in blob
    assert "credential_ref" not in blob
    assert "database" not in blob
    assert "/" not in result.get("message", "")


# ---- T1: targets.json blocked before tool execution ----


def test_t1_read_file_targets_json_blocked(tmp_path: Path, monkeypatch):
    ctx = _make_store(tmp_path, monkeypatch)
    result = on_pre_tool_call(
        tool_name="read_file",
        args={"path": str(ctx["targets"])},
    )
    _assert_safe_block(result)
    assert path_is_protected(str(ctx["targets"]))


def test_t1_read_file_targets_traversal_and_symlink_blocked(
    tmp_path: Path, monkeypatch
):
    ctx = _make_store(tmp_path, monkeypatch)
    traversal = str(ctx["store"] / ".." / "credential-guard" / "targets.json")
    assert path_is_protected(traversal)
    result = on_pre_tool_call(tool_name="read_file", args={"path": traversal})
    _assert_safe_block(result)

    link = tmp_path / "Innocent-targets.txt"
    link.symlink_to(ctx["targets"])
    assert path_is_protected(str(link))
    result2 = on_pre_tool_call(tool_name="read_file", args={"path": str(link)})
    _assert_safe_block(result2)


def test_t1_search_files_store_and_hermes_home_blocked(tmp_path: Path, monkeypatch):
    ctx = _make_store(tmp_path, monkeypatch)
    for root in (ctx["store"], ctx["hermes"], tmp_path):
        assert search_path_is_protected(str(root))
        result = on_pre_tool_call(
            tool_name="search_files",
            args={"path": str(root), "pattern": "*"},
        )
        _assert_safe_block(result)


def test_t1_search_files_default_cwd_covering_store_blocked(
    tmp_path: Path, monkeypatch
):
    ctx = _make_store(tmp_path, monkeypatch)
    # Hermes defaults omitted path to "."
    assert extract_path_candidates("search_files", {"pattern": "*"}) == ["."]
    monkeypatch.chdir(ctx["hermes"])
    assert args_target_protected("search_files", {"pattern": "*"})
    result = on_pre_tool_call(
        tool_name="search_files",
        args={"pattern": "*"},
    )
    _assert_safe_block(result)


# ---- T2: provider-bound secondary result guard ----


def test_t2_transform_and_provider_block_target_metadata(
    tmp_path: Path, monkeypatch
):
    ctx = _make_store(tmp_path, monkeypatch)
    canary_body = json.dumps(
        {
            "ssh_alias": ctx["alias"],
            "host": ctx["host"],
            "database": ctx["database"],
            "credential_ref": ctx["credential_ref"],
        }
    )
    out = on_transform_tool_result(
        tool_name="read_file",
        args={"path": str(ctx["targets"])},
        result=canary_body,
    )
    assert json.loads(out)["error"] == _SAFE_ERROR
    for needle in (
        ctx["alias"],
        ctx["host"],
        ctx["database"],
        ctx["credential_ref"],
    ):
        assert needle not in out

    calls = {"n": 0}
    captured = {"req": None}

    def next_call(req):
        calls["n"] += 1
        captured["req"] = req
        return {"ok": True}

    # Simulate tool result already redacted into safe JSON, then a follow-up
    # that still embeds canaries in the request — provider path must see 0.
    safe = on_transform_tool_result(
        tool_name="read_file",
        args={"path": str(ctx["targets"])},
        result=canary_body,
    )
    resp = on_llm_execution(
        request={"messages": [{"role": "tool", "content": safe}]},
        next_call=next_call,
    )
    assert calls["n"] == 1
    blob = json.dumps(captured["req"])
    assert ctx["alias"] not in blob
    assert ctx["database"] not in blob
    assert ctx["credential_ref"] not in blob
    # host 127.0.0.1 may appear in unrelated config; count canary-specific fields
    assert ctx["alias"] not in blob
    assert resp == {"ok": True}


# ---- T3: controlled HOME / HERMES_HOME expansion ----


@pytest.mark.parametrize(
    "command_fmt",
    [
        "cat $HOME/.ssh/config",
        "cat ${HOME}/.ssh/config",
        'cat "$HOME/.ssh/config"',
        "cat $HERMES_HOME/credential-guard/targets.json",
        "head ${HERMES_HOME}/credential-guard/credentials.json",
        "cat '${HERMES_HOME}/credential-guard/targets.json'",
    ],
)
def test_t3_env_var_direct_reads_blocked(
    tmp_path: Path, monkeypatch, command_fmt: str
):
    ctx = _make_store(tmp_path, monkeypatch)
    ssh = ctx["home"] / ".ssh"
    ssh.mkdir(parents=True)
    (ssh / "config").write_text("Host cg-b-ssh-alias\n", encoding="utf-8")

    assert terminal_command_reads_protected(command_fmt) is True
    result = on_pre_tool_call(
        tool_name="terminal",
        args={"command": command_fmt},
    )
    _assert_safe_block(result)
    blob = json.dumps(result)
    assert "$HOME" not in blob
    assert "HERMES_HOME" not in blob
    assert ctx["alias"] not in blob


def test_t3_undefined_and_other_vars_not_false_positive(tmp_path: Path, monkeypatch):
    _make_store(tmp_path, monkeypatch)
    monkeypatch.delenv("OTHER", raising=False)
    assert terminal_command_reads_protected("cat $OTHER/.ssh/config") is False
    assert terminal_command_reads_protected("cat $UNDEFINED/credential-guard/targets.json") is False
    assert (
        terminal_command_reads_protected("python -c 'open(dynamic).read()'") is False
    )


# ---- T4: terminal/execute_code result secondary protection ----


@pytest.mark.parametrize(
    "tool_name,arg_key",
    [
        ("terminal", "command"),
        ("execute_code", "code"),
        ("run_terminal_command", "command"),
    ],
)
def test_t4_terminal_result_secondary_blocks_by_command_args(
    tmp_path: Path, monkeypatch, tool_name: str, arg_key: str
):
    ctx = _make_store(tmp_path, monkeypatch)
    ssh = ctx["home"] / ".ssh"
    ssh.mkdir(parents=True)
    (ssh / "config").write_text("Host cg-b-ssh-alias\n", encoding="utf-8")
    command = "cat $HOME/.ssh/config"
    canary = f"Host {ctx['alias']}\nIdentityFile /tmp/id_ed25519\n"
    out = on_transform_tool_result(
        tool_name=tool_name,
        args={arg_key: command},
        result=canary,
    )
    assert json.loads(out)["error"] == _SAFE_ERROR
    assert ctx["alias"] not in out
    assert "IdentityFile" not in out
    assert canary not in out


def test_t4_terminal_result_blocks_even_without_pem_marker(
    tmp_path: Path, monkeypatch
):
    ctx = _make_store(tmp_path, monkeypatch)
    out = on_transform_tool_result(
        tool_name="terminal",
        args={"command": "cat $HERMES_HOME/credential-guard/targets.json"},
        result=json.dumps({"ssh_alias": ctx["alias"], "host": "10.9.9.9"}),
    )
    assert json.loads(out)["error"] == _SAFE_ERROR
    assert ctx["alias"] not in out
    assert "10.9.9.9" not in out


# ---- T5: positive / false-positive boundaries ----


def test_t5_ordinary_paths_and_searches_allowed(tmp_path: Path, monkeypatch):
    ctx = _make_store(tmp_path, monkeypatch)
    notes = tmp_path / "notes.json"
    notes.write_text('{"ok": true}', encoding="utf-8")
    src = tmp_path / "app.py"
    src.write_text("print('hi')\n", encoding="utf-8")
    alone = tmp_path / "isolated-project"
    alone.mkdir()
    (alone / "main.py").write_text("x=1\n", encoding="utf-8")

    assert on_pre_tool_call(tool_name="read_file", args={"path": str(notes)}) is None
    assert on_pre_tool_call(tool_name="read_file", args={"path": str(src)}) is None
    assert (
        on_pre_tool_call(
            tool_name="search_files",
            args={"path": str(alone), "pattern": "*.py"},
        )
        is None
    )
    assert (
        on_pre_tool_call(
            tool_name="terminal",
            args={"command": "cat /tmp/notes.txt"},
        )
        is None
    )
    # Default search from isolated cwd must stay usable.
    monkeypatch.chdir(alone)
    assert (
        on_pre_tool_call(tool_name="search_files", args={"pattern": "*.py"}) is None
    )


def test_t5_ssh_pubkey_and_known_hosts_example_allowed(
    tmp_path: Path, monkeypatch
):
    ctx = _make_store(tmp_path, monkeypatch)
    ssh = ctx["home"] / ".ssh"
    ssh.mkdir(parents=True)
    pub = ssh / "id_ed25519.pub"
    pub.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake cg-b-test\n", encoding="utf-8")
    example = ssh / "known_hosts.example"
    example.write_text("example-host ssh-ed25519 AAA\n", encoding="utf-8")
    real_kh = ssh / "known_hosts"
    real_kh.write_text("real-host ssh-ed25519 AAA\n", encoding="utf-8")
    backup = ssh / "known_hosts.old"
    backup.write_text("old\n", encoding="utf-8")

    assert not path_is_protected(str(pub))
    assert not path_is_protected(str(example))
    assert path_is_protected(str(real_kh))
    assert path_is_protected(str(backup))
    assert on_pre_tool_call(tool_name="read_file", args={"path": str(pub)}) is None
    assert on_pre_tool_call(tool_name="read_file", args={"path": str(example)}) is None
    assert on_pre_tool_call(tool_name="read_file", args={"path": str(real_kh)})[
        "action"
    ] == "block"
