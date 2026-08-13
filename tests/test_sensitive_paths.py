"""T2: sensitive path blocking + private-key content protection."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from credential_guard.approval import on_pre_tool_call
from credential_guard.hooks import on_transform_tool_result
from credential_guard.middleware import SAFE_BLOCK_MESSAGE, is_blocked_response_content, on_llm_execution, on_llm_request
from credential_guard.result_guard import REDACTED_SECRET, RESULT_GUARD_FAIL_TEXT
from credential_guard.sensitive_paths import (
    contains_private_key_material,
    extract_path_candidates,
    looks_like_private_key,
    path_is_protected,
    search_path_is_protected,
)


OPENSSH_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
-----END OPENSSH PRIVATE KEY-----
"""

RSA_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6PZGBw==
-----END RSA PRIVATE KEY-----
"""

EC_KEY = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFakeDecoyKeyMaterialForTestsOnly
-----END EC PRIVATE KEY-----
"""

PKCS8_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7
-----END PRIVATE KEY-----
"""


def test_looks_like_private_key_detects_common_pem_markers():
    assert looks_like_private_key(OPENSSH_KEY)
    assert looks_like_private_key(RSA_KEY)
    assert looks_like_private_key(EC_KEY)
    assert looks_like_private_key(PKCS8_KEY)
    # Common text variant: lowercase / extra spaces around markers.
    assert looks_like_private_key(
        "  -----begin openssh private key-----\nabc\n-----end openssh private key-----"
    )
    assert not looks_like_private_key("hello world, no key here")
    assert not looks_like_private_key("-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----")


def test_extract_path_candidates_from_read_and_search_args():
    assert extract_path_candidates("read_file", {"path": "/tmp/a.txt"}) == ["/tmp/a.txt"]
    assert extract_path_candidates("read_file", {"file_path": "/tmp/b.txt"}) == ["/tmp/b.txt"]
    assert extract_path_candidates(
        "search_files", {"path": "/tmp", "pattern": "*.py"}
    ) == ["/tmp"]
    assert extract_path_candidates("search_files", {"directory": "~/.ssh"}) == ["~/.ssh"]
    # Hermes search_files defaults omitted path to "."
    assert extract_path_candidates("search_files", {"pattern": "*"}) == ["."]
    assert extract_path_candidates("terminal", {"command": "ls"}) == []


def test_blocks_ssh_config_and_key_paths(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    ssh = home / ".ssh"
    ssh.mkdir(parents=True)
    (ssh / "config").write_text("Host decoy\n", encoding="utf-8")
    (ssh / "id_ed25519").write_text(OPENSSH_KEY, encoding="utf-8")
    (ssh / "known_hosts").write_text("host ssh-ed25519 AAA\n", encoding="utf-8")
    (ssh / "known_hosts.old").write_text("old\n", encoding="utf-8")
    key_dir = ssh / "ssh_key"
    key_dir.mkdir()
    (key_dir / "prod").write_text("k", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("HERMES_HOME", raising=False)

    assert path_is_protected(str(ssh / "config"))
    assert path_is_protected(str(ssh / "id_ed25519"))
    assert path_is_protected(str(ssh / "known_hosts"))
    assert path_is_protected(str(ssh / "known_hosts.old"))
    assert path_is_protected(str(key_dir / "prod"))
    assert path_is_protected("~/.ssh/config")
    assert path_is_protected(str(ssh / ".." / ".ssh" / "config"))


def test_blocks_credential_guard_credentials_json(tmp_path: Path, monkeypatch):
    hermes = tmp_path / "hermes"
    store = hermes / "credential-guard"
    store.mkdir(parents=True)
    cred = store / "credentials.json"
    cred.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    monkeypatch.setenv("HOME", str(tmp_path / "other-home"))
    assert path_is_protected(str(cred))
    assert path_is_protected(str(store / ".." / "credential-guard" / "credentials.json"))


def test_symlink_and_traversal_to_protected(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    ssh = home / ".ssh"
    ssh.mkdir(parents=True)
    target = ssh / "config"
    target.write_text("Host x\n", encoding="utf-8")
    link = tmp_path / "Innocent.txt"
    link.symlink_to(target)
    monkeypatch.setenv("HOME", str(home))
    assert path_is_protected(str(link))
    # Relative traversal from cwd inside tmp_path.
    monkeypatch.chdir(tmp_path)
    assert path_is_protected(os.path.join("home", ".ssh", "config"))


def test_ordinary_temp_file_not_blocked(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    ordinary = tmp_path / "notes.txt"
    ordinary.write_text("hello", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    assert not path_is_protected(str(ordinary))
    assert not path_is_protected(str(tmp_path / "readme.md"))


def test_search_from_parent_of_ssh_fail_closed(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    ssh = home / ".ssh"
    ssh.mkdir(parents=True)
    (ssh / "config").write_text("Host x\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    # Searching HOME or parent that can reach .ssh must fail closed.
    assert search_path_is_protected(str(home))
    assert search_path_is_protected(str(tmp_path))
    assert search_path_is_protected(str(ssh))
    # Unrelated branch under tmp is fine if it cannot reach .ssh as search root.
    other = tmp_path / "other"
    other.mkdir()
    # Searching tmp_path itself can reach home/.ssh — protected.
    assert search_path_is_protected(str(tmp_path))
    # Searching an unrelated sibling that does not contain protected trees.
    alone = tmp_path.parent / f"alone-{tmp_path.name}"
    alone.mkdir(exist_ok=True)
    (alone / "a.txt").write_text("x", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))  # HOME still under tmp_path
    # alone is outside home; searching it should not hit protected tree.
    assert not search_path_is_protected(str(alone))


def test_pre_tool_call_blocks_read_file_before_execution(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    ssh = home / ".ssh"
    ssh.mkdir(parents=True)
    cfg = ssh / "config"
    cfg.write_text("Host decoy-alias\nHostName 10.0.0.1\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    result = on_pre_tool_call(
        tool_name="read_file",
        args={"path": str(cfg)},
    )
    assert result is not None
    assert result["action"] == "block"
    blob = json.dumps(result)
    assert str(cfg) not in blob
    assert "decoy-alias" not in blob
    assert "10.0.0.1" not in blob
    assert "password" not in blob.lower()


def test_pre_tool_call_blocks_search_files_ssh(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    result = on_pre_tool_call(
        tool_name="search_files",
        args={"path": str(home / ".ssh"), "pattern": "*"},
    )
    assert result is not None
    assert result["action"] == "block"


def test_pre_tool_call_blocks_obvious_terminal_cat(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    ssh = home / ".ssh"
    ssh.mkdir(parents=True)
    key = ssh / "id_ed25519"
    key.write_text(OPENSSH_KEY, encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    result = on_pre_tool_call(
        tool_name="terminal",
        args={"command": f"cat {key}"},
    )
    assert result is not None
    assert result["action"] == "block"
    # Honest boundary: opaque dynamic construction is not claimed blocked.
    assert (
        on_pre_tool_call(
            tool_name="terminal",
            args={"command": "python -c 'print(open(p).read())'"},
        )
        is None
    )


def test_pre_tool_call_allows_ordinary_read(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    notes = tmp_path / "notes.txt"
    notes.write_text("ok", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    assert on_pre_tool_call(tool_name="read_file", args={"path": str(notes)}) is None


def test_transform_tool_result_blocks_private_key_content(tmp_path: Path, monkeypatch):
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

    out = on_transform_tool_result(
        tool_name="read_file",
        args={"path": "/tmp/notes.txt"},
        result=f"business-ok\n{OPENSSH_KEY}\ntrail",
    )
    assert "BEGIN OPENSSH PRIVATE KEY" not in out
    assert "PRIVATE KEY" not in out
    assert REDACTED_SECRET in out
    assert "business-ok" in out
    assert "trail" in out
    assert out != RESULT_GUARD_FAIL_TEXT


def test_transform_tool_result_blocks_protected_path_result(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    ssh = home / ".ssh"
    ssh.mkdir(parents=True)
    cfg = ssh / "config"
    cfg.write_text("Host secret-alias\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    out = on_transform_tool_result(
        tool_name="read_file",
        args={"path": str(cfg)},
        result="Host secret-alias\n",
    )
    assert "secret-alias" not in out
    # Protected-path pre-block remains the historical SAFE JSON (not R4 result-guard).
    assert json.loads(out)["error"]


def test_llm_execution_redacts_locatable_raw_pem_then_calls_provider():
    """Complete raw PEM is replaced; provider sees zero plaintext key bytes."""
    from credential_guard.result_guard import REDACTED_SECRET

    calls = []

    def next_call(req):
        calls.append(req)
        return {"ok": True}

    resp = on_llm_execution(
        request={"messages": [{"role": "user", "content": OPENSSH_KEY}]},
        next_call=next_call,
    )
    assert resp == {"ok": True}
    assert len(calls) == 1
    sent = json.dumps(calls[0], ensure_ascii=False)
    assert "BEGIN OPENSSH PRIVATE KEY" not in sent
    assert OPENSSH_KEY not in sent
    assert REDACTED_SECRET in calls[0]["messages"][0]["content"]


def test_llm_request_redacts_or_fail_closes_private_key():
    out = on_llm_request(
        request={"messages": [{"role": "user", "content": RSA_KEY}]}
    )
    blob = json.dumps(out)
    assert "BEGIN RSA PRIVATE KEY" not in blob
    assert "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn" not in blob


def test_safe_ordinary_text_not_blocked_by_key_detector(
    tmp_path: Path, monkeypatch
):
    """Ordinary text must pass when file backend is available (not ambient HOME)."""
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

    assert not looks_like_private_key("SELECT * FROM users WHERE id=1")
    req = on_llm_request(
        request={"messages": [{"role": "user", "content": "list tables please"}]}
    )
    assert "list tables please" in json.dumps(req)
    assert SAFE_BLOCK_MESSAGE not in json.dumps(req)


def _synthetic_pem(marker: str) -> str:
    return (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        f"{marker}\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )


def _urlsafe_distinct_synthetic_pem_b64() -> tuple[str, str, str]:
    """Return (pem, std_b64, urlsafe_b64) with real URL-safe alphabet divergence.

    The URL-safe form MUST contain '-' or '_' and MUST differ from standard Base64.
    Body is synthetic decoy text only — not a real private key.
    """
    import base64

    # Deterministic filler chosen so urlsafe_b64encode emits '-' (from '+') and
    # diverges from standard Base64 — avoids false coverage when alphabets match.
    pem = _synthetic_pem("CG_SYNTHETIC_DECOY_NOT_A_REAL_KEY_ >")
    raw = pem.encode("utf-8")
    std = base64.b64encode(raw).decode("ascii")
    url = base64.urlsafe_b64encode(raw).decode("ascii")
    assert "-" in url or "_" in url
    assert url != std
    assert ("+" in std) or ("/" in std)
    return pem, std, url


def test_urlsafe_b64_pem_with_dash_or_underscore_blocked(tmp_path, monkeypatch):
    """URL-safe Base64 PEM with -/_ : detect, whole-field replace on provider, tool fail-closed."""
    import base64

    # Normal pass-through assertions require an available isolated egress store.
    # Without this fixture, production fail-closed correctly blocks the innocent
    # controls because credentials.json is unavailable, creating a false failure.
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

    from credential_guard.middleware import REDACTED_UNRESOLVED_SENSITIVE_FIELD

    pem, std, url = _urlsafe_distinct_synthetic_pem_b64()
    assert contains_private_key_material(url) is True
    assert contains_private_key_material(std) is True

    calls: list = []
    resp = on_llm_execution(
        request={"messages": [{"role": "user", "content": url}]},
        next_call=lambda r: calls.append(r) or {"ok": True},
    )
    assert len(calls) == 1
    assert resp == {"ok": True}
    assert calls[0]["messages"][0]["content"] == REDACTED_UNRESOLVED_SENSITIVE_FIELD
    assert url not in json.dumps(calls[0], ensure_ascii=False)
    assert "BEGIN OPENSSH PRIVATE KEY" not in json.dumps(calls[0], ensure_ascii=False)

    tool_out = on_transform_tool_result(result=url, tool_name="dummy", arguments={})
    assert tool_out == RESULT_GUARD_FAIL_TEXT
    assert "BEGIN OPENSSH PRIVATE KEY" not in tool_out
    assert tool_out.count(url) == 0

    # Standard Base64 PEM: whole-field replace then continue (Provider=1, zero leak).
    std_calls: list = []
    on_llm_execution(
        request={"messages": [{"role": "user", "content": std}]},
        next_call=lambda r: std_calls.append(r) or {"ok": True},
    )
    assert len(std_calls) == 1
    assert std_calls[0]["messages"][0]["content"] == REDACTED_UNRESOLVED_SENSITIVE_FIELD
    assert std not in json.dumps(std_calls[0], ensure_ascii=False)

    # Ordinary URL-safe Base64 / cert / pubkey must not false-block.
    # Payload chosen so urlsafe form truly contains '-' and differs from std b64.
    innocent_raw = ("CG_INNOCENT_PAYLOAD_> " + ("Z" * 40)).encode("utf-8")
    innocent_url = base64.urlsafe_b64encode(innocent_raw).decode("ascii")
    innocent_std = base64.b64encode(innocent_raw).decode("ascii")
    assert "-" in innocent_url or "_" in innocent_url
    assert innocent_url != innocent_std
    cert = "-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----"
    pub = "-----BEGIN PUBLIC KEY-----\nMII\n-----END PUBLIC KEY-----"
    for ok_text in (innocent_url, cert, pub):
        assert contains_private_key_material(ok_text) is False
        ok_calls: list = []
        on_llm_execution(
            request={"messages": [{"role": "user", "content": ok_text}]},
            next_call=lambda r: ok_calls.append(r) or {"ok": True},
        )
        assert len(ok_calls) == 1, ok_text


def test_t5_encoded_pem_blocked_on_provider_and_tool_result(tmp_path, monkeypatch):
    """percent / b64 / urlsafe-b64 / JSON-escape PEM must not egress as raw material."""
    import base64
    import secrets
    from urllib.parse import quote

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

    marker = "CG_PEM_MARKER_" + secrets.token_hex(16)
    pem = _synthetic_pem(marker)
    pct = quote(pem, safe="")
    std = base64.b64encode(pem.encode("utf-8")).decode("ascii")
    # Prefer a URL-safe form that truly diverges (contains -/_).
    _, _, url = _urlsafe_distinct_synthetic_pem_b64()
    esc = json.dumps(pem, ensure_ascii=True)[1:-1]

    for label, encoded in (
        ("pct", pct),
        ("std", std),
        ("url", url),
        ("esc", esc),
    ):
        calls = []

        def next_call(request, _calls=calls):
            _calls.append(request)
            return {"ok": True}

        resp = on_llm_execution(
            request={"messages": [{"role": "user", "content": encoded}]},
            next_call=next_call,
        )
        blob = str(resp)
        assert marker not in blob
        assert encoded not in blob
        from credential_guard.middleware import REDACTED_UNRESOLVED_SENSITIVE_FIELD

        assert len(calls) == 1, label
        sent = json.dumps(calls[0], ensure_ascii=False)
        assert marker not in sent
        assert encoded not in sent
        assert "BEGIN OPENSSH PRIVATE KEY" not in sent
        if label == "esc":
            # JSON-escaped PEM still contains BEGIN/END markers → localizable redact.
            assert REDACTED_SECRET in calls[0]["messages"][0]["content"]
        else:
            # Boundary-unknown encodings → whole-field placeholder, continue.
            assert (
                calls[0]["messages"][0]["content"] == REDACTED_UNRESOLVED_SENSITIVE_FIELD
            )

        tool_out = on_transform_tool_result(
            result=encoded, tool_name="dummy", arguments={}
        )
        assert marker not in tool_out
        assert "BEGIN OPENSSH PRIVATE KEY" not in tool_out
        if label == "esc":
            # JSON-escaped PEM still contains BEGIN/END markers → localizable redact.
            assert REDACTED_SECRET in tool_out
            assert tool_out != RESULT_GUARD_FAIL_TEXT
        else:
            # Base64 / URL-safe / percent: not safely localizable → fixed fail text.
            assert tool_out == RESULT_GUARD_FAIL_TEXT
            assert tool_out.count(encoded) == 0
            assert tool_out.count(marker) == 0

    # Positive controls: must not false-block.
    innocent_b64 = base64.b64encode(b"short").decode("ascii")
    cert = "-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----"
    pub = "-----BEGIN PUBLIC KEY-----\nMII\n-----END PUBLIC KEY-----"
    for ok_text in (innocent_b64, cert, pub, "https://example.com/path?q=1"):
        calls = []
        on_llm_execution(
            request={"messages": [{"role": "user", "content": ok_text}]},
            next_call=lambda r: calls.append(r) or {"ok": True},
        )
        assert len(calls) == 1, ok_text
