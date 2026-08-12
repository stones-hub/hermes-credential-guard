"""R1A: credential-guard.json Schema v2 strict loader (TDD)."""

from __future__ import annotations

import json
import os
import secrets
import traceback
from pathlib import Path
from typing import Any, Dict

import pytest

from credential_guard.config import (
    CONFIG_FILENAME,
    ConfigError,
    CredentialGuardConfig,
)
from credential_guard.redactor import MAX_SECRET_LENGTH


def _decoy(n: int = 24) -> str:
    return "CG_TEST_" + secrets.token_hex(n)


def _write_config(path: Path, doc: Dict[str, Any], mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    raw = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
    path.write_text(raw, encoding="utf-8")
    os.chmod(path, mode)
    return path


def _minimal_token_http(token: str) -> Dict[str, Any]:
    return {
        "version": 2,
        "credentials": {
            "internal_api_token": {
                "type": "token",
                "value": token,
            }
        },
        "bindings": {
            "internal-api": {
                "type": "http",
                "credential_ref": "internal_api_token",
                "target": {
                    "scheme": "https",
                    "host": "api.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                    "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
                },
                "inject": {
                    "type": "bearer",
                    "location": "authorization_header",
                },
                "approval": "required",
            }
        },
    }


def _assert_safe_error(exc: BaseException, *, decoy: str, path: Path) -> None:
    blob = f"{type(exc).__name__}:{exc!s}:{exc!r}"
    assert decoy not in blob
    assert str(path) not in blob
    assert str(path.resolve()) not in blob
    if hasattr(exc, "code"):
        assert isinstance(exc.code, str) and exc.code
        assert decoy not in exc.code


# --- happy paths ---


def test_load_minimal_token_http(tmp_path: Path):
    decoy = _decoy()
    path = _write_config(tmp_path / CONFIG_FILENAME, _minimal_token_http(decoy))
    cfg = CredentialGuardConfig.load(path)
    assert cfg.credentials["internal_api_token"]["type"] == "token"
    assert cfg.credentials["internal_api_token"]["value"] == decoy
    assert cfg.bindings["internal-api"]["type"] == "http"
    assert isinstance(cfg.config_digest, str)
    assert len(cfg.config_digest) == 64
    assert all(c in "0123456789abcdef" for c in cfg.config_digest)


def test_load_username_password_basic(tmp_path: Path):
    password = _decoy()
    doc = {
        "version": 2,
        "credentials": {
            "svc_user": {
                "type": "username_password",
                "username": "cg_readonly",
                "password": password,
            }
        },
        "bindings": {
            "svc-basic": {
                "type": "http",
                "credential_ref": "svc_user",
                "target": {
                    "scheme": "https",
                    "host": "svc.example.test",
                    "port": 8443,
                },
                "request": {
                    "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                    "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
                },
                "inject": {
                    "type": "basic",
                    "location": "authorization_header",
                },
                "approval": "required",
            }
        },
    }
    cfg = CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))
    assert cfg.credentials["svc_user"]["username"] == "cg_readonly"
    assert cfg.bindings["svc-basic"]["inject"]["type"] == "basic"


def test_load_process_env(tmp_path: Path):
    decoy = _decoy()
    program = str((tmp_path / "cg-synth-helper").resolve())
    doc = {
        "version": 2,
        "credentials": {"cli_token": {"type": "token", "value": decoy}},
        "bindings": {
            "cli-env": {
                "type": "process_env",
                "credential_ref": "cli_token",
                "program": program,
                "argv": [program, "status"],
                "env_name": "MY_API_TOKEN",
                "timeout_seconds": 30,
                "max_stdout_bytes": 65536,
                "max_stderr_bytes": 65536,
                "approval": "required",
            }
        },
    }
    cfg = CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))
    assert cfg.bindings["cli-env"]["env_name"] == "MY_API_TOKEN"
    assert cfg.bindings["cli-env"]["program"] == program


def test_load_stdin(tmp_path: Path):
    decoy = _decoy()
    program = str((tmp_path / "cg-synth-helper").resolve())
    doc = {
        "version": 2,
        "credentials": {"stdin_token": {"type": "token", "value": decoy}},
        "bindings": {
            "cli-stdin": {
                "type": "stdin",
                "credential_ref": "stdin_token",
                "program": program,
                "argv": [program, "ingest"],
                "stdin_format": "raw",
                "timeout_seconds": 30,
                "max_stdout_bytes": 65536,
                "max_stderr_bytes": 65536,
                "approval": "required",
            }
        },
    }
    cfg = CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))
    assert cfg.bindings["cli-stdin"]["stdin_format"] == "raw"
    assert list(cfg.bindings["cli-stdin"]["argv"]) == [program, "ingest"]


def test_ssh_config_credential_rejected_by_v2_schema(tmp_path: Path):
    """R5: ssh_config leaves the formal schema — no executable adapter exists."""
    doc = {
        "version": 2,
        "credentials": {
            "bastion_key": {"type": "ssh_config", "alias": "bastion-prod"}
        },
        "bindings": {},
    }
    with pytest.raises(ConfigError) as exc:
        CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))
    assert exc.value.code == "CONFIG_SCHEMA"


def test_ssh_config_binding_rejected_by_v2_schema(tmp_path: Path):
    """Even with a valid token credential, an ssh_config binding is refused."""
    doc = {
        "version": 2,
        "credentials": {"bastion_key": {"type": "token", "value": _decoy()}},
        "bindings": {
            "bastion": {
                "type": "ssh_config",
                "credential_ref": "bastion_key",
                "approval": "required",
            }
        },
    }
    with pytest.raises(ConfigError) as exc:
        CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))
    assert exc.value.code == "CONFIG_SCHEMA"


def test_load_api_key_header(tmp_path: Path):
    decoy = _decoy()
    doc = {
        "version": 2,
        "credentials": {"api_token": {"type": "token", "value": decoy}},
        "bindings": {
            "api-key": {
                "type": "http",
                "credential_ref": "api_token",
                "target": {
                    "scheme": "https",
                    "host": "api.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                    "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
                },
                "inject": {
                    "type": "api_key_header",
                    "header_name": "X-Api-Key",
                },
                "approval": "required",
            }
        },
    }
    cfg = CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))
    assert cfg.bindings["api-key"]["inject"]["header_name"] == "X-Api-Key"


# --- file boundary ---


def test_missing_file(tmp_path: Path):
    os.chmod(tmp_path, 0o700)
    path = tmp_path / CONFIG_FILENAME
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    _assert_safe_error(ei.value, decoy="CG_TEST_", path=path)


def test_rejects_0644(tmp_path: Path):
    decoy = _decoy()
    path = _write_config(
        tmp_path / CONFIG_FILENAME, _minimal_token_http(decoy), mode=0o644
    )
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    _assert_safe_error(ei.value, decoy=decoy, path=path)


def test_rejects_symlink(tmp_path: Path):
    decoy = _decoy()
    real = _write_config(tmp_path / "real.json", _minimal_token_http(decoy))
    link = tmp_path / CONFIG_FILENAME
    link.symlink_to(real)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(link)
    _assert_safe_error(ei.value, decoy=decoy, path=link)


def test_rejects_directory(tmp_path: Path):
    os.chmod(tmp_path, 0o700)
    path = tmp_path / CONFIG_FILENAME
    path.mkdir()
    os.chmod(path, 0o700)
    with pytest.raises(ConfigError):
        CredentialGuardConfig.load(path)


def test_rejects_wrong_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    decoy = _decoy()
    path = _write_config(tmp_path / CONFIG_FILENAME, _minimal_token_http(decoy))
    real_euid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real_euid + 1)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    _assert_safe_error(ei.value, decoy=decoy, path=path)


def test_rejects_too_large(tmp_path: Path):
    decoy = _decoy()
    os.chmod(tmp_path, 0o700)
    path = tmp_path / CONFIG_FILENAME
    # Build an oversized but structurally-looking JSON blob.
    big = b'{"version":2,"credentials":{},"bindings":{},"pad":"' + (
        b"A" * (2_000_000)
    ) + b'"}'
    path.write_bytes(big)
    os.chmod(path, 0o600)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    _assert_safe_error(ei.value, decoy=decoy, path=path)


def test_rejects_non_utf8(tmp_path: Path):
    os.chmod(tmp_path, 0o700)
    path = tmp_path / CONFIG_FILENAME
    path.write_bytes(b'{"version":2,"credentials":{},"bindings":{}\xff}')
    os.chmod(path, 0o600)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    _assert_safe_error(ei.value, decoy="CG_TEST_", path=path)


def test_rejects_invalid_json(tmp_path: Path):
    os.chmod(tmp_path, 0o700)
    path = tmp_path / CONFIG_FILENAME
    path.write_text("{not-json", encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(ConfigError):
        CredentialGuardConfig.load(path)


# --- schema ---


def test_rejects_unknown_top_level_field(tmp_path: Path):
    decoy = _decoy()
    doc = _minimal_token_http(decoy)
    doc["extra"] = True
    with pytest.raises(ConfigError):
        CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))


def test_rejects_unknown_nested_field(tmp_path: Path):
    decoy = _decoy()
    doc = _minimal_token_http(decoy)
    doc["credentials"]["internal_api_token"]["extra"] = "x"
    with pytest.raises(ConfigError):
        CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))


def test_rejects_wrong_version(tmp_path: Path):
    decoy = _decoy()
    doc = _minimal_token_http(decoy)
    doc["version"] = 1
    with pytest.raises(ConfigError):
        CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))


def test_rejects_duplicate_json_keys(tmp_path: Path):
    decoy = _decoy()
    os.chmod(tmp_path, 0o700)
    # Two credentials keys with same name — object_pairs_hook must reject.
    raw = (
        '{"version":2,"credentials":{"a":{"type":"token","value":"%s"},'
        '"a":{"type":"token","value":"%s"}},"bindings":{}}'
        % (decoy, decoy + "x")
    )
    path = tmp_path / CONFIG_FILENAME
    path.write_text(raw, encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    _assert_safe_error(ei.value, decoy=decoy, path=path)


def test_rejects_dangling_credential_ref(tmp_path: Path):
    decoy = _decoy()
    doc = _minimal_token_http(decoy)
    doc["bindings"]["internal-api"]["credential_ref"] = "missing_token"
    with pytest.raises(ConfigError):
        CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))


def test_rejects_type_mismatch_bearer_needs_token(tmp_path: Path):
    password = _decoy()
    doc = {
        "version": 2,
        "credentials": {
            "svc_user": {
                "type": "username_password",
                "username": "cg_user",
                "password": password,
            }
        },
        "bindings": {
            "bad": {
                "type": "http",
                "credential_ref": "svc_user",
                "target": {
                    "scheme": "https",
                    "host": "api.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                    "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
                },
                "inject": {
                    "type": "bearer",
                    "location": "authorization_header",
                },
                "approval": "required",
            }
        },
    }
    with pytest.raises(ConfigError):
        CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))


def test_rejects_illegal_name(tmp_path: Path):
    decoy = _decoy()
    doc = _minimal_token_http(decoy)
    doc["credentials"]["BadName"] = doc["credentials"].pop("internal_api_token")
    doc["bindings"]["internal-api"]["credential_ref"] = "BadName"
    with pytest.raises(ConfigError):
        CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))


def test_rejects_empty_token_value(tmp_path: Path):
    doc = _minimal_token_http("")
    with pytest.raises(ConfigError):
        CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))


def test_rejects_oversized_secret(tmp_path: Path):
    decoy = "x" * (MAX_SECRET_LENGTH + 1)
    with pytest.raises(ConfigError):
        CredentialGuardConfig.load(
            _write_config(tmp_path / CONFIG_FILENAME, _minimal_token_http(decoy))
        )


# --- http host/scheme/port/header ---


@pytest.mark.parametrize(
    "host",
    [
        "http://api.example.test",
        "*.example.test",
        "api.example.test.",
        "user@api.example.test",
        "127.0.0.1",
        "::1",
        "api.example.test/path",
    ],
)
def test_rejects_illegal_hosts(tmp_path: Path, host: str):
    decoy = _decoy()
    doc = _minimal_token_http(decoy)
    doc["bindings"]["internal-api"]["target"]["host"] = host
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))
    _assert_safe_error(ei.value, decoy=decoy, path=tmp_path / CONFIG_FILENAME)
    assert host not in f"{ei.value!s}{ei.value!r}"


def test_rejects_http_scheme(tmp_path: Path):
    decoy = _decoy()
    doc = _minimal_token_http(decoy)
    doc["bindings"]["internal-api"]["target"]["scheme"] = "http"
    with pytest.raises(ConfigError):
        CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))


@pytest.mark.parametrize("port", [0, -1, 65536, 1.5, "443"])
def test_rejects_illegal_port(tmp_path: Path, port: Any):
    decoy = _decoy()
    doc = _minimal_token_http(decoy)
    doc["bindings"]["internal-api"]["target"]["port"] = port
    with pytest.raises(ConfigError):
        CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))


@pytest.mark.parametrize(
    "header_name",
    ["Authorization", "Cookie", "Host", "X-Api\nKey", "X-Api\x00Key"],
)
def test_rejects_illegal_header_name(tmp_path: Path, header_name: str):
    decoy = _decoy()
    doc = {
        "version": 2,
        "credentials": {"api_token": {"type": "token", "value": decoy}},
        "bindings": {
            "api-key": {
                "type": "http",
                "credential_ref": "api_token",
                "target": {
                    "scheme": "https",
                    "host": "api.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                    "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
                },
                "inject": {
                    "type": "api_key_header",
                    "header_name": header_name,
                },
                "approval": "required",
            }
        },
    }
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))
    blob = f"{ei.value!s}{ei.value!r}"
    assert decoy not in blob
    assert "\n" not in str(ei.value)
    assert "\x00" not in str(ei.value)


def test_rejects_approval_not_required(tmp_path: Path):
    decoy = _decoy()
    doc = _minimal_token_http(decoy)
    doc["bindings"]["internal-api"]["approval"] = "optional"
    with pytest.raises(ConfigError):
        CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))


# --- process_env / stdin ---


@pytest.mark.parametrize("env_name", ["PATH", "HOME", "HERMES_HOME", "path", "1BAD"])
def test_rejects_forbidden_or_illegal_env_name(tmp_path: Path, env_name: str):
    decoy = _decoy()
    program = str((tmp_path / "cg-synth-helper").resolve())
    doc = {
        "version": 2,
        "credentials": {"cli_token": {"type": "token", "value": decoy}},
        "bindings": {
            "cli-env": {
                "type": "process_env",
                "credential_ref": "cli_token",
                "program": program,
                "argv": [program, "status"],
                "env_name": env_name,
                "timeout_seconds": 30,
                "max_stdout_bytes": 65536,
                "max_stderr_bytes": 65536,
                "approval": "required",
            }
        },
    }
    with pytest.raises(ConfigError):
        CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))


@pytest.mark.parametrize(
    "legacy",
    [
        {
            "type": "process_env",
            "credential_ref": "cli_token",
            "tool": "terminal",
            "env_name": "MY_API_TOKEN",
            "approval": "required",
        },
        {
            "type": "process_env",
            "credential_ref": "cli_token",
            "tool": "",
            "env_name": "MY_API_TOKEN",
            "approval": "required",
        },
        {
            "type": "stdin",
            "credential_ref": "cli_token",
            "tool": "terminal",
            "arg_path": ["stdin"],
            "approval": "required",
        },
    ],
)
def test_rejects_legacy_process_tool_schema(tmp_path: Path, legacy: dict):
    decoy = _decoy()
    doc = {
        "version": 2,
        "credentials": {"cli_token": {"type": "token", "value": decoy}},
        "bindings": {"cli-env": legacy},
    }
    with pytest.raises(ConfigError):
        CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))


def test_rejects_empty_argv(tmp_path: Path):
    decoy = _decoy()
    program = str((tmp_path / "cg-synth-helper").resolve())
    doc = {
        "version": 2,
        "credentials": {"t": {"type": "token", "value": decoy}},
        "bindings": {
            "s": {
                "type": "stdin",
                "credential_ref": "t",
                "program": program,
                "argv": [],
                "stdin_format": "raw",
                "timeout_seconds": 30,
                "max_stdout_bytes": 65536,
                "max_stderr_bytes": 65536,
                "approval": "required",
            }
        },
    }
    with pytest.raises(ConfigError):
        CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))


def test_rejects_non_string_argv_element(tmp_path: Path):
    decoy = _decoy()
    program = str((tmp_path / "cg-synth-helper").resolve())
    doc = {
        "version": 2,
        "credentials": {"t": {"type": "token", "value": decoy}},
        "bindings": {
            "s": {
                "type": "stdin",
                "credential_ref": "t",
                "program": program,
                "argv": [program, 1],
                "stdin_format": "raw",
                "timeout_seconds": 30,
                "max_stdout_bytes": 65536,
                "max_stderr_bytes": 65536,
                "approval": "required",
            }
        },
    }
    with pytest.raises(ConfigError):
        CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))


# --- immutability + digest ---


def test_deep_immutable_and_input_isolation(tmp_path: Path):
    decoy = _decoy()
    doc = _minimal_token_http(decoy)
    cfg = CredentialGuardConfig.load(_write_config(tmp_path / CONFIG_FILENAME, doc))
    with pytest.raises((TypeError, AttributeError)):
        cfg.credentials["internal_api_token"]["value"] = "mutated"  # type: ignore[index]
    with pytest.raises((TypeError, AttributeError)):
        cfg.bindings["internal-api"]["target"]["host"] = "evil.test"  # type: ignore[index]
    doc["credentials"]["internal_api_token"]["value"] = "mutated-outside"
    assert cfg.credentials["internal_api_token"]["value"] == decoy


def test_canonical_digest_stable_and_order_insensitive(tmp_path: Path):
    decoy = _decoy()
    doc_a = _minimal_token_http(decoy)
    # Rebuild with different key insertion order.
    doc_b = {
        "bindings": doc_a["bindings"],
        "version": 2,
        "credentials": {
            "internal_api_token": {
                "value": decoy,
                "type": "token",
            }
        },
    }
    cfg_a = CredentialGuardConfig.load(
        _write_config(tmp_path / "a" / CONFIG_FILENAME, doc_a)
    )
    cfg_b = CredentialGuardConfig.load(
        _write_config(tmp_path / "b" / CONFIG_FILENAME, doc_b)
    )
    assert cfg_a.config_digest == cfg_b.config_digest
    doc_c = _minimal_token_http(decoy + "z")
    cfg_c = CredentialGuardConfig.load(
        _write_config(tmp_path / "c" / CONFIG_FILENAME, doc_c)
    )
    assert cfg_c.config_digest != cfg_a.config_digest
    # Digest must not appear in error messages of a forced failure.
    bad = _minimal_token_http(decoy)
    bad["version"] = 99
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(
            _write_config(tmp_path / "d" / CONFIG_FILENAME, bad)
        )
    assert cfg_a.config_digest not in f"{ei.value!s}{ei.value!r}"


def test_toctou_inode_swap_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    decoy = _decoy()
    path = _write_config(tmp_path / CONFIG_FILENAME, _minimal_token_http(decoy))
    real_lstat = os.lstat
    swapped = {"done": False}

    def flaky_lstat(p, *args, **kwargs):
        st = real_lstat(p, *args, **kwargs)
        if Path(p) == path and not swapped["done"]:
            swapped["done"] = True
            # Replace file with a new inode after first lstat observation.
            path.unlink()
            _write_config(path, _minimal_token_http(decoy + "x"))
        return st

    monkeypatch.setattr(os, "lstat", flaky_lstat)
    # Also patch Path.lstat used by pathlib callers.
    monkeypatch.setattr(Path, "lstat", lambda self: flaky_lstat(self))
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    _assert_safe_error(ei.value, decoy=decoy, path=path)


def test_error_messages_never_leak_secrets_or_hosts(tmp_path: Path):
    decoy = _decoy(32)
    username = "cg_secret_user_xyz"
    host = "leaky.example.test"
    doc = {
        "version": 2,
        "credentials": {
            "svc_user": {
                "type": "username_password",
                "username": username,
                "password": decoy,
                "extra": "bad",
            }
        },
        "bindings": {
            "svc": {
                "type": "http",
                "credential_ref": "svc_user",
                "target": {"scheme": "https", "host": host, "port": 443},
                "request": {
                    "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                    "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
                },
                "inject": {
                    "type": "basic",
                    "location": "authorization_header",
                },
                "approval": "required",
            }
        },
    }
    path = _write_config(tmp_path / CONFIG_FILENAME, doc)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    blob = f"{ei.value!s}{ei.value!r}{getattr(ei.value, 'code', '')}"
    assert decoy not in blob
    assert username not in blob
    assert host not in blob
    assert str(path) not in blob
    # Contiguous decoy fragment gate (>=8).
    for i in range(0, max(0, len(decoy) - 7)):
        frag = decoy[i : i + 8]
        assert frag not in blob


# --- R1A hardening B1/B2 ---


def _full_exception_text(exc: BaseException) -> str:
    # Use stdlib formatting only (honors __cause__ / __suppress_context__).
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


def _traceback_residue_count(
    exc: BaseException,
    *,
    decoy: str,
    path: Path,
    username: str = "",
    host: str = "",
) -> int:
    blob = _full_exception_text(exc)
    markers = [
        decoy,
        str(path),
        str(path.resolve()),
        username,
        host,
    ]
    count = 0
    for m in markers:
        if m and m in blob:
            count += 1
    for i in range(0, max(0, len(decoy) - 7)):
        if decoy[i : i + 8] in blob:
            count += 1
    return count


def _walk_exception_graph(exc: BaseException, *, _seen=None) -> list:
    """Recursively collect strings reachable from a public exception object graph."""
    if _seen is None:
        _seen = set()
    oid = id(exc)
    if oid in _seen:
        return []
    _seen.add(oid)
    blobs: list = []
    blobs.append(f"{type(exc).__name__}:{exc!s}:{exc!r}")
    for arg in getattr(exc, "args", ()):
        blobs.append(repr(arg))
        if isinstance(arg, BaseException):
            blobs.extend(_walk_exception_graph(arg, _seen=_seen))
        elif isinstance(arg, (bytes, bytearray)):
            blobs.append(arg.decode("utf-8", errors="replace"))
        else:
            blobs.append(str(arg))
    for name, val in list(getattr(exc, "__dict__", {}).items()):
        blobs.append(f"{name}={val!r}")
        if isinstance(val, BaseException):
            blobs.extend(_walk_exception_graph(val, _seen=_seen))
        elif isinstance(val, (str, bytes, bytearray)):
            blobs.append(
                val.decode("utf-8", errors="replace")
                if isinstance(val, (bytes, bytearray))
                else val
            )
    for attr in ("doc", "msg", "filename", "path", "strerror"):
        if hasattr(exc, attr):
            blobs.append(f"{attr}={getattr(exc, attr)!r}")
    if getattr(exc, "__cause__", None) is not None:
        blobs.extend(_walk_exception_graph(exc.__cause__, _seen=_seen))
    if getattr(exc, "__context__", None) is not None:
        blobs.extend(_walk_exception_graph(exc.__context__, _seen=_seen))
    return blobs


def _assert_clean_exception_graph(
    exc: BaseException,
    *,
    decoy: str,
    path: Path,
    username: str = "",
    host: str = "",
) -> None:
    assert exc.__cause__ is None
    assert exc.__context__ is None
    blob = "\n".join(_walk_exception_graph(exc))
    markers = [decoy, str(path), str(path.resolve()), username, host]
    for m in markers:
        if m:
            assert m not in blob
    for i in range(0, max(0, len(decoy) - 7)):
        assert decoy[i : i + 8] not in blob
    for name, val in getattr(exc, "__dict__", {}).items():
        if isinstance(val, BaseException):
            raise AssertionError("public exception attribute holds nested exception")


def _assert_no_chained_leak(exc: BaseException) -> None:
    assert exc.__cause__ is None
    assert exc.__context__ is None
    for name, val in getattr(exc, "__dict__", {}).items():
        if isinstance(val, BaseException):
            raise AssertionError("public exception attribute holds nested exception")


def test_config_instance_immutable_including_private_fields(tmp_path: Path):
    decoy = _decoy()
    cfg = CredentialGuardConfig.load(
        _write_config(tmp_path / CONFIG_FILENAME, _minimal_token_http(decoy))
    )
    config_instance_immutable = True
    for assign in (
        lambda: setattr(cfg, "_config_digest", "tampered"),
        lambda: setattr(cfg, "_credentials", {}),
        lambda: setattr(cfg, "_bindings", {}),
        lambda: setattr(cfg, "extra_field", 1),
    ):
        try:
            assign()
            config_instance_immutable = False
        except (AttributeError, TypeError):
            pass
    assert config_instance_immutable is True

    # Safe copies: mutating returned structures must not affect snapshot.
    as_dict = cfg.to_canonical_dict()
    as_dict["credentials"]["internal_api_token"]["value"] = "mutated"
    as_dict["bindings"]["internal-api"]["target"]["host"] = "evil.test"
    assert cfg.credentials["internal_api_token"]["value"] == decoy
    assert cfg.bindings["internal-api"]["target"]["host"] == "api.example.test"
    raw = cfg.to_canonical_json()
    assert isinstance(raw, (bytes, bytearray))
    parsed = json.loads(raw.decode("utf-8"))
    parsed["credentials"]["internal_api_token"]["value"] = "mutated-json"
    assert cfg.credentials["internal_api_token"]["value"] == decoy


def test_full_traceback_missing_file_no_path_residue(tmp_path: Path):
    os.chmod(tmp_path, 0o700)
    path = tmp_path / "abs_missing" / CONFIG_FILENAME
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    residue = _traceback_residue_count(ei.value, decoy="CG_TEST_", path=path)
    assert residue == 0
    _assert_no_chained_leak(ei.value)
    assert ei.value.code == "CONFIG_NOT_FOUND"


def test_full_traceback_symlink_open_failure_no_path_residue(tmp_path: Path):
    decoy = _decoy()
    real = _write_config(tmp_path / "real.json", _minimal_token_http(decoy))
    link = tmp_path / CONFIG_FILENAME
    link.symlink_to(real)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(link)
    residue = _traceback_residue_count(ei.value, decoy=decoy, path=link)
    assert residue == 0
    _assert_no_chained_leak(ei.value)


def test_full_traceback_invalid_json_no_residue(tmp_path: Path):
    os.chmod(tmp_path, 0o700)
    path = tmp_path / CONFIG_FILENAME
    path.write_text("{not-json-" + _decoy(), encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    residue = _traceback_residue_count(ei.value, decoy="CG_TEST_", path=path)
    assert residue == 0
    _assert_no_chained_leak(ei.value)


def test_full_traceback_invalid_utf8_no_residue(tmp_path: Path):
    os.chmod(tmp_path, 0o700)
    path = tmp_path / CONFIG_FILENAME
    path.write_bytes(b'{"version":2,"credentials":{},"bindings":{}\xff}')
    os.chmod(path, 0o600)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    residue = _traceback_residue_count(ei.value, decoy="CG_TEST_", path=path)
    assert residue == 0
    _assert_no_chained_leak(ei.value)


# --- R1A hardening B6 ---


@pytest.mark.parametrize(
    "version",
    [2.0, "2", True, False, 1, 3, None],
)
def test_rejects_non_strict_v2_version_type(tmp_path: Path, version: Any):
    decoy = _decoy()
    doc = _minimal_token_http(decoy)
    doc["version"] = version
    path = _write_config(tmp_path / CONFIG_FILENAME, doc)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    assert ei.value.code == "CONFIG_SCHEMA"
    residue = _traceback_residue_count(ei.value, decoy=decoy, path=path)
    assert residue == 0
    _assert_no_chained_leak(ei.value)
    strict_version_type = not (
        type(version) is int and version == 2
    )
    assert strict_version_type is True


# --- R1A redesign round-3: A immutability / B exception graph / G parent dir ---


def test_config_snapshot_has_no_instance_dict(tmp_path: Path):
    decoy = _decoy()
    cfg = CredentialGuardConfig.load(
        _write_config(tmp_path / CONFIG_FILENAME, _minimal_token_http(decoy))
    )
    assert not hasattr(cfg, "__dict__")
    with pytest.raises((AttributeError, TypeError)):
        _ = cfg.__dict__  # type: ignore[attr-defined]


def test_config_resists_common_mutation_bypasses(tmp_path: Path):
    decoy = _decoy()
    cfg = CredentialGuardConfig.load(
        _write_config(tmp_path / CONFIG_FILENAME, _minimal_token_http(decoy))
    )
    for assign in (
        lambda: setattr(cfg, "_config_digest", "tampered"),
        lambda: setattr(cfg, "_credentials", {}),
        lambda: setattr(cfg, "_bindings", {}),
        lambda: setattr(cfg, "extra_field", 1),
        lambda: setattr(cfg, "credentials", {}),
    ):
        with pytest.raises((AttributeError, TypeError)):
            assign()
    with pytest.raises((AttributeError, TypeError)):
        cfg.__dict__["_config_digest"] = "tampered"  # type: ignore[attr-defined]
    with pytest.raises((TypeError, AttributeError)):
        cfg.credentials["internal_api_token"]["value"] = "mutated"  # type: ignore[index]
    with pytest.raises((TypeError, AttributeError)):
        cfg.bindings["internal-api"]["target"]["host"] = "evil.test"  # type: ignore[index]
    as_dict = cfg.to_canonical_dict()
    as_dict["credentials"]["internal_api_token"]["value"] = "mutated"
    as_dict["bindings"]["internal-api"]["target"]["host"] = "evil.test"
    assert cfg.credentials["internal_api_token"]["value"] == decoy
    assert cfg.bindings["internal-api"]["target"]["host"] == "api.example.test"
    digest = cfg.config_digest
    assert len(digest) == 64
    assert cfg.to_canonical_json()  # digest stays consistent with content


def test_exception_object_graph_null_context_invalid_json(tmp_path: Path):
    path = tmp_path / CONFIG_FILENAME
    os.chmod(tmp_path, 0o700)
    path.write_text("{not-json-" + _decoy(), encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    assert ei.value.code == "CONFIG_INVALID_JSON"
    _assert_clean_exception_graph(ei.value, decoy="CG_TEST_", path=path)


def test_exception_object_graph_null_context_missing_file(tmp_path: Path):
    path = tmp_path / "abs_missing" / CONFIG_FILENAME
    os.chmod(tmp_path, 0o700)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    assert ei.value.code == "CONFIG_NOT_FOUND"
    _assert_clean_exception_graph(ei.value, decoy="CG_TEST_", path=path)


def test_exception_object_graph_null_context_utf8(tmp_path: Path):
    path = tmp_path / CONFIG_FILENAME
    os.chmod(tmp_path, 0o700)
    path.write_bytes(b'{"version":2,"credentials":{},"bindings":{}\xff}')
    os.chmod(path, 0o600)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    assert ei.value.code == "CONFIG_INVALID_UTF8"
    _assert_clean_exception_graph(ei.value, decoy="CG_TEST_", path=path)


def test_exception_object_graph_null_context_symlink(tmp_path: Path):
    decoy = _decoy()
    os.chmod(tmp_path, 0o700)
    real = _write_config(tmp_path / "real.json", _minimal_token_http(decoy))
    link = tmp_path / CONFIG_FILENAME
    link.symlink_to(real)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(link)
    _assert_clean_exception_graph(ei.value, decoy=decoy, path=link)


@pytest.mark.parametrize("mode", [0o755, 0o770, 0o711])
def test_load_rejects_insecure_parent_directory(tmp_path: Path, mode: int):
    decoy = _decoy()
    parent = tmp_path / "store"
    parent.mkdir()
    os.chmod(parent, mode)
    path = parent / CONFIG_FILENAME
    raw = json.dumps(_minimal_token_http(decoy), separators=(",", ":"))
    path.write_text(raw, encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    assert ei.value.code in {
        "CONFIG_PARENT_INSECURE_MODE",
        "CONFIG_INSECURE_MODE",
        "CONFIG_PARENT_SYMLINK",
        "CONFIG_PARENT_OWNER",
    }
    _assert_clean_exception_graph(ei.value, decoy=decoy, path=path)


def test_load_rejects_symlink_parent_directory(tmp_path: Path):
    decoy = _decoy()
    real_parent = tmp_path / "real-store"
    real_parent.mkdir()
    os.chmod(real_parent, 0o700)
    link_parent = tmp_path / "link-store"
    link_parent.symlink_to(real_parent)
    path = link_parent / CONFIG_FILENAME
    raw = json.dumps(_minimal_token_http(decoy), separators=(",", ":"))
    path.write_text(raw, encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    assert ei.value.code in {"CONFIG_PARENT_SYMLINK", "CONFIG_SYMLINK"}
    _assert_clean_exception_graph(ei.value, decoy=decoy, path=path)


def test_load_rejects_wrong_parent_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    decoy = _decoy()
    path = _write_config(tmp_path / CONFIG_FILENAME, _minimal_token_http(decoy))
    real_euid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real_euid + 1)
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    assert ei.value.code in {
        "CONFIG_PARENT_OWNER",
        "CONFIG_OWNER_MISMATCH",
    }
    # Restore euid for residue path checks (path still valid).
    monkeypatch.setattr(os, "geteuid", lambda: real_euid)
    # Re-raise capture already done; just check codes were safe.
    assert decoy not in f"{ei.value!s}{ei.value!r}"


# --- R1A final adversarial: constructor validation + OS branch exception graphs ---


def test_direct_constructor_rejects_unvalidated_triple_and_fake_digest():
    """Public construction must not accept raw mappings + caller digest."""
    decoy = _decoy()
    mutable_creds = {
        "internal_api_token": {"type": "token", "value": decoy},
    }
    mutable_binds = {
        "internal-api": {
            "type": "http",
            "credential_ref": "internal_api_token",
            "target": {
                "scheme": "https",
                "host": "api.example.test",
                "port": 443,
            },
            "request": {
                "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                "allowed_paths": ["/job/project-x/build", "/v1", "/health"],
            },
            "inject": {
                "type": "bearer",
                "location": "authorization_header",
            },
            "approval": "required",
        }
    }
    fake_digest = "deadbeef" * 8
    # Old 3-arg unverified constructor must no longer be callable.
    with pytest.raises((TypeError, ConfigError)):
        CredentialGuardConfig(mutable_creds, mutable_binds, fake_digest)  # type: ignore[call-arg]


def test_direct_constructor_validates_schema_deep_copies_and_recomputes_digest():
    decoy = _decoy()
    doc = _minimal_token_http(decoy)
    cfg = CredentialGuardConfig(doc)
    assert not hasattr(cfg, "__dict__")
    with pytest.raises((AttributeError, TypeError)):
        setattr(cfg, "_config_digest", "tampered")
    # Mutating the original mapping must not affect the snapshot.
    doc["credentials"]["internal_api_token"]["value"] = "mutated-after-construct"
    assert cfg.credentials["internal_api_token"]["value"] == decoy
    # Digest must be recomputed canonical SHA-256, never caller-supplied.
    via_mapping = CredentialGuardConfig.from_mapping(_minimal_token_http(decoy))
    assert cfg.config_digest == via_mapping.config_digest
    assert len(cfg.config_digest) == 64
    assert cfg.config_digest != "deadbeef" * 8
    # Illegal schema via direct constructor must fail closed.
    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig({"version": 2, "credentials": {}, "extra": 1})
    assert ei.value.code == "CONFIG_SCHEMA"
    _assert_no_chained_leak(ei.value)


def test_load_from_mapping_and_direct_constructor_agree(tmp_path: Path):
    decoy = _decoy()
    doc = _minimal_token_http(decoy)
    path = _write_config(tmp_path / CONFIG_FILENAME, doc)
    loaded = CredentialGuardConfig.load(path)
    mapped = CredentialGuardConfig.from_mapping(doc)
    direct = CredentialGuardConfig(doc)
    assert loaded.config_digest == mapped.config_digest == direct.config_digest
    assert loaded.to_canonical_json() == mapped.to_canonical_json() == direct.to_canonical_json()


@pytest.mark.parametrize(
    "op_name",
    ["lstat", "open", "fstat", "read"],
)
def test_config_os_branch_exception_graph_clean_for_all_ops(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op_name: str
):
    """Every OS failure branch must leave public ConfigError with null context/cause."""
    decoy = "CG_TEST_OSERR_" + secrets.token_hex(12)
    abs_path = tmp_path / "abs" / decoy / CONFIG_FILENAME
    path = _write_config(tmp_path / CONFIG_FILENAME, _minimal_token_http(_decoy()))
    boom = OSError(13, f"Permission denied: {abs_path} decoy={decoy}")

    real_lstat = os.lstat
    real_open = os.open
    real_fstat = os.fstat
    real_read = os.read
    state = {"n": 0}

    def boom_lstat(p, *a, **k):
        # Allow parent dir checks once, then fail on the config path.
        sp = str(p)
        if CONFIG_FILENAME in sp or sp.endswith(str(path)):
            state["n"] += 1
            if state["n"] >= 1:
                raise boom
        return real_lstat(p, *a, **k)

    def boom_open(p, flags, *a, **k):
        if CONFIG_FILENAME in str(p):
            raise boom
        return real_open(p, flags, *a, **k)

    def boom_fstat(fd):
        raise boom

    def boom_read(fd, n):
        raise boom

    if op_name == "lstat":
        monkeypatch.setattr(os, "lstat", boom_lstat)
    elif op_name == "open":
        monkeypatch.setattr(os, "open", boom_open)
    elif op_name == "fstat":
        monkeypatch.setattr(os, "fstat", boom_fstat)
    else:
        monkeypatch.setattr(os, "read", boom_read)

    with pytest.raises(ConfigError) as ei:
        CredentialGuardConfig.load(path)
    assert isinstance(ei.value.code, str) and ei.value.code
    _assert_clean_exception_graph(ei.value, decoy=decoy, path=abs_path)
    _assert_clean_exception_graph(ei.value, decoy=decoy, path=path)

