"""C10: offline ``hermes credential-guard validate [file]``.

Read-only Schema v2 validation. Must not publish RuntimeView, write sidecars,
invoke Provider/adapters, or echo secrets / hosts / programs / paths / JSON.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from credential_guard.cli import handle_command, run_validate, setup_parser
from credential_guard.config import CONFIG_FILENAME, NAME_RE
from credential_guard.runtime_config import default_config_path, reset_runtime_for_tests
from credential_guard.state import get_registry

CANARY = "SYNTHETIC_C10_CANARY_" + secrets.token_hex(12)
HOST_CANARY = "c10-host.example.test"
PROGRAM_CANARY = "/usr/local/libexec/c10-report-cli"
ENV_CANARY = "C10_REPORT_TOKEN"
PATH_CANARY = "/c10/status"
HEADER_CANARY = "X-C10-Api-Key"


def _reset() -> None:
    get_registry().clear()
    reset_runtime_for_tests()
    try:
        from credential_guard.target_catalog import reset_registration_catalog_for_tests

        reset_registration_catalog_for_tests()
    except Exception:
        pass


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes_home"
    home.mkdir()
    hermes.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    _reset()
    resolved = default_config_path()
    assert str(resolved).startswith(str(tmp_path)), resolved
    try:
        yield hermes, hermes / "credential-guard"
    finally:
        _reset()


def _mkstore(hermes: Path, mode: int = 0o700) -> Path:
    store = hermes / "credential-guard"
    store.mkdir(mode=mode, parents=True, exist_ok=True)
    os.chmod(store, mode)
    return store


def _write(path: Path, text: str, mode: int = 0o600) -> Path:
    path.write_text(text, encoding="utf-8")
    os.chmod(path, mode)
    return path


def _valid_doc(secret: str = CANARY) -> Dict[str, Any]:
    return {
        "version": 2,
        "credentials": {
            "api-token": {"type": "token", "value": secret},
            "report-token": {"type": "token", "value": secret + "_proc"},
        },
        "bindings": {
            "health-api": {
                "type": "http",
                "credential_ref": "api-token",
                "target": {"scheme": "https", "host": HOST_CANARY, "port": 443},
                "request": {
                    "allowed_methods": ["GET"],
                    "allowed_paths": [PATH_CANARY],
                },
                "inject": {
                    "type": "api_key_header",
                    "header_name": HEADER_CANARY,
                },
                "approval": "required",
            },
            "report-job": {
                "type": "process_env",
                "credential_ref": "report-token",
                "program": PROGRAM_CANARY,
                "argv": [PROGRAM_CANARY],
                "env_name": ENV_CANARY,
                "timeout_seconds": 10,
                "max_stdout_bytes": 4096,
                "max_stderr_bytes": 4096,
                "approval": "required",
            },
        },
    }


def _identity(path: Path) -> Tuple[int, int, str]:
    st = path.lstat()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return int(st.st_mtime_ns), int(st.st_size), digest


def _dir_listing(root: Path) -> List[str]:
    if not root.exists():
        return []
    return sorted(p.name for p in root.iterdir())


def _assert_zero_sensitive(blob: str, secret: str = CANARY) -> None:
    needles = (
        secret,
        secret + "_proc",
        HOST_CANARY,
        PROGRAM_CANARY,
        ENV_CANARY,
        PATH_CANARY,
        HEADER_CANARY,
        '"value"',
        "Traceback",
        "SYNTHETIC_C10_CANARY_",
    )
    for n in needles:
        assert n not in blob, f"leak: {n!r} in {blob!r}"


def _run_validate_args(
    *,
    file: Optional[str] = None,
    command: str = "validate",
) -> int:
    ns = argparse.Namespace(credential_guard_command=command)
    if file is not None:
        ns.file = file
    elif command == "validate":
        ns.file = None
    return handle_command(ns)


# ---------------------------------------------------------------------------
# 1. Happy path: http + process PASS lines, secret canary 0
# ---------------------------------------------------------------------------


def test_c10_valid_http_and_process_pass_lines(isolated_home, capsys):
    hermes, store = isolated_home
    _mkstore(hermes)
    path = store / CONFIG_FILENAME
    _write(path, json.dumps(_valid_doc()))

    rc = run_validate(None)
    out = capsys.readouterr()
    blob = out.out + out.err
    assert rc == 0
    lines = [ln for ln in out.out.splitlines() if ln.strip()]
    assert "PASS credential api-token" in lines
    assert "PASS credential report-token" in lines
    assert "PASS binding health-api" in lines
    assert "PASS binding report-job" in lines
    assert lines[-1] == "VALID"
    assert not any(ln.startswith("FAIL ") for ln in lines)
    _assert_zero_sensitive(blob)
    assert CANARY not in blob


# ---------------------------------------------------------------------------
# 2. Explicit path vs default path
# ---------------------------------------------------------------------------


def test_c10_explicit_path(isolated_home, tmp_path, capsys):
    hermes, _store = isolated_home
    # Explicit file lives in its own 0700 parent (not the default store).
    other = tmp_path / "other-store"
    other.mkdir(mode=0o700)
    os.chmod(other, 0o700)
    path = other / "alt.json"
    _write(path, json.dumps(_valid_doc()))

    rc = run_validate(str(path))
    out = capsys.readouterr()
    assert rc == 0
    assert "VALID" in out.out.splitlines()
    _assert_zero_sensitive(out.out + out.err)
    # Default store must remain absent — validate must not create it.
    assert not (hermes / "credential-guard").exists()


def test_c10_default_path(isolated_home, capsys):
    hermes, store = isolated_home
    _mkstore(hermes)
    path = store / CONFIG_FILENAME
    _write(path, json.dumps(_valid_doc()))
    assert path == default_config_path()

    rc = run_validate(None)
    out = capsys.readouterr()
    assert rc == 0
    assert out.out.strip().splitlines()[-1] == "VALID"
    _assert_zero_sensitive(out.out + out.err)


# ---------------------------------------------------------------------------
# 3. Fault matrix: accurate fixed codes, zero sensitive output
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fault,expected_code",
    [
        ("missing", "CONFIG_NOT_FOUND"),
        ("mode", "CONFIG_INSECURE_MODE"),
        ("symlink", "CONFIG_SYMLINK"),
        ("json", "CONFIG_INVALID_JSON"),
        ("duplicate", "CONFIG_DUPLICATE_KEY"),
        ("schema", "CONFIG_SCHEMA"),
        ("unknown", "CONFIG_SCHEMA"),
        ("bool_version", "CONFIG_SCHEMA"),
        ("name_secret_collision", "CONFIG_SCHEMA"),
        ("visible_secret_collision", "CONFIG_SCHEMA"),
    ],
)
def test_c10_fault_matrix_fixed_codes(
    isolated_home, tmp_path, capsys, fault, expected_code
):
    hermes, store = isolated_home
    _mkstore(hermes)
    path = store / CONFIG_FILENAME
    secret = CANARY

    if fault == "missing":
        pass
    elif fault == "mode":
        _write(path, json.dumps(_valid_doc(secret)), mode=0o644)
    elif fault == "symlink":
        real = tmp_path / "real.json"
        _write(real, json.dumps(_valid_doc(secret)))
        path.symlink_to(real)
    elif fault == "json":
        _write(path, "{not-json")
    elif fault == "duplicate":
        _write(
            path,
            '{"version":2,"credentials":{},"bindings":{},"credentials":{}}',
        )
    elif fault == "schema":
        _write(
            path,
            json.dumps(
                {
                    "version": 2,
                    "credentials": {"bad": {"type": "token"}},
                    "bindings": {},
                }
            ),
        )
    elif fault == "unknown":
        doc = _valid_doc(secret)
        doc["unexpected"] = True
        _write(path, json.dumps(doc))
    elif fault == "bool_version":
        doc = _valid_doc(secret)
        doc["version"] = True
        _write(path, json.dumps(doc))
    elif fault == "name_secret_collision":
        # Credential name equals another credential's secret (must be NAME_RE-valid).
        collision = "secretvalue12345"
        _write(
            path,
            json.dumps(
                {
                    "version": 2,
                    "credentials": {
                        "legit-token": {"type": "token", "value": collision},
                        collision: {
                            "type": "token",
                            "value": "othersecret99999",
                        },
                    },
                    "bindings": {},
                }
            ),
        )
        secret = collision
    elif fault == "visible_secret_collision":
        # Secret is a substring of a model-visible allowed_path.
        collision = "leakpath99"
        doc = {
            "version": 2,
            "credentials": {
                "api-token": {"type": "token", "value": collision},
            },
            "bindings": {
                "health-api": {
                    "type": "http",
                    "credential_ref": "api-token",
                    "target": {
                        "scheme": "https",
                        "host": HOST_CANARY,
                        "port": 443,
                    },
                    "request": {
                        "allowed_methods": ["GET"],
                        "allowed_paths": [f"/v1/{collision}/status"],
                    },
                    "inject": {
                        "type": "bearer",
                        "location": "authorization_header",
                    },
                    "approval": "required",
                }
            },
        }
        _write(path, json.dumps(doc))
        secret = collision
    else:
        raise AssertionError(fault)

    rc = run_validate(None)
    out = capsys.readouterr()
    blob = out.out + out.err
    assert rc == 1
    lines = [ln for ln in out.out.splitlines() if ln.strip()]
    assert len(lines) == 1, lines
    assert lines[0] == f"FAIL {expected_code} configuration"
    _assert_zero_sensitive(blob, secret=secret)
    assert secret not in blob
    assert HOST_CANARY not in blob
    assert str(path) not in blob
    assert "othersecret99999" not in blob
    assert "/v1/" not in blob


# ---------------------------------------------------------------------------
# 4. Monkeypatch: publish / catalog writer / Provider / adapter must not run
# ---------------------------------------------------------------------------


def test_c10_validate_never_publishes_or_writes_or_calls_adapters(
    isolated_home, monkeypatch, capsys
):
    hermes, store = isolated_home
    _mkstore(hermes)
    path = store / CONFIG_FILENAME
    _write(path, json.dumps(_valid_doc()))

    def _boom(label: str):
        def _inner(*_a, **_k):
            raise AssertionError(f"validate must not call {label}")

        return _inner

    monkeypatch.setattr(
        "credential_guard.runtime_config.load_and_publish_runtime",
        _boom("load_and_publish_runtime"),
    )
    monkeypatch.setattr(
        "credential_guard.runtime_config._publish",
        _boom("_publish"),
    )
    monkeypatch.setattr(
        "credential_guard.state.get_egress_registry_snapshot",
        _boom("get_egress_registry_snapshot"),
    )
    monkeypatch.setattr(
        "credential_guard.target_catalog.generate_and_write_target_catalog",
        _boom("generate_and_write_target_catalog"),
    )
    monkeypatch.setattr(
        "credential_guard.target_catalog.atomic_write_catalog",
        _boom("atomic_write_catalog"),
    )
    monkeypatch.setattr(
        "credential_guard.target_catalog.replace_config_and_refresh_targets",
        _boom("replace_config_and_refresh_targets"),
    )
    monkeypatch.setattr(
        "credential_guard.adapters.http.execute_http",
        _boom("http_adapter"),
    )
    monkeypatch.setattr(
        "credential_guard.adapters.process.execute_process",
        _boom("process_adapter"),
    )

    rc = run_validate(None)
    out = capsys.readouterr()
    assert rc == 0
    assert out.out.strip().splitlines()[-1] == "VALID"
    _assert_zero_sensitive(out.out + out.err)


# ---------------------------------------------------------------------------
# 5. File identity unchanged; directory has no new entries
# ---------------------------------------------------------------------------


def test_c10_validate_is_read_only_on_disk(isolated_home, capsys):
    hermes, store = isolated_home
    _mkstore(hermes)
    path = store / CONFIG_FILENAME
    _write(path, json.dumps(_valid_doc()))
    before_id = _identity(path)
    before_listing = _dir_listing(store)
    before_parent = _dir_listing(hermes)

    rc = run_validate(None)
    out = capsys.readouterr()
    assert rc == 0
    assert out.out.strip().splitlines()[-1] == "VALID"

    assert _identity(path) == before_id
    assert _dir_listing(store) == before_listing
    assert _dir_listing(hermes) == before_parent
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    _assert_zero_sensitive(out.out + out.err)


# ---------------------------------------------------------------------------
# 6. setup_parser + handle_command real dispatch
# ---------------------------------------------------------------------------


def test_c10_setup_parser_and_handle_command_dispatch(isolated_home, capsys):
    hermes, store = isolated_home
    _mkstore(hermes)
    path = store / CONFIG_FILENAME
    _write(path, json.dumps(_valid_doc()))

    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    cg = sub.add_parser("credential-guard")
    setup_parser(cg)

    # Default path via subcommand with no file arg.
    args = parser.parse_args(["credential-guard", "validate"])
    assert getattr(args, "credential_guard_command") == "validate"
    rc = handle_command(args)
    out = capsys.readouterr()
    assert rc == 0
    assert "PASS credential api-token" in out.out
    assert out.out.strip().splitlines()[-1] == "VALID"
    _assert_zero_sensitive(out.out + out.err)

    # Explicit path.
    other = store.parent / "alt-store"
    other.mkdir(mode=0o700)
    os.chmod(other, 0o700)
    alt = other / "cfg.json"
    _write(alt, json.dumps(_valid_doc(CANARY + "_alt")))
    args2 = parser.parse_args(["credential-guard", "validate", str(alt)])
    rc2 = handle_command(args2)
    out2 = capsys.readouterr()
    assert rc2 == 0
    assert out2.out.strip().splitlines()[-1] == "VALID"
    assert (CANARY + "_alt") not in (out2.out + out2.err)


def test_c10_safe_name_gate_uses_name_re():
    """PASS names must satisfy NAME_RE; defensive contract for the helper."""
    assert NAME_RE.fullmatch("api-token")
    assert not NAME_RE.fullmatch("Bad Name")
    assert not NAME_RE.fullmatch(CANARY)


def test_c10_usage_mentions_validate(capsys):
    rc = _run_validate_args(command="nope")
    out = capsys.readouterr().out
    assert rc == 1
    assert "validate" in out
    assert "check" in out
