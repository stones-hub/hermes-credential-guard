from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote, quote_plus

import pytest

from credential_guard.hooks import on_transform_tool_result
from credential_guard.result_guard import RESULT_GUARD_FAIL_TEXT
from credential_guard.state import get_registry


def _runtime_canary_with_specials() -> str:
    return "cg_" + secrets.token_hex(8) + "_p@ss 特殊"


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
    get_registry().clear()


def test_transform_tool_result_redacts_json_and_keeps_json_parseable():
    reg = get_registry()
    item = reg.register("api", "token", "decoy_token_ABC12345")
    raw = json.dumps({"result": "token=decoy_token_ABC12345"})
    redacted = on_transform_tool_result(result=raw, tool_name="dummy", arguments={})
    parsed = json.loads(redacted)
    assert parsed["result"] == f"token={item.token}"
    assert "decoy_token_ABC12345" not in redacted
    assert "<CREDENTIAL:" not in redacted
    assert item.token in redacted


def test_transform_tool_result_redacts_plain_string():
    reg = get_registry()
    item = reg.register("db", "password", "decoy_password_QWER1234")
    out = on_transform_tool_result(
        result="error decoy_password_QWER1234",
        tool_name="dummy",
        arguments={},
    )
    assert out == f"error {item.token}"


def test_transform_tool_result_failure_returns_safe_message_without_secret(monkeypatch):
    reg = get_registry()
    reg.register("db", "password", "decoy_password_QWER1234")

    def boom(*_args, **_kwargs):
        raise RuntimeError("decode decoy_password_QWER1234")

    monkeypatch.setattr("credential_guard.result_guard.redact_registered", boom)
    out = on_transform_tool_result(result="raw", tool_name="dummy", arguments={})
    assert out == RESULT_GUARD_FAIL_TEXT
    assert "decoy_password_QWER1234" not in out
    assert out.count("decoy_password_QWER1234") == 0


def test_transform_tool_result_failure_mutation_legacy_json_is_red(monkeypatch):
    """Mutation: legacy SAFE JSON body must not pass as R4 fail-closed."""
    reg = get_registry()
    reg.register("db", "password", "decoy_password_QWER1234")

    def boom(*_args, **_kwargs):
        raise RuntimeError("decode decoy_password_QWER1234")

    monkeypatch.setattr("credential_guard.result_guard.redact_registered", boom)
    out = on_transform_tool_result(result="raw", tool_name="dummy", arguments={})
    assert out == RESULT_GUARD_FAIL_TEXT
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


def test_t1_tool_result_redacts_percent_and_quote_plus_variants():
    canary = _runtime_canary_with_specials()
    pct = quote(canary, safe="")
    qp = quote_plus(canary)
    reg = get_registry()
    item = reg.register("db", "password", canary)

    out_pct = on_transform_tool_result(
        result=f"leak {pct}", tool_name="dummy", arguments={}
    )
    out_qp = on_transform_tool_result(
        result=f"leak {qp}", tool_name="dummy", arguments={}
    )
    assert canary not in out_pct and pct not in out_pct
    assert canary not in out_qp and qp not in out_qp
    assert item.token in out_pct
    assert item.token in out_qp
    assert "<CREDENTIAL:" not in out_pct
    assert "<CREDENTIAL:" not in out_qp


def test_hooks_failclosed_log_global_stderr_backpressure_caller_finishes(tmp_path):
    """Outer transform_tool_result fail-closed must not stall on blocked stderr.

    Triggers the real hooks outer catch (registry snapshot boom), with global
    ``sys.stderr`` permanently blocked and no logger handlers so lastResort is
    the write path. Caller must finish with exact RESULT_GUARD_FAIL_TEXT.
    """
    repo = Path(__file__).resolve().parents[1]
    marker = tmp_path / "hooks_fc_stderr_marker"
    status = tmp_path / "hooks_fc_stderr_status"
    script = f"""
import logging
import os
import sys
import tempfile
import threading
from pathlib import Path

repo = {str(repo)!r}
sys.path.insert(0, repo)
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
os.environ["PYTHONPATH"] = repo

home = Path(tempfile.mkdtemp()) / "home"
hermes = Path(tempfile.mkdtemp()) / "hermes"
home.mkdir(parents=True)
hermes.mkdir(parents=True)
store = hermes / "credential-guard"
store.mkdir(mode=0o700)
os.chmod(store, 0o700)
cfg = store / "credential-guard.json"
cfg.write_text('{{"version": 2, "credentials": {{}}, "bindings": {{}}}}', encoding="utf-8")
os.chmod(cfg, 0o600)
os.environ["HOME"] = str(home)
os.environ["HERMES_HOME"] = str(hermes)

from credential_guard.hooks import on_transform_tool_result
from credential_guard.result_guard import RESULT_GUARD_FAIL_TEXT
from credential_guard.state import get_registry

get_registry().clear()

cg_log = logging.getLogger("credential_guard")
cg_log.handlers.clear()
cg_log.propagate = True
logging.root.handlers.clear()

entered = threading.Event()
never = threading.Event()


class BlockingStderr:
    def write(self, data):
        entered.set()
        never.wait()
        return len(data) if data else 0

    def flush(self):
        return None

    def isatty(self):
        return False

    def fileno(self):
        raise OSError("no fileno")


sys.stderr = BlockingStderr()

decoy = "HOOKS_FC_DECOY_NEVER_ECHO_99"
run_done = threading.Event()
result_box = []
errors = []


def boom(*_a, **_k):
    raise RuntimeError(f"snapshot boom {{decoy}}")


import credential_guard.hooks as hooks_mod
hooks_mod.get_egress_registry_snapshot = boom

def run():
    try:
        result_box.append(
            on_transform_tool_result(
                result=f"leak {{decoy}}",
                tool_name="dummy",
                arguments={{}},
            )
        )
    except Exception as exc:  # pragma: no cover
        errors.append(repr(exc))
    finally:
        run_done.set()


t = threading.Thread(target=run, daemon=True)
t.start()

status_path = Path({str(status)!r})
marker_path = Path({str(marker)!r})

if not entered.wait(timeout=3.0):
    status_path.write_text("WRITE_NOT_ENTERED", encoding="utf-8")
    os._exit(3)
if not run_done.wait(timeout=2.0):
    status_path.write_text("CALLER_STALLED", encoding="utf-8")
    os._exit(2)
if errors:
    status_path.write_text("RUN_ERROR:" + ";".join(errors), encoding="utf-8")
    os._exit(4)
if not result_box:
    status_path.write_text("NO_RESULT", encoding="utf-8")
    os._exit(5)
out = result_box[0]
if out != RESULT_GUARD_FAIL_TEXT:
    status_path.write_text("RESULT_MISMATCH:" + repr(out)[:200], encoding="utf-8")
    os._exit(6)
if decoy in out:
    status_path.write_text("DECOY_ECHO", encoding="utf-8")
    os._exit(7)
if "snapshot boom" in out:
    status_path.write_text("EXC_ECHO", encoding="utf-8")
    os._exit(8)

marker_path.write_text("PASS", encoding="utf-8")
status_path.write_text("PASS", encoding="utf-8")
os._exit(0)
"""
    env = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(repo),
    }
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(repo),
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    status_text = status.read_text(encoding="utf-8") if status.exists() else "<missing>"
    assert proc.returncode == 0, (
        f"rc={proc.returncode} status={status_text!r}\n"
        f"stdout={proc.stdout[-2000:]}\nstderr={proc.stderr[-2000:]}"
    )
    assert marker.read_text(encoding="utf-8") == "PASS"
    assert status_text == "PASS"
