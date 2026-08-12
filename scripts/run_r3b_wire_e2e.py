#!/usr/bin/env python3
"""R3B wire E2E — public AIAgent + loopback OpenAI-compatible provider.

Candidate evidence only. Does not claim R3B/R3 PASS.
Captures *full* raw provider HTTP request bytes (request line + headers + body)
and approval raw reason/kwargs. Installs fail-closed loopback socket guards
before Agent/network imports. Uses a minimal env whitelist (never clone the
full process environment mapping).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO = Path(__file__).resolve().parents[1]
HERMES_AGENT_ROOT = Path(
    os.environ.get("HERMES_AGENT_ROOT", "/tmp/credential-guard-r2-hermes-source")
)
HERMES_SPIKE_PYTHON = Path(
    os.environ.get(
        "HERMES_SPIKE_PYTHON",
        "/tmp/credential-guard-r2-hermes-venv/bin/python",
    )
)

DECOY_ENV = "CG_R3B_WIRE_ENV_" + "e" * 24
DECOY_STDIN = "CG_R3B_WIRE_STDIN_" + "s" * 24


def _minimal_child_env(home: Path, hermes: Path, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Strict whitelist — never clone the full process environment mapping."""
    env = {
        "PATH": os.environ.get("PATH") or "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": os.environ.get("LANG") or "C",
        "LC_ALL": os.environ.get("LC_ALL") or "C",
        "TMPDIR": str(home / "tmp"),
        "TMP": str(home / "tmp"),
        "TEMP": str(home / "tmp"),
        "HOME": str(home),
        "HERMES_HOME": str(hermes),
        "HERMES_AGENT_ROOT": str(HERMES_AGENT_ROOT),
        "PYTHONPATH": str(HERMES_AGENT_ROOT),
        "CG_REPO": str(REPO),
    }
    if extra:
        env.update(extra)
    return env


def _env_construction_used_copy(source: str) -> bool:
    """Derive used_environ_copy from authenticity/env-construction facts."""
    patterns = (
        r"os\.environ\.copy\s*\(",
        r"dict\s*\(\s*os\.environ\s*\)",
        r"os\.environ\s*\|",
    )
    return any(re.search(p, source) for p in patterns)


def _install_plugin(hermes: Path) -> None:
    root = hermes / "plugins" / "credential-guard"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    shutil.copy2(REPO / "plugin.yaml", root / "plugin.yaml")
    shutil.copy2(REPO / "__init__.py", root / "__init__.py")
    shutil.copytree(REPO / "credential_guard", root / "credential_guard")
    man = (root / "plugin.yaml").read_text(encoding="utf-8")
    if "credential_process_run" not in man:
        (root / "plugin.yaml").write_text(
            man.rstrip() + "\n  - credential_process_run\n", encoding="utf-8"
        )


def _write_helpers(helper_dir: Path) -> Tuple[Path, Path]:
    env_h = helper_dir / "cg-env-probe"
    env_h.write_text(
        textwrap.dedent(
            """\
            #!/bin/sh
            MARK="$1"
            VAL="${CG_PROBE_ENV-}"
            if [ -z "$VAL" ]; then
              printf 'absent' > "$MARK"
            else
              printf '%s' "$VAL" | openssl dgst -sha256 -hex | awk '{last=""; for(i=1;i<=NF;i++) if($i~/^[0-9a-fA-F]{64}$/) last=$i; if(last!="") print last}' > "$MARK"
            fi
            printf 'ok\\n'
            """
        ),
        encoding="utf-8",
    )
    os.chmod(env_h, 0o700)
    stdin_h = helper_dir / "cg-stdin-probe"
    stdin_h.write_text(
        textwrap.dedent(
            """\
            #!/bin/sh
            MARK="$1"
            VAL=$(cat)
            if [ -z "$VAL" ]; then
              printf 'absent' > "$MARK"
            else
              printf '%s' "$VAL" | openssl dgst -sha256 -hex | awk '{last=""; for(i=1;i<=NF;i++) if($i~/^[0-9a-fA-F]{64}$/) last=$i; if(last!="") print last}' > "$MARK"
            fi
            printf 'ok\\n'
            """
        ),
        encoding="utf-8",
    )
    os.chmod(stdin_h, 0o700)
    return env_h, stdin_h


def _write_config(
    hermes: Path,
    *,
    env_program: Path,
    env_marker: Path,
    stdin_program: Path,
    stdin_marker: Path,
    decoy_env: str,
    decoy_stdin: str,
) -> None:
    store = hermes / "credential-guard"
    store.mkdir(parents=True, exist_ok=True)
    os.chmod(store, 0o700)
    doc = {
        "version": 2,
        "credentials": {
            "cli_token": {"type": "token", "value": decoy_env},
            "stdin_token": {"type": "token", "value": decoy_stdin},
        },
        "bindings": {
            "cli-env": {
                "type": "process_env",
                "credential_ref": "cli_token",
                "program": str(env_program),
                "argv": [str(env_program), str(env_marker)],
                "env_name": "CG_PROBE_ENV",
                "timeout_seconds": 10,
                "max_stdout_bytes": 4096,
                "max_stderr_bytes": 4096,
                "approval": "required",
            },
            "cli-stdin": {
                "type": "stdin",
                "credential_ref": "stdin_token",
                "program": str(stdin_program),
                "argv": [str(stdin_program), str(stdin_marker)],
                "stdin_format": "raw",
                "timeout_seconds": 10,
                "max_stdout_bytes": 4096,
                "max_stderr_bytes": 4096,
                "approval": "required",
            },
        },
    }
    cfg = store / "credential-guard.json"
    cfg.write_text(json.dumps(doc), encoding="utf-8")
    os.chmod(cfg, 0o600)
    (hermes / "config.yaml").write_text(
        textwrap.dedent(
            """\
            model: fake-model
            approvals:
              mode: "manual"
              timeout: 300
            plugins:
              enabled:
                - credential-guard
            tools:
              tool_search:
                enabled: off
            """
        ),
        encoding="utf-8",
    )


PROBE = textwrap.dedent(
    r"""
import hashlib
import ipaddress
import json
import os
import socket
import sys
import threading
import types
from pathlib import Path
from unittest.mock import patch

scenario = os.environ["CG_SCENARIO"]  # env_approve|stdin_approve|env_deny|stdin_deny|net_probe
token_env = os.environ["CG_DECOY_ENV"]
token_stdin = os.environ["CG_DECOY_STDIN"]
target = os.environ.get("CG_TARGET", "cli-env")
cred_ref = os.environ.get("CG_CRED_REF", "<CREDENTIAL:cli_token>")
token = token_env if target == "cli-env" else token_stdin
marker = Path(os.environ.get("CG_MARKER", "/tmp/unused"))
approve = scenario.endswith("_approve")
net_probe_only = scenario == "net_probe"

# --- fail-closed loopback socket guard + independent original bomb/spy ---
# Install BOTH layers BEFORE any Agent/network import.
_net_audit = {
    "attempts": 0,
    "loopback_allowed_calls": 0,
    "non_loopback_original_calls": 0,
    "violations": 0,
    "blocked_categories": [],
}
_ORIG_CONNECT = socket.socket.connect
_ORIG_CONNECT_EX = socket.socket.connect_ex
_ORIG_CREATE_CONNECTION = socket.create_connection
_ORIG_GETADDRINFO = socket.getaddrinfo
# Policy guard layer may be disabled for runtime mutation evidence only.
_GUARD_ENABLED = os.environ.get("CG_NET_GUARD_ENABLED", "1") != "0"

def _peer_host_port(address):
    if isinstance(address, tuple) and address:
        host = address[0]
        port = int(address[1]) if len(address) > 1 else 0
        if isinstance(host, bytes):
            host = host.decode("utf-8", "replace")
        if isinstance(host, str):
            return host, port
    return None

def _is_loopback(host: str) -> bool:
    h = host.strip().lower().strip("[]")
    if h in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False

def _classify_and_gate(address, kind: str):
    parsed = _peer_host_port(address)
    if parsed is None:
        # AF_UNIX / non-IP — left alone (same policy as hermes_loopback_launcher).
        return
    host, port = parsed
    _net_audit["attempts"] += 1
    if _is_loopback(host):
        _net_audit["loopback_allowed_calls"] += 1
        return
    # Non-loopback: reject BEFORE original/bomb primitive; never record secrets.
    _net_audit["violations"] += 1
    cat = "test_net" if host.startswith("203.0.113.") else "non_loopback"
    _net_audit["blocked_categories"].append(cat)
    raise OSError("credential-guard net guard blocked non-loopback peer")

def _bomb_record_and_maybe_block(address):
    # Independent original-primitive spy/bomb — never performs non-loopback syscall.
    parsed = _peer_host_port(address)
    if parsed is None:
        return False  # AF_UNIX: allow forwarding to real primitive
    host, _port = parsed
    if _is_loopback(host):
        return False  # loopback: forward to real primitive
    _net_audit["non_loopback_original_calls"] += 1
    raise OSError("credential-guard net bomb blocked non-loopback original")

def _bomb_connect(self, address):
    _bomb_record_and_maybe_block(address)
    return _ORIG_CONNECT(self, address)

def _bomb_connect_ex(self, address):
    import errno as _errno
    try:
        _bomb_record_and_maybe_block(address)
    except OSError:
        return _errno.EPERM
    return _ORIG_CONNECT_EX(self, address)

def _bomb_create_connection(address, *args, **kwargs):
    _bomb_record_and_maybe_block(address)
    return _ORIG_CREATE_CONNECTION(address, *args, **kwargs)

def _bomb_getaddrinfo(host, port, *args, **kwargs):
    # Resolved IPs are audited at connect time; still refuse non-loopback hostnames
    # at this layer when they would otherwise reach the real resolver.
    if isinstance(host, str) and host and not _is_loopback(host):
        try:
            ipaddress.ip_address(host.strip().lower().strip("[]"))
        except ValueError:
            _net_audit["non_loopback_original_calls"] += 1
            raise OSError("credential-guard net bomb blocked hostname resolution")
    return _ORIG_GETADDRINFO(host, port, *args, **kwargs)

def _guard_connect(self, address):
    _classify_and_gate(address, "connect")
    return _bomb_connect(self, address)

def _guard_connect_ex(self, address):
    import errno as _errno
    try:
        _classify_and_gate(address, "connect_ex")
    except OSError:
        return _errno.EPERM
    return _bomb_connect_ex(self, address)

def _guard_create_connection(address, *args, **kwargs):
    _classify_and_gate(address, "create_connection")
    return _bomb_create_connection(address, *args, **kwargs)

def _guard_getaddrinfo(host, port, *args, **kwargs):
    # Allow loopback name resolution; reject obvious non-loopback hostnames in policy.
    if isinstance(host, str) and host and not _is_loopback(host):
        try:
            ipaddress.ip_address(host.strip().lower().strip("[]"))
            # Numeric non-loopback IP — let connect gate reject later.
            pass
        except ValueError:
            _net_audit["attempts"] += 1
            _net_audit["violations"] += 1
            _net_audit["blocked_categories"].append("hostname")
            raise OSError("credential-guard net guard blocked hostname resolution")
    return _bomb_getaddrinfo(host, port, *args, **kwargs)

if _GUARD_ENABLED:
    socket.socket.connect = _guard_connect
    socket.socket.connect_ex = _guard_connect_ex
    socket.create_connection = _guard_create_connection
    socket.getaddrinfo = _guard_getaddrinfo
else:
    # Runtime mutation path: policy guard bypassed; bomb/spy still installed.
    socket.socket.connect = _bomb_connect
    socket.socket.connect_ex = _bomb_connect_ex
    socket.create_connection = _bomb_create_connection
    socket.getaddrinfo = _bomb_getaddrinfo

if net_probe_only:
    # Explicit TEST-NET attempt must be rejected before real syscall.
    blocked = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(0.2)
            s.connect(("203.0.113.1", 9))
        finally:
            s.close()
    except OSError:
        blocked = True
    # Derived metrics — never constant True / never violations>=0 tautology.
    loopback_only = (
        _net_audit["attempts"] > 0
        and _net_audit["non_loopback_original_calls"] == 0
        and _net_audit["violations"] > 0
        and blocked
        and _GUARD_ENABLED
    )
    print(json.dumps({
        "scenario": scenario,
        "net_attempts": _net_audit["attempts"],
        "net_violations": _net_audit["violations"],
        "non_loopback_original_calls": _net_audit["non_loopback_original_calls"],
        "blocked_categories": list(_net_audit["blocked_categories"]),
        "test_net_blocked_before_original": bool(
            blocked and _net_audit["non_loopback_original_calls"] == 0 and _GUARD_ENABLED
        ),
        "guard_enabled": bool(_GUARD_ENABLED),
        "loopback_only": bool(loopback_only),
    }, sort_keys=True))
    raise SystemExit(0)

sys.path.insert(0, os.environ["HERMES_AGENT_ROOT"])
for _name in ("modal", "anthropic", "firecrawl", "exa_py", "fal_client"):
    sys.modules.setdefault(_name, types.ModuleType(_name))

raw_requests = []  # list[bytes] — full raw HTTP request (line+headers+body)
approval_raw = []  # list of {reason, kwargs} raw captures

def _read_exact(conn, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(min(65536, n - len(buf)))
        if not chunk:
            break
        buf += chunk
    return buf

def _handle_client(conn, addr):
    try:
        conn.settimeout(30.0)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 1_048_576:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
        if b"\r\n\r\n" not in buf:
            return
        header_blob, rest = buf.split(b"\r\n\r\n", 1)
        # Parse Content-Length (bounded).
        content_length = 0
        for line in header_blob.split(b"\r\n")[1:]:
            if b":" not in line:
                continue
            k, v = line.split(b":", 1)
            if k.strip().lower() == b"content-length":
                try:
                    content_length = int(v.strip())
                except ValueError:
                    content_length = 0
                break
        content_length = max(0, min(content_length, 2_000_000))
        body = rest
        if len(body) < content_length:
            body += _read_exact(conn, content_length - len(body))
        body = body[:content_length]
        raw = header_blob + b"\r\n\r\n" + body
        raw_requests.append(raw)
        req = {}
        try:
            req = json.loads(body.decode("utf-8", errors="replace"))
        except Exception:
            req = {}
        msgs = req.get("messages") or []
        has_tool = any(isinstance(m, dict) and m.get("role") == "tool" for m in msgs)
        if not has_tool:
            args = json.dumps({"target": target, "credential": cred_ref}, separators=(",", ":"))
            resp = {
                "id": "c1", "object": "chat.completion", "created": 1, "model": "fake-model",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": None,
                    "tool_calls": [{"id": "call_1", "type": "function",
                        "function": {"name": "credential_process_run", "arguments": args}}]},
                    "finish_reason": "tool_calls"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        else:
            resp = {
                "id": "c2", "object": "chat.completion", "created": 1, "model": "fake-model",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "done"},
                             "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        data = json.dumps(resp).encode()
        header = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(data)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        conn.sendall(header + data)
    finally:
        try:
            conn.close()
        except Exception:
            pass

_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
_srv.bind(("127.0.0.1", 0))
_srv.listen(16)
_port = _srv.getsockname()[1]
_stop = threading.Event()

def _serve():
    _srv.settimeout(0.5)
    while not _stop.is_set():
        try:
            c, a = _srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=_handle_client, args=(c, a), daemon=True).start()

_th = threading.Thread(target=_serve, daemon=True)
_th.start()
base = f"http://127.0.0.1:{_port}/v1"

def gate(tool_name, reason, **kwargs):
    approval_raw.append({
        "tool_name": tool_name,
        "reason": reason,
        "kwargs": dict(kwargs),
    })
    if approve:
        return {"approved": True, "message": None}
    return {"approved": False, "message": "DENIED: r3b-wire"}

import hermes_cli.plugins as plugins_mod
plugins_mod._plugin_manager = None
from hermes_cli.plugins import discover_plugins
discover_plugins(force=True)

import hermes_plugins.credential_guard.credential_guard.runtime_config as rc
import hermes_plugins.credential_guard.credential_guard.tool_request as tr
import hermes_plugins.credential_guard.credential_guard.adapters.process as proc_mod

rc.reset_runtime_for_tests()
tr.reset_tool_request_state_for_tests()
rc.load_and_publish_runtime()
rc.reset_execution_secret_resolve_count_for_tests()
rc.reset_injection_secret_resolve_count_for_tests()
proc_mod.reset_process_start_count_for_tests()
inj_before = rc.get_injection_secret_resolve_count()
start_before = proc_mod.process_start_count()

from run_agent import AIAgent
with patch("tools.approval.request_tool_approval", side_effect=gate):
    agent = AIAgent(
        api_key="sk-synthetic-r3b-wire-only",
        base_url=base,
        model="fake-model",
        provider="custom",
        api_mode="chat_completions",
        max_iterations=4,
        quiet_mode=True,
        skip_context_files=True,
        skip_memory=True,
        enabled_toolsets=["credential_guard"],
    )
    agent._disable_streaming = True
    result = agent.run_conversation("Please invoke the configured credential process tool once.")

_stop.set()
try:
    _srv.close()
except Exception:
    pass

final = result.get("final_response") if isinstance(result, dict) else str(result)
blob = json.dumps(result, default=str) if not isinstance(result, str) else result
approval_blob = json.dumps(approval_raw, default=str)
raw_join = b"\n".join(raw_requests)

# Mechanical raw HTTP shape facts (do not persist raw bytes).
raw_http_has_request_line = 0
raw_http_has_headers = 0
raw_http_has_body = 0
for b in raw_requests:
    if b.startswith(b"POST ") or b.startswith(b"GET ") or b.startswith(b"PUT "):
        raw_http_has_request_line += 1
    if b"\r\nHost:" in b or b"\r\nhost:" in b or b"Content-Length:" in b or b"content-length:" in b:
        raw_http_has_headers += 1
    if b"\r\n\r\n" in b and len(b.split(b"\r\n\r\n", 1)[1]) > 0:
        raw_http_has_body += 1

marker_ok = False
if marker.is_file():
    expected = hashlib.sha256(token.encode("utf-8")).hexdigest()
    marker_ok = marker.read_text(encoding="utf-8").strip() == expected

turns = 0
for b in raw_requests:
    try:
        body = b.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in b else b
        j = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        continue
    msgs = j.get("messages") or []
    if any(isinstance(m, dict) and m.get("role") == "tool" for m in msgs):
        turns = max(turns, 2)
    else:
        turns = max(turns, 1)

wire_secret_count = (
    raw_join.count(token.encode("utf-8"))
    + approval_blob.count(token)
    + blob.count(token)
)

# Derive loopback_only from audit events — never a constant True assignment.
loopback_only = (
    _net_audit["attempts"] > 0
    and _net_audit["non_loopback_original_calls"] == 0
    and _net_audit["violations"] == 0
)

print(json.dumps({
    "scenario": scenario,
    "provider_raw_request_count": len(raw_requests),
    "provider_logical_turns": turns,
    "approval_raw_count": len(approval_raw),
    "approval_raw_has_reason": bool(approval_raw and isinstance(approval_raw[0].get("reason"), str)),
    "approval_raw_kwargs_keys": sorted(approval_raw[0]["kwargs"].keys()) if approval_raw else [],
    "marker_ok": marker_ok,
    "process_start_delta": proc_mod.process_start_count() - start_before,
    "injection_resolve_delta": rc.get_injection_secret_resolve_count() - inj_before,
    "wire_secret_count": int(wire_secret_count),
    "token_in_provider_raw": int(token.encode("utf-8") in raw_join),
    "token_in_approval_raw": int(token in approval_blob),
    "token_in_result": int(token in blob),
    "final_preview": (final if isinstance(final, str) else str(final))[:200],
    "raw_http_has_request_line": int(raw_http_has_request_line),
    "raw_http_has_headers": int(raw_http_has_headers),
    "raw_http_has_body": int(raw_http_has_body),
    "net_attempts": int(_net_audit["attempts"]),
    "net_loopback_allowed_calls": int(_net_audit["loopback_allowed_calls"]),
    "non_loopback_original_calls": int(_net_audit["non_loopback_original_calls"]),
    "net_violations": int(_net_audit["violations"]),
    "loopback_only": bool(loopback_only),
}, sort_keys=True))
"""
)


def _run_scenario(
    scenario: str,
    *,
    home: Path,
    hermes: Path,
    helper_dir: Path,
    env_marker: Path,
    stdin_marker: Path,
    guard_enabled: bool = True,
) -> dict:
    if scenario == "net_probe":
        target, cred, marker = "cli-env", "<CREDENTIAL:cli_token>", env_marker
    elif scenario.startswith("env_"):
        target, cred, marker = "cli-env", "<CREDENTIAL:cli_token>", env_marker
    else:
        target, cred, marker = "cli-stdin", "<CREDENTIAL:stdin_token>", stdin_marker
    env = _minimal_child_env(
        home,
        hermes,
        {
            "CG_SCENARIO": scenario,
            "CG_DECOY_ENV": DECOY_ENV,
            "CG_DECOY_STDIN": DECOY_STDIN,
            "CG_TARGET": target,
            "CG_CRED_REF": cred,
            "CG_MARKER": str(marker),
            "CG_NET_GUARD_ENABLED": "1" if guard_enabled else "0",
        },
    )
    for k in list(env):
        lk = k.lower()
        if lk.endswith("_proxy") or lk in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}:
            env.pop(k, None)
    proc = subprocess.run(
        [str(HERMES_SPIKE_PYTHON), "-c", PROBE],
        cwd=str(home),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if proc.returncode != 0 and scenario != "net_probe":
        raise RuntimeError(
            f"wire probe failed rc={proc.returncode}\nSTDERR:\n{proc.stderr[-4000:]}\nSTDOUT:\n{proc.stdout[-2000:]}"
        )
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip().startswith("{")]
    if not lines:
        raise RuntimeError(
            f"no json evidence\nSTDERR:\n{proc.stderr[-3000:]}\nSTDOUT:\n{proc.stdout[-2000:]}"
        )
    data = json.loads(lines[-1])
    # Derive used_environ_copy from harness source authenticity scan — never constant.
    harness_src = Path(__file__).read_text(encoding="utf-8") + "\n" + PROBE
    data["used_environ_copy"] = bool(_env_construction_used_copy(harness_src))
    return data


def run_net_probe(
    work: Path,
    *,
    guard_enabled: bool = True,
) -> Dict[str, Any]:
    """Same runtime net_probe path used by wire E2E — for guard on/off mutation evidence."""
    home = work / "home"
    hermes = work / "hermes"
    helper_dir = work / "helper"
    home.mkdir(parents=True, exist_ok=True)
    hermes.mkdir(parents=True, exist_ok=True)
    helper_dir.mkdir(mode=0o700, exist_ok=True)
    (home / "tmp").mkdir(exist_ok=True)
    if not (hermes / "plugins" / "credential-guard").exists():
        _install_plugin(hermes)
    env_h, stdin_h = _write_helpers(helper_dir)
    env_marker = helper_dir / "mark.env"
    stdin_marker = helper_dir / "mark.stdin"
    if not (hermes / "credential-guard" / "credential-guard.json").exists():
        _write_config(
            hermes,
            env_program=env_h,
            env_marker=env_marker,
            stdin_program=stdin_h,
            stdin_marker=stdin_marker,
            decoy_env=DECOY_ENV,
            decoy_stdin=DECOY_STDIN,
        )
    return _run_scenario(
        "net_probe",
        home=home,
        hermes=hermes,
        helper_dir=helper_dir,
        env_marker=env_marker,
        stdin_marker=stdin_marker,
        guard_enabled=guard_enabled,
    )


def run_all(work: Path) -> Dict[str, Any]:
    home = work / "home"
    hermes = work / "hermes"
    helper_dir = work / "helper"
    home.mkdir(parents=True)
    hermes.mkdir(parents=True)
    helper_dir.mkdir(mode=0o700)
    (home / "tmp").mkdir()
    _install_plugin(hermes)
    env_h, stdin_h = _write_helpers(helper_dir)
    env_marker = helper_dir / "mark.env"
    stdin_marker = helper_dir / "mark.stdin"
    _write_config(
        hermes,
        env_program=env_h,
        env_marker=env_marker,
        stdin_program=stdin_h,
        stdin_marker=stdin_marker,
        decoy_env=DECOY_ENV,
        decoy_stdin=DECOY_STDIN,
    )
    out: Dict[str, Any] = {}
    for scenario in ("env_approve", "stdin_approve", "env_deny", "stdin_deny", "net_probe"):
        for m in (env_marker, stdin_marker):
            if m.exists():
                m.unlink()
        out[scenario] = _run_scenario(
            scenario,
            home=home,
            hermes=hermes,
            helper_dir=helper_dir,
            env_marker=env_marker,
            stdin_marker=stdin_marker,
        )
    return out


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="r3b-wire-"))
    try:
        results = run_all(work)
        # Summarize without dumping raw request bytes or decoy tokens.
        safe = {
            k: {
                kk: vv
                for kk, vv in v.items()
                if kk
                not in {
                    "final_preview",
                }
            }
            for k, v in results.items()
        }
        print(json.dumps({"ok": True, "results": safe}, sort_keys=True, indent=2))
        for name in ("env_approve", "stdin_approve"):
            r = results[name]
            assert r["wire_secret_count"] == 0
            assert r["marker_ok"] is True
            assert r["process_start_delta"] == 1
            assert r["provider_logical_turns"] >= 2
            assert r["approval_raw_count"] >= 1
            assert r["used_environ_copy"] is False
            assert r["loopback_only"] is True
            assert r["raw_http_has_request_line"] >= 1
            assert r["raw_http_has_headers"] >= 1
            assert r["raw_http_has_body"] >= 1
        for name in ("env_deny", "stdin_deny"):
            r = results[name]
            assert r["process_start_delta"] == 0
            assert r["injection_resolve_delta"] == 0
            assert r["wire_secret_count"] == 0
        np = results["net_probe"]
        assert np["test_net_blocked_before_original"] is True
        assert np["net_violations"] >= 1
        assert np["non_loopback_original_calls"] == 0
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": type(exc).__name__}, sort_keys=True))
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
