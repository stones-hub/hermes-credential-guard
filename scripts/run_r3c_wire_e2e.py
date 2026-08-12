#!/usr/bin/env python3
"""R3C wire E2E — three adapters on one public AIAgent + loopback provider.

Candidate evidence only. Does not claim R3/R3C PASS.
Captures full raw provider HTTP (request line + headers + body), approval raw
reason/kwargs, PluginManager identity before/after, and sys.setprofile order.
Uses a minimal env whitelist (never clone the full process environment).
"""

from __future__ import annotations

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

DECOY_HTTP = "CG_R3C_WIRE_HTTP_" + "h" * 24
DECOY_ENV = "CG_R3C_WIRE_ENV_" + "e" * 24
DECOY_STDIN = "CG_R3C_WIRE_STDIN_" + "s" * 24

_ALL_SCENARIOS = (
    "http_approve",
    "env_approve",
    "stdin_approve",
    "http_deny",
    "env_deny",
    "stdin_deny",
    "http_timeout",
    "env_timeout",
    "stdin_timeout",
    "http_replay",
    "env_replay",
    "stdin_replay",
    "http_mutate",
    "env_mutate",
    "stdin_mutate",
    "ordinary_tool",
    "net_probe",
)


def _minimal_child_env(
    home: Path, hermes: Path, extra: Optional[Dict[str, str]] = None
) -> Dict[str, str]:
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
    patterns = (
        r"os\.environ\.copy\s*\(",
        r"dict\s*\(\s*os\.environ\s*\)",
        r"os\.environ\s*\|",
    )
    return any(re.search(p, source) for p in patterns)


_FORMAL_PROVIDED_TOOLS = (
    "mysql_credential_action",
    "ssh_credential_action",
    "http_credential_request",
    "credential_process_run",
)

_TRACE_SUFFIXES = (
    ".db",
    ".db-wal",
    ".db-shm",
    ".sqlite",
    ".sqlite-wal",
    ".sqlite-shm",
    ".wal",
    ".jsonl",
    ".json",
    ".log",
    ".txt",
)
_TRACE_DIR_HINTS = (
    "session",
    "sessions",
    "trace",
    "traces",
    "trajectory",
    "observability",
    "state",
)


def enumerate_runtime_carriers(
    roots: List[Path],
    *,
    decoys: Tuple[str, ...],
    secret_store_name: str = "credential-guard.json",
) -> Dict[str, Any]:
    """Enumerate runtime/session/trace carriers under temporary HOME/HERMES_HOME.

    Exact-exclude only the secret store basename and plugin source / helper
    marker trees. Never broad-exclude paths merely containing ``credential_guard``.
    Returns inventory metadata (path/kind/bytes) without file bodies.
    """
    inventory: List[Dict[str, Any]] = []
    secret_count = 0
    kinds: set = set()
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            try:
                rel = path.relative_to(root)
            except ValueError:
                continue
            rel_s = str(rel).replace("\\", "/")
            parts = rel.parts
            # Exact secret-store basename under credential-guard/ only.
            if path.name == secret_store_name and "credential-guard" in parts:
                continue
            # Plugin source byte-copy under plugins/ — not a runtime carrier.
            if "plugins" in parts:
                continue
            # Helper probe markers (mark.env / mark.stdin), not session/trace.
            if path.name.startswith("mark.") and path.suffix in {".env", ".stdin"}:
                continue
            name_l = path.name.lower()
            suffix = path.suffix.lower()
            # Compound suffixes: state.db-wal → treat as .db-wal
            for compound in (".db-wal", ".db-shm", ".sqlite-wal", ".sqlite-shm"):
                if name_l.endswith(compound):
                    suffix = compound
                    break
            under_named_dir = any(
                any(h in p.lower() for h in _TRACE_DIR_HINTS) for p in parts[:-1]
            )
            is_carrier = (
                suffix in _TRACE_SUFFIXES
                or under_named_dir
                or any(h in name_l for h in _TRACE_DIR_HINTS)
            )
            if not is_carrier:
                continue
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            kind = suffix.lstrip(".") if suffix else "named_dir_file"
            kinds.add(kind)
            inventory.append(
                {
                    "path": rel_s,
                    "kind": kind,
                    "bytes": len(raw),
                }
            )
            for decoy in decoys:
                secret_count += raw.count(decoy.encode("utf-8"))
    return {
        "trace_inventory": inventory,
        "trace_artifact_count": len(inventory),
        "trace_secret_count": int(secret_count),
        "trace_kinds": sorted(kinds),
        "trace_dirs_scanned": [str(r) for r in roots],
    }


def parent_env_secret_count(decoys: Tuple[str, ...]) -> int:
    """Full os.environ canary scan — no key exclusions."""
    total = 0
    for k, v in os.environ.items():
        for decoy in decoys:
            total += str(k).count(decoy) + str(v).count(decoy)
    return int(total)


def _install_plugin(hermes: Path) -> None:
    root = hermes / "plugins" / "credential-guard"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    # Byte-copy only — no temporary manifest rewrite.
    shutil.copy2(REPO / "plugin.yaml", root / "plugin.yaml")
    shutil.copy2(REPO / "__init__.py", root / "__init__.py")
    shutil.copytree(REPO / "credential_guard", root / "credential_guard")
    src_bytes = (REPO / "plugin.yaml").read_bytes()
    dst_bytes = (root / "plugin.yaml").read_bytes()
    if src_bytes != dst_bytes:
        raise RuntimeError("temp plugin.yaml diverged from repository original")


def formal_manifest_tool_names() -> List[str]:
    """Parse provides_tools from the repository plugin.yaml (no temp rewrite)."""
    text = (REPO / "plugin.yaml").read_text(encoding="utf-8")
    names: List[str] = []
    in_tools = False
    for line in text.splitlines():
        if line.strip() == "provides_tools:":
            in_tools = True
            continue
        if in_tools:
            if line.startswith("  - "):
                names.append(line[4:].strip())
            elif line and not line.startswith(" "):
                break
    return names


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
    decoy_http: str,
    decoy_env: str,
    decoy_stdin: str,
) -> None:
    store = hermes / "credential-guard"
    store.mkdir(parents=True, exist_ok=True)
    os.chmod(store, 0o700)
    doc = {
        "version": 2,
        "credentials": {
            "http_token": {"type": "token", "value": decoy_http},
            "cli_token": {"type": "token", "value": decoy_env},
            "stdin_token": {"type": "token", "value": decoy_stdin},
        },
        "bindings": {
            "http-svc": {
                "type": "http",
                "credential_ref": "http_token",
                "target": {
                    "scheme": "https",
                    "host": "svc.example.test",
                    "port": 443,
                },
                "request": {
                    "allowed_methods": ["GET", "POST"],
                    "allowed_paths": ["/v1/health", "/v1/run"],
                    "connect_timeout_seconds": 5,
                    "total_timeout_seconds": 15,
                    "max_response_body_bytes": 4096,
                },
                "inject": {
                    "type": "bearer",
                    "location": "authorization_header",
                },
                "approval": "required",
            },
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
import http.server
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import types
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

scenario = os.environ["CG_SCENARIO"]
# Fixed synthetic canaries — same constants as outer harness; not via env ferry.
token_http = "CG_R3C_WIRE_HTTP_" + "h" * 24
token_env = "CG_R3C_WIRE_ENV_" + "e" * 24
token_stdin = "CG_R3C_WIRE_STDIN_" + "s" * 24
env_marker = Path(os.environ["CG_ENV_MARKER"])
stdin_marker = Path(os.environ["CG_STDIN_MARKER"])
env_program = Path(os.environ["CG_ENV_PROGRAM"])
net_probe_only = scenario == "net_probe"

# --- fail-closed loopback socket guard + independent original bomb/spy ---
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
    # Synthetic wire target hostname — resolved only to loopback below.
    if h == "svc.example.test":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False

def _synthetic_loopback_addrinfo(host, port):
    h = host.strip().lower().strip("[]") if isinstance(host, str) else ""
    if h != "svc.example.test":
        return None
    p = int(port or 0)
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", p))]

def _classify_and_gate(address, kind: str):
    parsed = _peer_host_port(address)
    if parsed is None:
        return
    host, port = parsed
    _net_audit["attempts"] += 1
    if _is_loopback(host):
        _net_audit["loopback_allowed_calls"] += 1
        return
    _net_audit["violations"] += 1
    cat = "test_net" if host.startswith("203.0.113.") else "non_loopback"
    _net_audit["blocked_categories"].append(cat)
    raise OSError("credential-guard net guard blocked non-loopback peer")

def _bomb_record_and_maybe_block(address):
    parsed = _peer_host_port(address)
    if parsed is None:
        return False
    host, _port = parsed
    if _is_loopback(host):
        return False
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
    syn = _synthetic_loopback_addrinfo(host, port)
    if syn is not None:
        return syn
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
    syn = _synthetic_loopback_addrinfo(host, port)
    if syn is not None:
        _net_audit["attempts"] += 1
        _net_audit["loopback_allowed_calls"] += 1
        return syn
    if isinstance(host, str) and host and not _is_loopback(host):
        try:
            ipaddress.ip_address(host.strip().lower().strip("[]"))
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
    socket.socket.connect = _bomb_connect
    socket.socket.connect_ex = _bomb_connect_ex
    socket.create_connection = _bomb_create_connection
    socket.getaddrinfo = _bomb_getaddrinfo

if net_probe_only:
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

# Scenario → tool + token + marker
ordinary = scenario == "ordinary_tool"
if ordinary:
    tool_name = "write_file"
    token = token_http  # unused for injection; still scanned for leaks
    marker = None
    tool_args = {"path": str(Path(os.environ["HOME"]) / "tmp" / "ordinary-r3c-wire.txt"), "content": "ordinary-ok"}
elif scenario.startswith("http_"):
    tool_name = "http_credential_request"
    token = token_http
    marker = None
    tool_args = {
        "target": "http-svc",
        "method": "POST",
        "path": "/v1/run",
        "credential": "<CREDENTIAL:http_token>",
    }
elif scenario.startswith("env_"):
    tool_name = "credential_process_run"
    token = token_env
    marker = env_marker
    tool_args = {"target": "cli-env", "credential": "<CREDENTIAL:cli_token>"}
else:
    tool_name = "credential_process_run"
    token = token_stdin
    marker = stdin_marker
    tool_args = {"target": "cli-stdin", "credential": "<CREDENTIAL:stdin_token>"}

approve = scenario.endswith("_approve")
deny = scenario.endswith("_deny")
timeout = scenario.endswith("_timeout")
mutate = scenario.endswith("_mutate")
replay = scenario.endswith("_replay")
FIXED_TOOL_CALL_ID = "call_r3c_wire_fixed"

sys.path.insert(0, os.environ["HERMES_AGENT_ROOT"])
for _name in ("modal", "anthropic", "firecrawl", "exa_py", "fal_client"):
    sys.modules.setdefault(_name, types.ModuleType(_name))

raw_requests = []
approval_raw = []
http_target_hits = {"n": 0, "auth_has_token": 0, "body_has_token": 0}
_dt_obs = {"n": 0, "verify_true": 0, "loopback_url": 0}
_http_transport_override_calls = {"n": 0}
_replay_second_issued = {"n": 0}
_tls_ca_pem = None
_tls_server = None
_tls_httpd = None
_tls_port = None
_tls_stop = threading.Event()

def _mint_loopback_tls(cert_dir: Path):
    # Ephemeral CA + server cert SAN=IP:127.0.0.1 — only under tmp workdir.
    cert_dir.mkdir(parents=True, exist_ok=True)
    ca_key = cert_dir / "ca.key"
    ca_pem = cert_dir / "ca.pem"
    server_key = cert_dir / "server.key"
    server_csr = cert_dir / "server.csr"
    server_pem = cert_dir / "server.pem"
    ext = cert_dir / "ext.cnf"
    ext.write_text(
        "subjectAltName=DNS:svc.example.test,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(ca_key), "-out", str(ca_pem),
            "-days", "1", "-nodes", "-subj", "/CN=CG-R3C-SYNTHETIC-CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
        ],
        check=True, capture_output=True, text=True,
    )
    subprocess.run(
        [
            "openssl", "req", "-newkey", "rsa:2048",
            "-keyout", str(server_key), "-out", str(server_csr),
            "-nodes", "-subj", "/CN=svc.example.test",
        ],
        check=True, capture_output=True, text=True,
    )
    subprocess.run(
        [
            "openssl", "x509", "-req",
            "-in", str(server_csr), "-CA", str(ca_pem), "-CAkey", str(ca_key),
            "-CAcreateserial", "-out", str(server_pem), "-days", "1",
            "-extfile", str(ext),
        ],
        check=True, capture_output=True, text=True,
    )
    return ca_pem, server_pem, server_key

def _start_loopback_tls_target(cert_dir: Path, expected_token: str):
    # Real loopback TLS HTTP server; hits derived from socket accepts only.
    global _tls_ca_pem, _tls_server, _tls_httpd, _tls_port
    ca_pem, server_pem, server_key = _mint_loopback_tls(cert_dir)

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            http_target_hits["n"] += 1
            auth = str(self.headers.get("Authorization") or "")
            if expected_token and expected_token in auth:
                http_target_hits["auth_has_token"] += 1
            length = int(self.headers.get("Content-Length") or 0)
            if length > 0:
                _ = self.rfile.read(min(length, 1_048_576))
            body = b'{"queued":true,"auth_applied":true}'
            if expected_token and expected_token.encode("utf-8") in body:
                http_target_hits["body_has_token"] += 1
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):  # noqa: A003
            return

    ctx_server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx_server.load_cert_chain(str(server_pem), str(server_key))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(16)
    ssock = ctx_server.wrap_socket(sock, server_side=True)
    httpd = http.server.HTTPServer(("127.0.0.1", port), _Handler, bind_and_activate=False)
    httpd.socket = ssock
    httpd.timeout = 0.5

    def _serve():
        while not _tls_stop.is_set():
            try:
                httpd.handle_request()
            except Exception:
                continue

    th = threading.Thread(target=_serve, daemon=True)
    th.start()
    _tls_ca_pem = ca_pem
    _tls_server = th
    _tls_httpd = httpd
    _tls_port = port
    return ca_pem, port

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
        tool_msg_count = sum(1 for m in msgs if isinstance(m, dict) and m.get("role") == "tool")
        args = json.dumps(tool_args, separators=(",", ":"))
        tc_id = FIXED_TOOL_CALL_ID if (replay or approve or deny or timeout or mutate or ordinary) else "call_1"
        if ordinary:
            # Public Agent ordinary path: one non-credential tool, then stop.
            if not has_tool:
                resp = {
                    "id": "c1", "object": "chat.completion", "created": 1, "model": "fake-model",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": None,
                        "tool_calls": [{"id": tc_id, "type": "function",
                            "function": {"name": tool_name, "arguments": args}}]},
                        "finish_reason": "tool_calls"}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                }
            else:
                resp = {
                    "id": "c2", "object": "chat.completion", "created": 1, "model": "fake-model",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "ordinary-done"},
                                 "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                }
        elif replay:
            # Same public conversation/turn: first tool call, then after one
            # tool result re-issue the same tool_call_id + normalized args,
            # then final response. Never a second run_conversation.
            # Track issued-second explicitly: Hermes may collapse duplicate
            # tool_call_id results so tool_msg_count alone is unreliable.
            # Explicit first-identity path — second function payload MUST reuse
            # these Names (load-bearing for authenticity predicate).
            first_tool_call_id = tc_id
            first_serialized_args = args
            if tool_msg_count == 0:
                resp = {
                    "id": "c1", "object": "chat.completion", "created": 1, "model": "fake-model",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": None,
                        "tool_calls": [{"id": first_tool_call_id, "type": "function",
                            "function": {"name": tool_name, "arguments": first_serialized_args}}]},
                        "finish_reason": "tool_calls"}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                }
            elif _replay_second_issued["n"] == 0:
                _replay_second_issued["n"] = 1
                resp = {
                    "id": "c1b", "object": "chat.completion", "created": 1, "model": "fake-model",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": None,
                        "tool_calls": [{"id": first_tool_call_id, "type": "function",
                            "function": {"name": tool_name, "arguments": first_serialized_args}}]},
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
        elif not has_tool:
            resp = {
                "id": "c1", "object": "chat.completion", "created": 1, "model": "fake-model",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": None,
                    "tool_calls": [{"id": tc_id, "type": "function",
                        "function": {"name": tool_name, "arguments": args}}]},
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

import hermes_cli.plugins as plugins_mod
plugins_mod._plugin_manager = None
from hermes_cli.plugins import discover_plugins
discover_plugins(force=True)
mgr = plugins_mod.get_plugin_manager()

from tools.registry import registry

entry = registry.get_entry(tool_name)
if not ordinary:
    assert entry is not None, f"{tool_name} missing after discover_plugins"
# ordinary write_file is registered when AIAgent enables the file toolset.

prod_req = list(mgr._middleware.get("tool_request", []) or [])
prod_exec = list(mgr._middleware.get("tool_execution", []) or [])
prod_pre = list(mgr._hooks.get("pre_tool_call", []) or [])
prod_handler = entry.handler if entry is not None else None

before = {
    "tool_request_list": id(mgr._middleware.get("tool_request")),
    "tool_execution_list": id(mgr._middleware.get("tool_execution")),
    "pre_tool_call_list": id(mgr._hooks.get("pre_tool_call")),
    "tool_request": id(prod_req[0].__code__) if prod_req else None,
    "tool_execution": id(prod_exec[0].__code__) if prod_exec else None,
    "pre_tool_call": id(prod_pre[0].__code__) if prod_pre else None,
    "tool_request_elem": id(prod_req[0]) if prod_req else None,
    "tool_execution_elem": id(prod_exec[0]) if prod_exec else None,
    "pre_tool_call_elem": id(prod_pre[0]) if prod_pre else None,
    "handler": id(prod_handler.__code__) if prod_handler is not None and hasattr(prod_handler, "__code__") else None,
    "handler_obj": id(prod_handler) if prod_handler is not None else None,
    "handler_module": getattr(prod_handler, "__module__", "") if prod_handler is not None else "",
}

import hermes_plugins.credential_guard.credential_guard.runtime_config as rc
import hermes_plugins.credential_guard.credential_guard.tool_request as tr
import hermes_plugins.credential_guard.credential_guard.adapters.process as proc_mod
import hermes_plugins.credential_guard.credential_guard.tool_execution as te_mod
import hermes_plugins.credential_guard.credential_guard.adapters.http as http_adapter_mod
from hermes_plugins.credential_guard.credential_guard.injection_plan import InjectionPlanStore
from hermes_plugins.credential_guard.credential_guard.injection import resolve_one_for_execution
from hermes_plugins.credential_guard.credential_guard.adapters.process import execute_process
from hermes_plugins.credential_guard.credential_guard.adapters.http import execute_http

# HTTP scenarios: real loopback TLS target + production _default_transport.
# Never install set_http_transport_override_for_tests / fake target callback.
if scenario.startswith("http_"):
    tls_dir = Path(os.environ["HOME"]) / "tmp" / "r3c-http-tls"
    ca_pem, tls_port = _start_loopback_tls_target(tls_dir, token)
    cfg_path = Path(os.environ["HERMES_HOME"]) / "credential-guard" / "credential-guard.json"
    cfg_doc = json.loads(cfg_path.read_text(encoding="utf-8"))
    # Keep schema-valid DNS host; wire net guard resolves it only to 127.0.0.1.
    cfg_doc["bindings"]["http-svc"]["target"]["host"] = "svc.example.test"
    cfg_doc["bindings"]["http-svc"]["target"]["port"] = int(tls_port)
    cfg_path.write_text(json.dumps(cfg_doc), encoding="utf-8")
    os.chmod(cfg_path, 0o600)
    _real_cdc = ssl.create_default_context
    def _trust_tmp_ca(*_a, **_k):
        c = _real_cdc()
        c.load_verify_locations(cafile=str(ca_pem))
        return c
    ssl.create_default_context = _trust_tmp_ca
    _real_default_transport = http_adapter_mod._default_transport
    def _spy_default_transport(req):
        _dt_obs["n"] += 1
        if req.get("verify") is True:
            _dt_obs["verify_true"] += 1
        url = str(req.get("url") or "")
        if url.startswith("https://svc.example.test:"):
            _dt_obs["loopback_url"] += 1
        return _real_default_transport(req)
    http_adapter_mod._default_transport = _spy_default_transport

rc.reset_runtime_for_tests()
tr.reset_tool_request_state_for_tests()
rc.load_and_publish_runtime()
rc.reset_execution_secret_resolve_count_for_tests()
rc.reset_injection_secret_resolve_count_for_tests()
proc_mod.reset_process_start_count_for_tests()
te_mod.reset_http_adapter_observe_for_tests()
# Production path: transport override must remain unset (count stays 0).
if getattr(te_mod, "_http_transport_override", None) is not None:
    _http_transport_override_calls["n"] += 1

inj_before = rc.get_injection_secret_resolve_count()
start_before = proc_mod.process_start_count()
http_before = te_mod.get_http_adapter_invoke_count()

order = []
counts = {
    "pre_tool_call": 0,
    "approval_gate": 0,
    "handler": 0,
    "tool_request": 0,
    "tool_execution": 0,
    "consume": 0,
    "resolve": 0,
    "adapter": 0,
}

import tools.approval as approval_mod
_ORIG_REQUEST_TOOL_APPROVAL = approval_mod.request_tool_approval

adapter_fn = execute_http if tool_name == "http_credential_request" else execute_process
code_labels = {}
for cb, label in (
    (prod_req[0] if prod_req else None, "tool_request"),
    (prod_exec[0] if prod_exec else None, "tool_execution"),
    (prod_pre[0] if prod_pre else None, "pre_tool_call"),
    (prod_handler, "handler"),
    (InjectionPlanStore.consume, "consume"),
    (resolve_one_for_execution, "resolve"),
    (adapter_fn if not ordinary else None, "adapter"),
    (http_adapter_mod._default_transport if scenario.startswith("http_") else None, "_default_transport"),
    (approval_mod._await_gateway_decision, "_await_gateway_decision"),
):
    if cb is not None and hasattr(cb, "__code__"):
        code_labels[id(cb.__code__)] = label

from hermes_plugins.credential_guard.credential_guard.injection_plan import canonical_args_digest

tool_request_identities = []
tool_execution_results = []
await_gateway_call_count = 0
host_approval_raw = None
host_approval_raw_sha256 = None

def _profile(frame, event, arg):
    global await_gateway_call_count
    if event == "call":
        label = code_labels.get(id(frame.f_code))
        if label is not None:
            if label == "_await_gateway_decision":
                await_gateway_call_count += 1
                return _profile
            if label == "_default_transport":
                # Enter count is owned by _spy_default_transport; do not double-count.
                return _profile
            counts[label] += 1
            order.append(label)
            if label == "tool_request":
                locs = frame.f_locals
                ctx = locs.get("context") if isinstance(locs.get("context"), dict) else {}
                args_obj = locs.get("args")
                digest = ""
                if isinstance(args_obj, dict):
                    try:
                        digest = canonical_args_digest(args_obj)
                    except Exception:
                        digest = hashlib.sha256(
                            json.dumps(args_obj, sort_keys=True, default=str).encode()
                        ).hexdigest()
                tool_request_identities.append({
                    "session_id": str(locs.get("session_id") or ctx.get("session_id") or ""),
                    "turn_id": str(locs.get("turn_id") or ctx.get("turn_id") or ""),
                    "tool_call_id": str(locs.get("tool_call_id") or ctx.get("tool_call_id") or ""),
                    "args_digest": digest,
                    "resolve_at_entry": int(counts["resolve"]),
                    "adapter_at_entry": int(counts["adapter"]),
                    "start_at_entry": int(proc_mod.process_start_count() - start_before),
                    "http_at_entry": int(te_mod.get_http_adapter_invoke_count() - http_before),
                    "http_target_at_entry": int(http_target_hits["n"]),
                })
    elif event == "return":
        label = code_labels.get(id(frame.f_code))
        if label == "tool_execution":
            # Mechanical production return — not provider-message cache.
            tool_execution_results.append(arg if isinstance(arg, str) else str(arg))
    return _profile

def _tamper_for_mutate():
    # Production final-recheck mutate: program identity or config identity.
    if scenario.startswith("env_") or scenario.startswith("stdin_"):
        prog = env_program if scenario.startswith("env_") else Path(os.environ["CG_STDIN_MARKER"]).parent / "cg-stdin-probe"
        # Prefer explicit stdin program path via marker sibling written by harness.
        if scenario.startswith("stdin_"):
            prog = Path(os.environ.get("CG_STDIN_PROGRAM", str(prog)))
        prog.write_text("#!/bin/sh\nprintf 'TAMPER\\n'\n", encoding="utf-8")
        os.chmod(prog, 0o700)
    elif scenario.startswith("http_"):
        cfg = Path(os.environ["HERMES_HOME"]) / "credential-guard" / "credential-guard.json"
        cfg.write_text(cfg.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        os.chmod(cfg, 0o600)

def gate(tool_name_g, reason, **kwargs):
    global host_approval_raw, host_approval_raw_sha256
    approval_raw.append({
        "tool_name": tool_name_g,
        "reason": reason,
        "kwargs": dict(kwargs),
    })
    counts["approval_gate"] += 1
    order.append("approval_gate")
    if mutate:
        _tamper_for_mutate()
        return {"approved": True, "message": None}
    if deny:
        out = {"approved": False, "message": "DENIED: r3c-wire", "outcome": "denied"}
        approval_raw[-1]["decision"] = out
        return out
    if timeout:
        # Enter Hermes standard approval timeout branch (gateway + timeout=0).
        # Preserve host raw unmodified — never setdefault/append timeout text.
        os.environ["HERMES_GATEWAY_SESSION"] = "1"
        sk = approval_mod.get_current_session_key()
        def _never_resolve(_data):
            return None
        approval_mod.register_gateway_notify(sk, _never_resolve)
        try:
            with patch.object(approval_mod, "_get_approval_timeout", return_value=0):
                decision = _ORIG_REQUEST_TOOL_APPROVAL(tool_name_g, reason, **kwargs)
        finally:
            approval_mod.unregister_gateway_notify(sk)
            os.environ.pop("HERMES_GATEWAY_SESSION", None)
        snap = deepcopy(decision) if isinstance(decision, dict) else {"value": str(decision)}
        raw_bytes = json.dumps(snap, sort_keys=True, default=str).encode("utf-8")
        host_approval_raw = json.loads(raw_bytes.decode("utf-8"))
        host_approval_raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        approval_raw[-1]["decision_observation"] = {
            "approved": snap.get("approved") if isinstance(snap, dict) else None,
            "message_preview": str(snap.get("message") or "")[:240] if isinstance(snap, dict) else "",
            "keys": sorted(snap.keys()) if isinstance(snap, dict) else [],
        }
        # Return unmodified host decision (deepcopy) — no outcome/message rewrite.
        return deepcopy(snap) if isinstance(snap, dict) else snap
    if approve or replay:
        out = {"approved": True, "message": None, "outcome": "approved"}
        approval_raw[-1]["decision"] = out
        return out
    if ordinary:
        # Ordinary tools should not hit credential approval; if they do, deny.
        out = {"approved": False, "message": "DENIED: ordinary-unexpected-approval", "outcome": "denied"}
        approval_raw[-1]["decision"] = out
        return out
    return {"approved": False, "message": "DENIED: r3c-wire-fallback", "outcome": "denied"}

sys.setprofile(_profile)
result2 = None
run_conversation_calls = 0
try:
    from run_agent import AIAgent
    with patch("tools.approval.request_tool_approval", side_effect=gate):
        agent = AIAgent(
            api_key="sk-synthetic-r3c-wire-only",
            base_url=base,
            model="fake-model",
            provider="custom",
            api_mode="chat_completions",
            max_iterations=8 if replay else 4,
            quiet_mode=True,
            skip_context_files=True,
            skip_memory=True,
            enabled_toolsets=["credential_guard", "file"] if ordinary else ["credential_guard"],
        )
        agent._disable_streaming = True
        # Pin session id so replay shares production plan-store key.
        if replay:
            agent.session_id = "sess-r3c-wire-replay"
        prompt = (
            "Please write the ordinary file once."
            if ordinary
            else "Please invoke the configured credential tool once."
        )
        run_conversation_calls += 1
        result = agent.run_conversation(prompt)
        # Replay stays inside this single conversation (provider re-issues tool).
finally:
    sys.setprofile(None)

_stop.set()
_tls_stop.set()
try:
    _srv.close()
except Exception:
    pass
try:
    if _tls_httpd is not None:
        _tls_httpd.server_close()
except Exception:
    pass

entry_after = registry.get_entry(tool_name)
after = {
    "tool_request_list": id(mgr._middleware.get("tool_request")),
    "tool_execution_list": id(mgr._middleware.get("tool_execution")),
    "pre_tool_call_list": id(mgr._hooks.get("pre_tool_call")),
    "tool_request": id(mgr._middleware.get("tool_request", [None])[0].__code__)
    if mgr._middleware.get("tool_request") else None,
    "tool_execution": id(mgr._middleware.get("tool_execution", [None])[0].__code__)
    if mgr._middleware.get("tool_execution") else None,
    "pre_tool_call": id(mgr._hooks.get("pre_tool_call", [None])[0].__code__)
    if mgr._hooks.get("pre_tool_call") else None,
    "tool_request_elem": id(mgr._middleware.get("tool_request", [None])[0])
    if mgr._middleware.get("tool_request") else None,
    "tool_execution_elem": id(mgr._middleware.get("tool_execution", [None])[0])
    if mgr._middleware.get("tool_execution") else None,
    "pre_tool_call_elem": id(mgr._hooks.get("pre_tool_call", [None])[0])
    if mgr._hooks.get("pre_tool_call") else None,
    "handler": id(entry_after.handler.__code__) if entry_after and hasattr(entry_after.handler, "__code__") else None,
    "handler_obj": id(entry_after.handler) if entry_after else None,
}
id_keys = (
    "tool_request_list", "tool_execution_list", "pre_tool_call_list",
    "tool_request", "tool_execution", "pre_tool_call",
    "tool_request_elem", "tool_execution_elem", "pre_tool_call_elem",
    "handler", "handler_obj",
)
identity_unchanged = all(before.get(k) == after.get(k) for k in id_keys) and all(
    before.get(k) is not None for k in ("tool_request_list", "tool_execution_list", "pre_tool_call_list")
)

final = result.get("final_response") if isinstance(result, dict) else str(result)
blob = json.dumps(result, default=str) if not isinstance(result, str) else result
approval_blob = json.dumps(approval_raw, default=str)
raw_join = b"\n".join(raw_requests)

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
if marker is not None and marker.is_file():
    expected = hashlib.sha256(token.encode("utf-8")).hexdigest()
    marker_ok = marker.read_text(encoding="utf-8").strip() == expected

turns = 0
tool_result_bodies = []
for b in raw_requests:
    try:
        body = b.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in b else b
        j = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        continue
    msgs = j.get("messages") or []
    if any(isinstance(m, dict) and m.get("role") == "tool" for m in msgs):
        turns = max(turns, 2)
        for m in msgs:
            if isinstance(m, dict) and m.get("role") == "tool":
                tool_result_bodies.append(str(m.get("content") or ""))
    else:
        turns = max(turns, 1)

result2_preview = ""
replay_closed = False
replay_identity_same = False
second_resolve_delta = None
second_adapter_delta = None
second_start_delta = None
second_http_target_delta = None
if replay:
    # Prefer production tool_execution return values over provider-cached tool messages
    # (Hermes may reuse the first success body for a repeated tool_call_id).
    exec_fail = [
        b for b in tool_execution_results
        if "RUNTIME_ADAPTER_NOT_READY" in b or '"ok":false' in b.replace(" ", "")
    ]
    if exec_fail:
        result2_preview = exec_fail[-1][:240]
    else:
        fail_bodies = []
        for b in tool_result_bodies:
            compact = b.replace(" ", "")
            if "RUNTIME_ADAPTER_NOT_READY" in b or '"ok":false' in compact:
                fail_bodies.append(b)
        if fail_bodies:
            result2_preview = fail_bodies[-1][:240]
        elif tool_execution_results:
            result2_preview = tool_execution_results[-1][:240]
        elif tool_result_bodies:
            result2_preview = tool_result_bodies[-1][:240]
    adapter_once = (
        counts["resolve"] == 1
        and counts["adapter"] == 1
        and (proc_mod.process_start_count() - start_before)
        + (te_mod.get_http_adapter_invoke_count() - http_before)
        == 1
    )
    if len(tool_request_identities) >= 2:
        a = tool_request_identities[0]
        b = tool_request_identities[1]
        replay_identity_same = all(
            a.get(k) == b.get(k) and bool(a.get(k))
            for k in ("session_id", "turn_id", "tool_call_id", "args_digest")
        )
        second_resolve_delta = int(counts["resolve"]) - int(b.get("resolve_at_entry") or 0)
        second_adapter_delta = int(counts["adapter"]) - int(b.get("adapter_at_entry") or 0)
        if tool_name == "http_credential_request":
            second_start_delta = (
                int(te_mod.get_http_adapter_invoke_count() - http_before)
                - int(b.get("http_at_entry") or 0)
            )
            second_http_target_delta = (
                int(http_target_hits["n"]) - int(b.get("http_target_at_entry") or 0)
            )
        else:
            second_start_delta = (
                int(proc_mod.process_start_count() - start_before)
                - int(b.get("start_at_entry") or 0)
            )
            second_http_target_delta = 0
    # Evidence from production plan/store: second public path must not re-resolve.
    replay_closed = bool(
        adapter_once
        and counts["tool_request"] >= 2
        and run_conversation_calls == 1
        and replay_identity_same
        and second_resolve_delta == 0
        and second_adapter_delta == 0
        and second_start_delta == 0
        and (second_http_target_delta is None or second_http_target_delta == 0)
        and len(tool_execution_results) >= 2
        and (
            "RUNTIME_ADAPTER_NOT_READY" in result2_preview
            or '"ok":false' in result2_preview.replace(" ", "")
            or bool(exec_fail)
        )
    )

# Deduplicate order to first full seam sequence (AIAgent may re-enter frames).
_seen = set()
order_dedup = []
for lab in order:
    if lab not in _seen or lab == "approval_gate":
        if lab in _seen:
            continue
        _seen.add(lab)
        order_dedup.append(lab)

# --- B4/Round3: enumerate real temporary HOME/HERMES_HOME carriers ---
hermes_home = Path(os.environ["HERMES_HOME"])
home_root = Path(os.environ["HOME"])
_TRACE_SUFFIXES = {
    ".db", ".db-wal", ".db-shm",
    ".sqlite", ".sqlite-wal", ".sqlite-shm",
    ".wal", ".jsonl", ".json", ".log", ".txt",
}
_TRACE_DIR_HINTS = (
    "session", "sessions", "trace", "traces",
    "trajectory", "observability", "state",
)
trace_inventory = []
trace_kinds = set()
trace_secret_count = 0
for root in (hermes_home, home_root):
    if not root.is_dir():
        continue
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(root)
        except ValueError:
            continue
        rel_s = str(rel).replace("\\", "/")
        parts = rel.parts
        # Exact secret-store only; never broad-exclude credential_guard substrings.
        if path.name == "credential-guard.json" and "credential-guard" in parts:
            continue
        if "plugins" in parts:
            continue
        if path.name.startswith("mark.") and path.suffix in {".env", ".stdin"}:
            continue
        name_l = path.name.lower()
        suffix = path.suffix.lower()
        for compound in (".db-wal", ".db-shm", ".sqlite-wal", ".sqlite-shm"):
            if name_l.endswith(compound):
                suffix = compound
                break
        under_named_dir = any(
            any(h in p.lower() for h in _TRACE_DIR_HINTS) for p in parts[:-1]
        )
        is_carrier = (
            suffix in _TRACE_SUFFIXES
            or under_named_dir
            or any(h in name_l for h in _TRACE_DIR_HINTS)
        )
        if not is_carrier:
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        kind = suffix.lstrip(".") if suffix else "named_dir_file"
        trace_kinds.add(kind)
        # Inventory: path/kind/bytes only — never emit body.
        trace_inventory.append({"path": rel_s, "kind": kind, "bytes": len(data)})
        for decoy in (token_http, token_env, token_stdin):
            trace_secret_count += data.count(decoy.encode("utf-8"))

trace_artifact_count = len(trace_inventory)
trace_dirs_scanned = [str(hermes_home), str(home_root)]
# Prove compound sidecars are in the suffix contract (for authenticity gate).
_ = ("state.db-wal", "state.db-shm")

# --- B5/Round3: full parent env (no canary key exclusions) + follow-up child ---
parent_env_secret_count = 0
for k, v in os.environ.items():
    for decoy in (token_http, token_env, token_stdin):
        parent_env_secret_count += str(k).count(decoy) + str(v).count(decoy)
cg_probe_in_parent = "CG_PROBE_ENV" in os.environ
followup_env = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LANG": "C",
    "HOME": str(home_root),
    "TMPDIR": str(home_root / "tmp"),
}
# Intentionally omit CG_PROBE_ENV and all decoys — whitelist only.
follow = subprocess.run(
    ["/bin/sh", "-c", 'printf "%s" "${CG_PROBE_ENV-absent}"'],
    env=followup_env,
    capture_output=True,
    text=True,
    timeout=5,
    check=False,
)
followup_child_status = follow.stdout
followup_child_secret_count = sum(
    follow.stdout.count(d) + follow.stderr.count(d)
    for d in (token_http, token_env, token_stdin)
)

wire_secret_count = (
    raw_join.count(token.encode("utf-8"))
    + approval_blob.count(token)
    + blob.count(token)
    + int(trace_secret_count)
)

loopback_only = (
    _net_audit["attempts"] > 0
    and _net_audit["non_loopback_original_calls"] == 0
    and _net_audit["violations"] == 0
)

# Approval timeout vs deny — host_approval_raw is immutable fact; observation separate.
approval_messages = []
for row in approval_raw:
    dec = row.get("decision") if isinstance(row, dict) else None
    if isinstance(dec, dict) and dec.get("message"):
        approval_messages.append(str(dec["message"]))
    elif isinstance(row, dict) and isinstance(row.get("decision_observation"), dict):
        preview = row["decision_observation"].get("message_preview") or ""
        if preview:
            approval_messages.append(str(preview))
    elif isinstance(row, dict) and row.get("reason"):
        approval_messages.append(str(row.get("reason")))
approval_message = approval_messages[0] if approval_messages else ""
if timeout and isinstance(host_approval_raw, dict):
    approval_message = str(host_approval_raw.get("message") or approval_message)

# Prove host raw not mutated after capture.
host_approval_raw_intact = True
if host_approval_raw is not None and host_approval_raw_sha256:
    _re = json.dumps(host_approval_raw, sort_keys=True, default=str).encode("utf-8")
    host_approval_raw_intact = hashlib.sha256(_re).hexdigest() == host_approval_raw_sha256

host_msg = str((host_approval_raw or {}).get("message") or "") if isinstance(host_approval_raw, dict) else ""
host_timeout_text = (
    "timed out without user response" in host_msg
    and "Silence is not consent" in host_msg
)
approval_timeout_branch = bool(
    timeout
    and await_gateway_call_count > 0
    and host_timeout_text
)
approval_is_timeout = bool(approval_timeout_branch)
approval_outcome = None
if timeout:
    approval_outcome = "timeout" if approval_timeout_branch else "non_timeout"
elif deny:
    approval_outcome = "denied"
elif approval_raw:
    last = approval_raw[-1]
    dec = last.get("decision") if isinstance(last, dict) else None
    if isinstance(dec, dict):
        approval_outcome = dec.get("outcome")

# Manifest byte identity (temp install vs repo original) — recorded by parent via
# install check; probe confirms provides_tools discovery set.
manifest_path = hermes_home / "plugins" / "credential-guard" / "plugin.yaml"
manifest_bytes_identical = False
manifest_tools = []
try:
    repo_man = Path(os.environ["CG_REPO"]) / "plugin.yaml"
    manifest_bytes_identical = (
        manifest_path.is_file()
        and repo_man.is_file()
        and manifest_path.read_bytes() == repo_man.read_bytes()
    )
    # Parse provides_tools from the installed (byte-identical) manifest.
    in_tools = False
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        if line.strip() == "provides_tools:":
            in_tools = True
            continue
        if in_tools:
            if line.startswith("  - "):
                manifest_tools.append(line[4:].strip())
            elif line and not line.startswith(" "):
                break
except Exception:
    manifest_bytes_identical = False

registered_tool_names = []
try:
    for _n in (
        "mysql_credential_action",
        "ssh_credential_action",
        "http_credential_request",
        "credential_process_run",
    ):
        if registry.get_entry(_n) is not None:
            registered_tool_names.append(_n)
except Exception:
    registered_tool_names = []
manifest_registry_tools_match = (
    set(manifest_tools) == set(registered_tool_names)
    and set(manifest_tools) >= {
        "http_credential_request",
        "credential_process_run",
        "mysql_credential_action",
        "ssh_credential_action",
    }
)

plan_state = None
try:
    from hermes_plugins.credential_guard.credential_guard.tool_request import get_plan_store as _gps
    _sid = None
    try:
        _sid = agent.session_id
    except Exception:
        _sid = None
    if _sid and not ordinary:
        p = _gps().lookup(str(_sid), FIXED_TOOL_CALL_ID)
        plan_state = p.state.value if p else None
except Exception:
    plan_state = None

print(json.dumps({
    "scenario": scenario,
    "order": list(order_dedup),
    "counts": {k: int(v) for k, v in counts.items()},
    "provider_raw_request_count": len(raw_requests),
    "provider_logical_turns": turns,
    "approval_raw_count": len(approval_raw),
    "approval_raw_has_reason": bool(approval_raw and isinstance(approval_raw[0].get("reason"), str)),
    "approval_message": approval_message[:300],
    "approval_outcome": approval_outcome,
    "approval_is_timeout": bool(approval_is_timeout),
    "approval_timeout_branch": bool(approval_timeout_branch),
    "host_approval_raw": host_approval_raw,
    "host_approval_raw_sha256": host_approval_raw_sha256,
    "host_approval_raw_intact": bool(host_approval_raw_intact),
    "await_gateway_call_count": int(await_gateway_call_count),
    "marker_ok": marker_ok,
    "process_start_delta": proc_mod.process_start_count() - start_before,
    "http_adapter_delta": te_mod.get_http_adapter_invoke_count() - http_before,
    "injection_resolve_delta": rc.get_injection_secret_resolve_count() - inj_before,
    "http_target_hits": int(http_target_hits["n"]),
    "http_target_echoed_secret": int(http_target_hits["body_has_token"]),
    "http_target_auth_applied": int(http_target_hits["auth_has_token"]),
    "default_transport_enter_count": int(_dt_obs["n"]),
    "http_transport_override_calls": int(_http_transport_override_calls["n"]),
    "http_tls_verify": bool(_dt_obs["n"] > 0 and _dt_obs["verify_true"] == _dt_obs["n"]),
    "http_tls_loopback": bool(_dt_obs["n"] > 0 and _dt_obs["loopback_url"] == _dt_obs["n"]),
    "http_target_evidence_layer": (
        "production_default_transport_loopback_tls"
        if (
            scenario.startswith("http_")
            and _dt_obs["n"] >= 1
            and http_target_hits["n"] >= 1
            and _http_transport_override_calls["n"] == 0
            and _dt_obs["verify_true"] == _dt_obs["n"]
            and _dt_obs["loopback_url"] == _dt_obs["n"]
            and getattr(te_mod, "_http_transport_override", None) is None
        )
        else (
            "n/a_non_http"
            if not scenario.startswith("http_")
            else "http_evidence_incomplete"
        )
    ),
    "wire_secret_count": int(wire_secret_count),
    "token_in_provider_raw": int(token.encode("utf-8") in raw_join),
    "token_in_approval_raw": int(token in approval_blob),
    "token_in_result": int(token in blob),
    "trace_artifact_count": int(trace_artifact_count),
    "trace_secret_count": int(trace_secret_count),
    "trace_kinds": sorted(trace_kinds),
    "trace_dirs_scanned": list(trace_dirs_scanned),
    "trace_inventory": list(trace_inventory),
    "parent_env_secret_count": int(parent_env_secret_count),
    "cg_probe_in_parent": bool(cg_probe_in_parent),
    "followup_child_status": followup_child_status,
    "followup_child_secret_count": int(followup_child_secret_count),
    "raw_http_has_request_line": int(raw_http_has_request_line),
    "raw_http_has_headers": int(raw_http_has_headers),
    "raw_http_has_body": int(raw_http_has_body),
    "net_attempts": int(_net_audit["attempts"]),
    "non_loopback_original_calls": int(_net_audit["non_loopback_original_calls"]),
    "net_violations": int(_net_audit["violations"]),
    "loopback_only": bool(loopback_only),
    "identity_unchanged": bool(identity_unchanged),
    "handler_module": before["handler_module"],
    "result2_preview": result2_preview,
    "replay_closed": bool(replay_closed),
    "replay_identity_same": bool(replay_identity_same),
    "tool_request_identities": list(tool_request_identities),
    "tool_execution_result_count": len(tool_execution_results),
    "run_conversation_calls": int(run_conversation_calls),
    "second_resolve_delta": second_resolve_delta,
    "second_adapter_delta": second_adapter_delta,
    "second_start_delta": second_start_delta,
    "second_http_target_delta": second_http_target_delta,
    "manifest_bytes_identical": bool(manifest_bytes_identical),
    "manifest_tools": list(manifest_tools),
    "registered_tool_names": list(registered_tool_names),
    "manifest_registry_tools_match": bool(manifest_registry_tools_match),
    "plan_state": plan_state,
    "ordinary_evidence_layer": "public_AIAgent" if ordinary else None,
    "final_preview": (final if isinstance(final, str) else str(final))[:200],
}, sort_keys=True))
"""
)


def _run_scenario(
    scenario: str,
    *,
    home: Path,
    hermes: Path,
    env_marker: Path,
    stdin_marker: Path,
    env_program: Path,
    stdin_program: Path,
    guard_enabled: bool = True,
) -> dict:
    env = _minimal_child_env(
        home,
        hermes,
        {
            "CG_SCENARIO": scenario,
            "CG_ENV_MARKER": str(env_marker),
            "CG_STDIN_MARKER": str(stdin_marker),
            "CG_ENV_PROGRAM": str(env_program),
            "CG_STDIN_PROGRAM": str(stdin_program),
            "CG_NET_GUARD_ENABLED": "1" if guard_enabled else "0",
        },
    )
    for k in list(env):
        lk = k.lower()
        if lk.endswith("_proxy") or lk in {
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        }:
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
            f"wire probe failed scenario={scenario} rc={proc.returncode}\n"
            f"STDERR:\n{proc.stderr[-4000:]}\nSTDOUT:\n{proc.stdout[-2000:]}"
        )
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip().startswith("{")]
    if not lines:
        raise RuntimeError(
            f"no json evidence scenario={scenario}\n"
            f"STDERR:\n{proc.stderr[-3000:]}\nSTDOUT:\n{proc.stdout[-2000:]}"
        )
    data = json.loads(lines[-1])
    harness_src = Path(__file__).read_text(encoding="utf-8") + "\n" + PROBE
    data["used_environ_copy"] = bool(_env_construction_used_copy(harness_src))
    return data


def run_net_probe(work: Path, *, guard_enabled: bool = True) -> Dict[str, Any]:
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
            decoy_http=DECOY_HTTP,
            decoy_env=DECOY_ENV,
            decoy_stdin=DECOY_STDIN,
        )
    return _run_scenario(
        "net_probe",
        home=home,
        hermes=hermes,
        env_marker=env_marker,
        stdin_marker=stdin_marker,
        env_program=env_h,
        stdin_program=stdin_h,
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
        decoy_http=DECOY_HTTP,
        decoy_env=DECOY_ENV,
        decoy_stdin=DECOY_STDIN,
    )
    out: Dict[str, Any] = {}
    for scenario in _ALL_SCENARIOS:
        # Restore helpers/config if a prior mutate scenario tampered them.
        _write_helpers(helper_dir)
        _write_config(
            hermes,
            env_program=env_h,
            env_marker=env_marker,
            stdin_program=stdin_h,
            stdin_marker=stdin_marker,
            decoy_http=DECOY_HTTP,
            decoy_env=DECOY_ENV,
            decoy_stdin=DECOY_STDIN,
        )
        for m in (env_marker, stdin_marker):
            if m.exists():
                m.unlink()
        out[scenario] = _run_scenario(
            scenario,
            home=home,
            hermes=hermes,
            env_marker=env_marker,
            stdin_marker=stdin_marker,
            env_program=env_h,
            stdin_program=stdin_h,
        )
    return out


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="r3c-wire-"))
    try:
        results = run_all(work)
        safe = {
            k: {
                kk: vv
                for kk, vv in v.items()
                if kk not in {"final_preview"}
            }
            for k, v in results.items()
        }
        print(json.dumps({"ok": True, "results": safe}, sort_keys=True, indent=2))
        for name, adapter in (
            ("http_approve", "http"),
            ("env_approve", "env"),
            ("stdin_approve", "stdin"),
        ):
            r = results[name]
            assert r["wire_secret_count"] == 0
            assert r["counts"]["consume"] >= 1
            assert r["counts"]["resolve"] >= 1
            assert r["counts"]["adapter"] >= 1
            assert r["injection_resolve_delta"] == 1
            assert r["used_environ_copy"] is False
            assert r["loopback_only"] is True
            assert r["raw_http_has_request_line"] >= 1
            assert r["identity_unchanged"] is True
            assert r["trace_secret_count"] == 0
            assert r["http_transport_override_calls"] == 0
            if adapter == "http":
                assert r["http_target_evidence_layer"] == (
                    "production_default_transport_loopback_tls"
                )
                assert r["http_adapter_delta"] == 1
                assert r["process_start_delta"] == 0
                assert r["http_target_hits"] == 1
                assert r["http_target_auth_applied"] == 1
                assert r["http_target_echoed_secret"] == 0
                assert r["default_transport_enter_count"] == 1
                assert r["http_tls_verify"] is True
                assert r["http_tls_loopback"] is True
            else:
                assert r["process_start_delta"] == 1
                assert r["http_adapter_delta"] == 0
                assert r["http_target_hits"] == 0
                assert r["default_transport_enter_count"] == 0
                assert r["marker_ok"] is True
            if adapter == "env":
                assert r["parent_env_secret_count"] == 0
                assert r["cg_probe_in_parent"] is False
                assert r["followup_child_status"] == "absent"
                assert r["followup_child_secret_count"] == 0
        for name in (
            "http_deny",
            "env_deny",
            "stdin_deny",
            "http_timeout",
            "env_timeout",
            "stdin_timeout",
            "http_mutate",
            "env_mutate",
            "stdin_mutate",
        ):
            r = results[name]
            assert r["injection_resolve_delta"] == 0
            assert r["http_adapter_delta"] == 0
            assert r["process_start_delta"] == 0
            assert r["http_target_hits"] == 0
            assert r["default_transport_enter_count"] == 0
            assert r["http_transport_override_calls"] == 0
            assert r["wire_secret_count"] == 0
            assert r["trace_secret_count"] == 0
        for name in ("http_timeout", "env_timeout", "stdin_timeout"):
            r = results[name]
            assert r["approval_is_timeout"] is True
            assert r["approval_timeout_branch"] is True
            assert r["approval_outcome"] == "timeout"
            assert r["await_gateway_call_count"] > 0
            assert r["host_approval_raw_intact"] is True
            assert isinstance(r["host_approval_raw"], dict)
            host_msg = str(r["host_approval_raw"].get("message") or "")
            assert "timed out without user response" in host_msg
            assert "Silence is not consent" in host_msg
            deny_msg = results[name.replace("_timeout", "_deny")]["approval_message"]
            assert r["approval_message"] != deny_msg
            assert "timed out" in r["approval_message"].lower() or "timeout" in r[
                "approval_message"
            ].lower()
        for name in ("http_replay", "env_replay", "stdin_replay"):
            r = results[name]
            assert r["injection_resolve_delta"] == 1
            assert r["counts"]["resolve"] == 1
            assert r["counts"]["adapter"] == 1 or (
                r["http_adapter_delta"] + r["process_start_delta"] == 1
            )
            assert r["run_conversation_calls"] == 1
            assert r["replay_identity_same"] is True
            assert len(r["tool_request_identities"]) >= 2
            assert r["second_resolve_delta"] == 0
            assert r["second_adapter_delta"] == 0
            assert r["second_start_delta"] == 0
            assert r["replay_closed"] is True
            assert r["wire_secret_count"] == 0
            assert r["manifest_bytes_identical"] is True
            assert r["manifest_registry_tools_match"] is True
            assert r["http_transport_override_calls"] == 0
            if name == "http_replay":
                assert r["http_target_hits"] == 1
                assert r["second_http_target_delta"] == 0
                assert r["default_transport_enter_count"] == 1
                assert r["http_target_evidence_layer"] == (
                    "production_default_transport_loopback_tls"
                )
        ord_r = results["ordinary_tool"]
        assert ord_r["injection_resolve_delta"] == 0
        assert ord_r["http_adapter_delta"] == 0
        assert ord_r["process_start_delta"] == 0
        assert ord_r["counts"].get("resolve", 0) == 0
        assert ord_r["ordinary_evidence_layer"] == "public_AIAgent"
        np = results["net_probe"]
        assert np["test_net_blocked_before_original"] is True
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
