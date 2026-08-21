"""R4 result-guard authenticity gate — public AIAgent.run_conversation path only."""

from __future__ import annotations

import json
import os
import re
import subprocess
import textwrap
from pathlib import Path

import pytest

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

DECOY = "CG_R4_AUTH_" + "a" * 24

_FORBIDDEN = (
    re.compile(r"""mgr\._hooks\[\s*['"]transform_tool_result['"]\s*\]\s*="""),
    re.compile(r"""mgr\._hooks\[\s*['"]transform_tool_result['"]\s*\]\s*=\s*\[\s*\]"""),
    re.compile(r"""registry\.deregister\s*\("""),
    re.compile(r"""class\s+Ctx\s*:"""),
    re.compile(r"""secret_count\s*=\s*0\b"""),
    re.compile(r"""provider_secret_count\s*=\s*0\b"""),
    re.compile(r"""guard_entered\s*=\s*True\b"""),
    re.compile(r"""from\s+credential_guard\.hooks\s+import\s+on_transform_tool_result"""),
    re.compile(r"""from\s+credential_guard\.result_guard\s+import\s+guard_tool_result"""),
    re.compile(r"""on_transform_tool_result\s*\("""),
    # Direct invoke_hook must not impersonate the AIAgent main chain.
    re.compile(r"""invoke_hook\s*\(\s*['"]transform_tool_result['"]"""),
)


def _skip_if_no_hermes():
    if not HERMES_AGENT_ROOT.is_dir() or not HERMES_SPIKE_PYTHON.is_file():
        pytest.skip("Hermes spike source/venv unavailable")


def _probe_source() -> str:
    text = (REPO / "tests" / "test_result_guard_authenticity_gate.py").read_text(
        encoding="utf-8"
    )
    marker = "\nPROBE = textwrap.dedent(\n"
    start = text.find(marker)
    assert start > 0
    lit = text.find("r'''", start)
    assert lit > start
    end_lit = text.find("'''", lit + 4)
    assert end_lit > lit
    return text[start + 1 : end_lit + 3]


def _false_green_hits(text: str) -> list:
    hits = []
    for cre in _FORBIDDEN:
        for m in cre.finditer(text):
            line_start = text.rfind("\n", 0, m.start()) + 1
            line_end = text.find("\n", m.start())
            line = text[line_start:line_end]
            stripped = line.lstrip()
            if stripped.startswith("#") or "re.compile" in stripped:
                continue
            hits.append((cre.pattern, stripped[:120]))
    return hits


PROBE = textwrap.dedent(
    r'''
import json
import os
import socket
import sys
import threading
import types
from pathlib import Path
from unittest.mock import patch

token = os.environ["CG_DECOY"]
import hashlib as _hashlib
# C9: same registry token llm_request / tool-result emit for credentials.api / value.
_api_secret_token = (
    "<SECRET:cg_"
    + _hashlib.sha256(("api" + chr(0) + "value").encode("utf-8")).hexdigest()[:16]
    + ">"
)
hermes_home = Path(os.environ["HERMES_HOME"])
home = Path(os.environ["HOME"])
plugin_src = Path(os.environ["CG_PLUGIN_SRC"])

sys.path.insert(0, os.environ["HERMES_AGENT_ROOT"])
# Do not stub openai — AIAgent needs the real OpenAI client class.
for _name in ("modal", "anthropic", "firecrawl", "exa_py", "fal_client"):
    sys.modules.setdefault(_name, types.ModuleType(_name))

plug_root = hermes_home / "plugins" / "credential-guard"
if plug_root.exists():
    import shutil as _sh
    _sh.rmtree(plug_root)
plug_root.mkdir(parents=True)
for name in ("plugin.yaml", "__init__.py"):
    src = plugin_src / name
    if src.is_file():
        (plug_root / name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
import shutil as _sh
_sh.copytree(plugin_src / "credential_guard", plug_root / "credential_guard")

# Optional runtime mutation: break ONLY the temp install copy (repo source stays healthy).
if os.environ.get("CG_SABOTAGE_INSTALL_GUARD") == "1":
    _sab = plug_root / "credential_guard" / "result_guard.py"
    _nl = chr(10)
    _sab.write_text(
        _sab.read_text(encoding="utf-8")
        + _nl
        + _nl
        + "def guard_tool_result(text, registry, session_materials=None):"
        + _nl
        + '    return "CG_SABOTAGE_INSTALL_MARKER"'
        + _nl,
        encoding="utf-8",
    )

repo_root = Path(os.environ["CG_REPO"]).resolve()
plug_root = plug_root.resolve()

def _under(path, root):
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except (ValueError, OSError):
        return False

def _rel_to_plugin(path):
    return Path(path).resolve().relative_to(plug_root).as_posix()

store = hermes_home / "credential-guard"
store.mkdir(parents=True, exist_ok=True)
os.chmod(store, 0o700)
doc = {
    "version": 2,
    "credentials": {"api": {"type": "token", "value": token}},
    "bindings": {},
}
cfg = store / "credential-guard.json"
cfg.write_text(json.dumps(doc), encoding="utf-8")
os.chmod(cfg, 0o600)
(hermes_home / "config.yaml").write_text(
    "model: unused\n"
    "approvals:\n  mode: \"manual\"\n  timeout: 300\n"
    "plugins:\n  enabled:\n    - credential-guard\n",
    encoding="utf-8",
)

payload_dir = home / "tmp" / "r4-auth-payloads"
payload_dir.mkdir(parents=True, exist_ok=True)
raw_clean = '{\n  "ok": true,\n  "msg": "hello"\n}'
raw_secret = f"leak {token} trailing"
raw_auth = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def"
raw_field = "password=cg_r4_unknown_password_value_99"
pem = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7decoy_pem_body\n"
    "-----END PRIVATE KEY-----"
)
paths = []
for name, body in (
    ("clean.txt", raw_clean),
    ("secret.txt", raw_secret),
    ("auth.txt", raw_auth),
    ("field.txt", raw_field),
    ("pem.txt", pem),
):
    p = payload_dir / name
    p.write_text(body, encoding="utf-8")
    paths.append(str(p))

raw_requests = []

def _read_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(min(65536, n - len(buf)))
        if not chunk:
            break
        buf += chunk
    return buf

def _handle_client(conn, _addr):
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
        raw_requests.append(header_blob + b"\r\n\r\n" + body)
        req = {}
        try:
            req = json.loads(body.decode("utf-8", errors="replace"))
        except Exception:
            # Non-chat probe/health traffic — ignore without advancing tool sequence.
            data = b'{"object":"list","data":[]}'
            header = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(data)).encode() + b"\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            )
            conn.sendall(header + data)
            return
        msgs = req.get("messages") or []
        if not isinstance(msgs, list):
            msgs = []
        tool_msg_count = sum(
            1 for m in msgs if isinstance(m, dict) and m.get("role") == "tool"
        )
        if tool_msg_count < len(paths):
            path = paths[tool_msg_count]
            args = json.dumps({"path": path}, separators=(",", ":"))
            tc_id = f"call_{tool_msg_count + 1}"
            resp = {
                "id": f"c{tool_msg_count}",
                "object": "chat.completion",
                "created": 1,
                "model": "fake-model",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{
                            "id": tc_id,
                            "type": "function",
                            "function": {"name": "read_file", "arguments": args},
                        }],
                    },
                    "finish_reason": "tool_calls",
                }],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        else:
            resp = {
                "id": "c_done",
                "object": "chat.completion",
                "created": 1,
                "model": "fake-model",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "auth-done"},
                    "finish_reason": "stop",
                }],
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
from hermes_cli.plugins import discover_plugins

plugins_mod._plugin_manager = None
discover_plugins(force=True)
mgr = plugins_mod.get_plugin_manager()
loaded = mgr._plugins.get("credential-guard")
assert loaded is not None and loaded.enabled
cbs = list(mgr._hooks.get("transform_tool_result") or [])
assert cbs, "transform_tool_result callbacks missing after discover_plugins"

import inspect

cb0 = cbs[0]
cb_file = inspect.getfile(cb0)
cb_mod = inspect.getmodule(cb0)
assert cb_mod is not None
hooks_file = getattr(cb_mod, "__file__", "") or ""

rg_mod = None
for name, mod in list(sys.modules.items()):
    f = getattr(mod, "__file__", None) or ""
    if not f:
        continue
    if name.endswith(".result_guard") and "credential_guard" in name and _under(f, plug_root):
        rg_mod = mod
        break
assert rg_mod is not None, "result_guard must load from temp plugin install"
rg_file = getattr(rg_mod, "__file__", "") or ""
guard_fn = getattr(rg_mod, "guard_tool_result", None)
assert callable(guard_fn)
guard_code = guard_fn.__code__

# Install-source evidence (derived paths — not hardcoded labels).
callback_under_plugin = _under(cb_file, plug_root)
hooks_under_plugin = _under(hooks_file, plug_root)
result_guard_under_plugin = _under(rg_file, plug_root)
callback_under_repo_tree = _under(cb_file, repo_root)
hooks_under_repo_tree = _under(hooks_file, repo_root)
result_guard_under_repo_tree = _under(rg_file, repo_root)
plugin_rel_callback = _rel_to_plugin(cb_file) if callback_under_plugin else ""
plugin_rel_hooks = _rel_to_plugin(hooks_file) if hooks_under_plugin else ""
plugin_rel_result_guard = _rel_to_plugin(rg_file) if result_guard_under_plugin else ""

from run_agent import AIAgent
run_code = AIAgent.run_conversation.__code__

entered_guard = []
entered_run = []

def _profile(frame, event, arg):
    if event == "call":
        if frame.f_code is guard_code:
            entered_guard.append(frame.f_code.co_name)
        elif frame.f_code is run_code:
            entered_run.append(frame.f_code.co_name)
    return _profile

def gate(tool_name, reason, **kwargs):
    return {"approved": False, "message": "DENIED: r4-auth-unexpected-approval"}

sys.setprofile(_profile)
threading.setprofile(_profile)
try:
    with patch("tools.approval.request_tool_approval", side_effect=gate):
        agent = AIAgent(
            api_key="sk-synthetic-r4-auth-only",
            base_url=base,
            model="fake-model",
            provider="custom",
            api_mode="chat_completions",
            max_iterations=10,
            quiet_mode=True,
            skip_context_files=True,
            skip_memory=True,
            enabled_toolsets=["file", "credential_guard"],
        )
        agent._disable_streaming = True
        agent.run_conversation("Please read the prepared payload files once each.")
finally:
    sys.setprofile(None)
    threading.setprofile(None)

_stop.set()
try:
    _srv.close()
except Exception:
    pass

tool_blobs = []
for b in raw_requests:
    try:
        body = b.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in b else b
        j = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        continue
    for m in j.get("messages") or []:
        if isinstance(m, dict) and m.get("role") == "tool":
            tool_blobs.append(str(m.get("content") or ""))

provider_blob = "\n".join(tool_blobs)
full_jwt = "eyJhbGciOiJIUzI1NiJ9.abc.def"
print(json.dumps({
    "callback_count": len(cbs),
    "guard_entered": len(entered_guard) > 0,
    "guard_enter_count": len(entered_guard),
    "run_conversation_entered": len(entered_run) > 0,
    "run_conversation_enter_count": len(entered_run),
    "tool_result_message_count": len(tool_blobs),
    "clean_preserved": any("hello" in t and "ok" in t for t in tool_blobs),
    "provider_secret_count": int(provider_blob.count(token)),
    "auth_residue": int(provider_blob.count(full_jwt)),
    "pem_residue": int(provider_blob.count("BEGIN PRIVATE KEY")),
    "field_residue": int(provider_blob.count("cg_r4_unknown_password_value_99")),
    "credential_placeholder_count": int(provider_blob.count(_api_secret_token)),
    "redacted_secret_count": int(provider_blob.count("<REDACTED_SECRET>")),
    "callback_under_plugin": callback_under_plugin,
    "hooks_under_plugin": hooks_under_plugin,
    "result_guard_under_plugin": result_guard_under_plugin,
    "callback_under_repo_tree": callback_under_repo_tree,
    "hooks_under_repo_tree": hooks_under_repo_tree,
    "result_guard_under_repo_tree": result_guard_under_repo_tree,
    "plugin_rel_callback": plugin_rel_callback,
    "plugin_rel_hooks": plugin_rel_hooks,
    "plugin_rel_result_guard": plugin_rel_result_guard,
    "cwd_is_repo": str(Path.cwd().resolve()) == str(repo_root),
    "sabotage_marker_count": int(provider_blob.count("CG_SABOTAGE_INSTALL_MARKER")),
    "provider_raw_request_count": len(raw_requests),
}))
'''
)


def test_authenticity_gate_rejects_false_green_patterns():
    hits = _false_green_hits(_probe_source())
    assert hits == [], f"false-green hits: {hits}"


def test_authenticity_gate_requires_live_pluginmanager_symbols():
    probe = _probe_source()
    for needle in (
        "discover_plugins",
        "get_plugin_manager",
        "transform_tool_result",
        "sys.setprofile",
        "AIAgent",
        "run_conversation",
        "provider_secret_count",
        "guard_tool_result",
        "callback_under_plugin",
        "result_guard_under_plugin",
        "plugin_rel_result_guard",
        "CG_SABOTAGE_INSTALL_GUARD",
    ):
        assert needle in probe
    assert "load_path" not in probe or '"load_path": "discover_plugins"' not in probe
    assert '"agent_api": "AIAgent.run_conversation"' not in probe
    assert not re.search(
        r"""invoke_hook\s*\(\s*['"]transform_tool_result['"]""", probe
    )


def _run_auth_probe(tmp_path, *, sabotage: bool = False):
    home = tmp_path / "home"
    hermes = tmp_path / "hermes"
    neutral = tmp_path / "neutral_cwd"
    home.mkdir()
    hermes.mkdir()
    neutral.mkdir()
    (home / "tmp").mkdir()
    env = {
        "PATH": os.environ.get("PATH") or "/usr/bin:/bin",
        "HOME": str(home),
        "HERMES_HOME": str(hermes),
        "HERMES_AGENT_ROOT": str(HERMES_AGENT_ROOT),
        "PYTHONPATH": str(HERMES_AGENT_ROOT),
        "CG_REPO": str(REPO),
        "CG_PLUGIN_SRC": str(REPO),
        "CG_DECOY": DECOY,
        "LANG": "C",
        "LC_ALL": "C",
        "TMPDIR": str(home / "tmp"),
    }
    if sabotage:
        env["CG_SABOTAGE_INSTALL_GUARD"] = "1"
    proc = subprocess.run(
        [str(HERMES_SPIKE_PYTHON), "-c", PROBE],
        cwd=str(neutral),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    return proc


def test_live_pluginmanager_transform_enters_result_guard(tmp_path):
    _skip_if_no_hermes()
    proc = _run_auth_probe(tmp_path, sabotage=False)
    assert proc.returncode == 0, (proc.stdout[-2000:], proc.stderr[-3000:])
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip().startswith("{")]
    assert lines, proc.stdout[-2000:]
    data = json.loads(lines[-1])
    assert data["callback_count"] >= 1
    assert data["run_conversation_entered"] is True
    assert data["run_conversation_enter_count"] >= 1
    assert data["guard_entered"] is True
    assert data["guard_enter_count"] >= 1
    assert data["tool_result_message_count"] >= 5
    assert data["clean_preserved"] is True
    assert data["provider_secret_count"] == 0
    assert data["auth_residue"] == 0
    assert data["pem_residue"] == 0
    assert data["field_residue"] == 0
    assert data["credential_placeholder_count"] >= 1
    assert data["redacted_secret_count"] >= 1
    assert data["provider_raw_request_count"] >= 2
    # Install-source path evidence (temp plugin root — not repo tree).
    assert data["cwd_is_repo"] is False
    assert data["callback_under_plugin"] is True
    assert data["hooks_under_plugin"] is True
    assert data["result_guard_under_plugin"] is True
    assert data["callback_under_repo_tree"] is False
    assert data["hooks_under_repo_tree"] is False
    assert data["result_guard_under_repo_tree"] is False
    assert data["plugin_rel_result_guard"].endswith("result_guard.py")
    assert "credential_guard" in data["plugin_rel_result_guard"]
    assert data["plugin_rel_hooks"].endswith("hooks.py")


def test_mutation_sabotaged_install_does_not_fall_back_to_repo(tmp_path):
    """Break temp install guard; healthy repo copy must not shadow the install."""
    _skip_if_no_hermes()
    # Repo source must remain a healthy guard implementation (no sabotage marker).
    repo_rg = (REPO / "credential_guard" / "result_guard.py").read_text(encoding="utf-8")
    assert "RESULT_GUARD_FAIL_TEXT" in repo_rg
    assert "def guard_tool_result" in repo_rg
    assert "CG_SABOTAGE_INSTALL_MARKER" not in repo_rg

    proc = _run_auth_probe(tmp_path, sabotage=True)
    assert proc.returncode == 0, (proc.stdout[-2000:], proc.stderr[-3000:])
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip().startswith("{")]
    assert lines, proc.stdout[-2000:]
    data = json.loads(lines[-1])
    # Still loaded from the (sabotaged) install tree — not the repo tree.
    assert data["cwd_is_repo"] is False
    assert data["callback_under_plugin"] is True
    assert data["hooks_under_plugin"] is True
    assert data["result_guard_under_plugin"] is True
    assert data["result_guard_under_repo_tree"] is False
    assert data["hooks_under_repo_tree"] is False
    # Sabotaged install marker reaches Provider — healthy repo guard would never emit it.
    assert data["sabotage_marker_count"] >= 1
    assert data["clean_preserved"] is False
    assert data["credential_placeholder_count"] == 0


def test_mutation_direct_invoke_hook_impersonation_rejected():
    """Mutation: reintroducing direct hook invocation as Agent stand-in must be killed."""
    probe = _probe_source()
    # Build the forbidden call without embedding a static match in this test body.
    hook_name = "transform_tool_result"
    forbidden_call = (
        "invoke_hook(" + repr(hook_name) + ", tool_name='terminal', args={}, result='x')"
    )
    mutated = probe.replace(
        'agent.run_conversation("Please read the prepared payload files once each.")',
        forbidden_call,
        1,
    )
    assert mutated != probe
    hits = _false_green_hits(mutated)
    assert any("invoke_hook" in h[0] for h in hits)
