from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
COMPANION_ROOT = PLUGIN_ROOT / "tests" / "companions" / "credential_guard_test"
LOOPBACK_LAUNCHER = PLUGIN_ROOT / "tests" / "support" / "hermes_loopback_launcher.py"
HERMES_PYTHON = Path("/Users/yelei/.hermes/hermes-agent/venv/bin/python")
HERMES_BIN = Path("/Users/yelei/.local/bin/hermes")
WORKER_PROFILE = Path("/Users/yelei/.hermes/profiles/worker")
DECOY_SECRET = "decoy_db_password_123"


def opaque_token(key: str, field: str) -> str:
    digest = hashlib.sha256(f"{key}\0{field}".encode("utf-8")).hexdigest()[:16]
    return f"<SECRET:cg_{digest}>"


DECOY_TOKEN = opaque_token("db", "password")


@dataclass
class IsolatedHermes:
    root: Path
    home: Path
    hermes_home: Path
    cwd: Path
    tmp: Path
    fixture_path: Path
    net_audit_path: Path

    def env(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        env = {
            "HOME": str(self.home),
            "HERMES_HOME": str(self.hermes_home),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": os.environ.get("LANG", "C"),
            "LC_ALL": os.environ.get("LC_ALL", "C"),
            "TMPDIR": str(self.tmp),
            "NO_PROXY": "*",
            "no_proxy": "*",
            "CREDENTIAL_GUARD_NET_AUDIT_PATH": str(self.net_audit_path),
            "CREDENTIAL_GUARD_HERMES_BIN": str(
                Path("/Users/yelei/.hermes/hermes-agent/venv/bin/hermes")
            ),
            "PYTHONPATH": "/Users/yelei/.hermes/hermes-agent",
        }
        if extra:
            env.update(extra)
        return env


_WORKER_WATCH_PREFIXES = (
    "config.yaml",
    ".env",
    "plugins/",
    "sessions/",
    "logs/",
)
_WORKER_WATCH_EXACT = {
    "config.yaml",
    ".env",
    "state.db",
    "state.db-wal",
    "state.db-shm",
}
_CONFIG_OWNED_PREFIXES = ("config.yaml", ".env", "plugins/", "sessions/")
_LIVE_NOISE_SUFFIXES = (".db-wal", ".db-shm")
_LIVE_NOISE_PREFIXES = ("logs/",)


def _is_watched(rel: str) -> bool:
    if rel in _WORKER_WATCH_EXACT:
        return True
    return any(
        rel == prefix.rstrip("/") or rel.startswith(prefix)
        for prefix in _WORKER_WATCH_PREFIXES
    )


def _is_config_owned(rel: str) -> bool:
    if rel in {"config.yaml", ".env"}:
        return True
    return any(
        rel == prefix.rstrip("/") or rel.startswith(prefix)
        for prefix in _CONFIG_OWNED_PREFIXES
    )


def _is_live_noise_path(rel: str) -> bool:
    if rel.endswith(_LIVE_NOISE_SUFFIXES) or rel in {"state.db-wal", "state.db-shm"}:
        return True
    return any(rel.startswith(prefix) for prefix in _LIVE_NOISE_PREFIXES)


def _entry_fingerprint(root: Path, path: Path) -> Dict[str, Any]:
    """Fingerprint a single path using lstat (do not follow symlinks).

    Never returns file contents — only path, type, metadata, and sha256/link target.
    """
    rel = str(path.relative_to(root)).replace("\\", "/")
    st = path.lstat()
    entry: Dict[str, Any] = {
        "path": rel,
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "mode": st.st_mode,
        "inode": st.st_ino,
        "is_symlink": path.is_symlink(),
        "is_dir": path.is_dir() and not path.is_symlink(),
        "sha256": None,
        "link_target": None,
    }
    if path.is_symlink():
        try:
            entry["link_target"] = os.readlink(path)
        except OSError:
            entry["link_target"] = "unreadable-link"
        # Symlink identity only — do not hash the referent.
        entry["sha256"] = hashlib.sha256(
            f"symlink:{entry['link_target']}".encode("utf-8")
        ).hexdigest()
    elif path.is_dir():
        entry["sha256"] = hashlib.sha256(f"dir:{rel}".encode("utf-8")).hexdigest()
    elif path.is_file():
        try:
            entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            entry["sha256"] = "unreadable"
    else:
        entry["sha256"] = hashlib.sha256(f"other:{st.st_mode}".encode("utf-8")).hexdigest()
    return entry


def content_fingerprint(root: Path) -> Dict[str, Any]:
    """SHA-256 fingerprint of watched worker paths — files, dirs, symlink identity.

    Never returns file contents — only path, size, mode, mtime, sha256 / link target.
    Uses lstat/readlink so symlinks are fingerprinted by identity, not referent.
    """
    if not root.exists():
        return {"status": "missing", "files": [], "digest": "missing"}
    rows: List[str] = []
    files: List[Dict[str, Any]] = []
    seen: set = set()

    def _consider(path: Path) -> None:
        if path == root or not path.exists() and not path.is_symlink():
            # dangling symlink: still consider via is_symlink
            if not path.is_symlink():
                return
        rel = str(path.relative_to(root)).replace("\\", "/")
        if rel in seen:
            return
        watched = (
            rel in _WORKER_WATCH_EXACT
            or rel in {"plugins", "sessions", "logs"}
            or any(
                rel == prefix.rstrip("/") or rel.startswith(prefix)
                for prefix in _WORKER_WATCH_PREFIXES
            )
        )
        if not watched:
            return
        seen.add(rel)
        entry = _entry_fingerprint(root, path)
        files.append(entry)
        rows.append(
            f"{entry['path']}|{entry['size']}|{entry['mtime_ns']}|{entry['mode']}|"
            f"{entry['inode']}|{entry['sha256']}|{entry['link_target']}|{entry['is_symlink']}"
        )

    # Walk without following symlinks.
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        # Snapshot dirnames/filenames first; also fingerprint the directory itself.
        if base != root:
            _consider(base)
        for name in sorted(dirnames) + sorted(filenames):
            _consider(base / name)

    files.sort(key=lambda e: e["path"])
    rows = [
        f"{e['path']}|{e['size']}|{e['mtime_ns']}|{e['mode']}|"
        f"{e['inode']}|{e['sha256']}|{e['link_target']}|{e['is_symlink']}"
        for e in files
    ]
    digest = hashlib.sha256("\n".join(rows).encode("utf-8")).hexdigest()
    return {"status": "ok", "file_count": len(files), "files": files, "digest": digest}


def metadata_fingerprint(root: Path) -> str:
    """Backward-compatible digest string used by existing assertions."""
    fp = content_fingerprint(root)
    return f"{fp.get('file_count', 0)}:{fp.get('digest', 'missing')}"


def detect_worker_live(worker_root: Path) -> bool:
    """Best-effort check: a hermes process appears bound to this worker profile."""
    target = str(worker_root.resolve())
    try:
        proc = subprocess.run(
            ["ps", "-ax", "-o", "pid=,command="],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    for line in (proc.stdout or "").splitlines():
        lower = line.lower()
        if "hermes" not in lower and "gateway" not in lower:
            continue
        # Environ is not always visible; also match profile path in argv/cwd hints.
        if target in line or "profiles/worker" in line:
            return True
    # Secondary: recent mtime on logs/WAL suggests an active writer.
    for rel in ("logs/agent.log", "state.db-wal"):
        path = worker_root / rel
        if not path.exists():
            continue
        try:
            age = abs(path.stat().st_mtime - __import__("time").time())
        except OSError:
            continue
        if age < 30:
            return True
    return False


def classify_worker_delta(
    before: Dict[str, Any],
    after: Dict[str, Any],
    *,
    worker_live: Optional[bool] = None,
) -> Dict[str, Any]:
    """Classify worker fingerprint delta. Live log/WAL noise is never PASS.

    Status values:
      - unchanged: full monitored digest identical
      - changed: any attributable change (including log/WAL when worker idle)
      - inconclusive_live_noise: only log/WAL/state noise while worker appears live
    """
    before_map = {f["path"]: f for f in before.get("files", [])}
    after_map = {f["path"]: f for f in after.get("files", [])}
    all_changes = []
    config_changes = []
    noise_changes = []
    for path in sorted(set(before_map) | set(after_map)):
        b = before_map.get(path)
        a = after_map.get(path)
        if b == a:
            continue
        item = {"path": path, "before": b, "after": a}
        all_changes.append(item)
        if _is_config_owned(path):
            config_changes.append(item)
        elif _is_live_noise_path(path) or path == "state.db":
            noise_changes.append(item)
        else:
            config_changes.append(item)

    digest_equal = before.get("digest") == after.get("digest")
    if not all_changes and digest_equal:
        status = "unchanged"
    elif config_changes:
        status = "changed"
    elif noise_changes and worker_live:
        status = "inconclusive_live_noise"
    elif noise_changes:
        # Idle worker: log/WAL changes are not auto-exempted — fail-closed.
        status = "changed"
    else:
        status = "changed"

    return {
        "status": status,
        "stable": status == "unchanged",
        "unchanged": status == "unchanged",
        "config_plugins_sessions_unchanged": not config_changes,
        "natural_or_live_noise": noise_changes,
        "unexpected_changes": config_changes if config_changes else (
            all_changes if status == "changed" else []
        ),
        "all_changes": all_changes,
        "digest_equal": digest_equal,
        "worker_live": worker_live,
    }


def temp_isolation_evidence(iso: "IsolatedHermes") -> Dict[str, Any]:
    """Prove the test instance only writes under the temporary HERMES_HOME tree."""
    home = iso.home.resolve()
    hermes_home = iso.hermes_home.resolve()
    cwd = iso.cwd.resolve()
    tmp = iso.tmp.resolve()
    worker = WORKER_PROFILE.resolve()
    config_path = hermes_home / "config.yaml"
    state_db = hermes_home / "state.db"
    logs_path = hermes_home / "logs"
    evidence = {
        "HOME": str(home),
        "HERMES_HOME": str(hermes_home),
        "cwd": str(cwd),
        "TMPDIR": str(tmp),
        "config_path": str(config_path),
        "state_db_path": str(state_db),
        "logs_path": str(logs_path),
        "worker_profile": str(worker),
        "home_is_temp": worker not in home.parents and home != worker,
        "hermes_home_is_temp": hermes_home != worker and worker not in hermes_home.parents,
        "cwd_is_temp": cwd != worker and worker not in cwd.parents,
        "config_under_temp_hermes_home": config_path.resolve().parent == hermes_home,
        "state_under_temp_hermes_home": True,  # path is defined under hermes_home
        "logs_under_temp_hermes_home": True,
    }
    evidence["all_temp"] = all(
        [
            evidence["home_is_temp"],
            evidence["hermes_home_is_temp"],
            evidence["cwd_is_temp"],
            evidence["config_under_temp_hermes_home"],
            evidence["state_under_temp_hermes_home"],
            evidence["logs_under_temp_hermes_home"],
        ]
    )
    return evidence


def assert_worker_evidence(
    delta: Dict[str, Any],
    isolation: Dict[str, Any],
) -> None:
    """Hard-fail on config/plugins/sessions drift; never treat live noise as PASS."""
    assert isolation.get("all_temp") is True, isolation
    assert delta.get("config_plugins_sessions_unchanged") is True, delta
    status = delta.get("status")
    assert status in {"unchanged", "inconclusive_live_noise"}, delta
    if status == "inconclusive_live_noise":
        assert delta.get("stable") is False
        # Explicitly do not claim worker content unchanged.
        assert delta.get("unchanged") is False


def prepare_isolated_hermes(tmp_path: Path, base_url: str) -> IsolatedHermes:
    home = tmp_path / "home"
    hermes_home = tmp_path / "hermes_home"
    cwd = tmp_path / "neutral_cwd"
    tmp = tmp_path / "tmp"
    for path in (home, hermes_home, cwd, tmp):
        path.mkdir(parents=True, exist_ok=True)

    plugin_dest = hermes_home / "plugins" / "credential-guard"
    shutil.copytree(
        PLUGIN_ROOT,
        plugin_dest,
        ignore=shutil.ignore_patterns(
            ".venv",
            ".pytest_cache",
            "__pycache__",
            "tests",
            "scripts",
            "docs",
            "build",
            "dist",
            "*.egg-info",
            ".eggs",
            ".m0-m1-task.md",
            ".m0-m1-fix-task.md",
            ".m0-m1-close-task.md",
            ".m0-m1-release-fix-task.md",
            ".m0-m1-final-close-task.md",
            ".m0-m1-two-fixes-task.md",
            ".m2-task.md",
            ".m2-approval-fix-task.md",
            ".m2-release-blockers-task.md",
            "*.md",
            "setup.py",
            "MANIFEST.in",
            "pytest.ini",
        ),
    )
    # Production tree must not carry test companions / fixtures.
    companion_dest = hermes_home / "plugins" / "credential-guard-test"
    shutil.copytree(COMPANION_ROOT, companion_dest)

    # Production secret store: canary lives in credential-guard.json (not companion).
    store = hermes_home / "credential-guard"
    store.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(store, 0o700)
    unified = {
        "version": 2,
        "credentials": {
            "db": {
                "type": "username_password",
                "username": "cg_readonly",
                "password": DECOY_SECRET,
            }
        },
        "bindings": {},
    }
    cfg_path = store / "credential-guard.json"
    cfg_path.write_text(json.dumps(unified), encoding="utf-8")
    os.chmod(cfg_path, 0o600)

    # Legacy companion fixture path retained for optional fault harnesses only;
    # production egress must not depend on it (FIXTURE_ENABLE is unset).
    fixture_path = hermes_home / "credential-guard-test" / "canaries.yaml"
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    fixture_path.write_text(
        f"- key: db\n  field: password\n  secret: {DECOY_SECRET}\n",
        encoding="utf-8",
    )

    net_audit_path = tmp / "net_audit.json"
    net_audit_path.write_text("{\"attempts\": []}\n", encoding="utf-8")

    config = {
        "model": {
            "default": "fake-model",
            "provider": "custom",
            "base_url": base_url,
        },
        "plugins": {"enabled": ["credential-guard", "credential-guard-test"]},
        "approvals": {"mode": "manual"},
        "display": {"tool_progress": "off"},
        # Official empty tool surface for CLI: no terminal/file/browser/delegation.
        "platform_toolsets": {"cli": []},
        "agent": {"disabled_toolsets": ["kanban"]},
        # Prevent tirith auto-download from github.com during isolated E2E.
        "security": {"tirith_enabled": False},
        # Formal Hermes config: disable auto-title so main-chain E2E is not
        # conflated with auxiliary title_generation (which bypasses plugin
        # llm_* middleware — see docs/R7-…). This does NOT claim all
        # auxiliary paths are protected.
        "auxiliary": {
            "title_generation": {"enabled": False},
        },
    }
    (hermes_home / "config.yaml").write_text(
        _to_yaml(config),
        encoding="utf-8",
    )
    (hermes_home / ".env").write_text(
        "OPENAI_API_KEY=test-fake-key-not-real\n",
        encoding="utf-8",
    )
    return IsolatedHermes(
        root=tmp_path,
        home=home,
        hermes_home=hermes_home,
        cwd=cwd,
        tmp=tmp,
        fixture_path=fixture_path,
        net_audit_path=net_audit_path,
    )


def run_hermes(
    iso: IsolatedHermes,
    args: List[str],
    *,
    extra_env: Optional[Dict[str, str]] = None,
    timeout: int = 120,
    use_loopback_guard: bool = True,
) -> subprocess.CompletedProcess:
    assert HERMES_PYTHON.is_file(), "hermes python missing"
    assert LOOPBACK_LAUNCHER.is_file(), "loopback launcher missing"
    # Empty/minimal toolset via official -t context_engine (0 tools).
    if args and args[0] == "chat" and "-t" not in args and "--toolsets" not in args:
        args = [*args, "-t", "context_engine"]
    if use_loopback_guard:
        cmd = [str(HERMES_PYTHON), str(LOOPBACK_LAUNCHER), *args]
    else:
        assert HERMES_BIN.is_file(), "hermes binary missing"
        cmd = [str(HERMES_BIN), *args]
    return subprocess.run(
        cmd,
        cwd=str(iso.cwd),
        env=iso.env(extra_env),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def read_net_audit(iso: IsolatedHermes) -> Dict[str, Any]:
    if not iso.net_audit_path.is_file():
        return {"attempts": []}
    try:
        return json.loads(iso.net_audit_path.read_text(encoding="utf-8"))
    except Exception:
        return {"attempts": []}


def assert_all_loopback(audit: Dict[str, Any]) -> None:
    attempts = audit.get("attempts") or []
    for host, port in attempts:
        host_l = str(host).strip().lower().strip("[]")
        assert host_l in {"127.0.0.1", "localhost", "::1"}, (
            f"non-loopback connect attempted: {host}:{port}; all={attempts}"
        )


def assert_loopback_guards_present() -> None:
    """Import launcher and assert guarded socket entry points are installed."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "hermes_loopback_launcher_assert",
        LOOPBACK_LAUNCHER,
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # In the parent test process guards are not installed; document expected names.
    for name in mod.GUARDED_ENTRYPOINTS:
        assert name.startswith("socket."), name
    assert callable(mod.install_guards)
    assert callable(mod.assert_guards_installed)
    notes = mod.remaining_bypass_notes()
    assert notes, "bypass boundary notes required"


def count_decoy_in_tree(
    root: Path,
    decoy: str,
    *,
    ignore_suffixes: tuple = (),
) -> Dict[str, Any]:
    total = 0
    hits: List[Dict[str, Any]] = []
    decoy_b = decoy.encode("utf-8")
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(str(path).endswith(suf) for suf in ignore_suffixes):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        count = data.count(decoy_b)
        if count:
            total += count
            hits.append({"path": str(path.relative_to(root)), "count": count})
    return {"total": total, "hits": hits}


def count_decoy_in_paths(
    root: Path,
    decoy: str,
    relative_paths: List[str],
) -> Dict[str, Any]:
    """Count decoy occurrences in specific relative paths (AC8/AC9 split)."""
    decoy_b = decoy.encode("utf-8")
    out: Dict[str, Any] = {}
    for rel in relative_paths:
        path = root / rel
        if not path.exists():
            out[rel] = {"exists": False, "count": 0}
            continue
        if path.is_dir():
            total = 0
            for child in path.rglob("*"):
                if child.is_file():
                    try:
                        total += child.read_bytes().count(decoy_b)
                    except OSError:
                        pass
            out[rel] = {"exists": True, "count": total}
        else:
            try:
                count = path.read_bytes().count(decoy_b)
            except OSError:
                count = 0
            out[rel] = {"exists": True, "count": count}
    return out


def request_has_tools(body: bytes) -> bool:
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        return b'"tools"' in body and b"[]" not in body
    tools = payload.get("tools")
    if tools is None:
        return False
    if isinstance(tools, list) and len(tools) == 0:
        return False
    return bool(tools)


def is_title_generation_body(body: bytes) -> bool:
    """Detect Hermes auxiliary title_generation chat.completions payloads."""
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        return False
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        return False
    first = messages[0] if isinstance(messages[0], dict) else {}
    content = first.get("content") or ""
    if not isinstance(content, str):
        return False
    if "You name chat sessions" in content:
        return True
    rf = payload.get("response_format") or {}
    if isinstance(rf, dict):
        schema = rf.get("json_schema") or {}
        if isinstance(schema, dict) and schema.get("name") == "session_title":
            return True
    return False


def main_chain_chat_bodies(bodies: List[bytes]) -> List[bytes]:
    """Keep provider chat bodies that are not auxiliary title_generation."""
    return [b for b in bodies if not is_title_generation_body(b)]


def _to_yaml(data: Any, indent: int = 0) -> str:
    sp = "  " * indent
    if isinstance(data, dict):
        lines = []
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                lines.append(f"{sp}{key}:")
                lines.append(_to_yaml(value, indent + 1))
            else:
                lines.append(f"{sp}{key}: {_yaml_scalar(value)}")
        return "\n".join(lines) + ("\n" if indent == 0 else "")
    if isinstance(data, list):
        lines = []
        for item in data:
            if isinstance(item, (dict, list)):
                lines.append(f"{sp}-")
                lines.append(_to_yaml(item, indent + 1))
            else:
                lines.append(f"{sp}- {_yaml_scalar(item)}")
        return "\n".join(lines)
    return f"{sp}{_yaml_scalar(data)}"


def _yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if any(ch in text for ch in ":#{}[]&*?|>!%@`'\""):
        return json.dumps(text)
    return text
