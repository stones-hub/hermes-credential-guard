#!/usr/bin/env python3
"""R11 0.4.5 final plugin-ZIP isolated E2E harness (opt-in).

Installs the landed 0.4.5 plugin ZIP into a temporary Hermes home and proves:
1. real PluginManager discovers/loads from the install tree (not repo source);
2. key module bytes match the ZIP member;
3. long-session continuity cases (large request / collision / unresolved /
   protocol-field / residual / scanner / final gate);
4. protocol-field registered-secret fail-closed (0.4.4 narrow, retained);
5. fake Provider sees zero synthetic secrets; blocked cases Provider=0;
6. 0.4.5 R11 out-of-box behaviour from the INSTALL TREE:
   C1 zero-config chat passes through; C1 broken-store stays fail-closed;
   C6 redacted credential-code misuse returns the fixed refusal code;
   C10 offline ``validate`` accepts a good config and rejects a bad one;
7. source-tree fallback mutation is load-bearing: damaged install + healthy
   repo source + PluginManager must fail-closed (never load from source);
   factor-control with source on preferred sys.path must detect RED.

Landed phase: ``ARTIFACTS_LANDED=True`` with ``STRICT=True`` after the real
dual build wrote the four-file set into ``dist/``. Resolve binds the landed ZIP
hash (never silent skip / fake green). The pending-build hard-fail path is
retained for historical contract documentation; its sentinel constant
``PENDING_R11_045_DUAL_BUILD_BACKFILL`` is no longer the expected hash.

Never touches real default/worker profiles, real credentials, ~/.ssh, or
non-loopback peers. Never calls ``build_all``. Never modifies Hermes source.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import secrets
import subprocess
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PLUGIN_VERSION = "0.4.5"
EXPECTED_PLUGIN_ZIP = f"credential-guard-{PLUGIN_VERSION}-hermes-plugin.zip"
# Strict stage flag: True after the real dual build landed the four-file set.
ARTIFACTS_LANDED = True
STRICT = True
# Historical pending sentinel (kept for contract documentation only).
PENDING_SENTINEL = "PENDING_R11_045_DUAL_BUILD_BACKFILL"
# Backfilled from the landed build; must match dist/ + versioned manifest.
EXPECTED_PLUGIN_ZIP_SHA256 = (
    "a2d44717edee766f861e3484bbe051e14377409ed274c595ff0786d3b7a9f0e3"
)

OPENSSH_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
CG_SYNTHETIC_NOT_A_REAL_KEY_R11_045_ONLY
-----END OPENSSH PRIVATE KEY-----
"""

HERMES_ROOT = Path("/Users/yelei/.hermes/hermes-agent")


def _load_zip_helpers():
    """Shared install/extract helpers — single implementation, no fork."""
    path = ROOT / "scripts" / "installed_zip_plugin.py"
    spec = importlib.util.spec_from_file_location("installed_zip_plugin_r11", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_zip = _load_zip_helpers()


def resolve_plugin_zip(
    *,
    expected_name: str = EXPECTED_PLUGIN_ZIP,
    expected_sha256: str = EXPECTED_PLUGIN_ZIP_SHA256,
) -> Path:
    if STRICT and not ARTIFACTS_LANDED:
        raise FileNotFoundError(
            "R11_045_ARTIFACTS_PENDING_BUILD: "
            f"{expected_name} not landed; main-agent dual-build required "
            "(strict=True; not a skip)"
        )
    path = ROOT / "dist" / expected_name
    if not path.is_file():
        raise FileNotFoundError(f"missing landed plugin zip: {path}")
    digest = _zip.sha256_file(path)
    if (
        expected_sha256
        and "PENDING" not in expected_sha256
        and "PLACEHOLDER" not in expected_sha256
        and digest != expected_sha256
    ):
        raise AssertionError(
            f"plugin zip sha drift: got {digest} expected {expected_sha256}"
        )
    man_path = ROOT / "dist" / f"artifact-manifest-{PLUGIN_VERSION}.json"
    man = json.loads(man_path.read_text(encoding="utf-8"))
    assert man["version"] == PLUGIN_VERSION
    assert man["plugin_zip"]["filename"] == expected_name
    assert digest == man["plugin_zip"]["sha256"], "zip sha ≠ versioned manifest"
    return path


def _encoded_openssh_key() -> str:
    return base64.b64encode(OPENSSH_KEY.encode("utf-8")).decode("ascii")


def _write_isolated_profile(hermes_home: Path, *, secret: str) -> None:
    """Synthetic config + credential store under temporary HERMES_HOME only."""
    hermes_home.mkdir(parents=True, exist_ok=True)
    (hermes_home / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - credential-guard\n",
        encoding="utf-8",
    )
    store = hermes_home / "credential-guard"
    store.mkdir(parents=True, exist_ok=True)
    os.chmod(store, 0o700)
    cfg = {
        "version": 2,
        "credentials": {"tok": {"type": "token", "value": secret}},
        "bindings": {},
    }
    path = store / "credential-guard.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)


def _write_zero_config_profile(hermes_home: Path) -> None:
    """C1: plugin enabled, NO credential store at all (fresh user)."""
    hermes_home.mkdir(parents=True, exist_ok=True)
    (hermes_home / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - credential-guard\n",
        encoding="utf-8",
    )


def _write_broken_store_profile(hermes_home: Path) -> None:
    """C1 counter-case: a store EXISTS but is corrupt → must stay fail-closed."""
    hermes_home.mkdir(parents=True, exist_ok=True)
    (hermes_home / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - credential-guard\n",
        encoding="utf-8",
    )
    store = hermes_home / "credential-guard"
    store.mkdir(parents=True, exist_ok=True)
    os.chmod(store, 0o700)
    path = store / "credential-guard.json"
    path.write_text("{ this is not valid json", encoding="utf-8")
    os.chmod(path, 0o600)


def _purge_cg_modules() -> None:
    for k in list(sys.modules):
        if k == "credential_guard" or k.startswith("credential_guard."):
            sys.modules.pop(k, None)


def _plugin_manager_probe_script() -> str:
    """Hermes-venv subprocess body: real PluginManager discover/load + path audit."""
    return r'''
import json, os, sys
from pathlib import Path

hermes_root = Path(sys.argv[1]).resolve()
plugin_dest = Path(sys.argv[2]).resolve()
hermes_home = Path(sys.argv[3]).resolve()
source_root = Path(sys.argv[4]).resolve()
iso_home = Path(sys.argv[5]).resolve()
put_source_preferred = sys.argv[6] == "1"

cleaned = []
for entry in sys.path:
    if not entry:
        cleaned.append(entry)
        continue
    try:
        if Path(entry).resolve() == source_root:
            continue
    except OSError:
        pass
    cleaned.append(entry)
sys.path[:] = cleaned
if put_source_preferred:
    sys.path.insert(0, str(source_root))
sys.path.insert(0, str(hermes_root))

os.environ["HERMES_HOME"] = str(hermes_home)
os.environ["HOME"] = str(iso_home)

for key in list(sys.modules):
    if (
        key == "credential_guard"
        or key.startswith("credential_guard.")
        or key == "hermes_plugins"
        or key.startswith("hermes_plugins.")
    ):
        sys.modules.pop(key, None)

import hermes_cli.plugins as plugins_mod
from hermes_cli.plugins import PluginManager

plugins_mod._plugin_manager = None
mgr = PluginManager()
plugins_mod._plugin_manager = mgr
mgr.discover_and_load(force=True)

listed = list(mgr.list_plugins())
names = []
for item in listed:
    if isinstance(item, str):
        names.append(item)
    else:
        names.append(
            str(getattr(item, "name", None) or getattr(item, "key", None) or item)
        )

middleware = getattr(mgr, "_middleware", {}) or {}
callbacks = list(middleware.get("llm_request") or [])
loaded_file = None
if callbacks:
    cb = callbacks[0]
    mod = sys.modules.get(getattr(cb, "__module__", ""), None)
    if mod is not None and getattr(mod, "__file__", None):
        loaded_file = Path(mod.__file__).resolve()

plugins = getattr(mgr, "_plugins", {}) or {}
plugin_error = None
plugin_enabled = None
plugin_module_file = None
for key, loaded in plugins.items():
    key_s = str(key)
    name_s = str(getattr(getattr(loaded, "manifest", None), "name", "") or "")
    if "credential" not in key_s.lower() and "credential" not in name_s.lower():
        continue
    plugin_enabled = bool(getattr(loaded, "enabled", False))
    plugin_error = getattr(loaded, "error", None)
    mod = getattr(loaded, "module", None)
    if mod is not None and getattr(mod, "__file__", None):
        plugin_module_file = str(Path(mod.__file__).resolve())

cg_modules = {}
under_source_modules = []
for name, mod in sys.modules.items():
    if name != "credential_guard" and not name.startswith("credential_guard."):
        continue
    f = getattr(mod, "__file__", None)
    cg_modules[name] = f
    if f:
        resolved = Path(f).resolve()
        if source_root in resolved.parents:
            under_source_modules.append({"name": name, "file": str(resolved)})

preferred_paths = []
for entry in sys.path[:8]:
    if not entry:
        preferred_paths.append("")
        continue
    try:
        preferred_paths.append(str(Path(entry).resolve()))
    except OSError:
        preferred_paths.append(str(entry))

repo_preferred = any(
    p and Path(p).resolve() == source_root for p in preferred_paths if p
)
under_plugin = bool(loaded_file and plugin_dest in loaded_file.parents)
under_source = bool(loaded_file and source_root in loaded_file.parents)
any_under_source = bool(under_source_modules)
loaded_from_source = bool(
    (loaded_file and under_source)
    or (
        plugin_module_file
        and source_root in Path(plugin_module_file).resolve().parents
    )
    or any_under_source
)
fail_closed = (plugin_enabled is not True) or bool(plugin_error)
out = {
    "plugin_manager_attempted": True,
    "plugin_manager_loaded": True,
    "credential_guard_listed": any("credential-guard" in n for n in names),
    "has_llm_request": "llm_request" in middleware,
    "has_llm_execution": "llm_execution" in middleware,
    "middleware_registered": bool(
        middleware.get("llm_request") or middleware.get("llm_execution")
    ),
    "loaded_module_file": str(loaded_file) if loaded_file else None,
    "plugin_module_file": plugin_module_file,
    "plugin_enabled": plugin_enabled,
    "plugin_error": plugin_error,
    "plugin_names": names,
    "installed_module_file_under_plugin": under_plugin,
    "installed_module_file_under_source_tree": under_source,
    "any_cg_module_file_under_source_tree": any_under_source,
    "under_source_modules": under_source_modules,
    "cg_module_files": cg_modules,
    "loaded_from_source_tree": loaded_from_source,
    "load_failed_or_fail_closed": fail_closed and not loaded_from_source,
    "installed_from_zip": under_plugin and not under_source and not any_under_source,
    "plugin_path_is_source_tree": plugin_dest == source_root,
    "cwd": os.getcwd(),
    "preferred_sys_path": preferred_paths,
    "source_on_preferred_path": bool(put_source_preferred and repo_preferred),
    "repo_root_not_preferred_on_sys_path": (not repo_preferred),
    "no_cg_module_cache_pollution": True,
}
print(json.dumps(out))
'''


def _run_plugin_manager_probe(
    plugin_dest: Path,
    hermes_home: Path,
    *,
    put_source_preferred: bool = False,
    cwd: Path | None = None,
) -> Dict[str, Any]:
    """Discover/load with real Hermes PluginManager under isolated HERMES_HOME."""
    hermes_python = HERMES_ROOT / "venv" / "bin" / "python"
    if not hermes_python.is_file():
        raise FileNotFoundError(f"Hermes python missing: {hermes_python}")
    iso_home = hermes_home.parent / "home"
    iso_home.mkdir(exist_ok=True)
    work_cwd = Path(cwd) if cwd is not None else hermes_home.parent
    proc = subprocess.run(
        [
            str(hermes_python),
            "-c",
            _plugin_manager_probe_script(),
            str(HERMES_ROOT),
            str(plugin_dest),
            str(hermes_home),
            str(ROOT),
            str(iso_home),
            "1" if put_source_preferred else "0",
        ],
        cwd=str(work_cwd),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
            "HERMES_HOME": str(hermes_home),
            "HOME": str(iso_home),
        },
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "PluginManager subprocess failed: "
            f"code={proc.returncode} stderr={proc.stderr[-2000:]}"
        )
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    if not lines:
        raise RuntimeError("PluginManager subprocess produced no JSON")
    return json.loads(lines[-1])


def _load_via_plugin_manager(plugin_dest: Path, hermes_home: Path) -> Dict[str, Any]:
    """Healthy-path PluginManager load: must come from the install tree."""
    return _run_plugin_manager_probe(
        plugin_dest, hermes_home, put_source_preferred=False
    )


def _provider_probe(mw, request: dict) -> Dict[str, Any]:
    original = deepcopy(request)
    out = mw.on_llm_request(request=request)
    assert request == original
    calls: List[Any] = []
    if isinstance(out["request"], mw.LocalBlockRequest):
        blocked = mw.on_llm_execution(
            request=out["request"],
            next_call=lambda req: calls.append(deepcopy(req)) or {"ok": True},
        )
        text = blocked.choices[0].message.content
        return {
            "provider_calls": 0,
            "blocked": True,
            "block_text": text,
            "sent": None,
        }
    result = mw.on_llm_execution(
        request=out["request"],
        next_call=lambda req: calls.append(deepcopy(req)) or {"ok": True},
    )
    assert result == {"ok": True}
    assert len(calls) == 1
    return {
        "provider_calls": 1,
        "blocked": False,
        "block_text": None,
        "sent": calls[0],
    }


def _r11_probe_script() -> str:
    """Install-tree subprocess body for the 0.4.5 out-of-box (C1/C6/C10) checks.

    Runs in a fresh interpreter with ONLY the install tree on ``sys.path`` and a
    temporary ``HERMES_HOME``, so what is measured is the packaged plugin, not
    the repo working copy.
    """
    return r'''
import json, os, sys
from copy import deepcopy
from pathlib import Path

plugin_dest = Path(sys.argv[1]).resolve()
hermes_home = Path(sys.argv[2]).resolve()
iso_home = Path(sys.argv[3]).resolve()
mode = sys.argv[4]

sys.path.insert(0, str(plugin_dest))
os.environ["HERMES_HOME"] = str(hermes_home)
os.environ["HOME"] = str(iso_home)

out = {"mode": mode}

import credential_guard.middleware as mw
out["module_file"] = str(Path(mw.__file__).resolve())
out["under_install_tree"] = plugin_dest in Path(mw.__file__).resolve().parents

def probe(request):
    calls = []
    res = mw.on_llm_request(request=deepcopy(request))
    if isinstance(res["request"], mw.LocalBlockRequest):
        blocked = mw.on_llm_execution(
            request=res["request"],
            next_call=lambda req: calls.append(deepcopy(req)) or {"ok": True},
        )
        return {
            "provider_calls": 0,
            "blocked": True,
            "text": blocked.choices[0].message.content,
        }
    mw.on_llm_execution(
        request=res["request"],
        next_call=lambda req: calls.append(deepcopy(req)) or {"ok": True},
    )
    return {"provider_calls": len(calls), "blocked": False, "text": None}

chat = {"model": "m", "messages": [{"role": "user", "content": "hello there"}]}

if mode == "zero_config":
    r = probe(chat)
    out["chat_provider_calls"] = r["provider_calls"]
    out["chat_blocked"] = r["blocked"]
    out["block_text"] = r["text"]
elif mode == "broken_store":
    r = probe(chat)
    out["chat_provider_calls"] = r["provider_calls"]
    out["chat_blocked"] = r["blocked"]
    out["block_text"] = r["text"]
elif mode == "credential_code":
    from credential_guard.credential_code import (
        is_redacted_credential_code,
        credential_code_not_usable_error,
    )
    good = "<SECRET:cg_0123456789abcdef>"
    out["code_recognized"] = bool(is_redacted_credential_code(good))
    out["code_rejects_plain"] = not bool(is_redacted_credential_code("just text"))
    out["refusal_payload"] = credential_code_not_usable_error()
elif mode == "validate_cli":
    from credential_guard.cli import run_validate
    # validate enforces a 0700 parent (a config readable by others is unsafe),
    # so the fixtures live in a mode-0700 dir — same posture as a real Profile
    # store. This is the product's own precondition, not a test workaround.
    vdir = hermes_home / "validate-fixtures"
    vdir.mkdir(parents=True, exist_ok=True)
    os.chmod(vdir, 0o700)
    good = vdir / "good.json"
    good.write_text(json.dumps({
        "version": 2,
        "credentials": {"tok": {"type": "token", "value": "CG_SYNTHETIC_ONLY"}},
        "bindings": {},
    }), encoding="utf-8")
    os.chmod(good, 0o600)
    bad = vdir / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    os.chmod(bad, 0o600)
    import io, contextlib
    def run(path):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = run_validate(str(path))
        return code, buf.getvalue()
    out["good_rc"], out["good_out"] = run(good)
    out["bad_rc"], out["bad_out"] = run(bad)
    # Counter-case: an insecure (world-readable) parent must be refused, so
    # the "good" PASS above cannot be explained by validate being permissive.
    loose = hermes_home / "loose-fixtures"
    loose.mkdir(parents=True, exist_ok=True)
    os.chmod(loose, 0o755)
    loose_cfg = loose / "good.json"
    loose_cfg.write_text(good.read_text(encoding="utf-8"), encoding="utf-8")
    os.chmod(loose_cfg, 0o600)
    out["insecure_parent_rc"], out["insecure_parent_out"] = run(loose_cfg)

print(json.dumps(out))
'''


def _run_r11_probe(
    plugin_dest: Path, hermes_home: Path, iso_home: Path, mode: str
) -> Dict[str, Any]:
    """Run one 0.4.5 out-of-box probe inside the install tree."""
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            _r11_probe_script(),
            str(plugin_dest),
            str(hermes_home),
            str(iso_home),
            mode,
        ],
        cwd=str(hermes_home.parent),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
            "HERMES_HOME": str(hermes_home),
            "HOME": str(iso_home),
        },
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"R11 probe [{mode}] failed: code={proc.returncode} "
            f"stderr={proc.stderr[-2000:]}"
        )
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    if not lines:
        raise RuntimeError(f"R11 probe [{mode}] produced no JSON")
    return json.loads(lines[-1])


def run_r11_out_of_box_from_install_tree(plugin_zip: Path) -> Dict[str, Any]:
    """0.4.5 open-the-box proofs, all executed from the installed ZIP tree."""
    if STRICT and not ARTIFACTS_LANDED:
        raise FileNotFoundError(
            "R11_045_ARTIFACTS_PENDING_BUILD: out-of-box E2E requires landed "
            f"{PLUGIN_VERSION} plugin ZIP (strict=True; not a skip)"
        )
    with tempfile.TemporaryDirectory(prefix="cg-r11-045-oob-") as tmp:
        tmp_path = Path(tmp)
        iso_home = tmp_path / "home"
        iso_home.mkdir()

        # C1a: brand-new user, plugin enabled, no store whatsoever.
        zero_hermes = tmp_path / "hermes-zero"
        _write_zero_config_profile(zero_hermes)
        plugin_dest = _zip.install_zip_over_plugin(
            zero_hermes, plugin_zip, tmp_path / "zip-extract-zero"
        )
        zero = _run_r11_probe(plugin_dest, zero_hermes, iso_home, "zero_config")

        # C1b: store exists but is corrupt → must NOT pass through.
        broken_hermes = tmp_path / "hermes-broken"
        _write_broken_store_profile(broken_hermes)
        broken_dest = _zip.install_zip_over_plugin(
            broken_hermes, plugin_zip, tmp_path / "zip-extract-broken"
        )
        broken = _run_r11_probe(broken_dest, broken_hermes, iso_home, "broken_store")

        # C6 + C10 reuse the zero-config install tree (no store needed).
        code = _run_r11_probe(plugin_dest, zero_hermes, iso_home, "credential_code")
        validate = _run_r11_probe(plugin_dest, zero_hermes, iso_home, "validate_cli")

        assert zero["under_install_tree"] is True, zero
        assert broken["under_install_tree"] is True, broken

        return {
            "zero_config_chat_provider_calls": zero["chat_provider_calls"],
            "zero_config_chat_blocked": zero["chat_blocked"],
            "broken_store_chat_provider_calls": broken["chat_provider_calls"],
            "broken_store_chat_blocked": broken["chat_blocked"],
            "credential_code_recognized": code["code_recognized"],
            "credential_code_rejects_plain": code["code_rejects_plain"],
            "credential_code_refusal": code["refusal_payload"],
            "validate_good_rc": validate["good_rc"],
            "validate_bad_rc": validate["bad_rc"],
            "validate_good_out": validate["good_out"].strip(),
            "validate_bad_out": validate["bad_out"].strip(),
            "validate_insecure_parent_rc": validate["insecure_parent_rc"],
            "validate_insecure_parent_out": validate["insecure_parent_out"].strip(),
            "probes_ran_from_install_tree": True,
        }


def run_isolated_continuity_e2e(plugin_zip: Path) -> Dict[str, Any]:
    if STRICT and not ARTIFACTS_LANDED:
        raise FileNotFoundError(
            "R11_045_ARTIFACTS_PENDING_BUILD: continuity E2E requires landed "
            f"{PLUGIN_VERSION} plugin ZIP (strict=True; not a skip)"
        )
    decoy = "CG_SYNTHETIC_DECOY_" + secrets.token_hex(16)
    encoded = _encoded_openssh_key()
    with tempfile.TemporaryDirectory(prefix="cg-r11-045-zip-e2e-") as tmp:
        tmp_path = Path(tmp)
        old_cwd = Path.cwd()
        os.chdir(tmp_path)
        try:
            extract_root = tmp_path / "zip-extract"
            iso_hermes = tmp_path / "hermes-home"
            _write_isolated_profile(iso_hermes, secret=decoy)
            plugin_dest = _zip.install_zip_over_plugin(
                iso_hermes, plugin_zip, extract_root
            )

            digest_proof = _zip.assert_key_module_matches_zip(
                plugin_dest, plugin_zip, relative="credential_guard/middleware.py"
            )
            pm_proof = _load_via_plugin_manager(plugin_dest, iso_hermes)
            assert pm_proof.get("credential_guard_listed") is True, pm_proof
            assert pm_proof.get("has_llm_request") is True, pm_proof
            assert pm_proof.get("has_llm_execution") is True, pm_proof
            assert pm_proof.get("installed_from_zip") is True, pm_proof
            assert pm_proof.get("installed_module_file_under_source_tree") is False

            _purge_cg_modules()
            plugin_str = str(plugin_dest.resolve())
            sys.path.insert(0, plugin_str)
            os.environ["HERMES_HOME"] = str(iso_hermes)
            try:
                mw = __import__("credential_guard.middleware", fromlist=["*"])
                release_identity = __import__(
                    "credential_guard.release_identity", fromlist=["PLUGIN_VERSION"]
                )
                assert release_identity.PLUGIN_VERSION == PLUGIN_VERSION
                loaded_file = Path(mw.__file__).resolve()
                path_proof = _zip.prove_installed_module_path(
                    plugin_dest, ROOT, loaded_file
                )
                assert path_proof["installed_from_zip"] is True

                # 1) Cumulative large ordinary request → Provider=1.
                chunk = (
                    "Ordinary Hermes system prompt line with spaces, "
                    "punctuation, and words. " * 1200
                )
                messages = []
                for i in range(8):
                    role = "assistant" if i % 2 else "user"
                    messages.append({"role": role, "content": chunk})
                large_req = {"model": "m", "messages": messages}
                flat_bytes = len(
                    json.dumps(large_req, ensure_ascii=False).encode("utf-8")
                )
                assert flat_bytes > 512_000, flat_bytes
                large = _provider_probe(mw, large_req)
                assert large["provider_calls"] == 1, large.get("block_text")
                large_blob = json.dumps(large["sent"], ensure_ascii=False)
                assert decoy not in large_blob
                assert encoded not in large_blob

                # 2) Dynamic-key collision: plain secret key must not egress.
                coll = _provider_probe(
                    mw,
                    {
                        "model": "m",
                        "messages": [
                            {
                                "role": "user",
                                "content": "hi",
                                decoy: "value-A",
                                "<CREDENTIAL:tok>": "value-B",
                            },
                            {"role": "user", "content": "continue"},
                        ],
                    },
                )
                assert coll["provider_calls"] == 1, coll.get("block_text")
                coll_blob = json.dumps(coll["sent"], ensure_ascii=False)
                assert decoy not in coll_blob
                keys = list(coll["sent"]["messages"][0].keys())
                assert decoy not in keys
                assert any(
                    str(k).startswith("<SECRET:")
                    or str(k).startswith("<REDACTED_SENSITIVE_KEY_")
                    for k in keys
                ), keys

                # 3) Unresolved boundary-unknown in content → whole-field.
                unres = _provider_probe(
                    mw,
                    {
                        "model": "m",
                        "messages": [
                            {"role": "user", "content": "u"},
                            {"role": "assistant", "content": "a"},
                            {
                                "role": "tool",
                                "name": "t",
                                "content": f"blob {encoded}",
                            },
                            {"role": "user", "content": "continue"},
                        ],
                    },
                )
                assert unres["provider_calls"] == 1
                assert (
                    unres["sent"]["messages"][2]["content"]
                    == mw.REDACTED_UNRESOLVED_SENSITIVE_FIELD
                )
                assert encoded not in json.dumps(unres["sent"], ensure_ascii=False)

                # 4) Protocol-field unresolved → Provider=0.
                proto = _provider_probe(
                    mw,
                    {
                        "model": encoded,
                        "messages": [{"role": "user", "content": "continue"}],
                    },
                )
                assert proto["provider_calls"] == 0
                assert "CG-RESIDUAL-SECRET" in (proto["block_text"] or "")
                assert encoded not in (proto["block_text"] or "")
                assert decoy not in (proto["block_text"] or "")

                # 4b) Protocol-field registered secret → Provider=0.
                proto_reg = _provider_probe(
                    mw,
                    {
                        "model": decoy,
                        "messages": [{"role": "user", "content": "continue"}],
                    },
                )
                assert proto_reg["provider_calls"] == 0
                assert "CG-RESIDUAL-SECRET" in (proto_reg["block_text"] or "")
                assert decoy not in (proto_reg["block_text"] or "")

                # 5) Residual final-gate: force residual → Provider=0.
                def force_residual(payload, root, path=()):
                    if path == ():
                        return mw._detail_residual("request")
                    return None

                real_find = mw._find_residual_private_key
                mw._find_residual_private_key = force_residual
                try:
                    residual = _provider_probe(
                        mw,
                        {
                            "model": "m",
                            "messages": [
                                {"role": "tool", "name": "t", "content": "safe"},
                                {"role": "user", "content": "go"},
                            ],
                        },
                    )
                finally:
                    mw._find_residual_private_key = real_find
                assert residual["provider_calls"] == 0

                # 6) Scanner error on current user with trailing assistant/tool.
                real_scan = mw._scan_residuals

                def scan_current_user(payload, registry, root):
                    idx = mw._current_user_input_index(payload)
                    assert idx == 0
                    return [
                        mw.ResidualFinding(
                            kind="scanner-error",
                            path=("messages", 0, "content"),
                            detail=mw._detail_scanner_error(
                                "第 1 条消息（user）",
                                action_kind="current_input",
                            ),
                        )
                    ]

                mw._scan_residuals = scan_current_user
                try:
                    scanned = _provider_probe(
                        mw,
                        {
                            "model": "m",
                            "messages": [
                                {
                                    "role": "user",
                                    "content": "CURRENT_USER_SCAN_BOOM",
                                },
                                {"role": "assistant", "content": "trail-a"},
                                {
                                    "role": "tool",
                                    "name": "t",
                                    "content": "trail-t",
                                },
                            ],
                        },
                    )
                finally:
                    mw._scan_residuals = real_scan
                assert scanned["provider_calls"] == 0
                assert "CG-SCANNER-ERROR" in (scanned["block_text"] or "")

                return {
                    "plugin_version": PLUGIN_VERSION,
                    "installed_from_zip": True,
                    "plugin_manager_loaded": pm_proof["plugin_manager_loaded"],
                    "credential_guard_listed": pm_proof["credential_guard_listed"],
                    "middleware_digest_sha256": digest_proof["sha256"],
                    "large_request_provider_calls": large["provider_calls"],
                    "collision_provider_calls": coll["provider_calls"],
                    "unresolved_provider_calls": unres["provider_calls"],
                    "protocol_unresolved_provider_calls": proto["provider_calls"],
                    "protocol_registered_secret_provider_calls": proto_reg[
                        "provider_calls"
                    ],
                    "residual_force_provider_calls": residual["provider_calls"],
                    "scanner_trailing_provider_calls": scanned["provider_calls"],
                    "final_gate_blocks_residual": residual["provider_calls"] == 0,
                    "decoy_absent_from_provider": True,
                    **path_proof,
                }
            finally:
                if plugin_str in sys.path:
                    sys.path.remove(plugin_str)
                _purge_cg_modules()
                os.environ.pop("HERMES_HOME", None)
        finally:
            os.chdir(old_cwd)


def prove_source_fallback_mutation_red(plugin_zip: Path) -> Dict[str, Any]:
    """Damage the temp install copy; prove PluginManager does not fall back."""
    if STRICT and not ARTIFACTS_LANDED:
        raise FileNotFoundError(
            "R11_045_ARTIFACTS_PENDING_BUILD: source-fallback mutation requires "
            f"landed {PLUGIN_VERSION} plugin ZIP (strict=True; not a skip)"
        )
    import shutil

    source_middleware = (ROOT / "credential_guard" / "middleware.py").resolve()
    if not source_middleware.is_file():
        raise AssertionError("repo source temptation missing: middleware.py")

    with tempfile.TemporaryDirectory(prefix="cg-r11-045-src-mut-") as tmp:
        tmp_path = Path(tmp)
        extract_root = tmp_path / "zip-extract"
        iso_home = tmp_path / "home"
        iso_hermes = tmp_path / "hermes-home"
        iso_home.mkdir()
        iso_hermes.mkdir()
        _write_isolated_profile(iso_hermes, secret="CG_SYNTHETIC_MUTATION_ONLY")
        plugin_dest = _zip.install_zip_over_plugin(
            iso_hermes, plugin_zip, extract_root
        )

        damage_target = (plugin_dest / "credential_guard").resolve()
        if not damage_target.is_dir():
            raise AssertionError(f"install copy missing package: {damage_target}")
        shutil.rmtree(damage_target)
        if damage_target.exists():
            raise AssertionError(f"failed to damage install copy: {damage_target}")
        if not source_middleware.is_file():
            raise AssertionError("repo source was damaged; mutation invalid")

        old_cwd = Path.cwd()
        os.chdir(tmp_path)
        try:
            primary = _run_plugin_manager_probe(
                plugin_dest, iso_hermes, put_source_preferred=False, cwd=tmp_path
            )
            factor = _run_plugin_manager_probe(
                plugin_dest, iso_hermes, put_source_preferred=True, cwd=tmp_path
            )
        finally:
            os.chdir(old_cwd)

        if primary.get("plugin_manager_attempted") is not True:
            raise AssertionError("PluginManager was not attempted on damaged install")
        if primary.get("repo_root_not_preferred_on_sys_path") is not True:
            raise AssertionError(
                "primary mutation must keep repo root off preferred sys.path"
            )
        if primary.get("load_failed_or_fail_closed") is not True:
            raise AssertionError(
                f"damaged install must fail-closed without source fallback: {primary}"
            )
        if primary.get("loaded_from_source_tree") is True:
            raise AssertionError(
                f"damaged install loaded from healthy repo source tree: {primary}"
            )
        if primary.get("any_cg_module_file_under_source_tree") is True:
            raise AssertionError(
                "credential_guard* __file__ pointed at repo source: "
                f"{primary.get('under_source_modules')}"
            )
        if primary.get("middleware_registered") is True:
            raise AssertionError(
                f"damaged install must not register middleware: {primary}"
            )
        if primary.get("installed_from_zip") is not False:
            raise AssertionError(
                "damaged install must not claim installed_from_zip=True"
            )

        detected = bool(
            factor.get("source_on_preferred_path") is True
            and (
                factor.get("loaded_from_source_tree") is True
                or factor.get("any_cg_module_file_under_source_tree") is True
            )
            and factor.get("installed_from_zip") is False
        )
        if not detected:
            raise AssertionError(
                "factor-control must detect source-on-path fallback (not vacuous): "
                f"{factor}"
            )

        failure_mode = primary.get("plugin_error") or (
            "plugin_disabled_without_middleware"
            if primary.get("plugin_enabled") is not True
            else "fail_closed"
        )
        return {
            "install_damaged": True,
            "source_tree_healthy": True,
            "damage_target": str(damage_target),
            "plugin_dest": str(plugin_dest),
            "plugin_manager_attempted": True,
            "neutral_cwd": Path(primary.get("cwd") or tmp_path).resolve()
            == tmp_path.resolve(),
            "repo_root_not_preferred_on_sys_path": True,
            "no_cg_module_cache_pollution": True,
            "load_failed_or_fail_closed": True,
            "loaded_from_source_tree": False,
            "any_cg_module_file_under_source_tree": False,
            "installed_from_zip": False,
            "middleware_registered": False,
            "failure_mode": failure_mode,
            "plugin_error": primary.get("plugin_error"),
            "plugin_enabled": primary.get("plugin_enabled"),
            "primary_probe": {
                "loaded_module_file": primary.get("loaded_module_file"),
                "plugin_module_file": primary.get("plugin_module_file"),
                "preferred_sys_path": primary.get("preferred_sys_path"),
                "cg_module_files": primary.get("cg_module_files"),
            },
            "factor_control_source_on_preferred_path": {
                "source_on_preferred_path": True,
                "detected_source_fallback": True,
                "installed_from_zip": False,
                "any_cg_module_file_under_source_tree": True,
                "loaded_from_source_tree": factor.get("loaded_from_source_tree"),
                "plugin_enabled": factor.get("plugin_enabled"),
                "plugin_module_file": factor.get("plugin_module_file"),
                "under_source_modules": factor.get("under_source_modules"),
            },
            "installed_module_file_under_plugin": False,
            "installed_module_file_under_source_tree": False,
            "plugin_path_is_source_tree": False,
        }


def evaluate_r11_045_final_zip_gates(summary: dict) -> int:
    if summary.get("plugin_version") != PLUGIN_VERSION:
        return 10
    if summary.get("installed_from_zip") is not True:
        return 7
    if summary.get("installed_module_file_under_source_tree") is True:
        return 7
    if summary.get("plugin_manager_loaded") is not True:
        return 11
    if summary.get("credential_guard_listed") is not True:
        return 11
    if summary.get("large_request_provider_calls") != 1:
        return 2
    if summary.get("collision_provider_calls") != 1:
        return 3
    if summary.get("unresolved_provider_calls") != 1:
        return 4
    if summary.get("protocol_unresolved_provider_calls") != 0:
        return 5
    if summary.get("protocol_registered_secret_provider_calls") != 0:
        return 14
    if summary.get("residual_force_provider_calls") != 0:
        return 6
    if summary.get("scanner_trailing_provider_calls") != 0:
        return 8
    if summary.get("final_gate_blocks_residual") is not True:
        return 9
    if summary.get("decoy_absent_from_provider") is not True:
        return 12
    return 0


def evaluate_r11_out_of_box_gates(oob: dict) -> int:
    """R11 0.4.5 open-the-box gates (C1 / C6 / C10) from the install tree."""
    if oob.get("probes_ran_from_install_tree") is not True:
        return 20
    # C1: fresh user with no store must chat normally.
    if oob.get("zero_config_chat_provider_calls") != 1:
        return 21
    if oob.get("zero_config_chat_blocked") is not False:
        return 21
    # C1 counter-case: broken store must stay fail-closed.
    if oob.get("broken_store_chat_provider_calls") != 0:
        return 22
    if oob.get("broken_store_chat_blocked") is not True:
        return 22
    # C6: redacted credential-code recognition + fixed refusal code.
    if oob.get("credential_code_recognized") is not True:
        return 23
    if oob.get("credential_code_rejects_plain") is not True:
        return 23
    if "CREDENTIAL_CODE_NOT_USABLE" not in (oob.get("credential_code_refusal") or ""):
        return 23
    # C10: offline validate accepts a well-formed config, rejects a broken one,
    # and still refuses an otherwise-valid config under an insecure parent.
    if oob.get("validate_good_rc") != 0:
        return 24
    if oob.get("validate_bad_rc") != 1:
        return 24
    if "PASS" not in (oob.get("validate_good_out") or ""):
        return 24
    if "FAIL" not in (oob.get("validate_bad_out") or ""):
        return 24
    if oob.get("validate_insecure_parent_rc") != 1:
        return 25
    if "FAIL" not in (oob.get("validate_insecure_parent_out") or ""):
        return 25
    return 0


def main() -> int:
    zip_path = resolve_plugin_zip()
    summary = run_isolated_continuity_e2e(zip_path)
    oob = run_r11_out_of_box_from_install_tree(zip_path)
    summary["out_of_box"] = oob
    src_mut = prove_source_fallback_mutation_red(zip_path)
    fc = src_mut.get("factor_control_source_on_preferred_path") or {}
    summary["source_fallback_mutation_red"] = (
        src_mut.get("install_damaged") is True
        and src_mut.get("source_tree_healthy") is True
        and src_mut.get("plugin_manager_attempted") is True
        and src_mut.get("load_failed_or_fail_closed") is True
        and src_mut.get("loaded_from_source_tree") is False
        and src_mut.get("any_cg_module_file_under_source_tree") is False
        and src_mut.get("installed_from_zip") is False
        and fc.get("detected_source_fallback") is True
    )
    summary["source_fallback_mutation_proof"] = {
        "damage_target": src_mut.get("damage_target"),
        "failure_mode": src_mut.get("failure_mode"),
        "factor_control_detected": fc.get("detected_source_fallback"),
    }
    print(json.dumps(summary, sort_keys=True))
    code = evaluate_r11_045_final_zip_gates(summary)
    if code != 0:
        print(f"R11_045_FINAL_ZIP_GATE_FAIL code={code}", file=sys.stderr)
        return code
    oob_code = evaluate_r11_out_of_box_gates(oob)
    if oob_code != 0:
        print(f"R11_045_OUT_OF_BOX_GATE_FAIL code={oob_code}", file=sys.stderr)
        return oob_code
    if not summary.get("source_fallback_mutation_red"):
        print("R11_045_SOURCE_FALLBACK_MUTATION_NOT_RED", file=sys.stderr)
        return 13
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
