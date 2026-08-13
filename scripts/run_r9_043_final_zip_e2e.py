#!/usr/bin/env python3
"""R9 0.4.3 final plugin-ZIP isolated E2E harness (opt-in).

Installs the landed 0.4.3 plugin ZIP into a temporary Hermes home and proves:
1. real PluginManager discovers/loads from the install tree (not repo source);
2. key module bytes match the ZIP member;
3. long-session continuity cases (large request / collision / unresolved /
   residual / scanner / trailing assistant+tool / final gate);
4. fake Provider sees zero synthetic secrets; blocked cases Provider=0;
5. source-tree fallback mutation is load-bearing: damaged install + healthy
   repo source + PluginManager must fail-closed (never load from source);
   factor-control with source on preferred sys.path must detect RED.

Never touches real default/worker profiles, real credentials, ~/.ssh, or
non-loopback peers. Never calls ``build_all``. Never modifies Hermes source.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import secrets
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PLUGIN_VERSION = "0.4.3"
EXPECTED_PLUGIN_ZIP = f"credential-guard-{PLUGIN_VERSION}-hermes-plugin.zip"
# Filled after dual-build copy2; resolve also cross-checks versioned manifest.
EXPECTED_PLUGIN_ZIP_SHA256 = (
    "738bc8ae4e1973a50efba604602a9fb3c7a6739efb95e48024b6a1975e97dacb"
)

OPENSSH_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
-----END OPENSSH PRIVATE KEY-----
"""

HERMES_ROOT = Path("/Users/yelei/.hermes/hermes-agent")


def _load_zip_helpers():
    path = ROOT / "scripts" / "installed_zip_plugin.py"
    spec = importlib.util.spec_from_file_location("installed_zip_plugin_r9", path)
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
    path = ROOT / "dist" / expected_name
    if not path.is_file():
        raise FileNotFoundError(f"missing landed plugin zip: {path}")
    digest = _zip.sha256_file(path)
    if (
        expected_sha256
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
    store.mkdir(parents=True)
    os.chmod(store, 0o700)
    cfg = {
        "version": 2,
        "credentials": {"tok": {"type": "token", "value": secret}},
        "bindings": {},
    }
    path = store / "credential-guard.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
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

# Drop any pre-existing source-root entries, then optionally re-insert as a
# single-factor control (never the healthy product path).
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
            str(
                getattr(item, "name", None)
                or getattr(item, "key", None)
                or item
            )
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
    """Discover/load with real Hermes PluginManager under isolated HERMES_HOME.

    Hermes requires Python 3.10+; project ``.venv`` may be 3.9. Run the
    PluginManager proof in a short Hermes-venv subprocess and return JSON.
    """
    import subprocess

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


def run_isolated_continuity_e2e(plugin_zip: Path) -> Dict[str, Any]:
    decoy = "CG_SYNTHETIC_DECOY_" + secrets.token_hex(16)
    encoded = _encoded_openssh_key()
    with tempfile.TemporaryDirectory(prefix="cg-r9-043-zip-e2e-") as tmp:
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
                # Spaces/punctuation break Base64 runs; each field stays under
                # MAX_PRIVATE_KEY_CANDIDATE_LENGTH while the flattened request
                # exceeds the historical 512KB false-block budget.
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

                # 2) Dynamic-key collision: plain secret key must not egress;
                # Provider continues with renamed/safe keys on the bound copy.
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

                # 3) Unresolved boundary-unknown in content → whole-field, Provider=1.
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

                # 4) Protocol-field unresolved → Provider=0 (0.4.3 narrow).
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
                    assert idx == 0  # last role=user is index 0; trail follows
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
    """Damage the temp install copy; prove PluginManager does not fall back.

    Real load-bearing mutation (not a path-bool helper):
    1. Install final ZIP into a fresh temporary HOME/HERMES_HOME plugin tree.
    2. Keep the repo source tree healthy (temptation available).
    3. Destroy the installed ``credential_guard`` package subtree only.
    4. From a neutral cwd, with repo root removed from preferred ``sys.path``,
       run the normal Hermes PluginManager discover/load chain in a clean
       subprocess interpreter.
    5. Expect fail-closed load failure — never a successful source-tree load.
    6. Factor control: deliberately put the repo root back on preferred
       ``sys.path``; the probe must detect source fallback (RED), proving the
       judgment is not vacuously always-true. That path is never treated as
       the healthy product path.
    """
    import shutil

    source_middleware = (ROOT / "credential_guard" / "middleware.py").resolve()
    if not source_middleware.is_file():
        raise AssertionError("repo source temptation missing: middleware.py")

    with tempfile.TemporaryDirectory(prefix="cg-r9-043-src-mut-") as tmp:
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
                plugin_dest,
                iso_hermes,
                put_source_preferred=False,
                cwd=tmp_path,
            )
            factor = _run_plugin_manager_probe(
                plugin_dest,
                iso_hermes,
                put_source_preferred=True,
                cwd=tmp_path,
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
                "damaged install must fail-closed without source fallback: "
                f"{primary}"
            )
        if primary.get("loaded_from_source_tree") is True:
            raise AssertionError(
                "damaged install loaded from healthy repo source tree: "
                f"{primary}"
            )
        if primary.get("any_cg_module_file_under_source_tree") is True:
            raise AssertionError(
                "credential_guard* __file__ pointed at repo source: "
                f"{primary.get('under_source_modules')}"
            )
        if primary.get("middleware_registered") is True:
            raise AssertionError(
                "damaged install must not register middleware: "
                f"{primary}"
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
            # Retain legacy path-proof keys for summary compatibility.
            "installed_module_file_under_plugin": False,
            "installed_module_file_under_source_tree": False,
            "plugin_path_is_source_tree": False,
        }


def evaluate_r9_043_final_zip_gates(summary: dict) -> int:
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
    if summary.get("residual_force_provider_calls") != 0:
        return 6
    if summary.get("scanner_trailing_provider_calls") != 0:
        return 8
    if summary.get("final_gate_blocks_residual") is not True:
        return 9
    if summary.get("decoy_absent_from_provider") is not True:
        return 12
    return 0


def main() -> int:
    zip_path = resolve_plugin_zip()
    summary = run_isolated_continuity_e2e(zip_path)
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
    code = evaluate_r9_043_final_zip_gates(summary)
    if code != 0:
        print(f"R9_043_FINAL_ZIP_GATE_FAIL code={code}", file=sys.stderr)
        return code
    if not summary.get("source_fallback_mutation_red"):
        print("R9_043_SOURCE_FALLBACK_MUTATION_NOT_RED", file=sys.stderr)
        return 13
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
