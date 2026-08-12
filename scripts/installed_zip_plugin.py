#!/usr/bin/env python3
"""Shared install/load helpers for plugin ZIPs in isolated Hermes homes.

Single implementation of the ZIP→plugin-dir path used by:
- ``scripts/run_final_zip_encoding_canary.py`` (historical encoding canary)
- R6 installed-ZIP approval-chain E2E

Do not duplicate these helpers elsewhere — two copies will drift.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import shutil
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict, Tuple

ROOT = Path(__file__).resolve().parents[1]


def _load_build_mod():
    """Lazy-load release builder solely for ``extract_plugin_zip``."""
    path = ROOT / "scripts" / "build_release_artifacts.py"
    spec = importlib.util.spec_from_file_location(
        "build_release_artifacts_installed_zip", path
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def zip_member_sha256(plugin_zip: Path, member: str) -> str:
    with zipfile.ZipFile(plugin_zip) as zf:
        return hashlib.sha256(zf.read(member)).hexdigest()


def prove_installed_module_path(
    plugin_dest: Path, source_root: Path, loaded_file: Path
) -> Dict[str, bool]:
    """Prove loaded module came from isolated plugin dir, not the source tree."""
    plugin_r = plugin_dest.resolve()
    source_r = source_root.resolve()
    loaded = loaded_file.resolve()
    under_plugin = plugin_r in loaded.parents
    under_source = source_r in loaded.parents
    return {
        "installed_module_file_under_plugin": under_plugin,
        "installed_module_file_under_source_tree": under_source,
        "installed_from_zip": under_plugin and not under_source,
        "plugin_path_is_source_tree": plugin_r == source_r,
    }


def load_credential_guard_from_plugin(plugin_dest: Path):
    """Import credential_guard from an installed plugin directory (not source tree)."""
    plugin_str = str(plugin_dest.resolve())
    purged = {
        k: sys.modules.pop(k)
        for k in list(sys.modules)
        if k == "credential_guard" or k.startswith("credential_guard.")
    }
    removed_path = False
    if plugin_str in sys.path:
        sys.path.remove(plugin_str)
        removed_path = True
    sys.path.insert(0, plugin_str)
    try:
        sp = importlib.import_module("credential_guard.sensitive_paths")
        mw = importlib.import_module("credential_guard.middleware")
        hooks = importlib.import_module("credential_guard.hooks")
        # Re-bind in case a prior import was cached under another path.
        sp = importlib.reload(sp)
        mw = importlib.reload(mw)
        hooks = importlib.reload(hooks)
        return sp, mw, hooks
    finally:
        sys.path.remove(plugin_str)
        if removed_path:
            sys.path.insert(0, plugin_str)
        # Leave purged modules out so subsequent source imports re-resolve cleanly.
        for name in list(sys.modules):
            if name == "credential_guard" or name.startswith("credential_guard."):
                sys.modules.pop(name, None)
        sys.modules.update(purged)


def install_zip_over_plugin(
    iso_hermes_home: Path, plugin_zip: Path, extract_root: Path
) -> Path:
    """Extract plugin ZIP into ``iso_hermes_home/plugins/credential-guard``."""
    build = _load_build_mod()
    extracted = build.extract_plugin_zip(plugin_zip, extract_root)
    plugin_dest = iso_hermes_home / "plugins" / "credential-guard"
    if plugin_dest.exists():
        shutil.rmtree(plugin_dest)
    shutil.copytree(extracted, plugin_dest)
    return plugin_dest.resolve()


def assert_key_module_matches_zip(
    plugin_dest: Path, plugin_zip: Path, *, relative: str
) -> Dict[str, str]:
    """Compare an installed file's sha256 to the matching ZIP member."""
    installed = plugin_dest / relative
    member = f"credential-guard/{relative.replace(chr(92), '/')}"
    file_digest = sha256_file(installed)
    zip_digest = zip_member_sha256(plugin_zip, member)
    if file_digest != zip_digest:
        raise AssertionError(
            f"installed module digest mismatch for {relative}: "
            f"file={file_digest} zip_member={zip_digest}"
        )
    return {
        "relative": relative,
        "member": member,
        "sha256": file_digest,
    }


def count_secret_encoding_forms(blob: bytes, secret: str) -> Dict[str, int]:
    """Count plain + common encoding forms of ``secret`` in ``blob``.

    Refuses vacuous needles (empty / too short) so a zero-appearance check
    cannot silently pass by counting the empty string.
    """
    if not isinstance(secret, str) or len(secret) < 8:
        raise AssertionError(
            "vacuous needle refused: secret must be a non-empty string of length>=8"
        )
    import base64
    from urllib.parse import quote, quote_plus

    raw = secret.encode("utf-8")
    forms = {
        "plain": secret,
        "percent": quote(secret, safe=""),
        "quote_plus": quote_plus(secret),
        "base64": base64.b64encode(raw).decode("ascii"),
        "urlsafe_base64": base64.urlsafe_b64encode(raw).decode("ascii"),
    }
    out: Dict[str, int] = {}
    for name, needle in forms.items():
        if name == "percent" and needle == forms["plain"]:
            out[name] = 0
            continue
        if name == "quote_plus" and needle in {forms["plain"], forms["percent"]}:
            out[name] = 0
            continue
        if name == "urlsafe_base64" and needle == forms["base64"]:
            out[name] = out.get("base64", blob.count(forms["base64"].encode("utf-8")))
            continue
        out[name] = blob.count(needle.encode("utf-8"))
    return out


def assert_secret_absent_in_blob(blob: bytes, secret: str) -> Dict[str, int]:
    """Fail unless every encoding form of ``secret`` appears 0 times."""
    counts = count_secret_encoding_forms(blob, secret)
    bad = {k: v for k, v in counts.items() if v != 0}
    if bad:
        raise AssertionError(f"secret encoding forms leaked: {bad}")
    return counts
