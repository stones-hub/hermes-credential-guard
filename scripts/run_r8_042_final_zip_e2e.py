#!/usr/bin/env python3
"""R8 0.4.2 final plugin-ZIP isolated E2E harness (opt-in).

Installs the landed 0.4.2 plugin ZIP into a temporary tree and proves:
1. modules load from the install tree (not the repo source tree);
2. installed bindings accept scheme=http and scheme=https;
3. installed HTTP adapter builds http:// URLs and scrubs decoy echoes.

Never touches real default/worker profiles, real credentials, ~/.ssh, or
non-loopback peers. Never calls ``build_all``. Never modifies Hermes source.
"""

from __future__ import annotations

import importlib.util
import json
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

EXPECTED_PLUGIN_ZIP = "credential-guard-0.4.2-hermes-plugin.zip"
EXPECTED_PLUGIN_ZIP_SHA256 = (
    "95d96aa82f64701dfc0b5862ba3671feb98b7d5c07a61f350dbe65287fb60ccf"
)


def _load_zip_helpers():
    path = ROOT / "scripts" / "installed_zip_plugin.py"
    spec = importlib.util.spec_from_file_location("installed_zip_plugin_r8", path)
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
    if digest != expected_sha256:
        raise AssertionError(
            f"plugin zip sha drift: got {digest} expected {expected_sha256}"
        )
    return path


def _decoy() -> str:
    return "CG_SYNTHETIC_DECOY_" + secrets.token_hex(12)


def run_isolated_http_scheme_e2e(plugin_zip: Path) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="cg-r8-042-zip-e2e-") as tmp:
        tmp_path = Path(tmp)
        extract_root = tmp_path / "zip-extract"
        iso_hermes = tmp_path / "hermes-home"
        iso_hermes.mkdir()
        plugin_dest = _zip.install_zip_over_plugin(
            iso_hermes, plugin_zip, extract_root
        )

        # Purge source-tree credential_guard before loading install tree.
        for k in list(sys.modules):
            if k == "credential_guard" or k.startswith("credential_guard."):
                sys.modules.pop(k, None)
        plugin_str = str(plugin_dest.resolve())
        sys.path.insert(0, plugin_str)
        try:
            bindings = __import__(
                "credential_guard.bindings", fromlist=["validate_binding"]
            )
            http_adapter = __import__(
                "credential_guard.adapters.http", fromlist=["execute_http"]
            )
            injection = __import__(
                "credential_guard.injection", fromlist=["SecretLease"]
            )
            release_identity = __import__(
                "credential_guard.release_identity", fromlist=["PLUGIN_VERSION"]
            )
            loaded_file = Path(bindings.__file__).resolve()
            path_proof = _zip.prove_installed_module_path(
                plugin_dest, ROOT, loaded_file
            )
            assert path_proof["installed_from_zip"] is True
            assert path_proof["installed_module_file_under_source_tree"] is False
            assert release_identity.PLUGIN_VERSION == "0.4.2"

            creds = {"tok": {"type": "token", "value": _decoy()}}
            http_entry = {
                "type": "http",
                "credential_ref": "tok",
                "target": {
                    "scheme": "http",
                    "host": "internal-api.example.test",
                    "port": 8080,
                },
                "request": {
                    "allowed_methods": ["GET"],
                    "allowed_paths": ["/v1/status"],
                },
                "inject": {"type": "bearer", "location": "authorization_header"},
                "approval": "required",
            }
            out_http = bindings.validate_binding("b-http", http_entry, creds)
            assert out_http["target"]["scheme"] == "http"

            https_entry = dict(http_entry)
            https_entry["target"] = {
                "scheme": "https",
                "host": "api.example.test",
                "port": 443,
            }
            out_https = bindings.validate_binding("b-https", https_entry, creds)
            assert out_https["target"]["scheme"] == "https"

            decoy = _decoy()
            captured: list = []

            def transport(req):
                captured.append(req)
                return {
                    "status": 200,
                    "headers": {"content-type": "text/plain"},
                    "body": f"echo={decoy}".encode(),
                }

            lease = injection.SecretLease({"kind": "token", "value": decoy})
            result = http_adapter.execute_http(
                binding=out_http,
                method="GET",
                path="/v1/status",
                lease=lease,
                transport=transport,
            )
            dumped = json.dumps(result)
            assert len(captured) == 1
            assert captured[0]["url"].startswith("http://")
            assert decoy not in dumped
            assert result["ok"] is True or result.get("error") == "HTTP_RESULT_SCRUBBED"
        finally:
            if plugin_str in sys.path:
                sys.path.remove(plugin_str)
            for k in list(sys.modules):
                if k == "credential_guard" or k.startswith("credential_guard."):
                    sys.modules.pop(k, None)

        return {
            "plugin_version": "0.4.2",
            "installed_from_zip": True,
            "http_scheme_accepted": True,
            "https_scheme_accepted": True,
            "http_url_used": True,
            "decoy_scrubbed": True,
            **path_proof,
        }


def main() -> int:
    zip_path = resolve_plugin_zip()
    summary = run_isolated_http_scheme_e2e(zip_path)
    print(json.dumps(summary, sort_keys=True))
    assert summary["installed_from_zip"] is True
    assert summary["http_scheme_accepted"] is True
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
