#!/usr/bin/env python3
"""Final plugin-ZIP encoding canary: install dist ZIP into temp Hermes, prove wire=0.

Never uses the source tree as the installed plugin. Loopback fake Provider only.

Historical note
---------------
This canary's *live* ``main()`` still targets the frozen 0.3.1 plugin ZIP
(``credential-guard-0.3.1-hermes-plugin.zip``). That binding is intentional:
R3/C-era evidence and M3 acceptance ran against that artifact. The current
release 0.4.0 approval-chain E2E lives in a separate opt-in entry that reuses
the same install/load helpers from ``scripts/installed_zip_plugin.py``.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, Tuple
from urllib.parse import quote, quote_plus

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _load_installed_zip_helpers():
    """Load the single shared ZIP install/load implementation (no fork)."""
    path = ROOT / "scripts" / "installed_zip_plugin.py"
    spec = importlib.util.spec_from_file_location("installed_zip_plugin_canary", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_zip_helpers = _load_installed_zip_helpers()
prove_installed_module_path = _zip_helpers.prove_installed_module_path
_install_zip_over_plugin = _zip_helpers.install_zip_over_plugin
_load_credential_guard_from_plugin = _zip_helpers.load_credential_guard_from_plugin

from tests.fake_provider import FakeProvider  # noqa: E402
from tests.hermes_e2e_helpers import (  # noqa: E402
    DECOY_SECRET,
    DECOY_TOKEN,
    PLUGIN_ROOT,
    assert_all_loopback,
    assert_loopback_guards_present,
    opaque_token,
    prepare_isolated_hermes,
    read_net_audit,
    request_has_tools,
    run_hermes,
)

# Frozen 0.3.1 historical artifact — do not retarget this canary to 0.4.0.
HISTORICAL_PLUGIN_ZIP_FILENAME = "credential-guard-0.3.1-hermes-plugin.zip"

DECOY_USERNAME = "cg_readonly"
DECOY_BASIC_COMBO = f"{DECOY_USERNAME}:{DECOY_SECRET}"
DECOY_BASIC_TOKEN = opaque_token("db", "basic_auth")

_SAFE_TOOL_BLOCK = json.dumps(
    {"error": "tool result blocked by credential-guard"},
    ensure_ascii=False,
)


def _wire_forms() -> dict:
    raw = DECOY_SECRET.encode("utf-8")
    combo_raw = DECOY_BASIC_COMBO.encode("utf-8")
    return {
        "plain": DECOY_SECRET,
        "percent": quote(DECOY_SECRET, safe=""),
        "quote_plus": quote_plus(DECOY_SECRET),
        "base64": base64.b64encode(raw).decode("ascii"),
        "urlsafe_base64": base64.urlsafe_b64encode(raw).decode("ascii"),
        "basic_auth": base64.b64encode(combo_raw).decode("ascii"),
        "basic_auth_plain": DECOY_BASIC_COMBO,
    }


def urlsafe_distinct_synthetic_pem_b64() -> Tuple[str, str, str]:
    """Return (pem, std_b64, urlsafe_b64) with real URL-safe alphabet divergence.

    Synthetic decoy PEM only — not a real private key. URL-safe form MUST contain
    '-' or '_' and MUST differ from standard Base64.
    """
    pem = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "CG_SYNTHETIC_DECOY_NOT_A_REAL_KEY_ >\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    raw = pem.encode("utf-8")
    std = base64.b64encode(raw).decode("ascii")
    url = base64.urlsafe_b64encode(raw).decode("ascii")
    if not (("-" in url or "_" in url) and url != std):
        raise RuntimeError("urlsafe pem fixture must diverge from std alphabet")
    return pem, std, url


def probe_urlsafe_pem_provider_bound(
    *,
    contains_private_key_material: Callable[[str], bool],
    on_llm_execution: Callable[..., Any],
    on_transform_tool_result: Callable[..., str],
    urlsafe_pem_b64: str,
) -> Dict[str, Any]:
    """Provider-bound / tool-bound negative probe for URL-safe PEM form."""
    helper_hit = contains_private_key_material(urlsafe_pem_b64) is True
    calls: list = []
    on_llm_execution(
        request={"messages": [{"role": "user", "content": urlsafe_pem_b64}]},
        next_call=lambda r: calls.append(r) or {"ok": True},
    )
    tool_out = on_transform_tool_result(
        result=urlsafe_pem_b64, tool_name="dummy", arguments={}
    )
    return {
        "urlsafe_pem_has_url_alphabet": ("-" in urlsafe_pem_b64)
        or ("_" in urlsafe_pem_b64),
        "urlsafe_pem_helper_detected": helper_hit,
        "urlsafe_pem_provider_call_count": len(calls),
        "urlsafe_pem_tool_blocked": tool_out == _SAFE_TOOL_BLOCK,
    }


def evaluate_final_zip_encoding_gates(summary: dict) -> int:
    """Return 0 only when all encoding wire counts are 0 and refs present."""
    if summary.get("chat_exit") != 0:
        return 6
    if summary.get("check_exit") != 0:
        return 1
    if summary.get("captured_chat_requests", 0) < 1:
        return 2
    if summary.get("plain_secret_count", -1) != 0:
        return 2
    for key in (
        "wire_percent_count",
        "wire_quote_plus_count",
        "wire_base64_count",
        "wire_urlsafe_base64_count",
        "wire_basic_auth_count",
    ):
        if summary.get(key, -1) != 0:
            return 2
    if summary.get("stable_ref_count", 0) < 1:
        return 2
    if summary.get("tools_in_request") is True:
        return 2
    if summary.get("installed_from_zip") is not True:
        return 7
    if summary.get("plugin_path_is_source_tree") is True:
        return 7
    if summary.get("installed_module_file_under_plugin") is not True:
        return 7
    if summary.get("installed_module_file_under_source_tree") is True:
        return 7
    if summary.get("urlsafe_pem_has_url_alphabet") is not True:
        return 8
    if summary.get("urlsafe_pem_helper_detected") is not True:
        return 8
    if summary.get("urlsafe_pem_provider_call_count", -1) != 0:
        return 8
    if summary.get("urlsafe_pem_tool_blocked") is not True:
        return 8
    return 0


def main() -> int:
    plugin_zip = ROOT / "dist" / HISTORICAL_PLUGIN_ZIP_FILENAME
    if not plugin_zip.is_file():
        print(f"missing historical plugin zip: {plugin_zip}")
        return 9

    forms = _wire_forms()
    provider = FakeProvider()
    provider.start()
    try:
        with tempfile.TemporaryDirectory(prefix="cg-final-zip-canary-") as tmp:
            tmp_path = Path(tmp)
            iso = prepare_isolated_hermes(tmp_path / "iso", provider.base_url)
            plugin_resolved = _install_zip_over_plugin(
                iso.hermes_home, plugin_zip, tmp_path / "zip-extract"
            )
            source_resolved = PLUGIN_ROOT.resolve()
            assert_loopback_guards_present()

            # Load detectors from the *installed* ZIP plugin, not the source tree.
            sp, mw, hooks = _load_credential_guard_from_plugin(plugin_resolved)
            path_proof = prove_installed_module_path(
                plugin_resolved, source_resolved, Path(sp.__file__)
            )
            _pem, _std, url_pem = urlsafe_distinct_synthetic_pem_b64()
            pem_probe = probe_urlsafe_pem_provider_bound(
                contains_private_key_material=sp.contains_private_key_material,
                on_llm_execution=mw.on_llm_execution,
                on_transform_tool_result=hooks.on_transform_tool_result,
                urlsafe_pem_b64=url_pem,
            )

            check = run_hermes(iso, ["credential-guard", "check"])
            prompt = (
                "Reply with ok only. "
                f"password is {forms['plain']}; "
                f"pct={forms['percent']}; "
                f"qp={forms['quote_plus']}; "
                f"b64={forms['base64']}; "
                f"url={forms['urlsafe_base64']}; "
                f"basic={forms['basic_auth']}; "
                f"combo={forms['basic_auth_plain']}"
            )
            chat = run_hermes(
                iso,
                [
                    "chat",
                    "-q",
                    prompt,
                    "-Q",
                    "--ignore-rules",
                    "--provider",
                    "custom",
                    "-m",
                    "fake-model",
                ],
                timeout=180,
            )
            bodies = list(provider.chat_completion_bodies)

            def _sum_count(needle: str) -> int:
                raw = needle.encode("utf-8")
                return sum(b.count(raw) for b in bodies)

            plain = _sum_count(forms["plain"])
            wire_percent = (
                _sum_count(forms["percent"])
                if forms["percent"] != forms["plain"]
                else 0
            )
            wire_qp = (
                _sum_count(forms["quote_plus"])
                if forms["quote_plus"] not in {forms["plain"], forms["percent"]}
                else 0
            )
            wire_b64 = _sum_count(forms["base64"])
            wire_url = (
                _sum_count(forms["urlsafe_base64"])
                if forms["urlsafe_base64"] != forms["base64"]
                else wire_b64
            )
            wire_basic = _sum_count(forms["basic_auth"]) + _sum_count(
                forms["basic_auth_plain"]
            )
            refs = _sum_count(DECOY_TOKEN) + _sum_count(DECOY_BASIC_TOKEN)
            summary = {
                "check_exit": check.returncode,
                "chat_exit": chat.returncode,
                "captured_chat_requests": len(bodies),
                "plain_secret_count": plain,
                "wire_percent_count": wire_percent,
                "wire_quote_plus_count": wire_qp,
                "wire_base64_count": wire_b64,
                "wire_urlsafe_base64_count": wire_url,
                "wire_basic_auth_count": wire_basic,
                "stable_ref_count": refs,
                "tools_in_request": any(request_has_tools(b) for b in bodies),
                "plugin_zip": str(plugin_zip.name),
                "plugin_install_path": str(plugin_resolved),
                **path_proof,
                **pem_probe,
            }
            print(json.dumps(summary, ensure_ascii=False, indent=2))
            audit = read_net_audit(iso)
            try:
                assert_all_loopback(audit)
            except AssertionError as exc:
                print("net_guard_failed:", exc)
                return 5
            return evaluate_final_zip_encoding_gates(summary)
    finally:
        provider.stop()


if __name__ == "__main__":
    raise SystemExit(main())
