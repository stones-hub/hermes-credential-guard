#!/usr/bin/env python3
"""R7 0.4.1 final plugin-ZIP isolated Hermes E2E harness (opt-in).

Installs the landed 0.4.1 plugin ZIP into a temporary HOME/HERMES_HOME via the
shared installer, proves modules load from the install tree (not the repo
source tree), and exercises main-chat coverage plus the disclosed auxiliary
host-boundary messaging from ``credential-guard check``.

Never touches real default/worker profiles, real credentials, ~/.ssh, or
non-loopback peers. Never calls ``build_all``. Never modifies Hermes source.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

EXPECTED_PLUGIN_ZIP = "credential-guard-0.4.1-hermes-plugin.zip"
# Filled after designated dual-build copy2; gate fails closed if bytes drift.
EXPECTED_PLUGIN_ZIP_SHA256 = (
    "3bee46a83c45579faae693d8dd4f681d9128373014e36069eaabadbd1677d16c"
)

KEY_ENCODING_KEYS: Tuple[str, ...] = (
    "raw",
    "base64",
    "urlsafe_base64",
    "percent",
    "json_escape",
    "unicode_escape",
)

from credential_guard.cli import (  # noqa: E402
    COVERAGE_BOUNDARY_AUXILIARY,
    COVERAGE_BOUNDARY_MAIN,
    COVERAGE_BOUNDARY_NOTE,
)
from credential_guard.middleware import SAFE_BLOCK_MESSAGE  # noqa: E402
from credential_guard.release_identity import PLUGIN_VERSION  # noqa: E402
from credential_guard.sensitive_paths import (  # noqa: E402
    MAX_PRIVATE_KEY_CANDIDATE_LENGTH,
    MAX_PRIVATE_KEY_SCAN_BYTES,
)
from tests.fake_provider import FakeProvider  # noqa: E402
from tests.hermes_e2e_helpers import (  # noqa: E402
    DECOY_SECRET,
    DECOY_TOKEN,
    PLUGIN_ROOT,
    assert_all_loopback,
    assert_loopback_guards_present,
    main_chain_chat_bodies,
    opaque_token,
    prepare_isolated_hermes,
    read_net_audit,
    run_hermes,
)


def _load_zip_helpers():
    path = ROOT / "scripts" / "installed_zip_plugin.py"
    spec = importlib.util.spec_from_file_location("installed_zip_plugin_r7", path)
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
    if expected_sha256.startswith("PENDING"):
        raise RuntimeError(
            "EXPECTED_PLUGIN_ZIP_SHA256 still PENDING_AFTER_BUILD; "
            "fill after designated copy2"
        )
    if digest != expected_sha256:
        raise AssertionError(
            f"plugin zip sha drift: got {digest} expected {expected_sha256}"
        )
    return path


SYNTHETIC_PEM_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
SYNTHETIC_PEM_END = "-----END OPENSSH PRIVATE KEY-----"


def urlsafe_distinct_synthetic_pem_b64():
    pem = (
        f"{SYNTHETIC_PEM_BEGIN}\n"
        "CG_SYNTHETIC_DECOY_NOT_A_REAL_KEY_ >\n"
        f"{SYNTHETIC_PEM_END}\n"
    )
    raw = pem.encode("utf-8")
    std = base64.b64encode(raw).decode("ascii")
    url = base64.urlsafe_b64encode(raw).decode("ascii")
    if not (("-" in url or "_" in url) and url != std):
        raise RuntimeError("urlsafe pem fixture must diverge from std alphabet")
    return pem, std, url


def fully_json_unicode_escape(text: str) -> str:
    """Per-char \\uXXXX form recovered by production ``_try_json_unescape``."""
    return "".join(f"\\u{ord(ch):04x}" for ch in text)


def legacy_json_dumps_escape(pem: str) -> str:
    """Historical non-authentic fixture: json.dumps leaves raw PEM markers."""
    return json.dumps(pem)[1:-1]


def build_unicode_escape_long_prompt(escaped_pem: str) -> str:
    """Embed a \\uXXXX PEM run inside overlong ordinary prose (escape-run path)."""
    pad = (
        "Ordinary isolated prompt line with spaces and punctuation. " * 2000
    )
    mid = max(0, (MAX_PRIVATE_KEY_CANDIDATE_LENGTH // 2) - (len(escaped_pem) // 2))
    text = pad[:mid] + escaped_pem + pad
    while len(text) <= MAX_PRIVATE_KEY_CANDIDATE_LENGTH:
        text += " more ordinary words for length."
    if len(text.encode("utf-8")) >= MAX_PRIVATE_KEY_SCAN_BYTES:
        raise RuntimeError("unicode_escape long prompt exceeds scan budget")
    return text


def assert_json_escape_fixture_authentic(material: str, sp) -> None:
    """Authenticity gate: JSON cell must not be pre-hit by raw PEM detection."""
    if SYNTHETIC_PEM_BEGIN in material or SYNTHETIC_PEM_END in material:
        raise AssertionError(
            "json_escape fixture still contains raw PEM begin/end marker "
            f"(RAW_MARKER_PRESENT=True); material_len={len(material)}"
        )
    if sp.looks_like_private_key(material) is not False:
        raise AssertionError(
            "json_escape fixture looks_like_private_key must be False "
            "(raw detector must not pre-hit)"
        )
    decoded = sp._try_json_unescape(material)
    if not decoded or not (
        SYNTHETIC_PEM_BEGIN in decoded and SYNTHETIC_PEM_END in decoded
    ):
        raise AssertionError(
            "json_escape fixture must JSON-unescape to synthetic PEM markers"
        )
    if sp.contains_private_key_material(material) is not True:
        raise AssertionError(
            "json_escape fixture must hit contains_private_key_material via JSON seam"
        )


def prove_installed_json_unescape_seam_load_bearing(
    plugin_zip: Path, json_material: str
) -> Dict[str, Any]:
    """Disable installed-ZIP ``_try_json_unescape`` only; detection must go RED."""
    with tempfile.TemporaryDirectory(prefix="cg-r7-041-json-seam-mut-") as tmp:
        tmp_path = Path(tmp)
        extract_root = tmp_path / "zip-extract"
        plugin_dest = tmp_path / "plugins" / "credential-guard"
        build = _zip._load_build_mod()
        extracted = build.extract_plugin_zip(plugin_zip, extract_root)
        shutil.copytree(extracted, plugin_dest)
        sp, _mw, _hooks = _zip.load_credential_guard_from_plugin(plugin_dest)
        proof = _zip.prove_installed_module_path(
            plugin_dest, PLUGIN_ROOT.resolve(), Path(sp.__file__)
        )
        if proof.get("installed_from_zip") is not True:
            raise AssertionError(f"mutation must load installed ZIP module: {proof}")
        assert_json_escape_fixture_authentic(json_material, sp)
        # Load-bearing: only the JSON-unescape seam — not summary fields.
        sp._try_json_unescape = lambda _candidate: None  # type: ignore[method-assign]
        if sp.contains_private_key_material(json_material) is not False:
            raise AssertionError(
                "after disabling installed _try_json_unescape, "
                "contains_private_key_material must be False (seam not load-bearing)"
            )
        return {
            "installed_from_zip": True,
            "raw_marker_absent": True,
            "raw_detector_false": True,
            "json_unescape_disabled_contains_false": True,
            "installed_module_file": str(Path(sp.__file__).resolve()),
        }


def _encoding_forms(secret: str) -> Dict[str, str]:
    raw = secret.encode("utf-8")
    return {
        "plain": secret,
        "percent": quote(secret, safe=""),
        "base64": base64.b64encode(raw).decode("ascii"),
        "urlsafe_base64": base64.urlsafe_b64encode(raw).decode("ascii"),
    }


def build_key_encoding_materials() -> Tuple[str, Dict[str, str]]:
    """Return (pem, name→material) for the closed six-cell matrix.

    ``json_escape`` and ``unicode_escape`` share the per-char ``\\uXXXX`` glyph
    recovered by the same production ``_try_json_unescape`` seam. They differ
    in prompt shape: short standalone JSON-string material vs overlong ordinary
    text embedding a bounded escape run (``_JSON_ESCAPE_RUN_RE`` path).
    """
    pem, std_b64, url_b64 = urlsafe_distinct_synthetic_pem_b64()
    unicode_glyph = fully_json_unicode_escape(pem)
    # Short independent JSON-string form (whole-candidate JSON unescape).
    json_escape = unicode_glyph
    # Long ordinary prose with the same glyph embedded (bounded escape-run path).
    unicode_escape = build_unicode_escape_long_prompt(unicode_glyph)
    materials = {
        "raw": pem,
        "base64": std_b64,
        "urlsafe_base64": url_b64,
        "percent": quote(pem, safe=""),
        "json_escape": json_escape,
        "unicode_escape": unicode_escape,
    }
    return pem, materials


def _key_encoding_matrix_ok(matrix: Any) -> bool:
    """Closed six-cell matrix: exact keys; each cell exit/blocked/provider_delta."""
    if not isinstance(matrix, dict):
        return False
    if set(matrix.keys()) != set(KEY_ENCODING_KEYS):
        return False
    for key in KEY_ENCODING_KEYS:
        cell = matrix.get(key)
        if not isinstance(cell, dict):
            return False
        # Missing cell fields must fail closed (no green defaults).
        if cell.get("exit") != 0:
            return False
        if cell.get("blocked") is not True:
            return False
        if cell.get("provider_delta") != 0:
            return False
    return True


def evaluate_r7_041_final_zip_gates(summary: dict) -> int:
    """Map every measured acceptance field onto a non-zero exit code."""
    if summary.get("plugin_version") != PLUGIN_VERSION:
        return 10
    if summary.get("installed_from_zip") is not True:
        return 7
    if summary.get("installed_module_file_under_plugin") is not True:
        return 7
    if summary.get("installed_module_file_under_source_tree") is True:
        return 7
    if summary.get("plugin_path_is_source_tree") is True:
        return 7
    if summary.get("check_exit") != 0:
        return 1
    if not summary.get("check_has_main_coverage"):
        return 11
    if not summary.get("check_has_auxiliary_out_of_scope"):
        return 11
    if not summary.get("check_has_title_not_full_coverage_note"):
        return 11
    if summary.get("hello_exit") != 0:
        return 6
    if summary.get("hello_provider_bodies") != 1:
        return 2
    if summary.get("hello_has_fake_blocked_model"):
        return 2
    if summary.get("registered_secret_plain_count") != 0:
        return 2
    if not isinstance(summary.get("registered_secret_ref_count"), int):
        return 2
    if summary.get("registered_secret_ref_count", 0) < 1:
        return 2
    if not _key_encoding_matrix_ok(summary.get("key_encoding_matrix")):
        return 8
    if summary.get("key_block_provider_delta") != 0:
        return 8
    if summary.get("key_block_exit") != 0:
        return 8
    if summary.get("installed_key_urlsafe_provider_calls") != 0:
        return 8
    if summary.get("fail_closed_exit") != 0:
        return 3
    if summary.get("fail_closed_provider_delta") != 0:
        return 3
    if summary.get("fail_closed_has_decoy"):
        return 3
    if summary.get("fail_closed_has_block_msg") is not True:
        return 3
    if summary.get("disabled_exit") != 0:
        return 9
    if summary.get("disabled_provider_bodies") != 1:
        return 9
    if summary.get("disabled_plain_visible") is not True:
        return 9
    if summary.get("title_generation_disabled_is_isolation_only") is not True:
        return 11
    if summary.get("opaque_token_smoke") is not True:
        return 4
    return 0


def _run_single_key_encoding_chat(
    iso, provider, *, material: str, timeout: int = 180
) -> Dict[str, Any]:
    """One main-chat call whose prompt carries exactly one encoding form."""
    before = len(provider.chat_completion_bodies)
    prompt = f"Reply with ok only. material={material}"
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
        timeout=timeout,
    )
    delta = len(main_chain_chat_bodies(provider.chat_completion_bodies[before:]))
    stdout = chat.stdout or ""
    return {
        "exit": chat.returncode,
        "blocked": SAFE_BLOCK_MESSAGE in stdout,
        "provider_delta": delta,
    }


def run_suite() -> Dict[str, Any]:
    plugin_zip = resolve_plugin_zip()
    _pem, materials = build_key_encoding_materials()
    # Authenticity precondition for the JSON cell (must not be raw-marker pre-hit).
    from credential_guard import sensitive_paths as _sp_src  # local import for gate

    assert_json_escape_fixture_authentic(materials["json_escape"], _sp_src)
    url_b64 = materials["urlsafe_base64"]
    encoding_materials: Tuple[Tuple[str, str], ...] = tuple(
        (name, materials[name]) for name in KEY_ENCODING_KEYS
    )

    provider = FakeProvider()
    provider.start()
    try:
        with tempfile.TemporaryDirectory(prefix="cg-r7-041-final-zip-") as tmp:
            tmp_path = Path(tmp)
            iso = prepare_isolated_hermes(tmp_path / "iso", provider.base_url)
            plugin_dest = _zip.install_zip_over_plugin(
                iso.hermes_home, plugin_zip, tmp_path / "zip-extract"
            )
            sp, mw, hooks = _zip.load_credential_guard_from_plugin(plugin_dest)
            proof = _zip.prove_installed_module_path(
                plugin_dest, PLUGIN_ROOT.resolve(), Path(sp.__file__)
            )
            _zip.assert_key_module_matches_zip(
                plugin_dest, plugin_zip, relative="plugin.yaml"
            )
            assert_loopback_guards_present()

            yaml_text = (plugin_dest / "plugin.yaml").read_text(encoding="utf-8")
            plugin_version = None
            for line in yaml_text.splitlines():
                if line.startswith("version:"):
                    plugin_version = line.split(":", 1)[1].strip()
                    break

            check = run_hermes(iso, ["credential-guard", "check"])
            check_out = check.stdout or ""

            # 3) long ordinary + 你好 main chat
            before = len(provider.chat_completion_bodies)
            long_ordinary = (
                "Ordinary isolated prompt line with spaces and punctuation. " * 2000
            )
            assert len(long_ordinary) > MAX_PRIVATE_KEY_CANDIDATE_LENGTH
            assert len(long_ordinary.encode("utf-8")) < MAX_PRIVATE_KEY_SCAN_BYTES
            hello = run_hermes(
                iso,
                [
                    "chat",
                    "-q",
                    f"{long_ordinary}\n\n你好. password is {DECOY_SECRET}",
                    "-Q",
                    "--ignore-rules",
                    "--provider",
                    "custom",
                    "-m",
                    "fake-model",
                ],
                timeout=180,
            )
            hello_bodies = main_chain_chat_bodies(
                provider.chat_completion_bodies[before:]
            )
            hello_joined = b"".join(hello_bodies)
            hello_plain = hello_joined.count(DECOY_SECRET.encode("utf-8"))
            hello_refs = hello_joined.count(DECOY_TOKEN.encode("utf-8"))
            hello_fake_model = (
                b"credential-guard-blocked" in hello_joined
                or b"credential-guard-local-block" in hello_joined
            )

            # 6) six encoding forms — separate main-chat calls (not one mixed prompt)
            key_encoding_matrix: Dict[str, Any] = {}
            for name, material in encoding_materials:
                key_encoding_matrix[name] = _run_single_key_encoding_chat(
                    iso, provider, material=material
                )
            key_block_exit = max(
                int(cell["exit"]) for cell in key_encoding_matrix.values()
            )
            key_block_provider_delta = sum(
                int(cell["provider_delta"]) for cell in key_encoding_matrix.values()
            )

            # 7) fail-closed inject
            before_fc = len(provider.chat_completion_bodies)
            fail_closed = run_hermes(
                iso,
                [
                    "chat",
                    "-q",
                    f"password is {DECOY_SECRET}",
                    "-Q",
                    "--ignore-rules",
                    "--provider",
                    "custom",
                    "-m",
                    "fake-model",
                ],
                extra_env={"CREDENTIAL_GUARD_TEST_INJECT_FAILURE": "llm_request"},
                timeout=180,
            )
            fc_delta = len(
                main_chain_chat_bodies(provider.chat_completion_bodies[before_fc:])
            )
            fc_out = (fail_closed.stdout or "") + (fail_closed.stderr or "")
            fc_has_decoy = DECOY_SECRET in fc_out

            # 8) plugin disabled control
            from tests.hermes_e2e_helpers import _to_yaml

            cfg_path = iso.hermes_home / "config.yaml"
            cfg_path.write_text(
                _to_yaml(
                    {
                        "model": {
                            "default": "fake-model",
                            "provider": "custom",
                            "base_url": provider.base_url,
                        },
                        "plugins": {"enabled": []},
                        "approvals": {"mode": "manual"},
                        "display": {"tool_progress": "off"},
                        "platform_toolsets": {"cli": []},
                        "agent": {"disabled_toolsets": ["kanban"]},
                        "security": {"tirith_enabled": False},
                        "auxiliary": {"title_generation": {"enabled": False}},
                    }
                ),
                encoding="utf-8",
            )
            before_dis = len(provider.chat_completion_bodies)
            disabled = run_hermes(
                iso,
                [
                    "chat",
                    "-q",
                    f"Reply with ok only. password is {DECOY_SECRET}",
                    "-Q",
                    "--ignore-rules",
                    "--provider",
                    "custom",
                    "-m",
                    "fake-model",
                ],
                timeout=180,
            )
            dis_bodies = main_chain_chat_bodies(
                provider.chat_completion_bodies[before_dis:]
            )
            dis_joined = b"".join(dis_bodies)

            # In-process URL-safe probe (defense-in-depth; not a substitute for
            # the urlsafe_base64 Hermes main-chain matrix cell).
            calls: List[Any] = []
            mw.on_llm_execution(
                request={"messages": [{"role": "user", "content": url_b64}]},
                next_call=lambda r: calls.append(r) or {"ok": True},
            )

            summary = {
                "plugin_version": plugin_version,
                "plugin_zip": EXPECTED_PLUGIN_ZIP,
                "plugin_zip_sha256": EXPECTED_PLUGIN_ZIP_SHA256,
                "check_exit": check.returncode,
                "check_has_main_coverage": COVERAGE_BOUNDARY_MAIN in check_out,
                "check_has_auxiliary_out_of_scope": (
                    COVERAGE_BOUNDARY_AUXILIARY in check_out
                ),
                "check_has_title_not_full_coverage_note": (
                    COVERAGE_BOUNDARY_NOTE in check_out
                ),
                "hello_exit": hello.returncode,
                "hello_provider_bodies": len(hello_bodies),
                "hello_has_fake_blocked_model": hello_fake_model,
                "registered_secret_plain_count": hello_plain,
                "registered_secret_ref_count": hello_refs,
                "key_encoding_matrix": key_encoding_matrix,
                "key_block_exit": key_block_exit,
                "key_block_provider_delta": key_block_provider_delta,
                "installed_key_urlsafe_provider_calls": len(calls),
                "fail_closed_exit": fail_closed.returncode,
                "fail_closed_provider_delta": fc_delta,
                "fail_closed_has_decoy": fc_has_decoy,
                "fail_closed_has_block_msg": SAFE_BLOCK_MESSAGE in (
                    fail_closed.stdout or ""
                ),
                "disabled_exit": disabled.returncode,
                "disabled_provider_bodies": len(dis_bodies),
                "disabled_plain_visible": DECOY_SECRET.encode("utf-8") in dis_joined,
                # Isolation condition only — never a global security proof.
                "title_generation_disabled_is_isolation_only": True,
                "opaque_token_smoke": opaque_token("db", "password") == DECOY_TOKEN,
                **proof,
            }
            assert_all_loopback(read_net_audit(iso))
            return summary
    finally:
        provider.stop()


def main() -> int:
    try:
        summary = run_suite()
    except Exception as exc:
        print(f"R7_041_FINAL_ZIP_E2E_FAIL: {exc}", file=sys.stderr)
        return 12
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    code = evaluate_r7_041_final_zip_gates(summary)
    if code != 0:
        print(f"R7_041_FINAL_ZIP_GATE_FAIL exit={code}", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
