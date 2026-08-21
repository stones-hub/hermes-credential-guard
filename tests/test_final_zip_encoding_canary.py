"""Gate tests for final ZIP encoding canary evaluator."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

from credential_guard.hooks import on_transform_tool_result
from credential_guard.middleware import on_llm_execution
from credential_guard.runtime_config import reset_runtime_for_tests
from credential_guard.sensitive_paths import contains_private_key_material


def _load():
    path = Path(__file__).resolve().parents[1] / "scripts" / "run_final_zip_encoding_canary.py"
    spec = importlib.util.spec_from_file_location("run_final_zip_encoding_canary", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _passing(**overrides):
    base = {
        "check_exit": 0,
        "chat_exit": 0,
        "captured_chat_requests": 1,
        "plain_secret_count": 0,
        "wire_percent_count": 0,
        "wire_quote_plus_count": 0,
        "wire_base64_count": 0,
        "wire_urlsafe_base64_count": 0,
        "wire_basic_auth_count": 0,
        "stable_ref_count": 1,
        "tools_in_request": False,
        "installed_from_zip": True,
        "plugin_path_is_source_tree": False,
        "installed_module_file_under_plugin": True,
        "installed_module_file_under_source_tree": False,
        "urlsafe_pem_has_url_alphabet": True,
        "urlsafe_pem_helper_detected": True,
        "urlsafe_pem_provider_call_count": 0,
        "urlsafe_pem_tool_blocked": True,
    }
    base.update(overrides)
    return base


def test_final_zip_encoding_gates_pass():
    mod = _load()
    assert mod.evaluate_final_zip_encoding_gates(_passing()) == 0


def test_final_zip_encoding_gates_require_zip_install():
    mod = _load()
    assert mod.evaluate_final_zip_encoding_gates(_passing(installed_from_zip=False)) != 0
    assert (
        mod.evaluate_final_zip_encoding_gates(_passing(plugin_path_is_source_tree=True))
        != 0
    )
    assert (
        mod.evaluate_final_zip_encoding_gates(
            _passing(installed_module_file_under_plugin=False)
        )
        != 0
    )
    assert (
        mod.evaluate_final_zip_encoding_gates(
            _passing(installed_module_file_under_source_tree=True)
        )
        != 0
    )


def test_final_zip_encoding_gates_mutate_wire_counts():
    mod = _load()
    for key in (
        "plain_secret_count",
        "wire_percent_count",
        "wire_quote_plus_count",
        "wire_base64_count",
        "wire_urlsafe_base64_count",
        "wire_basic_auth_count",
    ):
        assert mod.evaluate_final_zip_encoding_gates(_passing(**{key: 1})) != 0, key


def test_final_zip_encoding_gates_mutate_urlsafe_pem_fields():
    mod = _load()
    mutations = {
        "urlsafe_pem_has_url_alphabet": False,
        "urlsafe_pem_helper_detected": False,
        "urlsafe_pem_provider_call_count": 1,
        "urlsafe_pem_tool_blocked": False,
    }
    for key, bad in mutations.items():
        assert mod.evaluate_final_zip_encoding_gates(_passing(**{key: bad})) != 0, key


def test_urlsafe_distinct_synthetic_pem_b64_diverges():
    mod = _load()
    _pem, std, url = mod.urlsafe_distinct_synthetic_pem_b64()
    assert ("-" in url) or ("_" in url)
    assert url != std
    assert ("+" in std) or ("/" in std)
    # Do not print pem/url bodies.


def test_probe_urlsafe_pem_provider_bound_live_source_whole_field_replace(
    tmp_path, monkeypatch
):
    """Live source: urlsafe PEM is detected, whole-field replaced, Provider=1.

    Historical ZIP canary evaluator still requires provider_call_count==0 against
    the frozen installed artifact; this live-source probe tracks current product
    rules (continue after unresolved-field placeholder).
    """
    from credential_guard.middleware import REDACTED_UNRESOLVED_SENSITIVE_FIELD
    from credential_guard.result_guard import RESULT_GUARD_FAIL_TEXT

    hermes = tmp_path / "hermes_home"
    store = hermes / "credential-guard"
    store.mkdir(parents=True)
    os.chmod(store, 0o700)
    cfg = store / "credential-guard.json"
    cfg.write_text(
        json.dumps({"version": 2, "credentials": {}, "bindings": {}}),
        encoding="utf-8",
    )
    os.chmod(cfg, 0o600)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    (tmp_path / "home").mkdir(exist_ok=True)
    reset_runtime_for_tests()

    mod = _load()
    _pem, _std, url = mod.urlsafe_distinct_synthetic_pem_b64()
    probe = mod.probe_urlsafe_pem_provider_bound(
        contains_private_key_material=contains_private_key_material,
        on_llm_execution=on_llm_execution,
        on_transform_tool_result=on_transform_tool_result,
        urlsafe_pem_b64=url,
    )
    assert probe["urlsafe_pem_has_url_alphabet"] is True
    assert probe["urlsafe_pem_helper_detected"] is True
    assert probe["urlsafe_pem_provider_call_count"] == 1

    calls: list = []
    result = on_llm_execution(
        request={"messages": [{"role": "user", "content": url}]},
        next_call=lambda r: calls.append(r) or {"ok": True},
    )
    assert result == {"ok": True}
    assert len(calls) == 1
    assert calls[0]["messages"][0]["content"] == REDACTED_UNRESOLVED_SENSITIVE_FIELD
    assert url not in json.dumps(calls[0], ensure_ascii=False)

    live_tool = on_transform_tool_result(result=url, tool_name="dummy", arguments={})
    assert live_tool == RESULT_GUARD_FAIL_TEXT
    assert "BEGIN" not in live_tool
    assert live_tool.count(url) == 0
    reset_runtime_for_tests()


def test_prove_installed_module_path_requires_plugin_not_source(tmp_path):
    mod = _load()
    source = tmp_path / "src"
    plugin = tmp_path / "iso" / "plugins" / "credential-guard"
    (plugin / "credential_guard").mkdir(parents=True)
    (source / "credential_guard").mkdir(parents=True)
    loaded = plugin / "credential_guard" / "sensitive_paths.py"
    loaded.write_text("# decoy\n", encoding="utf-8")
    proof = mod.prove_installed_module_path(plugin, source, loaded)
    assert proof["installed_module_file_under_plugin"] is True
    assert proof["installed_module_file_under_source_tree"] is False
    assert proof["installed_from_zip"] is True
    assert proof["plugin_path_is_source_tree"] is False

    # Source-tree load must not count as zip install.
    src_loaded = source / "credential_guard" / "sensitive_paths.py"
    src_loaded.write_text("# decoy\n", encoding="utf-8")
    bad = mod.prove_installed_module_path(plugin, source, src_loaded)
    assert bad["installed_from_zip"] is False
    assert bad["installed_module_file_under_source_tree"] is True
