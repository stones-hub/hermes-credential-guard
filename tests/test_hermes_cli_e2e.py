from __future__ import annotations

import json

from credential_guard.middleware import SAFE_BLOCK_MESSAGE
from credential_guard.sensitive_paths import (
    MAX_PRIVATE_KEY_CANDIDATE_LENGTH,
    MAX_PRIVATE_KEY_SCAN_BYTES,
)
from tests.fake_provider import FakeProvider
from tests.hermes_e2e_helpers import (
    DECOY_SECRET,
    DECOY_TOKEN,
    WORKER_PROFILE,
    assert_all_loopback,
    assert_loopback_guards_present,
    assert_worker_evidence,
    classify_worker_delta,
    content_fingerprint,
    count_decoy_in_paths,
    detect_worker_live,
    main_chain_chat_bodies,
    prepare_isolated_hermes,
    read_net_audit,
    request_has_tools,
    run_hermes,
    temp_isolation_evidence,
)


def test_hermes_credential_guard_check_exit_zero(tmp_path):
    provider = FakeProvider()
    provider.start()
    try:
        iso = prepare_isolated_hermes(tmp_path, provider.base_url)
        result = run_hermes(iso, ["credential-guard", "check"])
        assert result.returncode == 0, result.stdout + result.stderr
        assert "credential-guard: enabled" in result.stdout
        assert "llm_request" in result.stdout
        assert "llm_execution" in result.stdout
        assert "transform_tool_result" in result.stdout
        assert DECOY_SECRET not in result.stdout
        assert DECOY_SECRET not in result.stderr
    finally:
        provider.stop()


def test_hermes_chat_real_cli_e2e_redacts_outbound_http(tmp_path):
    before_fp = content_fingerprint(WORKER_PROFILE)
    worker_live = detect_worker_live(WORKER_PROFILE)
    provider = FakeProvider()
    provider.start()
    try:
        iso = prepare_isolated_hermes(tmp_path, provider.base_url)
        isolation = temp_isolation_evidence(iso)
        assert_loopback_guards_present()
        query = f"Reply with ok only. Ignore tools. password is {DECOY_SECRET}"
        result = run_hermes(
            iso,
            [
                "chat",
                "-q",
                query,
                "-Q",
                "--ignore-rules",
                "--provider",
                "custom",
                "-m",
                "fake-model",
            ],
            timeout=180,
        )
        assert result.returncode == 0, (
            f"exit={result.returncode} stdout={result.stdout[-1500]!r} "
            f"stderr={result.stderr[-1500]!r}"
        )
        bodies = provider.chat_completion_bodies
        main_bodies = main_chain_chat_bodies(bodies)
        assert len(main_bodies) == 1, (
            f"expected exactly 1 main-chain chat/completions; "
            f"main={len(main_bodies)} total={len(bodies)}; "
            f"reqs={[ (m,p) for m,p,_ in provider.requests ]}"
        )
        body = main_bodies[0]
        payload = json.loads(body.decode("utf-8"))
        assert payload.get("model") == "fake-model", payload.get("model")
        plain = body.count(DECOY_SECRET.encode("utf-8"))
        refs = body.count(DECOY_TOKEN.encode("utf-8"))
        assert plain == 0, body[:2000]
        assert refs >= 1, body[:2000]
        assert not request_has_tools(body), body[:500]

        audit = read_net_audit(iso)
        assert_all_loopback(audit)

        split = count_decoy_in_paths(
            iso.hermes_home,
            DECOY_SECRET,
            [
                "logs",
                "logs/agent.log",
                "state.db",
                "state.db-wal",
                "state.db-shm",
                "sessions",
            ],
        )

        after_fp = content_fingerprint(WORKER_PROFILE)
        delta = classify_worker_delta(before_fp, after_fp, worker_live=worker_live)
        assert_worker_evidence(delta, isolation)

        summary = {
            "chat_http_requests_total": len(bodies),
            "main_chain_http_requests": len(main_bodies),
            "plain_secret_count": plain,
            "stable_ref_count": refs,
            "net_attempts": audit.get("attempts"),
            "local_persisted_split": split,
            "worker_delta": {
                "status": delta["status"],
                "stable": delta["stable"],
                "config_plugins_sessions_unchanged": delta[
                    "config_plugins_sessions_unchanged"
                ],
                "natural_or_live_noise_count": len(delta["natural_or_live_noise"]),
                "unexpected_changes": [c["path"] for c in delta["unexpected_changes"]],
            },
            "isolation": isolation,
            "hermes_exit_code": result.returncode,
            "temp_hermes_home": str(iso.hermes_home),
        }
        print("E2E_SUMMARY " + json.dumps(summary, ensure_ascii=False))
    finally:
        provider.stop()


def test_hermes_chat_long_system_prompt_does_not_false_block(tmp_path):
    """Ordinary long text (>65_536) in the outbound request must not fail-closed."""
    provider = FakeProvider()
    provider.start()
    try:
        iso = prepare_isolated_hermes(tmp_path, provider.base_url)
        long_ordinary = (
            "Ordinary isolated prompt line with spaces and punctuation. " * 2000
        )
        assert len(long_ordinary) > MAX_PRIVATE_KEY_CANDIDATE_LENGTH
        assert len(long_ordinary.encode("utf-8")) < MAX_PRIVATE_KEY_SCAN_BYTES
        # Put the long ordinary string in the user turn so it is present in the
        # provider-bound request regardless of SOUL.md truncation policy.
        query = (
            f"{long_ordinary}\n\nReply with ok only. password is {DECOY_SECRET}"
        )
        result = run_hermes(
            iso,
            [
                "chat",
                "-q",
                query,
                "-Q",
                "--ignore-rules",
                "--provider",
                "custom",
                "-m",
                "fake-model",
            ],
            timeout=180,
        )
        assert result.returncode == 0, (
            f"exit={result.returncode} stdout={result.stdout[-1500]!r} "
            f"stderr={result.stderr[-1500]!r}"
        )
        assert SAFE_BLOCK_MESSAGE not in result.stdout
        main_bodies = main_chain_chat_bodies(provider.chat_completion_bodies)
        assert len(main_bodies) == 1, (
            f"long ordinary prompt must allow exactly 1 main-chain request; "
            f"got {len(main_bodies)}; total={len(provider.chat_completion_bodies)}"
        )
        body = main_bodies[0]
        payload = json.loads(body.decode("utf-8"))
        assert payload.get("model") == "fake-model"
        assert DECOY_SECRET.encode("utf-8") not in body
        assert DECOY_TOKEN.encode("utf-8") in body
        assert_all_loopback(read_net_audit(iso))
    finally:
        provider.stop()


def test_hermes_chat_fail_closed_llm_execution_http_zero_exit_zero(tmp_path):
    before_fp = content_fingerprint(WORKER_PROFILE)
    worker_live = detect_worker_live(WORKER_PROFILE)
    provider = FakeProvider()
    provider.start()
    try:
        iso = prepare_isolated_hermes(tmp_path, provider.base_url)
        isolation = temp_isolation_evidence(iso)
        before_http = len(provider.chat_completion_bodies)
        result = run_hermes(
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
            extra_env={"CREDENTIAL_GUARD_TEST_INJECT_FAILURE": "redact"},
            timeout=180,
        )
        new_bodies = provider.chat_completion_bodies[before_http:]
        main_new = main_chain_chat_bodies(new_bodies)
        assert len(main_new) == 0, (
            f"fail-closed must send 0 main-chain provider bodies; got {len(main_new)}; "
            f"total_new={len(new_bodies)}; reqs={provider.requests}"
        )
        assert result.returncode == 0, (
            f"fail-closed must exit 0; got {result.returncode}; "
            f"stdout={result.stdout[-1500]!r} stderr={result.stderr[-1500]!r}"
        )
        assert "request blocked by credential-guard" in result.stdout
        assert DECOY_SECRET not in result.stdout
        assert DECOY_SECRET not in result.stderr
        assert_all_loopback(read_net_audit(iso))
        after_fp = content_fingerprint(WORKER_PROFILE)
        delta = classify_worker_delta(before_fp, after_fp, worker_live=worker_live)
        assert_worker_evidence(delta, isolation)
    finally:
        provider.stop()


def test_hermes_chat_fail_closed_llm_request_provider_zero(tmp_path):
    """llm_request internal failure → local terminate; Provider chat bodies == 0."""
    provider = FakeProvider()
    provider.start()
    try:
        iso = prepare_isolated_hermes(tmp_path, provider.base_url)
        before_http = len(provider.chat_completion_bodies)
        result = run_hermes(
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
        new_bodies = provider.chat_completion_bodies[before_http:]
        # Mechanical count: zero provider chat bodies (not merely "no fake model name").
        assert len(new_bodies) == 0, (
            f"llm_request fail-closed must send 0 provider chat bodies; "
            f"got {len(new_bodies)}; reqs={provider.requests}"
        )
        assert result.returncode == 0, (
            f"exit={result.returncode} "
            f"stdout={(result.stdout or '')[-1500]!r} "
            f"stderr={(result.stderr or '')[-1500]!r}"
        )
        assert "request blocked by credential-guard" in (result.stdout or "")
        assert DECOY_SECRET not in (result.stdout or "")
        assert DECOY_SECRET not in (result.stderr or "")
        joined = b"".join(new_bodies)
        assert b"credential-guard-blocked" not in joined
        assert b"credential-guard-local-block" not in joined
        assert_all_loopback(read_net_audit(iso))
    finally:
        provider.stop()


def test_hermes_chat_plugin_disabled_no_interference(tmp_path):
    """With credential-guard not enabled, ordinary chat must reach provider unredacted."""
    from tests.hermes_e2e_helpers import _to_yaml

    provider = FakeProvider()
    provider.start()
    try:
        iso = prepare_isolated_hermes(tmp_path, provider.base_url)
        # Rewrite config with empty plugin enable list (formal non-interference).
        cfg_path = iso.hermes_home / "config.yaml"
        config = {
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
        cfg_path.write_text(_to_yaml(config), encoding="utf-8")
        result = run_hermes(
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
        assert result.returncode == 0, (
            f"exit={result.returncode} stdout={result.stdout[-1500]!r} "
            f"stderr={result.stderr[-1500]!r}"
        )
        main_bodies = main_chain_chat_bodies(provider.chat_completion_bodies)
        assert len(main_bodies) == 1, (
            f"plugin-disabled chat must send 1 main-chain body; got {len(main_bodies)}"
        )
        body = main_bodies[0]
        payload = json.loads(body.decode("utf-8"))
        assert payload.get("model") == "fake-model"
        # Without the plugin, registered decoy is not redacted (non-interference).
        assert DECOY_SECRET.encode("utf-8") in body
        assert SAFE_BLOCK_MESSAGE not in result.stdout
        assert_all_loopback(read_net_audit(iso))
    finally:
        provider.stop()
