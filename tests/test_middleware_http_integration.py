"""Middleware + local HTTP integration tests (not full Hermes CLI E2E)."""

from __future__ import annotations

import json
import os
from urllib import request

import pytest

from credential_guard.middleware import on_llm_execution, on_llm_request
from credential_guard.state import get_registry
from tests.fake_provider import FakeProvider
from tests.hermes_e2e_helpers import DECOY_TOKEN


@pytest.fixture(autouse=True)
def _isolated_empty_store(tmp_path, monkeypatch):
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
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    get_registry().clear()


def test_middleware_chain_local_http_capture_integration():
    reg = get_registry()
    reg.register("db", "password", "decoy_db_password_123")
    provider = FakeProvider()
    provider.start()
    try:
        raw_request = {
            "messages": [
                {"role": "user", "content": "password is decoy_db_password_123"},
            ],
            "model": "fake-model",
        }
        req_stage = on_llm_request(request=raw_request)["request"]

        def next_call(redacted_request):
            data = json.dumps(redacted_request).encode("utf-8")
            req = request.Request(
                f"{provider.base_url}/chat/completions",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode("utf-8"))

        _ = on_llm_execution(request=req_stage, next_call=next_call)
        captured = provider.chat_completion_bodies
        assert len(captured) == 1
        body = captured[0].decode("utf-8")
        assert "decoy_db_password_123" not in body
        assert DECOY_TOKEN in body
    finally:
        provider.stop()
