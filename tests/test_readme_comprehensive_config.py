from __future__ import annotations

import json
import re
from pathlib import Path

from credential_guard.config import CredentialGuardConfig

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
START = "## 最全面的完整配置示例"
END = "## HTTP/HTTPS Bearer 示例"


def _section() -> str:
    text = README.read_text(encoding="utf-8")
    return text[text.index(START) : text.index(END)]


def _example() -> dict:
    section = _section()
    match = re.search(r"```json\n(.*?)\n```", section, re.DOTALL)
    assert match is not None, "comprehensive README JSON block missing"
    return json.loads(match.group(1))


def test_readme_comprehensive_config_is_schema_valid_and_canonicalizable():
    config = CredentialGuardConfig(_example())
    canonical = config.to_canonical_dict()
    assert canonical["version"] == 2
    assert set(canonical) == {"version", "credentials", "bindings"}


def test_readme_comprehensive_config_covers_every_supported_shape():
    config = _example()
    credentials = config["credentials"]
    bindings = config["bindings"]

    assert {entry["type"] for entry in credentials.values()} == {
        "token",
        "username_password",
    }
    assert {entry["type"] for entry in bindings.values()} == {
        "http",
        "process_env",
        "stdin",
    }

    http_bindings = [entry for entry in bindings.values() if entry["type"] == "http"]
    assert {entry["target"]["scheme"] for entry in http_bindings} == {"http", "https"}
    assert {entry["inject"]["type"] for entry in http_bindings} == {
        "bearer",
        "basic",
        "api_key_header",
    }

    for entry in http_bindings:
        assert set(entry["request"]) == {
            "allowed_methods",
            "allowed_paths",
            "connect_timeout_seconds",
            "total_timeout_seconds",
            "max_response_body_bytes",
        }

    stdin_bindings = [entry for entry in bindings.values() if entry["type"] == "stdin"]
    assert {entry["stdin_format"] for entry in stdin_bindings} == {"raw", "line"}

    process_env = {
        name: entry
        for name, entry in bindings.items()
        if entry["type"] == "process_env"
    }
    assert set(process_env) == {"service-status-check"}
    assert process_env["service-status-check"]["argv"] == [
        process_env["service-status-check"]["program"],
        "--status",
    ]

    for binding in bindings.values():
        if binding["type"] in {"process_env", "stdin"}:
            assert set(binding) == (
                {
                    "type",
                    "credential_ref",
                    "program",
                    "argv",
                    "env_name",
                    "timeout_seconds",
                    "max_stdout_bytes",
                    "max_stderr_bytes",
                    "approval",
                }
                if binding["type"] == "process_env"
                else {
                    "type",
                    "credential_ref",
                    "program",
                    "argv",
                    "stdin_format",
                    "timeout_seconds",
                    "max_stdout_bytes",
                    "max_stderr_bytes",
                    "approval",
                }
            )

    referenced = {entry["credential_ref"] for entry in bindings.values()}
    unreferenced = set(credentials) - referenced
    assert {credentials[name]["type"] for name in unreferenced} == {
        "token",
        "username_password",
    }


def test_readme_comprehensive_config_uses_only_safe_synthetic_material():
    section = _section()
    config = _example()

    for entry in config["credentials"].values():
        secret = entry["value"] if entry["type"] == "token" else entry["password"]
        assert secret.startswith("SYNTHETIC_")
        assert secret.endswith("_NOT_REAL")

    for binding in config["bindings"].values():
        if binding["type"] == "http":
            assert binding["target"]["host"].endswith(".test")
        else:
            assert binding["program"].startswith("/Users/example/")
            assert binding["argv"][0] == binding["program"]

    assert "[REDACTED]" not in section
    assert "***" not in section
    assert "`credential-guard check`" not in section
    assert 'hermes -p "$PROFILE" credential-guard check' in section
