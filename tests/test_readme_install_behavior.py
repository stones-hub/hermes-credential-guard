from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"


def _blocks() -> list[str]:
    text = README.read_text(encoding="utf-8")
    return re.findall(r"```bash\n(.*?)\n```", text, re.S)


def _block_with(marker: str) -> str:
    matches = [block for block in _blocks() if marker in block]
    assert len(matches) == 1, marker
    return matches[0]


def _run(block: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/bash", "-c", block],
        text=True,
        capture_output=True,
        env=env,
        cwd=ROOT,
        timeout=30,
    )


def _base_env(tmp: Path) -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "PROFILE": "default",
            "PLUGIN_ZIP": str(ROOT / "dist/credential-guard-0.4.4-hermes-plugin.zip"),
            "CONFIG_PATH": str(tmp / "profile/config.yaml"),
            "PROFILE_ROOT": str(tmp / "profile"),
            "PLUGIN_DIR": str(tmp / "profile/plugins/credential-guard"),
            "STAGE_DIR": str(tmp / "stage"),
        }
    )
    return env


def _fake_hermes(tmp: Path) -> Path:
    fake_bin = tmp / "bin"
    fake_bin.mkdir()
    hermes = fake_bin / "hermes"
    hermes.write_text(
        """#!/bin/bash
set -u
printf '%s\n' "$*" >> "$HERMES_CALL_LOG"
match="${HERMES_FAIL_MATCH:-}"
if [ -n "$match" ] && [[ "$*" == *"$match"* ]]; then
  exit "${HERMES_FAIL_CODE:-29}"
fi
exit 0
""",
        encoding="utf-8",
    )
    hermes.chmod(0o755)
    return fake_bin


def _run_hermes_block(block: str, tmp: Path, *, fail_match: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    fake_bin = _fake_hermes(tmp)
    log = tmp / "hermes-calls.log"
    env = _base_env(tmp)
    env.update(
        {
            "PATH": f"{fake_bin}:{env['PATH']}",
            "HERMES_CALL_LOG": str(log),
            "HERMES_FAIL_MATCH": fail_match,
            "HERMES_FAIL_CODE": "29",
        }
    )
    result = _run(block, env)
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return result, calls


def test_online_install_block_stops_after_install_failure():
    block = _block_with("ONLINE_INSTALL_OK")
    with tempfile.TemporaryDirectory() as raw:
        result, calls = _run_hermes_block(
            block,
            Path(raw),
            fail_match="plugins install",
        )
        assert result.returncode == 29
        assert "ONLINE_INSTALL_OK" not in result.stdout
        assert len(calls) == 1
        assert "plugins install" in calls[0]


def test_enable_block_stops_after_plugin_enable_failure():
    block = _block_with("PLUGIN_ENABLE_OK")
    with tempfile.TemporaryDirectory() as raw:
        result, calls = _run_hermes_block(
            block,
            Path(raw),
            fail_match="plugins enable",
        )
        assert result.returncode == 29
        assert "PLUGIN_ENABLE_OK" not in result.stdout
        assert len(calls) == 1
        assert "plugins enable" in calls[0]


def test_online_update_block_does_not_restart_after_update_failure():
    block = _block_with("PLUGIN_UPDATE_OK")
    with tempfile.TemporaryDirectory() as raw:
        result, calls = _run_hermes_block(
            block,
            Path(raw),
            fail_match="plugins update",
        )
        assert result.returncode == 29
        assert "PLUGIN_UPDATE_OK" not in result.stdout
        assert len(calls) == 1
        assert "plugins update" in calls[0]
        assert not any("gateway restart" in call for call in calls)


def test_hash_block_rejects_wrong_zip_before_success_marker():
    block = _block_with("EXPECTED_SHA256=")
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        wrong = tmp / "wrong.zip"
        wrong.write_bytes(b"not-the-release")
        env = _base_env(tmp)
        # Preserve the README assignments while replacing only the example path.
        block = block.replace(
            'PLUGIN_ZIP="/path/to/credential-guard-0.4.4-hermes-plugin.zip"',
            f'PLUGIN_ZIP="{wrong}"',
        )
        result = _run(block, env)
        assert result.returncode != 0
        assert "ZIP_SHA256_OK" not in result.stdout
        assert "SHA-256 不匹配" in result.stdout


def test_hash_block_accepts_designated_zip():
    block = _block_with("EXPECTED_SHA256=")
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        release = ROOT / "dist/credential-guard-0.4.4-hermes-plugin.zip"
        block = block.replace(
            'PLUGIN_ZIP="/path/to/credential-guard-0.4.4-hermes-plugin.zip"',
            f'PLUGIN_ZIP="{release}"',
        )
        result = _run(block, _base_env(tmp))
        assert result.returncode == 0, result.stderr
        assert "ZIP_SHA256_OK" in result.stdout


def test_structure_block_validates_designated_zip():
    block = _block_with("ZIP_STRUCTURE_OK")
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        env = _base_env(tmp)
        result = _run(block, env)
        assert result.returncode == 0, result.stderr
        assert "ZIP_STRUCTURE_OK" in result.stdout
        assert (tmp / "stage/credential-guard/plugin.yaml").is_file()
        assert not (tmp / "stage/credential-guard/credential-guard").exists()


def test_fresh_install_block_installs_exact_plugin_root():
    block = _block_with("PLUGIN_INSTALL_OK")
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        stage_plugin = tmp / "stage/credential-guard"
        stage_plugin.mkdir(parents=True)
        (stage_plugin / "plugin.yaml").write_text("version: 0.4.4\n", encoding="utf-8")
        (stage_plugin / "__init__.py").write_text("", encoding="utf-8")
        env = _base_env(tmp)
        result = _run(block, env)
        assert result.returncode == 0, result.stderr
        assert "PLUGIN_INSTALL_OK" in result.stdout
        plugin = tmp / "profile/plugins/credential-guard"
        assert (plugin / "plugin.yaml").read_text(encoding="utf-8") == "version: 0.4.4\n"
        assert not (plugin / "credential-guard").exists()


def test_upgrade_block_stops_when_backup_move_fails():
    block = _block_with("PLUGIN_UPGRADE_OK")
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        stage_plugin = tmp / "stage/credential-guard"
        stage_plugin.mkdir(parents=True)
        (stage_plugin / "plugin.yaml").write_text("version: 0.4.4\n", encoding="utf-8")
        (stage_plugin / "__init__.py").write_text("", encoding="utf-8")

        old_plugin = tmp / "profile/plugins/credential-guard"
        old_plugin.mkdir(parents=True)
        (old_plugin / "plugin.yaml").write_text("version: 0.4.2\n", encoding="utf-8")

        fake_bin = tmp / "bin"
        fake_bin.mkdir()
        hermes = fake_bin / "hermes"
        hermes.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
        hermes.chmod(0o755)
        mv = fake_bin / "mv"
        mv.write_text("#!/bin/bash\nexit 23\n", encoding="utf-8")
        mv.chmod(0o755)

        env = _base_env(tmp)
        env["PATH"] = f"{fake_bin}:{env['PATH']}"
        result = _run(block, env)
        assert result.returncode == 23
        assert "PLUGIN_UPGRADE_OK" not in result.stdout
        assert (old_plugin / "plugin.yaml").read_text(encoding="utf-8") == "version: 0.4.2\n"
        assert not (old_plugin / "credential-guard").exists()


def test_upgrade_block_replaces_root_without_nested_plugin():
    block = _block_with("PLUGIN_UPGRADE_OK")
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        stage_plugin = tmp / "stage/credential-guard"
        stage_plugin.mkdir(parents=True)
        (stage_plugin / "plugin.yaml").write_text("version: 0.4.4\n", encoding="utf-8")
        (stage_plugin / "__init__.py").write_text("", encoding="utf-8")

        old_plugin = tmp / "profile/plugins/credential-guard"
        old_plugin.mkdir(parents=True)
        (old_plugin / "plugin.yaml").write_text("version: 0.4.2\n", encoding="utf-8")

        fake_bin = tmp / "bin"
        fake_bin.mkdir()
        hermes = fake_bin / "hermes"
        hermes.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
        hermes.chmod(0o755)

        env = _base_env(tmp)
        env["PATH"] = f"{fake_bin}:{env['PATH']}"
        result = _run(block, env)
        assert result.returncode == 0, result.stderr
        assert "PLUGIN_UPGRADE_OK" in result.stdout
        assert (old_plugin / "plugin.yaml").read_text(encoding="utf-8") == "version: 0.4.4\n"
        assert not (old_plugin / "credential-guard").exists()
        backups = list((tmp / "profile/plugins").glob("credential-guard.backup-*"))
        assert len(backups) == 1
        assert (backups[0] / "plugin.yaml").read_text(encoding="utf-8") == "version: 0.4.2\n"
