"""README local-ZIP install blocks must fail closed."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
EXPECTED_SHA256 = "d6ee2bf6a92a4ca55ee37f24802cf26316ab38adcbe27b9d59a4ee9e944ae265"


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def test_readme_zip_hash_gate_is_automatic_and_fail_closed():
    text = _readme()
    assert f'EXPECTED_SHA256="{EXPECTED_SHA256}"' in text
    assert 'ACTUAL_SHA256="$(shasum -a 256 "$PLUGIN_ZIP"' in text
    assert 'if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then' in text
    assert 'exit 1' in text


def test_readme_zip_install_blocks_enable_errexit_and_validate_installed_root():
    text = _readme()
    assert text.count("set -euo pipefail") >= 3
    assert 'test ! -e "$PLUGIN_DIR"' in text
    assert 'test -f "$PLUGIN_DIR/plugin.yaml"' in text
    assert "grep -qx 'version: 0.4.4' \"$PLUGIN_DIR/plugin.yaml\"" in text
    assert 'test ! -e "$PLUGIN_DIR/credential-guard"' in text


def test_readme_all_multi_command_lifecycle_blocks_enable_errexit():
    text = _readme()
    for marker in ("ONLINE_INSTALL_OK", "PLUGIN_ENABLE_OK", "PLUGIN_UPDATE_OK"):
        marker_index = text.index(marker)
        block_start = text.rfind("```bash", 0, marker_index)
        block_end = text.index("```", marker_index)
        block = text[block_start:block_end]
        assert "set -euo pipefail" in block, marker


def test_readme_upgrade_moves_before_copy_and_checks_backup_exists():
    text = _readme()
    upgrade_start = text.index('BACKUP_DIR="$PROFILE_ROOT/plugins/credential-guard.backup-')
    upgrade_end = text.index("```", upgrade_start)
    block = text[upgrade_start:upgrade_end]
    assert block.index('mv "$PLUGIN_DIR" "$BACKUP_DIR"') < block.index(
        'cp -R "$STAGE_DIR/credential-guard" "$PLUGIN_DIR"'
    )
    assert 'test -d "$BACKUP_DIR"' in block
    assert 'test ! -e "$PLUGIN_DIR"' in block
