from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
HERMES_PYTHON = Path("/Users/yelei/.hermes/hermes-agent/venv/bin/python")
HERMES_AGENT_ROOT = Path("/Users/yelei/.hermes/hermes-agent")


def _whitelist_env(home: Path, hermes_home: Path) -> dict[str, str]:
    path = os.environ.get("PATH", "/usr/bin:/bin")
    return {
        "HOME": str(home),
        "HERMES_HOME": str(hermes_home),
        "PATH": path,
        "LANG": os.environ.get("LANG", "C"),
        "LC_ALL": os.environ.get("LC_ALL", "C"),
        "TMPDIR": str(home / "tmp"),
        "NO_PROXY": "*",
        "no_proxy": "*",
        "PYTHONPATH": str(HERMES_AGENT_ROOT),
    }


def test_plugin_manager_loads_from_neutral_cwd_and_registers_all():
    """Real Hermes PluginManager load must work without repo root on sys.path."""
    assert HERMES_PYTHON.is_file(), "Hermes Python 3.11 runtime missing"

    with tempfile.TemporaryDirectory(prefix="cg-plugin-load-") as tmp:
        tmp_path = Path(tmp)
        home = tmp_path / "home"
        hermes_home = tmp_path / "hermes_home"
        neutral_cwd = tmp_path / "neutral_cwd"
        home.mkdir()
        hermes_home.mkdir()
        (home / "tmp").mkdir()
        neutral_cwd.mkdir()

        plugins_dir = hermes_home / "plugins"
        plugins_dir.mkdir()
        dest = plugins_dir / "credential-guard"
        shutil.copytree(
            PLUGIN_ROOT,
            dest,
            ignore=shutil.ignore_patterns(
                ".venv",
                ".pytest_cache",
                "__pycache__",
                "tests",
                "scripts",
                "docs",
                ".m0-m1-task.md",
                ".m0-m1-fix-task.md",
            ),
        )
        (hermes_home / "config.yaml").write_text(
            "plugins:\n  enabled:\n    - credential-guard\n",
            encoding="utf-8",
        )

        probe = r"""
import json
import os
import sys
from pathlib import Path

# Neutral cwd: repo must not be importable as top-level credential_guard.
cwd = Path.cwd().resolve()
sys.path = [p for p in sys.path if "hermes-credential-guard" not in p.replace("\\\\", "/")]

from hermes_cli.plugins import PluginManager

mgr = PluginManager()
mgr.discover_and_load()
loaded = mgr._plugins.get("credential-guard")
info = {
    "cwd": str(cwd),
    "enabled": bool(loaded and loaded.enabled),
    "error": getattr(loaded, "error", None) if loaded else "missing",
    "middleware": sorted(mgr._middleware.keys()),
    "hooks": sorted(mgr._hooks.keys()),
    "cli_commands": sorted(mgr._cli_commands.keys()),
    "top_level_credential_guard": "credential_guard" in sys.modules,
}
print(json.dumps(info))
"""
        result = subprocess.run(
            [str(HERMES_PYTHON), "-c", probe],
            cwd=str(neutral_cwd),
            env=_whitelist_env(home, hermes_home),
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, (
            f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
        )
        info = json.loads(result.stdout.strip().splitlines()[-1])
        assert info["enabled"] is True, info
        assert info["error"] in (None, ""), info
        assert "llm_request" in info["middleware"], info
        assert "llm_execution" in info["middleware"], info
        assert "transform_tool_result" in info["hooks"], info
        assert "credential-guard" in info["cli_commands"], info
        assert info["top_level_credential_guard"] is False, info
