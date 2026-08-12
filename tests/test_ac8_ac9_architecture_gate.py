from __future__ import annotations

"""Architecture-gate tests for AC8/AC9.

Split into independent strict-xfail gates so AC8 failure cannot mask AC9
(and vice versa). Each asserts decoy count == 0 for its own persistence
surface. Do not weaken assertions or exclude paths to force green.
"""

import pytest

from tests.fake_provider import FakeProvider
from tests.hermes_e2e_helpers import (
    DECOY_SECRET,
    prepare_isolated_hermes,
    count_decoy_in_paths,
    run_hermes,
)


def _run_chat_and_split(tmp_path):
    provider = FakeProvider()
    provider.start()
    try:
        iso = prepare_isolated_hermes(tmp_path, provider.base_url)
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
        assert result.returncode == 0, result.stdout + result.stderr
        split = count_decoy_in_paths(
            iso.hermes_home,
            DECOY_SECRET,
            [
                "logs/agent.log",
                "state.db",
                "state.db-wal",
                "state.db-shm",
                "sessions",
            ],
        )
        return split
    finally:
        provider.stop()


@pytest.mark.architecture_gate
@pytest.mark.xfail(
    strict=True,
    reason=(
        "AC8: Hermes v0.19.0 has no unified fail-closed pre-log seam covering "
        "CLI/Gateway/ACP/TUI/cron/subagent; agent.log may retain decoy plaintext. "
        "Gate keeps zero-plaintext red until the user chooses local-trust vs core patch."
    ),
)
def test_ac8_agent_log_must_be_zero_plaintext(tmp_path):
    split = _run_chat_and_split(tmp_path)
    assert split["logs/agent.log"]["exists"] is True
    log_count = split["logs/agent.log"]["count"]
    # Record real count in assertion message for the acceptance report.
    assert log_count == 0, f"AC8 agent.log decoy count={log_count}; split={split}"


@pytest.mark.architecture_gate
@pytest.mark.xfail(
    strict=True,
    reason=(
        "AC9: Hermes v0.19.0 has no unified fail-closed pre-persist seam; "
        "state.db / WAL / sessions may retain decoy plaintext. Gate keeps "
        "zero-plaintext red until the user chooses local-trust vs core patch."
    ),
)
def test_ac9_state_and_sessions_must_be_zero_plaintext(tmp_path):
    split = _run_chat_and_split(tmp_path)
    assert (
        split["state.db"]["exists"]
        or split["state.db-wal"]["exists"]
        or split["sessions"]["exists"]
    ), split
    wal_count = split["state.db-wal"]["count"]
    db_count = split["state.db"]["count"]
    sessions_count = split["sessions"]["count"]
    total = wal_count + db_count + sessions_count
    assert total == 0, (
        f"AC9 state/sessions decoy total={total} "
        f"(db={db_count}, wal={wal_count}, sessions={sessions_count}); split={split}"
    )
