from __future__ import annotations

from pathlib import Path

import pytest

from tests.hermes_e2e_helpers import (
    assert_worker_evidence,
    classify_worker_delta,
    content_fingerprint,
    temp_isolation_evidence,
)


def _fake_iso(tmp_path: Path):
    from tests.hermes_e2e_helpers import IsolatedHermes

    home = tmp_path / "home"
    hermes_home = tmp_path / "hermes_home"
    cwd = tmp_path / "cwd"
    tmp = tmp_path / "tmp"
    for p in (home, hermes_home, cwd, tmp):
        p.mkdir(parents=True, exist_ok=True)
    (hermes_home / "config.yaml").write_text("x: 1\n", encoding="utf-8")
    return IsolatedHermes(
        root=tmp_path,
        home=home,
        hermes_home=hermes_home,
        cwd=cwd,
        tmp=tmp,
        fixture_path=hermes_home / "f.yaml",
        net_audit_path=tmp / "net.json",
    )


def test_deterministic_unchanged_when_digest_identical(tmp_path):
    root = tmp_path / "worker"
    root.mkdir()
    (root / "config.yaml").write_text("a: 1\n", encoding="utf-8")
    (root / "logs").mkdir()
    (root / "logs" / "agent.log").write_text("same\n", encoding="utf-8")
    before = content_fingerprint(root)
    after = content_fingerprint(root)
    delta = classify_worker_delta(before, after, worker_live=False)
    assert delta["status"] == "unchanged"
    assert delta["stable"] is True
    assert delta["unchanged"] is True
    assert before["digest"] == after["digest"]


def test_assert_worker_evidence_rejects_changed(tmp_path):
    root = tmp_path / "worker"
    root.mkdir()
    (root / "config.yaml").write_text("a: 1\n", encoding="utf-8")
    before = content_fingerprint(root)
    (root / "config.yaml").write_text("a: 2\n", encoding="utf-8")
    after = content_fingerprint(root)
    delta = classify_worker_delta(before, after, worker_live=False)
    assert delta["status"] == "changed"
    iso = _fake_iso(tmp_path / "iso")
    isolation = temp_isolation_evidence(iso)
    with pytest.raises(AssertionError):
        assert_worker_evidence(delta, isolation)


def test_assert_worker_evidence_allows_inconclusive_but_not_unchanged(tmp_path):
    root = tmp_path / "worker"
    root.mkdir()
    (root / "state.db-wal").write_bytes(b"aaa")
    (root / "config.yaml").write_text("a: 1\n", encoding="utf-8")
    before = content_fingerprint(root)
    (root / "state.db-wal").write_bytes(b"bbb")
    after = content_fingerprint(root)
    delta = classify_worker_delta(before, after, worker_live=True)
    assert delta["status"] == "inconclusive_live_noise"
    assert delta["stable"] is False
    assert delta["unchanged"] is False
    iso = _fake_iso(tmp_path / "iso")
    isolation = temp_isolation_evidence(iso)
    # Continues (no raise) but must not claim unchanged.
    assert_worker_evidence(delta, isolation)
    assert delta["unchanged"] is False
    assert delta["stable"] is False


def test_assert_worker_evidence_requires_temp_isolation(tmp_path):
    root = tmp_path / "worker"
    root.mkdir()
    (root / "config.yaml").write_text("a: 1\n", encoding="utf-8")
    fp = content_fingerprint(root)
    delta = classify_worker_delta(fp, fp, worker_live=False)
    assert delta["status"] == "unchanged"
    with pytest.raises(AssertionError):
        assert_worker_evidence(delta, {"all_temp": False})


def test_log_or_wal_change_is_changed_when_worker_idle(tmp_path):
    root = tmp_path / "worker"
    (root / "logs").mkdir(parents=True)
    (root / "logs" / "agent.log").write_text("before\n", encoding="utf-8")
    (root / "config.yaml").write_text("a: 1\n", encoding="utf-8")
    before = content_fingerprint(root)
    (root / "logs" / "agent.log").write_text("after\n", encoding="utf-8")
    after = content_fingerprint(root)
    delta = classify_worker_delta(before, after, worker_live=False)
    assert delta["status"] == "changed"
    assert delta["stable"] is False
    assert delta["unchanged"] is False


def test_wal_change_inconclusive_only_when_worker_live(tmp_path):
    root = tmp_path / "worker"
    root.mkdir()
    (root / "state.db-wal").write_bytes(b"aaa")
    (root / "config.yaml").write_text("a: 1\n", encoding="utf-8")
    before = content_fingerprint(root)
    (root / "state.db-wal").write_bytes(b"bbb")
    after = content_fingerprint(root)
    live = classify_worker_delta(before, after, worker_live=True)
    assert live["status"] == "inconclusive_live_noise"
    assert live["stable"] is False
    assert live["config_plugins_sessions_unchanged"] is True
    idle = classify_worker_delta(before, after, worker_live=False)
    assert idle["status"] == "changed"


def test_config_change_always_changed_even_if_live(tmp_path):
    root = tmp_path / "worker"
    root.mkdir()
    (root / "config.yaml").write_text("a: 1\n", encoding="utf-8")
    before = content_fingerprint(root)
    (root / "config.yaml").write_text("a: 2\n", encoding="utf-8")
    after = content_fingerprint(root)
    delta = classify_worker_delta(before, after, worker_live=True)
    assert delta["status"] == "changed"
    assert delta["config_plugins_sessions_unchanged"] is False


def test_symlink_fingerprinted_by_identity_not_target(tmp_path):
    root = tmp_path / "worker"
    (root / "logs").mkdir(parents=True)
    target = tmp_path / "outside_secret.txt"
    target.write_text("do-not-follow\n", encoding="utf-8")
    link = root / "logs" / "agent.log"
    link.symlink_to(target)
    fp = content_fingerprint(root)
    entry = next(e for e in fp["files"] if e["path"] == "logs/agent.log")
    assert entry["is_symlink"] is True
    assert entry["link_target"] == str(target)
    # Content of referent must not appear as fingerprint material beyond link path.
    assert "do-not-follow" not in str(fp)


def test_temp_isolation_evidence(tmp_path):
    iso = _fake_iso(tmp_path)
    evidence = temp_isolation_evidence(iso)
    assert evidence["all_temp"] is True
    assert evidence["config_under_temp_hermes_home"] is True
