"""
tests/test_correlation_pipeline.py
----------------------------------
Tests for the Phase 5 correlation engine (correlation/).

Two layers:
  1. Matching logic — event-time comparison, nearest-preceding, tier and
     group semantics, severity ranking.
  2. Full incident lifecycle through the REAL pipeline (load -> match ->
     build -> save/merge/archive), against hand-built alerts written to
     a tmp_path alerts.json. Never touches the real reports/ directory.

Identity resolution runs for real: fixture users are taken from the
machine's actual /etc/passwd (the current user plus one other), so these
tests behave the same on your EC2 box, a laptop, and CI runners.
"""

import json
import os
import pwd
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from schemas import Alert, ATTCKTechnique, Severity, LogSource

import correlation.identity as identity
import correlation.loader as loader
import correlation.matching as matching
import correlation.storage as storage
from correlation.incident import build_all_incidents
from correlation.matching import (
    build_indices,
    find_nearest_preceding_match,
    highest_severity,
    run_correlation,
)

NOW = datetime.now(timezone.utc)

RULE_001 = "rule_001_ssh_brute_force"
RULE_003 = "rule_003_new_user_created"
RULE_007 = "rule_007_brute_force_success"
RULE_008 = "rule_008_cron_persistence"


# ── helpers ─────────────────────────────────────────────────────────────────

def minutes_ago(m: float) -> datetime:
    return NOW - timedelta(minutes=m)


def pick_users():
    """(uid, name) for the current user and for a different real user."""
    uid_a = os.getuid()
    name_a = pwd.getpwuid(uid_a).pw_name
    for entry in pwd.getpwall():
        if entry.pw_uid != uid_a:
            return (uid_a, name_a), (entry.pw_uid, entry.pw_name)
    pytest.skip("need at least two distinct users in /etc/passwd")


def mk(rule_id, technique=ATTCKTechnique.T1053_003, severity=Severity.HIGH,
       log_source=LogSource.AUDITD, description="synthetic", dedup_key=None,
       first_seen=None, last_seen=None, username=None, auid=None, source_ip=None):
    # `timestamp` is alert-GENERATION time. Every alert here is "generated
    # in the same engine run" (NOW) no matter when its event happened —
    # the real-world situation that broke generation-time correlation.
    return Alert(
        rule_id=rule_id, technique=technique, severity=severity,
        timestamp=NOW, first_seen=first_seen, last_seen=last_seen,
        username=username, auid=auid, source_ip=source_ip,
        dedup_key=dedup_key or f"{rule_id}:{first_seen}:{last_seen}:{username}:{auid}",
        log_source=log_source, description=description,
    )


def breach(username, ended_min_ago, started_min_ago=None, ip="203.0.113.7"):
    return mk(
        RULE_007, ATTCKTechnique.T1110_001, Severity.CRITICAL, LogSource.AUTH_LOG,
        f"Brute force SUCCESS — failures from {ip} followed by login as '{username}'",
        dedup_key=f"{ip}:{username}",
        first_seen=minutes_ago(started_min_ago or ended_min_ago + 5),
        last_seen=minutes_ago(ended_min_ago), username=username, source_ip=ip,
    )


def cron_edit(uid, started_min_ago, path="/etc/cron.d/backdoor", exe="/usr/bin/bash"):
    return mk(
        RULE_008, ATTCKTechnique.T1053_003, Severity.HIGH, LogSource.AUDITD,
        f"Cron file modified: {path} by {exe} (auid={uid}, euid=0)",
        dedup_key=f"{exe}:{uid}:{path}",
        first_seen=minutes_ago(started_min_ago), auid=uid,
    )


@pytest.fixture(autouse=True)
def isolate_error_logs(tmp_path, monkeypatch):
    """Failed-lookup / parse-error logging must never write into the repo."""
    log = str(tmp_path / "correlation_errors.log")
    monkeypatch.setattr(identity, "ERROR_LOG_PATH", log)
    monkeypatch.setattr(loader, "ERROR_LOG_PATH", log)
    monkeypatch.setattr(storage, "ERROR_LOG_PATH", log)


# ── 1. matching logic ───────────────────────────────────────────────────────

def test_highest_severity_ranks_by_severity_not_alphabetically():
    # Severity is a str Enum: naive max() would call HIGH "greater" than
    # CRITICAL alphabetically. This is the exact trap the ranking avoids.
    assert highest_severity([Severity.CRITICAL, Severity.HIGH]) == Severity.CRITICAL
    assert highest_severity([Severity.MEDIUM, Severity.LOW, Severity.INFO]) == Severity.MEDIUM
    assert highest_severity([Severity.HIGH]) == Severity.HIGH


def test_nearest_preceding_picks_closest_and_ignores_out_of_window():
    (uid, user), _ = pick_users()
    anchor = cron_edit(uid, started_min_ago=0)
    near = breach(user, ended_min_ago=40)
    too_old = breach(user, ended_min_ago=180, ip="198.51.100.1")

    index, _, cache = build_indices([anchor, near, too_old])
    match = find_nearest_preceding_match(anchor, RULE_007, index, cache)

    assert match is not None
    assert match.dedup_key == near.dedup_key


def test_unresolvable_identity_returns_none():
    anchor = cron_edit(uid=999999, started_min_ago=0)
    index, _, cache = build_indices([anchor])

    assert find_nearest_preceding_match(anchor, RULE_007, index, cache) is None


def test_matching_uses_event_time_not_generation_time():
    (uid, user), _ = pick_users()
    anchor = cron_edit(uid, started_min_ago=30)
    # generated in the same run as the anchor, but its EVENT ended 20 min
    # before the anchor began
    true_breach = breach(user, ended_min_ago=50, ip="203.0.113.7")
    # generated "just now" too, but the event was 4h+ before the anchor
    stale = breach(user, ended_min_ago=270, ip="198.51.100.9")

    index, _, cache = build_indices([anchor, true_breach, stale])
    match = find_nearest_preceding_match(anchor, RULE_007, index, cache)

    assert match is not None, "generation-time comparison would reject this"
    assert match.last_seen == true_breach.last_seen


def test_first_tier_wins_within_a_group():
    (uid, user), _ = pick_users()
    anchor = cron_edit(uid, started_min_ago=20)
    weak = mk(RULE_001, ATTCKTechnique.T1110_001, Severity.HIGH, LogSource.AUTH_LOG,
              "failed attempts", dedup_key="fx-001",
              first_seen=minutes_ago(75), last_seen=minutes_ago(74), username=user)
    strong = breach(user, ended_min_ago=40)

    results = run_correlation([anchor, weak, strong])

    assert len(results) == 1
    assert len(results[0].group_matches) == 1
    assert results[0].group_matches[0].candidate_rule_id == RULE_007
    assert results[0].group_matches[0].severity == Severity.CRITICAL


def test_independent_groups_are_combined_into_one_anchor_match(monkeypatch):
    (uid, user), _ = pick_users()
    monkeypatch.setattr(matching, "CORRELATION_RULES", {
        RULE_008: [
            [(RULE_007, Severity.CRITICAL), (RULE_001, Severity.MEDIUM)],
            [(RULE_003, Severity.HIGH)],
        ],
    })
    anchor = cron_edit(uid, started_min_ago=15)
    new_user = mk(RULE_003, ATTCKTechnique.T1136_001, Severity.HIGH, LogSource.AUTH_LOG,
                  "New user created", dedup_key="fx-003",
                  first_seen=minutes_ago(30), username=user)

    results = run_correlation([anchor, breach(user, ended_min_ago=40), new_user])

    assert len(results) == 1
    assert {gm.candidate_rule_id for gm in results[0].group_matches} == {RULE_007, RULE_003}


# ── 2. full incident lifecycle through the real pipeline ────────────────────

class Pipeline:
    """Drives load -> match -> build -> save against tmp files."""

    def __init__(self, tmp_path):
        self.alerts = tmp_path / "alerts.json"
        self.active_path = tmp_path / "correlated_alerts.json"
        self.archive_path = tmp_path / "archive.json"

    def write_alerts(self, alerts):
        self.alerts.write_text(json.dumps(
            [a.model_dump(mode="json") for a in alerts], indent=2, default=str))

    def run(self):
        incidents = build_all_incidents(run_correlation(loader.load_alerts()))
        storage.save_incidents(incidents)
        return incidents

    def _read(self, path):
        return json.loads(path.read_text()) if path.exists() else []

    def active(self):
        return self._read(self.active_path)

    def archive(self):
        return self._read(self.archive_path)

    def write_active(self, data):
        self.active_path.write_text(json.dumps(data, indent=2))


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    p = Pipeline(tmp_path)
    monkeypatch.setattr(loader, "ALERTS_PATH", str(p.alerts))
    monkeypatch.setattr(storage, "CORRELATED_ALERTS_PATH", str(p.active_path))
    monkeypatch.setattr(storage, "ARCHIVE_PATH", str(p.archive_path))

    (uid_a, user_a), (uid_b, user_b) = pick_users()
    p.write_alerts([
        # A: really breached, then planted a cron job 20 min after the breach ended
        breach(user_a, ended_min_ago=40, started_min_ago=75),
        cron_edit(uid_a, started_min_ago=20),
        # B: edits cron, but their only breach is 5h old -> outside the window
        breach(user_b, ended_min_ago=300, ip="198.51.100.9"),
        cron_edit(uid_b, started_min_ago=10, path="/etc/cron.d/routine", exe="/usr/bin/vim"),
        # noise: no identity at all, not a configured anchor
        mk("rule_012_account_enumeration", ATTCKTechnique.T1087_001, Severity.HIGH,
           LogSource.AUDITD, "enumeration, identity unknown", dedup_key="fx-012",
           first_seen=minutes_ago(30)),
    ])
    return p


def close_and_backdate(pipeline, hours_ago):
    """Flip only `closed` like a UI would, run once so closed_at gets
    stamped, then backdate closed_at."""
    active = pipeline.active()
    active[0]["closed"] = True
    pipeline.write_active(active)
    pipeline.run()
    active = pipeline.active()
    active[0]["closed_at"] = (NOW - timedelta(hours=hours_ago)).isoformat()
    pipeline.write_active(active)


def test_first_run_builds_exactly_one_correct_incident(pipeline):
    incidents = pipeline.run()

    assert len(incidents) == 1, "only user A matches; user B's breach is stale"
    inc = pipeline.active()[0]
    assert inc["severity"] == "CRITICAL"
    assert inc["severity_modified"] is True
    assert inc["chain"][0].startswith(RULE_007)
    assert inc["chain"][1].startswith(RULE_008)
    assert len(inc["chain"]) == 2
    assert "20 min later" in inc["info"]  # gap measured in event time
    assert inc["closed"] is False


def test_rerun_is_idempotent_and_preserves_created_at(pipeline):
    pipeline.run()
    created = pipeline.active()[0]["created_at"]

    pipeline.run()

    assert len(pipeline.active()) == 1
    assert pipeline.active()[0]["created_at"] == created


def test_closed_incident_is_not_resurrected_and_gets_closed_at(pipeline):
    pipeline.run()
    active = pipeline.active()
    active[0]["closed"] = True
    pipeline.write_active(active)

    pipeline.run()

    active = pipeline.active()
    assert len(active) == 1 and active[0]["closed"] is True
    assert active[0]["closed_at"] is not None, "without closed_at it can never archive"


def test_closed_incident_archives_after_delay(pipeline):
    pipeline.run()
    close_and_backdate(pipeline, hours_ago=3)  # delay is 2h

    pipeline.run()

    assert pipeline.active() == []
    assert len(pipeline.archive()) == 1


def test_recently_closed_incident_stays_active(pipeline):
    pipeline.run()
    close_and_backdate(pipeline, hours_ago=0.5)

    pipeline.run()

    assert len(pipeline.active()) == 1
    assert pipeline.archive() == []


def test_archived_incident_is_not_recreated(pipeline):
    pipeline.run()
    close_and_backdate(pipeline, hours_ago=3)
    pipeline.run()  # archives it

    pipeline.run()  # alerts.json still holds the breach + cron alerts

    assert pipeline.active() == [], "archived incident re-created as a fresh open one"
    assert len(pipeline.archive()) == 1