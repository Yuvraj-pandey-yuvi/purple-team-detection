# tests/test_rule_018_collector_heartbeat.py
# A log source that goes silent must raise an alert, once per outage, and close it.
import json
from datetime import datetime, timedelta, timezone

from detection import engine
from logs import log_collector
from rules.rule_018_collector_heartbeat import detect as detect_silence, RULE_ID
from schemas import Alert, ATTCKTechnique, LogSource, Severity

START = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
HEALTHY = {"auth_log": 5, "auditd": 300, "cowrie": 2, "cloudtrail": 1}
SILENT = {"auth_log": 0, "auditd": 0, "cowrie": 0, "cloudtrail": 0}


def at(minutes):
    return START + timedelta(minutes=minutes)


def cycle(received, state, minutes):
    return detect_silence(received, state, at(minutes))


def sources_of(alerts):
    return sorted(alert.extra["source"] for alert in alerts)


def test_first_run_without_input_does_not_alert_yet():
    alerts, state = cycle(SILENT, {}, 0)
    assert alerts == []
    assert state["auth_log"]["watching_since"] == at(0).isoformat()


def test_regular_input_never_alerts_and_is_recorded():
    state = {}
    for minute in range(0, 180, 5):
        alerts, state = cycle(HEALTHY, state, minute)
        assert alerts == []
    assert state["auth_log"]["last_input"] == at(175).isoformat()


def test_silence_shorter_than_the_limit_is_quiet():
    _, state = cycle(HEALTHY, {}, 0)
    alerts, _ = cycle(SILENT, state, 59)          # the auth_log limit is 60 minutes
    assert alerts == []


def test_silence_longer_than_the_limit_opens_an_alert_only_for_sources_past_their_limit():
    _, state = cycle(HEALTHY, {}, 0)
    alerts, _ = cycle(SILENT, state, 61)
    assert sources_of(alerts) == ["auditd", "auth_log"]    # cowrie and cloudtrail get 24 hours
    assert all(alert.extra["state"] == "open" for alert in alerts)


def test_alert_fields():
    _, state = cycle(HEALTHY, {}, 0)
    alerts, _ = cycle({**HEALTHY, "auth_log": 0}, state, 90)
    alert = alerts[0]
    assert alert.rule_id == RULE_ID == "rule_018_collector_heartbeat"
    assert alert.extra["source"] == "auth_log"
    assert alert.severity == Severity.HIGH
    assert alert.log_source == LogSource.AUTH_LOG
    assert alert.technique == ATTCKTechnique.T1562_001
    assert alert.first_seen == at(0)                       # the silence began at the last input
    assert alert.extra["silent_seconds"] == 90 * 60
    assert alert.dedup_key == f"auth_log|open|{at(0).isoformat()}"


def test_one_alert_per_outage_not_one_per_cycle():
    _, state = cycle(HEALTHY, {}, 0)
    first, state = cycle(SILENT, state, 61)
    second, state = cycle(SILENT, state, 66)
    third, _ = cycle(SILENT, state, 71)
    assert len(first) == 2
    assert second == []
    assert third == []


def test_input_resuming_closes_the_outage_once():
    _, state = cycle(HEALTHY, {}, 0)
    _, state = cycle(SILENT, state, 61)
    closed, state = cycle(HEALTHY, state, 70)
    assert sources_of(closed) == ["auditd", "auth_log"]
    assert all(alert.extra["state"] == "closed" for alert in closed)
    assert all(alert.severity == Severity.INFO for alert in closed)
    assert closed[0].extra["outage_seconds"] == 70 * 60
    again, _ = cycle(HEALTHY, state, 75)
    assert again == []


def test_a_later_outage_alerts_again():
    _, state = cycle(HEALTHY, {}, 0)
    _, state = cycle(SILENT, state, 61)
    _, state = cycle(HEALTHY, state, 70)
    alerts, _ = cycle(SILENT, state, 135)                  # 65 minutes after the input at 70
    assert sources_of(alerts) == ["auditd", "auth_log"]
    assert alerts[0].dedup_key == f"auth_log|open|{at(70).isoformat()}"


def test_sources_are_independent():
    _, state = cycle(HEALTHY, {}, 0)
    alerts, _ = cycle({**HEALTHY, "auditd": 0}, state, 61)
    assert sources_of(alerts) == ["auditd"]


def test_a_source_that_never_delivers_alerts_after_its_limit_not_at_once():
    cloudtrail_silent = {**HEALTHY, "cloudtrail": 0}
    alerts, state = cycle(cloudtrail_silent, {}, 0)
    assert alerts == []
    alerts, state = cycle(cloudtrail_silent, state, 24 * 60 - 5)
    assert alerts == []
    alerts, state = cycle(cloudtrail_silent, state, 24 * 60 + 5)
    assert sources_of(alerts) == ["cloudtrail"]
    assert alerts[0].technique == ATTCKTechnique.T1562_002


def test_unmonitored_sources_are_ignored():
    _, state = cycle({**HEALTHY, "falco": 0}, {}, 0)
    assert "falco" not in state


def test_the_previous_state_is_not_modified_in_place():
    _, state = cycle(HEALTHY, {}, 0)
    snapshot = {source: dict(entry) for source, entry in state.items()}
    cycle(SILENT, state, 61)
    assert state == snapshot


def test_run_heartbeat_keeps_its_state_between_engine_runs(tmp_path, monkeypatch):
    state_file = tmp_path / "state.json"
    monkeypatch.setattr(log_collector, "STATE_FILE", str(state_file))
    state_file.write_text('{"auth_log_position": 123}')
    engine.run_heartbeat(HEALTHY, now=at(0))
    alerts = engine.run_heartbeat(SILENT, now=at(61))
    assert sources_of(alerts) == ["auditd", "auth_log"]
    saved = json.loads(state_file.read_text())
    assert saved["auth_log_position"] == 123               # the collectors' positions survive
    assert "heartbeat" in saved


def test_heartbeat_alerts_are_kept_out_of_attack_coverage():
    _, state = cycle(HEALTHY, {}, 0)
    heartbeat_alerts, _ = cycle(SILENT, state, 61)
    real_alert = Alert(
        rule_id="rule_010_auditd_disabled",
        technique=ATTCKTechnique.T1562_001,
        severity=Severity.HIGH,
        timestamp=at(0),
        description="auditd was switched off",
        log_source=LogSource.AUDITD,
    )
    assert engine.alerts_for_coverage(heartbeat_alerts + [real_alert]) == [real_alert]


def test_heartbeat_is_off_unless_the_engine_pod_switches_it_on():
    assert engine.HEARTBEAT_ENABLED is False
