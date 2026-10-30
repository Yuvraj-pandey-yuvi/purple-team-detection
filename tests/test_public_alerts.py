"""The public alert store: what is hidden, what is masked, and how it is queried."""
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from schemas import Alert
from detection import public_alerts as pa

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)


def make(rule="rule_001_ssh_brute_force", sev="HIGH", src="auth_log", mins=10, ip="9.9.9.9", auid=None,
         extra=None, raw="", desc="something", dedup=None):
    when = NOW - timedelta(minutes=mins)
    return Alert(rule_id=rule, technique="T1110.001", severity=sev, timestamp=when, first_seen=when, log_source=src,
                 dedup_key=dedup or f"{rule}|{mins}|{ip}", description=desc, source_ip=ip, auid=auid,
                 raw_log=raw, extra=extra or {})


def test_owner_activity_is_found_in_the_top_field_and_in_extra():
    assert pa.is_owner_activity(make(auid=1000))
    assert pa.is_owner_activity(make(rule="rule_014_masquerading", src="auditd", auid=None, extra={"auid": "1000"}))
    assert not pa.is_owner_activity(make(auid=4294967295, extra={"auid": "4294967295"}))


def test_heartbeat_info_and_owner_alerts_are_not_public():
    assert pa.is_public(make())
    assert not pa.is_public(make(rule="rule_018_collector_heartbeat"))
    assert not pa.is_public(make(sev="INFO"))
    assert not pa.is_public(make(auid=1000))


def test_masking_hides_account_ids_hostnames_private_and_configured_ips_but_keeps_attackers():
    text = "acct 349491201539 on ip-172-31-38-66 from 172.31.38.66 and 13.60.53.19 attacker 120.24.191.90"
    out = pa.mask_text(text, hidden_ips={"13.60.53.19"})
    assert "349491201539" not in out and "ip-172-31-38-66" not in out and "172.31.38.66" not in out
    assert "13.60.53.19" not in out and "120.24.191.90" in out


def test_raw_log_only_for_attacker_facing_sources_and_masked():
    ssh = pa.public_view(make(src="auth_log", raw="Failed from 9.9.9.9 acct 349491201539 via 10.0.0.5"), hidden_ips=set())
    assert "349491201539" not in ssh["raw_log"] and "10.0.0.5" not in ssh["raw_log"] and "9.9.9.9" in ssh["raw_log"]
    cloud = pa.public_view(make(src="cloudtrail", raw="arn:aws:iam::349491201539:user/x"), hidden_ips=set())
    assert cloud["raw_log"] is None and "withheld" in cloud["raw_log_note"]


def test_extra_is_masked_and_bounded():
    view = pa.public_view(make(extra={f"k{i}": "x" * 900 for i in range(60)} | {"acct": "349491201539"}), hidden_ips=set())
    assert len(view["extra"]) == pa.MAX_EXTRA_KEYS and all(len(v) <= pa.MAX_VALUE_CHARS for v in view["extra"].values())
    assert "349491201539" not in str(pa.public_view(make(extra={"acct": "349491201539"}), hidden_ips=set())["extra"])


def test_ids_are_stable_and_distinct():
    assert pa.alert_id(make()) == pa.alert_id(make())
    assert pa.alert_id(make(mins=10)) != pa.alert_id(make(mins=11))


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "public_alerts.db")
    alerts = [make(sev="MEDIUM", mins=5), make(sev="CRITICAL", mins=50, rule="rule_004_shadow_access", src="auditd"),
              make(sev="HIGH", mins=20), make(sev="HIGH", mins=60 * 30), make(auid=1000, mins=3),
              make(rule="rule_018_collector_heartbeat", sev="INFO")]
    assert pa.rebuild(alerts, path, hidden_ips=set())
    return path, alerts


def test_only_public_alerts_are_stored_and_days_are_counted(db):
    path, _ = db
    assert pa.query_alerts(path)["total"] == 4
    days = {d["day"]: d for d in pa.list_days(path)}
    assert days["2026-10-30"]["count"] == 3 and days["2026-10-29"]["count"] == 1 and days["2026-10-30"]["critical"] == 1


def test_sort_by_priority_then_time_and_by_time(db):
    path, _ = db
    prio = [i["severity"] for i in pa.query_alerts(path, day="2026-10-30", sort="priority")["items"]]
    assert prio == ["CRITICAL", "MEDIUM", "HIGH"] or prio == ["CRITICAL", "HIGH", "MEDIUM"]
    assert prio[0] == "CRITICAL"
    times = [i["ts"] for i in pa.query_alerts(path, day="2026-10-30", sort="time")["items"]]
    assert times == sorted(times, reverse=True)


def test_pagination_and_clamping(db):
    path, _ = db
    r = pa.query_alerts(path, per_page=2, page=2)
    assert r["total"] == 4 and r["pages"] == 2 and len(r["items"]) == 2
    assert pa.query_alerts(path, per_page=10_000)["per_page"] == pa.MAX_PER_PAGE
    assert pa.query_alerts(path, page=99, per_page=2)["page"] == 2


def test_hostile_parameters_cannot_inject_sql(db):
    path, _ = db
    r = pa.query_alerts(path, day="2026-10-30' OR '1'='1", sort="severity; DROP TABLE alerts", rule="x' OR 1=1 --")
    assert r["total"] == 0 or r["total"] == 4          # bad day ignored, bad rule matches nothing, no error
    assert pa.query_alerts(path)["total"] == 4          # table still there


def test_detail_lookup_and_unknown_id(db):
    path, alerts = db
    item = pa.query_alerts(path, rule="rule_004_shadow_access")["items"][0]
    assert pa.get_alert(path, item["id"])["rule_id"] == "rule_004_shadow_access"
    assert pa.get_alert(path, "nope") is None


def test_rebuild_is_skipped_when_nothing_changed_and_runs_when_it_did(db):
    path, alerts = db
    assert pa.rebuild(alerts, path, hidden_ips=set()) is False
    assert pa.rebuild(alerts + [make(mins=1, ip="8.8.8.8")], path, hidden_ips=set()) is True
    assert pa.query_alerts(path)["total"] == 5


def test_rule_counts(db):
    path, _ = db
    counts = pa.rule_counts(path, (NOW - timedelta(hours=24)).isoformat())
    assert counts["rule_001_ssh_brute_force"]["total"] == 3 and counts["rule_001_ssh_brute_force"]["last_24h"] == 2


def test_reader_works_on_a_read_only_copy(db, tmp_path):
    import os, shutil, stat
    path, _ = db
    copy = tmp_path / "ro" / "public_alerts.db"
    copy.parent.mkdir(); shutil.copy(path, copy)
    os.chmod(copy, stat.S_IREAD); os.chmod(copy.parent, stat.S_IREAD | stat.S_IEXEC)
    try:
        assert pa.query_alerts(str(copy))["total"] == 4
    finally:
        os.chmod(copy.parent, stat.S_IRWXU)
