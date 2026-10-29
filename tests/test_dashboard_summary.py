"""Tests for the dashboard summary and the cached geolocation (no real network)."""
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from schemas import Alert, CoverageSummary
from storage.cowrie_store import init_db
from detection import geo_lookup
from detection.geo_lookup import RateLimited
from detection.dashboard_summary import (
    build_summary, daily_timeline, honeypot_daily_sessions, notable_alerts, pipeline_health, write_summary, clean_text,
)

NOW = datetime(2026, 10, 29, 12, 30, tzinfo=timezone.utc)


def make_alert(rule="rule_001_ssh_brute_force", severity="HIGH", source="auth_log", minutes_ago=10,
               ip=None, auid=None, text="something happened", technique="T1110.001"):
    when = NOW - timedelta(minutes=minutes_ago)
    return Alert(rule_id=rule, technique=technique, severity=severity, timestamp=when, first_seen=when,
                 log_source=source, dedup_key=f"{rule}|{minutes_ago}|{ip}", description=text,
                 source_ip=ip, auid=auid, raw_log="SECRET RAW LOG", extra={"password": "SECRET EXTRA"})


@pytest.fixture
def honeypot_db(tmp_path):
    path = tmp_path / "cowrie.db"
    init_db(path)
    with sqlite3.connect(path) as c:
        recent = (NOW - timedelta(hours=1)).isoformat()
        old = (NOW - timedelta(days=5)).isoformat()
        c.execute("INSERT INTO sessions VALUES ('s1','8.8.8.8',?,NULL,NULL)", (recent,))
        c.execute("INSERT INTO sessions VALUES ('s2','8.8.8.8',?,NULL,NULL)", (old,))
        c.execute("INSERT INTO sessions VALUES ('s3','1.1.1.1',?,NULL,NULL)", (old,))
        for n, (session, user, pw) in enumerate([("s1", "root", "123456"), ("s2", "root", "admin"),
                                                  ("s3", "<script>alert(1)</script>", "x\x00y")]):
            c.execute("INSERT INTO session_logins(session_id,username,password,success,timestamp) VALUES (?,?,?,0,?)",
                      (session, user, pw, f"2026-10-0{n+1}T00:00:00"))
    return str(path)


def test_summary_never_leaks_raw_log_or_extra(honeypot_db):
    alerts = [make_alert(ip="9.9.9.9")]
    summary = build_summary(alerts, CoverageSummary.from_alerts(alerts), {}, honeypot_db, {}, NOW)
    text = json.dumps(summary)
    assert "SECRET RAW LOG" not in text and "SECRET EXTRA" not in text


def test_owner_activity_is_left_out_of_notable_but_counted_in_totals():
    alerts = [make_alert(rule="rule_012", source="auditd", auid=1000, ip=None),
              make_alert(rule="rule_001_ssh_brute_force", ip="9.9.9.9")]
    notable = notable_alerts(alerts, NOW)
    assert [n["rule"] for n in notable] == ["rule_001_ssh_brute_force"]


def test_info_and_honeypot_alerts_not_notable():
    alerts = [make_alert(severity="INFO"), make_alert(source="cowrie", rule="rule_015_cowrie_login")]
    assert notable_alerts(alerts, NOW) == []


def test_daily_timeline_has_30_days_and_uses_sessions_for_the_honeypot(honeypot_db):
    by_day = honeypot_daily_sessions(honeypot_db, NOW)
    alerts = [make_alert(minutes_ago=5), make_alert(minutes_ago=60 * 24 * 2),
              make_alert(minutes_ago=5, auid=1000, source="auditd"),   # owner activity: not counted
              make_alert(minutes_ago=60 * 24 * 40)]                    # outside the 30 days
    timeline = daily_timeline(alerts, by_day, NOW)
    assert len(timeline) == 30 and timeline[-1]["day"] == "2026-10-29"
    assert timeline[-1] == {"day": "2026-10-29", "honeypot": 1, "other": 1}
    assert {b["day"]: b["honeypot"] for b in timeline}["2026-10-24"] == 2     # two sessions, five days ago
    assert sum(b["other"] for b in timeline) == 2


def test_naive_timestamps_are_treated_as_utc():
    alert = make_alert()
    alert = alert.model_copy(update={"timestamp": NOW.replace(tzinfo=None), "first_seen": None})
    assert daily_timeline([alert], {}, NOW)[-1]["other"] == 1


def test_attackers_merge_honeypot_and_ssh_probes_and_attach_geo(honeypot_db):
    alerts = [make_alert(ip="8.8.8.8"), make_alert(ip="7.7.7.7", minutes_ago=20)]
    geo = {"8.8.8.8": {"lat": 1.0, "lon": 2.0, "city": "X", "country": "Y", "cc": "YY"}}
    summary = build_summary(alerts, CoverageSummary.from_alerts(alerts), {}, honeypot_db, geo, NOW)
    by_ip = {a["ip"]: a for a in summary["attackers"]}
    assert by_ip["8.8.8.8"]["sessions"] == 2 and by_ip["8.8.8.8"]["ssh_probe_alerts"] == 1
    assert by_ip["8.8.8.8"]["geo"]["cc"] == "YY"
    assert by_ip["7.7.7.7"]["geo"] is None and by_ip["7.7.7.7"]["sessions"] == 0
    assert summary["totals"]["attackers_total"] == 2 and summary["totals"]["attackers_24h"] == 1
    assert summary["totals"]["honeypot_sessions_24h"] == 1


def test_hostile_credentials_are_flattened_but_kept_as_text(honeypot_db):
    summary = build_summary([], CoverageSummary.from_alerts([]), {}, honeypot_db, {}, NOW)
    names = [u["value"] for u in summary["usernames"]]
    assert "<script>alert(1)</script>" in names          # kept as text: the page escapes it
    assert all("\x00" not in p["value"] for p in summary["passwords"])
    assert clean_text("a" * 500, 40) == "a" * 40


def test_missing_honeypot_db_degrades_with_a_warning_not_a_crash(tmp_path):
    summary = build_summary([], CoverageSummary.from_alerts([]), {}, str(tmp_path / "nope.db"), {}, NOW)
    assert summary["attackers"] == [] and summary["warnings"]


def test_pipeline_health_statuses():
    start = (NOW - timedelta(hours=30)).isoformat()
    state = {
        "auth_log": {"watching_since": start, "last_input": (NOW - timedelta(minutes=3)).isoformat(), "outage_since": None},
        "auditd": {"watching_since": start, "last_input": (NOW - timedelta(hours=3)).isoformat(), "outage_since": None},
        "cowrie": {"watching_since": (NOW - timedelta(hours=2)).isoformat(), "last_input": None, "outage_since": None},
        "cloudtrail": {"watching_since": start, "last_input": None, "outage_since": None},
    }
    rows = {r["source"]: r["status"] for r in pipeline_health(state, NOW)}
    assert rows == {"auth_log": "ok", "auditd": "silent", "cowrie": "waiting",
                    "cloudtrail": "silent", "falco": "not_monitored"}
    assert pipeline_health(None, NOW)[0]["status"] == "unknown"


def test_summary_is_small_and_written_atomically(tmp_path, honeypot_db):
    alerts = [make_alert(source="cowrie", rule="rule_015_cowrie_login", minutes_ago=m % 1000) for m in range(3000)]
    summary = build_summary(alerts, CoverageSummary.from_alerts(alerts), {}, honeypot_db, {}, NOW)
    path = tmp_path / "dashboard_summary.json"
    write_summary(summary, str(path))
    assert json.loads(path.read_text())["totals"]["alerts_total"] == 3000
    assert path.stat().st_size < 100_000 and not (tmp_path / "dashboard_summary.json.tmp").exists()


# ── geolocation ────────────────────────────────────────────────────────────────

GOOD = {"lat": 47.0, "lon": 28.8, "city": "Chisinau", "country": "Moldova", "cc": "MD"}


def test_geo_looks_up_once_then_serves_from_cache(tmp_path):
    cache, calls = str(tmp_path / "geo.json"), []
    def fetch(ip): calls.append(ip); return GOOD
    assert geo_lookup.enrich(["8.8.8.8"], cache, fetch=fetch, now=NOW)["8.8.8.8"]["cc"] == "MD"
    geo_lookup.enrich(["8.8.8.8"], cache, fetch=fetch, now=NOW)
    assert calls == ["8.8.8.8"]                      # second cycle made no request


def test_geo_skips_private_and_invalid_addresses(tmp_path):
    calls = []
    geo_lookup.enrich(["10.0.0.1", "192.168.1.5", "127.0.0.1", "not-an-ip"], str(tmp_path / "g.json"),
                      fetch=lambda ip: calls.append(ip), now=NOW)
    assert calls == []


def test_geo_respects_the_per_cycle_cap(tmp_path):
    calls = []
    ips = [f"8.8.8.{n}" for n in range(1, 11)]
    geo_lookup.enrich(ips, str(tmp_path / "g.json"), fetch=lambda ip: calls.append(ip) or GOOD, max_new=3, now=NOW)
    assert len(calls) == 3


def test_geo_failure_is_retried_only_after_the_wait(tmp_path):
    cache, calls = str(tmp_path / "g.json"), []
    def fetch(ip): calls.append(ip); return None
    geo_lookup.enrich(["8.8.8.8"], cache, fetch=fetch, now=NOW)
    geo_lookup.enrich(["8.8.8.8"], cache, fetch=fetch, now=NOW + timedelta(minutes=10))
    assert len(calls) == 1
    geo_lookup.enrich(["8.8.8.8"], cache, fetch=fetch, now=NOW + timedelta(hours=2))
    assert len(calls) == 2


def test_geo_rate_limit_stops_the_cycle_but_keeps_earlier_results(tmp_path):
    cache = str(tmp_path / "g.json")
    def fetch(ip):
        if ip == "8.8.8.2": raise RateLimited()
        return GOOD
    found = geo_lookup.enrich(["8.8.8.1", "8.8.8.2", "8.8.8.3"], cache, fetch=fetch, now=NOW)
    assert set(found) == {"8.8.8.1"}                 # .3 was not tried, .2 will be retried next cycle
    assert "8.8.8.2" not in geo_lookup.load_cache(cache)


def test_geo_corrupt_cache_file_is_replaced_not_fatal(tmp_path):
    path = tmp_path / "g.json"
    path.write_text("{ broken")
    assert geo_lookup.enrich(["8.8.8.8"], str(path), fetch=lambda ip: GOOD, now=NOW)["8.8.8.8"]["cc"] == "MD"
