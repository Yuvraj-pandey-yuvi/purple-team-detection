"""Per-day statistics, findings, campaign timeline, ATT&CK tactics, and the engine publish step."""
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from schemas import Alert, CoverageSummary, ATTCKTechnique
from schemas.alert import PIPELINE_ONLY_TECHNIQUES
from storage.cowrie_store import init_db
from detection import public_stats as ps, rule_catalog
from detection.dashboard_summary import publish

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
A, B, C = "120.24.191.90", "178.128.36.18", "7.7.7.7"
GEO = {A: {"lat": 30.274, "lon": 120.155, "city": "H", "country": "China", "cc": "CN", "org": "Cloud Co", "asn": "AS1"},
       B: {"lat": 51.5, "lon": -0.1, "city": "L", "country": "United Kingdom", "cc": "GB", "org": "Other Co", "asn": "AS2"}}
OK = 'echo -e "\\x6F\\x6B"'


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "cowrie.db"
    init_db(path)
    rows = [("s1", A, "2026-10-28T03:10:00+00:00"), ("s2", A, "2026-10-28T03:20:00+00:00"), ("s3", A, "2026-10-30T15:00:00+00:00"),
            ("s4", B, "2026-10-30T15:30:00+00:00"), ("s5", C, "2026-10-30T23:59:00+00:00")]
    with sqlite3.connect(path) as c:
        for sid, ip, t in rows:
            c.execute("INSERT INTO sessions(session_id, src_ip, start_time) VALUES (?,?,?)", (sid, ip, t))
            c.execute("INSERT INTO session_logins(session_id, username, password, success, timestamp) VALUES (?,?,?,1,?)",
                      (sid, "root" if sid != "s4" else "ad\x00min", "pw1", t))
        for sid, cmd in (("s1", OK), ("s2", OK), ("s3", "uname -a"), ("s4", OK)):
            c.execute("INSERT INTO session_commands(session_id, command_text, ran_at) VALUES (?,?,?)", (sid, cmd, "t"))
    return str(path)


def test_day_rows_are_scoped_and_all_is_their_sum(db, tmp_path):
    out = str(tmp_path / "s.db")
    ps.build(db, GEO, out, NOW)
    allrow, d28, d30 = ps.get(out, "all"), ps.get(out, "2026-10-28"), ps.get(out, "2026-10-30")
    assert (allrow["sessions"], d28["sessions"], d30["sessions"]) == (5, 2, 3)
    assert [a["ip"] for a in d28["attackers"]] == [A] and {a["ip"] for a in d30["attackers"]} == {A, B, C}
    assert d28["hours"][3] == 2 and d30["hours"][15] == 2 and d30["hours"][23] == 1 and sum(allrow["hours"]) == 5
    assert d28["commands"]["total"] == 2 and d30["commands"]["total"] == 2 and allrow["commands"]["total"] == 4
    assert allrow["commands"]["sessions_with_commands"] == 4 and d30["commands"]["sessions_with_commands"] == 2


def test_map_countries_and_networks_use_only_that_scope_and_only_located_ips(db, tmp_path):
    out = str(tmp_path / "s.db")
    ps.build(db, GEO, out, NOW)
    d28 = ps.get(out, "2026-10-28")
    assert [p["ip"] for p in d28["map"]] == [A] and d28["map"][0]["lat"] == 30.27           # rounded to 2 decimals
    assert d28["countries"] == [{"cc": "CN", "country": "China", "sessions": 2, "attackers": 1}]
    d30 = ps.get(out, "2026-10-30")
    assert C not in json.dumps(d30["map"]) and d30["located_sessions"] == 2 and d30["sessions"] == 3
    assert {n["network"] for n in d30["networks"]} == {"Cloud Co", "Other Co"}


def test_hostile_text_is_flattened_and_binary_is_hidden(db, tmp_path):
    out = str(tmp_path / "s.db")
    ps.build(db, GEO, out, NOW)
    assert all("\x00" not in u["value"] for u in ps.get(out, "all")["usernames"])


def test_findings_are_computed_from_the_data(db, tmp_path):
    f = ps.build(db, GEO, str(tmp_path / "s.db"), NOW)["findings"]
    assert f[0]["stat"] == "100%"                                                          # three IPs cover all 5 sessions
    assert f[1]["stat"] == "75%" and "80%" in f[1]["text"]                                 # OK is 3 of 4 commands; 4 of 5 sessions ran one
    assert f[2]["stat"] == "80%" and "root" in f[2]["text"]                                # 4 of 5 logins used root


def test_campaign_timeline_fills_the_gaps_and_ranks_by_total(db, tmp_path):
    c = ps.build(db, GEO, str(tmp_path / "s.db"), NOW)["campaigns"]
    assert c["days"] == ["2026-10-28", "2026-10-29", "2026-10-30"]
    assert c["rows"][0]["ip"] == A and c["rows"][0]["counts"] == [2, 0, 1] and c["rows"][0]["network"] == "Cloud Co"


def test_stat_days_are_newest_first(db, tmp_path):
    d = ps.build(db, GEO, str(tmp_path / "s.db"), NOW)["stat_days"]
    assert d == [{"day": "2026-10-30", "sessions": 3, "alerts": 0}, {"day": "2026-10-28", "sessions": 2, "alerts": 0}]


def test_only_valid_day_keys_are_accepted(db, tmp_path):
    out = str(tmp_path / "s.db")
    ps.build(db, GEO, out, NOW)
    for bad in ("2026-10-30' OR '1'='1", "../all", "2026-1-3", "", "ALL"):
        assert ps.get(out, bad) is None
    assert ps.get(out, "2026-01-01") is None


def test_rebuild_is_skipped_when_nothing_changed_and_runs_when_locations_change(db, tmp_path):
    out = tmp_path / "s.db"
    ps.build(db, GEO, str(out), NOW)
    inode = out.stat().st_ino
    ps.build(db, GEO, str(out), NOW)
    assert out.stat().st_ino == inode                                                      # untouched
    ps.build(db, {**GEO, C: {"lat": 1.0, "lon": 2.0, "cc": "US", "country": "United States", "org": "X"}}, str(out), NOW)
    assert out.stat().st_ino != inode and ps.get(str(out), "all")["located_sessions"] == 5


def test_empty_database_gives_empty_but_valid_output(tmp_path):
    path = tmp_path / "cowrie.db"; init_db(path)
    r = ps.build(str(path), {}, str(tmp_path / "s.db"), NOW)
    assert r == {"stat_days": [], "findings": [], "campaigns": {"days": [], "rows": []}}
    assert ps.get(str(tmp_path / "s.db"), "all")["sessions"] == 0


# ── ATT&CK data ────────────────────────────────────────────────────────────────

def test_every_coverage_technique_has_valid_tactics():
    coverage = CoverageSummary.from_alerts([])
    assert coverage.total_techniques == 13
    for t in coverage.techniques:
        tactics = rule_catalog.tactics_of(t.technique.value)
        assert tactics and all(x in rule_catalog.TACTICS for x in tactics), t.technique


def test_no_coverage_technique_is_unreachable():
    """A technique only the heartbeat rule uses must not sit in the coverage list as 'never detected'."""
    used = set()
    for p in Path("rules").glob("rule_0*.py"):
        if p.stem.startswith("rule_018"):
            continue
        used |= set(re.findall(r"ATTCKTechnique\.(T\d+(?:_\d+)?)", p.read_text()))
    covered = {t.technique.name for t in CoverageSummary.from_alerts([]).techniques}
    assert covered <= used, covered - used
    assert ATTCKTechnique.T1562_001 in PIPELINE_ONLY_TECHNIQUES


def test_the_two_relabelled_rules_use_the_cloud_and_linux_audit_techniques():
    assert "T1562_008" in Path("rules/rule_009_cloudtrail_disabled.py").read_text()
    assert "T1562_012" in Path("rules/rule_010_auditd_disabled.py").read_text()
    ids = {r[0]: r[2] for r in rule_catalog.CATALOG}
    assert ids["rule_009_cloudtrail_disabled"] == "T1562.008" and ids["rule_010_auditd_tamper"] == "T1562.012"


# ── the engine's publish step writes every public file ─────────────────────────

def test_publish_writes_all_public_files_and_the_new_summary_fields(db, tmp_path):
    reports = tmp_path / "reports"; reports.mkdir()
    (reports / "cowrie.db").write_bytes(Path(db).read_bytes())
    when = NOW - timedelta(hours=2)
    alerts = [Alert(rule_id="rule_015_cowrie_login", technique="T1110.001", severity="CRITICAL", timestamp=when, first_seen=when,
                    log_source="cowrie", dedup_key="k", description="x", source_ip=A)]
    s = publish(alerts, CoverageSummary.from_alerts(alerts), reports, geo_enabled=False, now=NOW)
    for f in ("dashboard_summary.json", "public_alerts.db", "public_attackers.json", "public_stats.db"):
        assert (reports / f).exists(), f
    assert s["warnings"] == [] and len(s["findings"]) == 4 and s["findings"][3]["stat"] == "1 of 17"
    assert s["coverage"]["attack_version"] == "v17" and s["coverage"]["techniques"][0]["tactics"]
    assert s["stat_days"] and s["campaigns"]["rows"]


def test_the_day_key_validator_works_independently_of_the_database(db, tmp_path):
    """Parameter binding already stops injection; the validator is a second layer. Prove it by planting
    rows under invalid keys: they exist in the table, yet get() must still refuse to serve them."""
    out = str(tmp_path / "s.db")
    ps.build(db, GEO, out, NOW)
    c = sqlite3.connect(out)
    for key in ("../secret", "2026-1-3", "ALL", "x' OR '1'='1"):
        c.execute("INSERT INTO stats VALUES (?, ?)", (key, json.dumps({"planted": True})))
    c.commit(); c.close()
    for key in ("../secret", "2026-1-3", "ALL", "x' OR '1'='1"):
        assert ps.get(out, key) is None
    assert ps.get(out, "all")["sessions"] == 5


# ── attackers that only the detections saw (SSH brute force on the real server) ────────────

def _alert(ip, day="2026-10-30", source="auth_log", rule="rule_001_ssh_brute_force", auid=None, sev="MEDIUM"):
    when = datetime.fromisoformat(day + "T05:00:00+00:00")
    return Alert(rule_id=rule, technique="T1110.001", severity=sev, timestamp=when, first_seen=when, log_source=source,
                 dedup_key=f"{rule}{ip}{day}", description="5 failed SSH attempts", source_ip=ip, auid=auid)


SSH = "115.190.178.190"
GEO2 = {**GEO, SSH: {"lat": 22.5, "lon": 114.1, "city": "S", "country": "China", "cc": "CN", "org": "Telecom", "asn": "AS2"}}


def test_ssh_scanners_join_the_table_and_the_map_but_not_the_honeypot_statistics(db, tmp_path):
    out = str(tmp_path / "s.db")
    ps.build(db, GEO2, out, NOW, alerts=[_alert(SSH), _alert(A, source="cowrie", rule="rule_015_cowrie_login")])
    d30 = ps.get(out, "2026-10-30")
    rows = {a["ip"]: a for a in d30["attackers"]}
    assert rows[SSH]["kind"] == "ssh" and rows[SSH]["sessions"] == 0 and rows[SSH]["alerts"] == 1 and rows[SSH]["network"] == "Telecom"
    assert rows[A]["kind"] == "honeypot"                                       # a honeypot login alert does not make it an SSH scanner
    assert any(p["ip"] == SSH and p["kind"] == "ssh" for p in d30["map"])
    assert d30["ssh_scanners"] == 1 and d30["sessions"] == 3 and d30["attackers_count"] == 3     # honeypot figures are unchanged
    assert sum(c["sessions"] for c in d30["countries"]) == d30["located_sessions"]               # countries still count sessions only


def test_an_ip_seen_by_both_is_marked_both_and_a_day_with_only_alerts_gets_a_row(db, tmp_path):
    out = str(tmp_path / "s.db")
    r = ps.build(db, GEO2, out, NOW, alerts=[_alert(A, day="2026-10-28"), _alert(SSH, day="2026-10-29")])
    assert {a["ip"]: a["kind"] for a in ps.get(out, "2026-10-28")["attackers"]}[A] == "both"
    quiet = ps.get(out, "2026-10-29")
    assert quiet["sessions"] == 0 and quiet["attackers"][0]["ip"] == SSH and quiet["ssh_scanners"] == 1
    assert {"day": "2026-10-29", "sessions": 0, "alerts": 1} in r["stat_days"]


def test_owner_and_heartbeat_alerts_do_not_create_attackers(db, tmp_path):
    out = str(tmp_path / "s.db")
    ps.build(db, GEO2, out, NOW, alerts=[_alert(SSH, auid=1000), _alert(SSH, rule="rule_018_collector_heartbeat")])
    assert SSH not in json.dumps(ps.get(out, "all")["attackers"])


def test_some_ssh_scanners_always_make_the_table_even_on_a_busy_day(tmp_path):
    path = tmp_path / "cowrie.db"; init_db(path)
    with sqlite3.connect(path) as c:
        for i in range(40):
            c.execute("INSERT INTO sessions(session_id, src_ip, start_time) VALUES (?,?,?)", (f"s{i}", f"9.9.9.{i}", "2026-10-30T10:00:00+00:00"))
    out = str(tmp_path / "s.db")
    ps.build(str(path), {}, out, NOW, alerts=[_alert("115.1.1.1"), _alert("115.1.1.2")])
    shown = ps.get(out, "2026-10-30")["attackers"]
    assert len(shown) == ps.TOP_ATTACKERS and {"115.1.1.1", "115.1.1.2"} <= {a["ip"] for a in shown}


# ── three states: real traffic / my own testing / never ───────────────────────────────────

def _owner(rule, tech):
    return Alert(rule_id=rule, technique=tech, severity="HIGH", timestamp=NOW, first_seen=NOW, log_source="auditd",
                 dedup_key=rule, description="x", auid=1000)


def test_rules_and_techniques_have_three_states_and_the_finding_says_so(db, tmp_path):
    reports = tmp_path / "reports"; reports.mkdir()
    (reports / "cowrie.db").write_bytes(Path(db).read_bytes())
    real = Alert(rule_id="rule_015_cowrie_login", technique="T1110.001", severity="CRITICAL", timestamp=NOW, first_seen=NOW,
                 log_source="cowrie", dedup_key="a", description="x", source_ip=A)
    alerts = [real, _owner("rule_012_account_enumeration", "T1087.001"), _owner("rule_013_system_discovery", "T1082")]
    s = publish(alerts, CoverageSummary.from_alerts(alerts), reports, geo_enabled=False, now=NOW)
    states = {r["id"]: r["state"] for r in s["rules"]}
    assert states["rule_015_cowrie_login"] == "real" and states["rule_012_account_enumeration"] == "testing"
    assert states["rule_002_console_login_no_mfa"] == "never"
    tech = {t["id"]: t["state"] for t in s["coverage"]["techniques"]}
    assert tech["T1110.001"] == "real" and tech["T1087.001"] == "testing" and tech["T1053.003"] == "never"
    assert (s["coverage"]["real"], s["coverage"]["testing"]) == (1, 2) and s["coverage"]["detected"] == 3
    f = s["findings"][3]
    assert f["stat"] == "1 of 17" and "2 more fired only during my own testing" in f["text"] and "14 have not met a trigger" in f["text"]
    assert next(r for r in s["rules"] if r["id"] == "rule_012_account_enumeration")["testing"] == 1


def test_a_technique_that_fired_on_real_traffic_is_never_downgraded_to_testing(db, tmp_path):
    reports = tmp_path / "reports"; reports.mkdir()
    (reports / "cowrie.db").write_bytes(Path(db).read_bytes())
    real = Alert(rule_id="rule_001_ssh_brute_force", technique="T1110.001", severity="MEDIUM", timestamp=NOW, first_seen=NOW,
                 log_source="auth_log", dedup_key="a", description="x", source_ip=A)
    alerts = [real, _owner("rule_015_cowrie_login", "T1110.001")]
    s = publish(alerts, CoverageSummary.from_alerts(alerts), reports, geo_enabled=False, now=NOW)
    assert {t["id"]: t["state"] for t in s["coverage"]["techniques"]}["T1110.001"] == "real" and s["coverage"]["testing"] == 0
