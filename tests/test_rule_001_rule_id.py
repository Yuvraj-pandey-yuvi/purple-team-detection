# tests/test_rule_001_rule_id.py
# Every rule names its alerts "rule_NNN_<name>"; rule_001 used the ATT&CK id instead.
from datetime import datetime, timedelta, timezone
from rules.rule_001_ssh_brute_force import detect

START = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)


def test_alert_rule_id_follows_the_rule_naming_convention(make_auth_event):
    events = [
        make_auth_event(
            timestamp=START + timedelta(seconds=index * 2),
            source_ip="1.1.1.1",
            auth_result="failed",
        )
        for index in range(5)
    ]
    alert = detect(events)[0]
    assert alert.rule_id == "rule_001_ssh_brute_force"
    assert alert.technique == "T1110.001"
