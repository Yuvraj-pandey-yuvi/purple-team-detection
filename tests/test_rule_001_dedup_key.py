# tests/test_rule_001_dedup_key.py
from datetime import datetime, timedelta, timezone
from rules.rule_001_ssh_brute_force import detect
from detection.engine import deduplicate_alerts


def failed_burst(make_auth_event, source_ip, start_time, attempts=5):
    return [
        make_auth_event(
            timestamp=start_time + timedelta(seconds=i * 2),
            source_ip=source_ip,
            auth_result="failed",
        )
        for i in range(attempts)
    ]


def test_dedup_key_is_ip_and_event_date(make_auth_event):
    start = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    alerts = detect(failed_burst(make_auth_event, "1.1.1.1", start))
    assert [a.dedup_key for a in alerts] == ["1.1.1.1|2026-01-15"]


def test_last_event_in_batch_does_not_change_other_alerts_keys(make_auth_event):
    start = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = []
    for index, attacker_ip in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3"]):
        events += failed_burst(make_auth_event, attacker_ip, start + timedelta(minutes=index * 5))
    # the LAST event of the batch is a failed login from a 4th IP (below threshold)
    events += failed_burst(make_auth_event, "4.4.4.4", start + timedelta(minutes=30), attempts=1)
    alerts = detect(events)
    assert sorted(a.dedup_key for a in alerts) == [
        "1.1.1.1|2026-01-15", "2.2.2.2|2026-01-15", "3.3.3.3|2026-01-15",
    ]


def test_three_attackers_survive_engine_deduplication(make_auth_event):
    start = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = []
    for index, attacker_ip in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3"]):
        events += failed_burst(make_auth_event, attacker_ip, start + timedelta(minutes=index * 5))
    kept = deduplicate_alerts([], detect(events))
    assert len(kept) == 3


def test_two_bursts_same_ip_same_day_become_one_alert(make_auth_event):
    start = datetime(2026, 1, 15, 3, 0, 0, tzinfo=timezone.utc)
    events = (failed_burst(make_auth_event, "1.1.1.1", start)
              + failed_burst(make_auth_event, "1.1.1.1", start + timedelta(hours=9)))
    kept = deduplicate_alerts([], detect(events))
    assert len(kept) == 1


def test_same_ip_on_a_different_day_is_a_new_alert(make_auth_event):
    day_one = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    day_two = day_one + timedelta(days=1)
    first_day_alerts = detect(failed_burst(make_auth_event, "1.1.1.1", day_one))
    second_day_alerts = detect(failed_burst(make_auth_event, "1.1.1.1", day_two))
    kept = deduplicate_alerts(first_day_alerts, second_day_alerts)
    assert len(kept) == 1
