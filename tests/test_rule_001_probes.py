# tests/test_rule_001_probes.py
# rule_001 counts failed passwords AND SSH probes, one per connection, per source IP.
from datetime import datetime, timedelta, timezone
from schemas import AuthLogEvent
from rules.rule_001_ssh_brute_force import detect as detect_ssh_burst
from rules.rule_007_brute_force_success import detect as detect_brute_force_success

START = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)


def events_from(make_auth_event, source_ip, result, count, spacing_seconds=2, start=START):
    return [
        make_auth_event(
            timestamp=start + timedelta(seconds=index * spacing_seconds),
            source_ip=source_ip,
            auth_result=result,
            username=f"user{index}",
        )
        for index in range(count)
    ]


def test_probe_burst_from_one_ip_raises_an_alert(make_auth_event):
    alerts = detect_ssh_burst(events_from(make_auth_event, "1.1.1.1", "probe", 5))
    assert len(alerts) == 1
    assert alerts[0].source_ip == "1.1.1.1"
    assert alerts[0].extra["attempt_count"] == 5


def test_failed_passwords_and_probes_add_up_for_the_same_ip(make_auth_event):
    events = (events_from(make_auth_event, "1.1.1.1", "failed", 3)
              + events_from(make_auth_event, "1.1.1.1", "probe", 2, start=START + timedelta(seconds=10)))
    alerts = detect_ssh_burst(events)
    assert len(alerts) == 1
    assert alerts[0].extra["attempt_count"] == 5
    assert alerts[0].extra["probe_count"] == 2


def test_probes_from_different_ips_do_not_add_up(make_auth_event):
    events = (events_from(make_auth_event, "1.1.1.1", "probe", 3)
              + events_from(make_auth_event, "2.2.2.2", "probe", 3))
    assert detect_ssh_burst(events) == []


def test_four_probes_is_below_the_threshold(make_auth_event):
    assert detect_ssh_burst(events_from(make_auth_event, "1.1.1.1", "probe", 4)) == []


def test_slow_probing_outside_the_60_second_window_is_not_an_alert(make_auth_event):
    # 5 probes, 20 seconds apart: any 60-second window holds at most 4
    assert detect_ssh_burst(events_from(make_auth_event, "1.1.1.1", "probe", 5, spacing_seconds=20)) == []


def test_alert_lists_which_usernames_were_tried(make_auth_event):
    alerts = detect_ssh_burst(events_from(make_auth_event, "1.1.1.1", "probe", 5))
    assert alerts[0].extra["usernames_tried"] == ["user0", "user1", "user2", "user3", "user4"]


def test_real_log_lines_count_connections_not_lines():
    # 5 connections from one IP, each writing the REAL two lines
    # ("Invalid user" then "Connection closed by invalid user"): 10 lines, 5 connections.
    # Counting lines would cross the threshold twice (2 alerts); counting connections once.
    lines = []
    for index in range(5):
        pid = 1000 + index
        second = index * 2
        stamp = f"2026-01-15T10:00:{second:02d}.000000+00:00 ip-172-31-38-66"
        lines.append(f"{stamp} sshd-session[{pid}]: Invalid user  from 9.9.9.9 port {40000 + index}")
        lines.append(f"{stamp} sshd-session[{pid}]: Connection closed by invalid user  9.9.9.9 port {40000 + index} [preauth]")
    alerts = detect_ssh_burst([AuthLogEvent.from_raw(line) for line in lines])
    assert len(alerts) == 1
    assert alerts[0].extra["attempt_count"] == 5


def test_probes_followed_by_a_login_do_not_trigger_rule_007(make_auth_event):
    events = events_from(make_auth_event, "1.1.1.1", "probe", 6) + [
        make_auth_event(
            timestamp=START + timedelta(minutes=5),
            source_ip="1.1.1.1",
            auth_result="accepted",
            username="ubuntu",
        )
    ]
    assert detect_brute_force_success(events) == []


def test_failed_passwords_followed_by_a_login_still_trigger_rule_007(make_auth_event):
    events = events_from(make_auth_event, "1.1.1.1", "failed", 6) + [
        make_auth_event(
            timestamp=START + timedelta(minutes=5),
            source_ip="1.1.1.1",
            auth_result="accepted",
            username="ubuntu",
        )
    ]
    assert len(detect_brute_force_success(events)) == 1
