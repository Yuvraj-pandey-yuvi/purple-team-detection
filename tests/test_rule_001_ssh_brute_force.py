from datetime import datetime, timedelta, timezone
from rules.rule_001_ssh_brute_force import detect

def test_five_failed_attempts_same_ip_fires_alert(make_auth_event):
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        make_auth_event(
            timestamp=base_time + timedelta(seconds=i * 5),
            source_ip="178.175.167.68",
            auth_result="failed",
        )
        for i in range(5)
    ]
    alerts=detect(events)
    assert len(alerts) == 1
    assert alerts[0].source_ip == "178.175.167.68"
    assert alerts[0].extra["attempt_count"] == 5
    assert alerts[0].extra["attack_speed"]=="slow_scan"

def test_four_failed_attempts_does_not_fire(make_auth_event):
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        make_auth_event(
            timestamp=base_time + timedelta(seconds=i * 5),
            source_ip="178.175.167.68",
            auth_result="failed",
        )
        for i in range(4)
    ]
    alerts=detect(events)
    assert len(alerts) == 0

def test_two_different_ip_failed_attempts_does_not_fire(make_auth_event):
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        make_auth_event(
            timestamp=base_time + timedelta(seconds=i * 5),
            source_ip="178.175.167.68",
            auth_result="failed",
        )
        for i in range(2)
    ]
    events += [
        make_auth_event(
            timestamp=base_time + timedelta(seconds=i * 5),
            source_ip="192.168.1.100",
            auth_result="failed",
        )
        for i in range(2)
    ]
    events += [
            make_auth_event(
                timestamp=base_time + timedelta(seconds=i * 5),
                source_ip="178.175.167.68",
                auth_result="failed",
            )
            for i in range(2)
        ]
    events += [
            make_auth_event(
                timestamp=base_time + timedelta(seconds=i * 5),
                source_ip="192.168.1.100",
                auth_result="failed",
            )
            for i in range(2)
        ]
    
    alerts=detect(events)
    assert len(alerts) == 0

def test_five_failed_attempts_different_ips_does_not_fire(make_auth_event): 
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        make_auth_event(
            timestamp=base_time + timedelta(seconds=i * 5),
            source_ip=f"178.175.167.{68+i}",
            auth_result="failed",
        )
        for i in range(5)
    ]
    alerts=detect(events)
    assert len(alerts) == 0

def test_five_failed_attempts_same_ip_different_users_fires_alert(make_auth_event):
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    user=['one','two','three','four','five']
    events = [
        make_auth_event(
            timestamp=base_time + timedelta(seconds=i * 5),
            source_ip="178.175.167.68",
            auth_result="failed",
            username=f"user{i}"
        )
        for i in range(5)
    ]
    alerts=detect(events)
    assert len(alerts) == 1
    assert alerts[0].source_ip == "178.175.167.68"
    assert alerts[0].extra["attempt_count"] == 5
    assert alerts[0].extra["attack_speed"]=="slow_scan"

def test_five_attempts_spread_outside_60_second_does_not_fires(make_auth_event):
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        make_auth_event(
            timestamp=base_time + timedelta(seconds=i * 20),
            source_ip="178.175.167.68",
            auth_result="failed",
        )
        for i in range(5)
    ]
    alerts=detect(events)
    assert len(alerts) == 0

def test_four_failed_attempts_and_one_success_does_not_fire(make_auth_event):
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        make_auth_event(
            timestamp=base_time + timedelta(seconds=i * 5),
            source_ip="178.175.167.68",
            auth_result="failed",
        )
        for i in range(4)
    ]
    events.append(
        make_auth_event(
            timestamp=base_time + timedelta(seconds=20),
            source_ip="178.175.167.68",
            auth_result="accepted",
        )
    )
    alerts=detect(events)
    assert len(alerts) == 0
