from datetime import datetime, timedelta, timezone
from rules.rule_007_brute_force_success import detect


def _make_failures(make_auth_event, ip, base_time, count=5, spacing=5):
    return [
        make_auth_event(
            timestamp=base_time + timedelta(seconds=i * spacing),
            source_ip=ip,
            auth_result="failed",
        )
        for i in range(count)
    ]


def test_threshold_failures_then_success_within_window_fires_alert(make_auth_event):
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    failures = _make_failures(make_auth_event, "1.2.3.4", base_time, count=5)
    # last failure is at +20s; success 30s after that = well within 600s window
    success = make_auth_event(
        timestamp=base_time + timedelta(seconds=20 + 30),
        source_ip="1.2.3.4",
        auth_result="accepted",
        username="root",
    )
    alerts = detect(failures + [success])
    assert len(alerts) == 1
    assert alerts[0].source_ip == "1.2.3.4"
    assert alerts[0].username == "root"
    assert alerts[0].extra["attempt_count"] == 5


def test_below_threshold_failures_then_success_no_alert(make_auth_event):
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    failures = _make_failures(make_auth_event, "1.2.3.4", base_time, count=4)
    success = make_auth_event(
        timestamp=base_time + timedelta(seconds=15 + 30),
        source_ip="1.2.3.4",
        auth_result="accepted",
    )
    alerts = detect(failures + [success])
    assert alerts == []


def test_success_outside_window_no_alert(make_auth_event):
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    failures = _make_failures(make_auth_event, "1.2.3.4", base_time, count=5)
    # last failure at +20s; success 601s after that -> just past the 600s window
    success = make_auth_event(
        timestamp=base_time + timedelta(seconds=20 + 601),
        source_ip="1.2.3.4",
        auth_result="accepted",
    )
    alerts = detect(failures + [success])
    assert alerts == []


def test_success_with_no_prior_failures_no_alert(make_auth_event):
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    success = make_auth_event(
        timestamp=base_time,
        source_ip="9.9.9.9",
        auth_result="accepted",
    )
    alerts = detect([success])
    assert alerts == []


def test_success_before_last_failure_no_alert(make_auth_event):
    """time_diff must be >= 0 — a success that happened BEFORE the last
    recorded failure (e.g. clock skew, or the success just isn't related
    to this failure burst) should not fire."""
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    failures = _make_failures(make_auth_event, "1.2.3.4", base_time, count=5)
    success = make_auth_event(
        timestamp=base_time - timedelta(seconds=100),  # BEFORE all failures
        source_ip="1.2.3.4",
        auth_result="accepted",
    )
    alerts = detect(failures + [success])
    assert alerts == []


def test_different_ip_failures_dont_combine_with_success(make_auth_event):
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    failures = _make_failures(make_auth_event, "1.2.3.4", base_time, count=5)
    # success from a DIFFERENT ip that never had failures
    success = make_auth_event(
        timestamp=base_time + timedelta(seconds=30),
        source_ip="9.9.9.9",
        auth_result="accepted",
    )
    alerts = detect(failures + [success])
    assert alerts == []