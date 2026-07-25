from rules.rule_014_masquerading import detect
from datetime import datetime, timezone


def test_masquerading_name_mismatch(make_auditd_event):
    """comm doesn't match exe's basename, not a truncation, not whitelisted."""
    event = make_auditd_event(
        exe="/usr/bin/ssh",
        comm="sshd",
        auid=1000,
        pid=1234,
        timestamp=datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
    )
    alerts = detect([event])
    assert len(alerts) == 1
    assert alerts[0].extra["signal"] == "name_mismatch"
    assert alerts[0].severity.name == "CRITICAL"


def test_masquerading_untrusted_path(make_auditd_event):
    """Name matches (sshd == sshd), but exe lives outside trusted dirs."""
    event = make_auditd_event(
        exe="/tmp/sshd",
        comm="sshd",
        auid=1000,
        pid=1234,
        timestamp=datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
    )
    alerts = detect([event])
    assert len(alerts) == 1
    assert alerts[0].extra["signal"] == "untrusted_path"


def test_masquerading_no_alert_for_legit_truncation(make_auditd_event):
    """comm is EXACTLY 15 chars and a real prefix of exe's basename ->
    legitimate kernel truncation, not masquerading. 'ssh' (3 chars) would
    NOT qualify — must be exactly 15 to be a genuine truncation case."""
    event = make_auditd_event(
        exe="/usr/bin/unattended-upgrades",
        comm="unattended-upgr",  # exactly 15 chars, real prefix
        auid=1000,
        pid=1234,
        timestamp=datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
    )
    alerts = detect([event])
    assert alerts == []


def test_masquerading_no_alert_for_known_symlink(make_auditd_event):
    """sh/dash IS a real mismatch (basename 'dash' != comm 'sh'), but
    it's explicitly whitelisted as a known Ubuntu symlink pair."""
    event = make_auditd_event(
        exe="/usr/bin/dash",
        comm="sh",
        auid=1000,
        pid=1234,
        timestamp=datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
    )
    alerts = detect([event])
    assert alerts == []


def test_masquerading_no_alert_for_trusted_path(make_auditd_event):
    """Sensitive name, but running from a legitimate trusted directory."""
    event = make_auditd_event(
        exe="/usr/sbin/sshd",
        comm="sshd",
        auid=1000,
        pid=1234,
        timestamp=datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
    )
    alerts = detect([event])
    assert alerts == []


def test_masquerading_both_signals_fire_on_same_event(make_auditd_event):
    """comm='sshd' from exe='/tmp/evil': name mismatch (evil != sshd) AND
    sensitive name in untrusted path -> ONE event, TWO alerts."""
    event = make_auditd_event(
        exe="/tmp/evil",
        comm="sshd",
        auid=1000,
        pid=1234,
        timestamp=datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
    )
    alerts = detect([event])
    assert len(alerts) == 2
    signals = {a.extra["signal"] for a in alerts}
    assert signals == {"name_mismatch", "untrusted_path"}


def test_masquerading_multiple_separate_events(make_auditd_event):
    """Two DIFFERENT events, each independently triggering a different
    signal — distinct from the single-event-two-signals case above."""
    event1 = make_auditd_event(
        exe="/usr/bin/ssh", comm="sshd", auid=1000, pid=1234,
        timestamp=datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
    )
    event2 = make_auditd_event(
        exe="/tmp/sshd", comm="sshd", auid=1000, pid=1235,
        timestamp=datetime(2026, 1, 15, 10, 31, 0, tzinfo=timezone.utc),
    )
    alerts = detect([event1, event2])
    assert len(alerts) == 2
    signals = {a.extra["signal"] for a in alerts}
    assert signals == {"name_mismatch", "untrusted_path"}


def test_masquerading_empty_exe_or_comm_guarded(make_auditd_event):
    """exe/comm are required, non-Optional str fields — can't be None.
    Empty string is the realistic 'missing' case, and correctly triggers
    the `if not event.exe or not event.comm: continue` guard."""
    event = make_auditd_event(
        exe="", comm="", auid=1000, pid=1234,
        timestamp=datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
    )
    alerts = detect([event])
    assert alerts == []