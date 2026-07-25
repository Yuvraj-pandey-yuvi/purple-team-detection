from rules.rule_012_account_enumeration import detect, ENUMERATION_COMMANDS, SENSITIVE_FILES

from datetime import datetime, timedelta, timezone

def test_detect(make_auditd_event):
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        make_auditd_event(auid=1000, exe="/usr/bin/whoami", name="/etc/passwd",
                           timestamp=base_time + timedelta(seconds=0)),
        make_auditd_event(auid=1000, exe="/usr/bin/id", name="/etc/group",
                           timestamp=base_time + timedelta(seconds=1)),
        make_auditd_event(auid=1000, exe="/usr/bin/who", name="/etc/sudoers",
                           timestamp=base_time + timedelta(seconds=2)),
        make_auditd_event(auid=1000, exe="/usr/bin/w", name="/etc/shadow",
                           timestamp=base_time + timedelta(seconds=3)),
        make_auditd_event(auid=1000, exe="/usr/bin/getent", name="/etc/passwd",
                           timestamp=base_time + timedelta(seconds=4)),
    ]
    alerts = detect(events)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "rule_012_account_enumeration"
    assert alert.severity == "HIGH"
    assert alert.first_seen == events[0].timestamp
    assert alert.last_seen == events[-1].timestamp
def test_detect_excluded_auid(make_auditd_event):
    # Create a list of AuditdEvent instances with an excluded AUID
    events = [
        make_auditd_event(auid=0, exe="/usr/bin/whoami", name="/etc/passwd", timestamp=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)),
        make_auditd_event(auid=4294967295, exe="/usr/bin/id", name="/etc/group", timestamp=datetime(2026, 1, 15, 10, 0, 1, tzinfo=timezone.utc)),
        make_auditd_event(auid=1000, exe="/usr/bin/who", name="/etc/sudoers", timestamp=datetime(2026, 1, 15, 10, 0, 2, tzinfo=timezone.utc)),
        make_auditd_event(auid=1000, exe="/usr/bin/w", name="/etc/shadow", timestamp=datetime(2026, 1, 15, 10, 0, 3, tzinfo=timezone.utc)),
        make_auditd_event(auid=1000, exe="/usr/bin/getent", name="/etc/passwd", timestamp=datetime(2026, 1, 15, 10, 0, 4, tzinfo=timezone.utc)),
    ]
    alerts = detect(events)
    # No alerts should be generated for excluded AUIDs
    assert len(alerts) == 0

def test_detect_non_enumeration_commands(make_auditd_event):
    # Create a list of AuditdEvent instances with non-enumeration commands
    events = [
        make_auditd_event(auid=1000, exe="/usr/bin/ls", name="/etc", timestamp=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)),
        make_auditd_event(auid=1000, exe="/usr/bin/cat", name="/etc/hosts", timestamp=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)),
    ]

    alerts = detect(events)

    # No alerts should be generated for non-enumeration commands
    assert len(alerts) == 0
def test_detect_sensitive_file_without_cat(make_auditd_event):
    # Create a list of AuditdEvent instances with sensitive files accessed without 'cat'
    events = [
        make_auditd_event(auid=1000, exe="/usr/bin/less", name="/etc/passwd", timestamp=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)),
        make_auditd_event(auid=1000, exe="/usr/bin/less", name="/etc/group", timestamp=datetime(2026, 1, 15, 10, 0, 1, tzinfo=timezone.utc)),
        make_auditd_event(auid=1000, exe="/usr/bin/less", name="/etc/sudoers", timestamp=datetime(2026, 1, 15, 10, 0, 2, tzinfo=timezone.utc)),
        make_auditd_event(auid=1000, exe="/usr/bin/less", name="/etc/shadow", timestamp=datetime(2026, 1, 15, 10, 0, 3, tzinfo=timezone.utc)),
        make_auditd_event(auid=1000, exe="/usr/bin/less", name="/etc/passwd", timestamp=datetime(2026, 1, 15, 10, 0, 4, tzinfo=timezone.utc)),
    ]

    alerts = detect(events)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "rule_012_account_enumeration"
    assert alert.severity == "HIGH"
    assert alert.first_seen == events[0].timestamp
    assert alert.last_seen == events[-1].timestamp
def test_detect_sensitive_file_with_cat(make_auditd_event):
    # Create a list of AuditdEvent instances with sensitive files accessed using 'cat'
    events = [
        make_auditd_event(auid=1000, exe="/usr/bin/cat", name="/etc/passwd", timestamp=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)),
        make_auditd_event(auid=1000, exe="/usr/bin/cat", name="/etc/group", timestamp=datetime(2026, 1, 15, 10, 0, 1, tzinfo=timezone.utc)),
        make_auditd_event(auid=1000, exe="/usr/bin/cat", name="/etc/sudoers", timestamp=datetime(2026, 1, 15, 10, 0, 2, tzinfo=timezone.utc)),
        make_auditd_event(auid=1000, exe="/usr/bin/cat", name="/etc/shadow", timestamp=datetime(2026, 1, 15, 10, 0, 3, tzinfo=timezone.utc)),
        make_auditd_event(auid=1000, exe="/usr/bin/cat", name="/etc/passwd", timestamp=datetime(2026, 1, 15, 10, 0, 4, tzinfo=timezone.utc)),
    ]

    alerts = detect(events)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "rule_012_account_enumeration"
    assert alert.severity == "HIGH"
    assert alert.first_seen == events[0].timestamp
    assert alert.last_seen == events[-1].timestamp

def test_detect_threshold_met_but_different_auid(make_auditd_event):
    # Create a list of AuditdEvent instances where the threshold is met but with different AUIDs
    events = [
        make_auditd_event(auid=1000, exe="/usr/bin/whoami", name="/etc/passwd", timestamp=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)),
        make_auditd_event(auid=1001, exe="/usr/bin/id", name="/etc/group", timestamp=datetime(2026, 1, 15, 10, 0, 1, tzinfo=timezone.utc)),
        make_auditd_event(auid=1000, exe="/usr/bin/who", name="/etc/sudoers", timestamp=datetime(2026, 1, 15, 10, 0, 2, tzinfo=timezone.utc)),
        make_auditd_event(auid=1001, exe="/usr/bin/w", name="/etc/shadow", timestamp=datetime(2026, 1, 15, 10, 0, 3, tzinfo=timezone.utc)),
        make_auditd_event(auid=1000, exe="/usr/bin/getent", name="/etc/passwd", timestamp=datetime(2026, 1, 15, 10, 0, 4, tzinfo=timezone.utc)),
    ]

    alerts = detect(events)

    # No alerts should be generated because the threshold is not met for any single AUID
    assert len(alerts) == 0
def test_five_enumeration_event_but_outside_window(make_auditd_event):
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        make_auditd_event(auid=1000, exe="/usr/bin/whoami", name="/etc/passwd",
                           timestamp=base_time + timedelta(seconds=0)),
        make_auditd_event(auid=1000, exe="/usr/bin/id", name="/etc/group",
                           timestamp=base_time + timedelta(seconds=30)),
        make_auditd_event(auid=1000, exe="/usr/bin/who", name="/etc/sudoers",
                           timestamp=base_time + timedelta(seconds=60)),
        make_auditd_event(auid=1000, exe="/usr/bin/w", name="/etc/shadow",
                           timestamp=base_time + timedelta(seconds=90)),
        make_auditd_event(auid=1000, exe="/usr/bin/getent", name="/etc/passwd",
                           timestamp=base_time + timedelta(seconds=150)),  # Outside the 120s window
    ]
    alerts = detect(events)
    # No alerts should be generated because the last event is outside the 120s window
    assert len(alerts) == 0
