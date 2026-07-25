from rules.rule_008_cron_persisitence import detect

def test_detect_cron_modification(make_auditd_event):
    event = make_auditd_event(
        key="cron_modification",
        syscall=257,  # openat
        auid=1000,
        euid=0,
    )
    alerts = detect([event])
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "rule_008_cron_persistence"
    assert alert.severity == "CRITICAL"
def test_detect_non_cron_modification(make_auditd_event):
    event = make_auditd_event(
        key="some_other_key",
        syscall=257,  # openat
        auid=1000,
        euid=0,
    )
    alerts = detect([event])
    assert len(alerts) == 0
def test_detect_non_write_syscall(make_auditd_event):
    event = make_auditd_event(
        key="cron_modification",
        syscall=1,  # write
        auid=1000,
        euid=0,
    )
    alerts = detect([event])
    assert len(alerts) == 0
def test_detect_non_privileged_escalation(make_auditd_event):
    event = make_auditd_event(
        key="cron_modification",
        syscall=257,  # openat
        auid=0,
        euid=0,
    )
    alerts = detect([event])
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity == "HIGH"
def test_detect_missing_syscall(make_auditd_event):
    event = make_auditd_event(
        key="cron_modification",
        syscall=None,
        auid=1000,
        euid=0,
    )
    alerts = detect([event])
    assert len(alerts) == 0