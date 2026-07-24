from rules.rule_004_shadow_access import detect

def test_detect_shadow_access(make_auditd_event):
    events = [
        make_auditd_event(
            auid=1001,
            euid=1,
            exe="/usr/bin/unknown",
            comm="unknown",
            key="shadow_access",
        )
    ]

    alerts = detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"

def test_detect_shadow_access_whitelisted_exe(make_auditd_event):
    events = [
        make_auditd_event(
            auid=1001,
            euid=1,
            exe="/usr/bin/passwd",
            comm="passwd",
            key="shadow_access",
        )
    ]

    alerts = detect(events)

    assert len(alerts) == 0

def test_detect_shadow_access_admin_non_privileged(make_auditd_event):
    events = [
        make_auditd_event(
            auid=1000,  # admin user
            euid=1001,  # non-privileged
            exe="/usr/bin/unknown",
            comm="unknown",
            key="shadow_access",
        )
    ]

    alerts = detect(events)

    assert len(alerts) == 0
def test_detect_shadow_access_non_shadow_key(make_auditd_event):
    events = [
        make_auditd_event(
            auid=1001,
            euid=1,
            exe="/usr/bin/unknown",
            comm="unknown",
            key="other_key",
        )
    ]

    alerts = detect(events)

    assert len(alerts) == 0