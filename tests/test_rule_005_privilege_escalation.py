from rules.rule_005_privilige_escalation import detect

def test_detect_privilege_escalation_fires_alert(make_auditd_event):
    event = make_auditd_event(
        key="sudo_execution",
        exe="/usr/bin/sudo",
        auid=1000,
        uid=1000,
        euid=0,
    )
    alerts = detect([event])
    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"
def test_key_not_in_privilege_escalation_keys_but_is_privileged_escalation(make_auditd_event):
    event = make_auditd_event(
        key="some_other_key",
        exe="/usr/bin/sudo",
        auid=1000,
        uid=1000,
        euid=0,
    )
    alerts = detect([event])
    assert len(alerts) == 0

def test_key_not_in_privilege_escalation_keys_and_not_privileged_escalation(make_auditd_event):
    event = make_auditd_event(
        key="some_other_key",
        exe="/usr/bin/sudo",
        auid=1000,
        uid=1000,
        euid=1000,
    )
    alerts = detect([event])
    assert len(alerts) == 0
def test_key_in_privilege_escalation_keys_but_not_privileged_escalation(make_auditd_event):
    event = make_auditd_event(
        key="sudo_execution",
        exe="/usr/bin/sudo",
        auid=1000,
        uid=1000,
        euid=1000,
    )
    alerts = detect([event])
    assert len(alerts) == 0
def test_detect_privilege_escalation_with_non_privileged_user(make_auditd_event):
    event = make_auditd_event(
        key="sudo_execution",
        exe="/usr/bin/sudo",
        auid=1001,  # non-privileged user
        uid=1001,
        euid=0,
    )
    alerts = detect([event])
    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"
def test_detect_privilege_escalation_with_unset_auid(make_auditd_event):
    event = make_auditd_event(
        key="sudo_execution",
        exe="/usr/bin/sudo",
        auid=4294967295,  # unset auid
        uid=1000,
        euid=0,
    )
    alerts = detect([event])
    assert len(alerts) == 0
def test_detect_privilege_escalation_with_root_user(make_auditd_event):
    event = make_auditd_event(
        key="sudo_execution",
        exe="/usr/bin/sudo",
        auid=0,  # root user
        uid=0,
        euid=0,
    )
    alerts = detect([event])
    assert len(alerts) == 0

    


    