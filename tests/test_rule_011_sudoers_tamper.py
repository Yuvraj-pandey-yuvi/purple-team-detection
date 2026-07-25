from rules.rule_011_sudoers_tamper import detect
from schemas.base import Severity 

def test_detect_sudoers_tamper(make_auditd_event):
    events = [
        make_auditd_event(
            key="sudoers_tamper",
            name="/etc/sudoers",
            auid=1000,
            euid=0,
            exe="/usr/bin/vim",
            comm="vim"
        )
    ]

    alerts = detect(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "rule_011_sudoers_tamper"
    assert alerts[0].severity == Severity.CRITICAL
def test_detect_non_sudoers_event(make_auditd_event):
    events = [
        make_auditd_event(
            key="some_other_event"
        )
    ]

    alerts = detect(events)

    assert len(alerts) == 0
def test_detect_multiple_events(make_auditd_event):
    events = [
        make_auditd_event(
            key="sudoers_tamper",
            name="/etc/sudoers",
            auid=1000,
            euid=0,
            exe="/usr/bin/vim",
            comm="vim"
        ),
        make_auditd_event(
            key="some_other_event"
        ),
        make_auditd_event(
            key="sudoers_tamper",
            name="/etc/sudoers",
            auid=1000,
            euid=0,
            exe="/usr/bin/vim",
            comm="vim"
        )
    ]

    alerts = detect(events)

    assert len(alerts) == 2
    for alert in alerts:
        assert alert.rule_id == "rule_011_sudoers_tamper"
        assert alert.severity == Severity.CRITICAL