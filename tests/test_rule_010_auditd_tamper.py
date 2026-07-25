from rules.rule_010_auditd_disabled import detect, TAMPER_KEYS
from tests.conftest import make_auditd_event

def test_detect_auditd_tamper(make_auditd_event):
    events=[
        make_auditd_event(key="auditd_tamper",auid=1000,euid=1000,),
        make_auditd_event(key="auditd_rules_tamper",auid=1000,euid=1000,),
        make_auditd_event(key="syslog_tamper",auid=1000,euid=1000,),
        make_auditd_event(key="bootloader_tamper",auid=1000,euid=1000,),
    ]
    alerts = detect(events)
    assert len(alerts) == 4
    assert alerts[0].severity == "HIGH"
    assert alerts[1].severity == "HIGH"
    assert alerts[2].severity == "HIGH"
    assert alerts[3].severity == "HIGH"
def test_detect_auditd_tamper_privileged(make_auditd_event):
    events=[
        make_auditd_event(key="auditd_tamper",auid=1000,euid=0,),
        make_auditd_event(key="auditd_rules_tamper",auid=1000,euid=0,),
        make_auditd_event(key="syslog_tamper",auid=1000,euid=0,),
        make_auditd_event(key="bootloader_tamper",auid=1000,euid=0,),
    ]
    alerts = detect(events)
    assert len(alerts) == 4
    assert alerts[0].severity == "CRITICAL"
    assert alerts[1].severity == "CRITICAL"
    assert alerts[2].severity == "CRITICAL"
    assert alerts[3].severity == "CRITICAL"
def test_detect_auditd_tamper_ignore_non_tamper(make_auditd_event):
    event = make_auditd_event(
        key="non_tamper_key", 
        auid=1000, 
        euid=1000, 
        )
    alerts = detect([event])
    assert len(alerts) == 0
def test_tamper_keys():
    assert TAMPER_KEYS == {
        "auditd_tamper",
        "auditd_rules_tamper",
        "syslog_tamper",
        "bootloader_tamper"
    }       
       