# tests/test_auth_log_iso_fields.py
# hostname / process / pid must be read correctly from BOTH log formats.
from schemas import AuthLogEvent

ISO_SSHD_LINE = (
    "2026-10-18T00:48:08.985656+00:00 ip-172-31-38-66 "
    "sshd-session[190819]: Invalid user  from 180.76.183.185 port 58152"
)
ISO_SUDO_LINE = (
    "2026-10-24T10:53:54.984159+00:00 ip-172-31-38-66 sudo: ubuntu : TTY=/dev/pts/0 ; "
    "PWD=/home/ubuntu/project ; USER=root ; COMMAND=/usr/bin/tail -2 /var/log/auth.log"
)
ISO_FAILED_PASSWORD_LINE = (
    "2026-10-20T03:00:01.123456+00:00 ip-172-31-38-66 "
    "sshd[4242]: Failed password for root from 1.2.3.4 port 22 ssh2"
)
SYSLOG_FAILED_PASSWORD_LINE = (
    "Jan 15 10:30:00 myhost sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"
)


def test_iso_sshd_session_line_has_host_process_and_pid():
    event = AuthLogEvent.from_raw(ISO_SSHD_LINE)
    assert event.hostname == "ip-172-31-38-66"
    assert event.process == "sshd-session"
    assert event.pid == 190819


def test_iso_sudo_line_has_process_and_no_pid():
    event = AuthLogEvent.from_raw(ISO_SUDO_LINE)
    assert event.hostname == "ip-172-31-38-66"
    assert event.process == "sudo"
    assert event.pid is None


def test_iso_failed_password_line_still_parses_and_now_has_pid():
    event = AuthLogEvent.from_raw(ISO_FAILED_PASSWORD_LINE)
    assert event.auth_result == "failed"
    assert event.source_ip == "1.2.3.4"
    assert event.hostname == "ip-172-31-38-66"
    assert event.process == "sshd"
    assert event.pid == 4242


def test_classic_syslog_line_still_works():
    event = AuthLogEvent.from_raw(SYSLOG_FAILED_PASSWORD_LINE)
    assert event.hostname == "myhost"
    assert event.process == "sshd"
    assert event.pid == 1234
