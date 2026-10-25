# tests/test_auth_log_probe_events.py
# SSH probes on a key-only server: one "probe" event per connection, from REAL log lines.
from schemas import AuthLogEvent

PREFIX = "2026-10-18T00:48:08.985656+00:00 ip-172-31-38-66 "


def parse(message):
    return AuthLogEvent.from_raw(PREFIX + message)


def test_invalid_user_line_with_empty_username_is_a_probe():
    event = parse("sshd-session[190819]: Invalid user  from 180.76.183.185 port 58152")
    assert event.auth_result == "probe"
    assert event.username is None
    assert event.source_ip == "180.76.183.185"
    assert event.port == 58152
    assert event.pid == 190819


def test_invalid_user_line_with_a_name_is_a_probe():
    event = parse("sshd-session[77]: Invalid user admin from 1.2.3.4 port 4000")
    assert event.auth_result == "probe"
    assert event.username == "admin"
    assert event.source_ip == "1.2.3.4"


def test_connection_closed_by_authenticating_user_is_a_probe():
    event = parse(
        "sshd-session[338337]: Connection closed by authenticating user root "
        "144.225.8.54 port 37912 [preauth]"
    )
    assert event.auth_result == "probe"
    assert event.username == "root"
    assert event.source_ip == "144.225.8.54"
    assert event.pid == 338337


def test_second_line_of_an_invalid_user_connection_is_not_counted_again():
    event = parse(
        "sshd-session[190819]: Connection closed by invalid user  "
        "180.76.183.185 port 58152 [preauth]"
    )
    assert event.auth_result is None


def test_closed_by_invalid_user_with_a_name_is_not_counted():
    event = parse(
        "sshd-session[5]: Connection closed by invalid user admin 1.2.3.4 port 9 [preauth]"
    )
    assert event.auth_result is None


def test_connect_and_drop_without_a_username_is_not_a_probe():
    event = parse("sshd-session[6]: Connection closed by 1.2.3.4 port 9 [preauth]")
    assert event.auth_result is None


def test_key_exchange_failure_is_not_a_probe():
    event = parse(
        "sshd-session[8]: Unable to negotiate with 1.2.3.4 port 9: no matching key "
        "exchange method found. Their offer: diffie-hellman-group1-sha1 [preauth]"
    )
    assert event.auth_result is None


def test_our_own_sudo_grep_for_these_words_is_not_a_probe():
    event = parse(
        "sudo: ubuntu : TTY=/dev/pts/0 ; PWD=/home/ubuntu/project ; USER=root ; "
        "COMMAND=/usr/bin/grep -c Failed password\\|Invalid user /var/log/auth.log"
    )
    assert event.auth_result is None


def test_classic_syslog_format_probe_also_works():
    event = AuthLogEvent.from_raw(
        "Jan 15 10:30:00 myhost sshd[1234]: Invalid user test from 5.6.7.8 port 22"
    )
    assert event.auth_result == "probe"
    assert event.source_ip == "5.6.7.8"
    assert event.pid == 1234


def test_failed_password_is_still_failed_not_probe():
    event = parse("sshd[4242]: Failed password for root from 1.2.3.4 port 22 ssh2")
    assert event.auth_result == "failed"
