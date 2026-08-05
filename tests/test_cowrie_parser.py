"""
tests/test_cowrie_parser.py
----------------------------
Tests parse_cowrie_sessions() against a REAL captured Cowrie session
(one full SSH connection: connect -> login success -> 4 commands -> close),
pulled directly from var/log/cowrie/cowrie.json during manual testing.
Using real output, not fabricated JSON, so the test catches actual
format mismatches Cowrie's own log writer produces.
"""

from schemas import parse_cowrie_sessions


REAL_COWRIE_SESSION = """\
{"session":"43707ec1b68e","protocol":"ssh","src_ip":"172.18.0.1","src_port":56386,"dst_ip":"172.18.0.2","dst_port":2222,"eventid":"cowrie.session.connect","sensor":"58b90443c871","uuid":"8409e476-8f21-11f1-a428-b2564507e741","timestamp":"2026-08-03T09:57:04.574711Z","message":"New connection"}
{"session":"43707ec1b68e","protocol":"ssh","src_ip":"172.18.0.1","src_port":56386,"dst_ip":"172.18.0.2","dst_port":2222,"username":"root","password":"12345678","eventid":"cowrie.login.success","sensor":"58b90443c871","uuid":"8409e476-8f21-11f1-a428-b2564507e741","timestamp":"2026-08-03T09:57:17.550525Z","message":"login attempt [root/12345678] succeeded"}
{"session":"43707ec1b68e","protocol":"ssh","src_ip":"172.18.0.1","src_port":56386,"dst_ip":"172.18.0.2","dst_port":2222,"input":"whoami","eventid":"cowrie.command.input","sensor":"58b90443c871","uuid":"8409e476-8f21-11f1-a428-b2564507e741","timestamp":"2026-08-03T09:57:26.197548Z","message":"CMD: whoami"}
{"session":"43707ec1b68e","protocol":"ssh","src_ip":"172.18.0.1","src_port":56386,"dst_ip":"172.18.0.2","dst_port":2222,"input":"ls","eventid":"cowrie.command.input","sensor":"58b90443c871","uuid":"8409e476-8f21-11f1-a428-b2564507e741","timestamp":"2026-08-03T09:57:29.404460Z","message":"CMD: ls"}
{"session":"43707ec1b68e","protocol":"ssh","src_ip":"172.18.0.1","src_port":56386,"dst_ip":"172.18.0.2","dst_port":2222,"input":"cd ..","eventid":"cowrie.command.input","sensor":"58b90443c871","uuid":"8409e476-8f21-11f1-a428-b2564507e741","timestamp":"2026-08-03T09:57:33.049707Z","message":"CMD: cd .."}
{"session":"43707ec1b68e","protocol":"ssh","src_ip":"172.18.0.1","src_port":56386,"dst_ip":"172.18.0.2","dst_port":2222,"input":"ls","eventid":"cowrie.command.input","sensor":"58b90443c871","uuid":"8409e476-8f21-11f1-a428-b2564507e741","timestamp":"2026-08-03T09:57:34.868031Z","message":"CMD: ls"}
{"session":"43707ec1b68e","protocol":"ssh","src_ip":"172.18.0.1","src_port":56386,"dst_ip":"172.18.0.2","dst_port":2222,"duration_ms":44963,"eventid":"cowrie.session.closed","sensor":"58b90443c871","uuid":"8409e476-8f21-11f1-a428-b2564507e741","timestamp":"2026-08-03T09:57:49.538533Z","message":"Connection lost after 44963 milliseconds"}
"""


def test_parses_single_real_session(tmp_path):
    log_file = tmp_path / "cowrie.json"
    log_file.write_text(REAL_COWRIE_SESSION)

    sessions = parse_cowrie_sessions(str(log_file))

    assert len(sessions) == 1
    session = sessions[0]

    assert session.session_id == "43707ec1b68e"
    assert session.src_ip == "172.18.0.1"
    assert session.duration_ms == 44963


def test_login_attempt_captured_correctly():
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(REAL_COWRIE_SESSION)
        path = f.name

    sessions = parse_cowrie_sessions(path)
    os.unlink(path)

    session = sessions[0]
    assert len(session.login_attempts) == 1
    attempt = session.login_attempts[0]
    assert attempt.username == "root"
    assert attempt.password == "12345678"
    assert attempt.success is True


def test_commands_captured_in_order():
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(REAL_COWRIE_SESSION)
        path = f.name

    sessions = parse_cowrie_sessions(path)
    os.unlink(path)

    session = sessions[0]
    assert len(session.commands) == 4
    assert [c.input for c in session.commands] == ["whoami", "ls", "cd ..", "ls"]


def test_multiple_sessions_stay_separated():
    """Simulates two attackers connecting close together — the exact
    interleaving scenario that makes session-id grouping necessary."""
    line_a = '{"session":"aaa111","protocol":"ssh","src_ip":"1.1.1.1","src_port":1,"dst_ip":"2.2.2.2","dst_port":2222,"eventid":"cowrie.session.connect","sensor":"x","uuid":"x","timestamp":"2026-08-03T10:00:00.000000Z","message":"connect"}\n'
    line_b = '{"session":"bbb222","protocol":"ssh","src_ip":"9.9.9.9","src_port":2,"dst_ip":"2.2.2.2","dst_port":2222,"eventid":"cowrie.session.connect","sensor":"x","uuid":"x","timestamp":"2026-08-03T10:00:01.000000Z","message":"connect"}\n'
    line_a_cmd = '{"session":"aaa111","protocol":"ssh","src_ip":"1.1.1.1","src_port":1,"dst_ip":"2.2.2.2","dst_port":2222,"input":"whoami","eventid":"cowrie.command.input","sensor":"x","uuid":"x","timestamp":"2026-08-03T10:00:02.000000Z","message":"CMD"}\n'
    line_b_cmd = '{"session":"bbb222","protocol":"ssh","src_ip":"9.9.9.9","src_port":2,"dst_ip":"2.2.2.2","dst_port":2222,"input":"ls","eventid":"cowrie.command.input","sensor":"x","uuid":"x","timestamp":"2026-08-03T10:00:03.000000Z","message":"CMD"}\n'

    interleaved = line_a + line_b + line_a_cmd + line_b_cmd

    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(interleaved)
        path = f.name

    sessions = parse_cowrie_sessions(path)
    os.unlink(path)

    assert len(sessions) == 2
    by_id = {s.session_id: s for s in sessions}
    assert by_id["aaa111"].src_ip == "1.1.1.1"
    assert by_id["aaa111"].commands[0].input == "whoami"
    assert by_id["bbb222"].src_ip == "9.9.9.9"
    assert by_id["bbb222"].commands[0].input == "ls"
