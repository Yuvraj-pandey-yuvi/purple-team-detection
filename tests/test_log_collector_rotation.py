# tests/test_log_collector_rotation.py
import os
from logs import log_collector


def append_to_file(path, text):
    with open(path, "a") as log_file:
        log_file.write(text)


def simulate_logrotate(log_directory, base_name):
    """What logrotate does: rename old file to .1, create a brand-new file."""
    current_path = os.path.join(log_directory, base_name)
    rotated_path = os.path.join(log_directory, base_name + ".1")
    os.rename(current_path, rotated_path)
    open(current_path, "w").close()   # new file, new inode
    return rotated_path


def make_collector(tmp_path, monkeypatch):
    monkeypatch.setattr(log_collector, "STATE_FILE", str(tmp_path / "state.json"))
    log_path = tmp_path / "auth.log"
    log_path.write_text("")
    return str(log_path)


def read(log_path):
    return log_collector.read_new_lines(log_path, "auth_log_position")


def test_first_run_reads_everything(tmp_path, monkeypatch):
    log_path = make_collector(tmp_path, monkeypatch)
    append_to_file(log_path, "line 1\nline 2\n")
    assert read(log_path) == ["line 1", "line 2"]


def test_second_run_reads_only_new_lines(tmp_path, monkeypatch):
    log_path = make_collector(tmp_path, monkeypatch)
    append_to_file(log_path, "line 1\n")
    read(log_path)
    append_to_file(log_path, "line 2\n")
    assert read(log_path) == ["line 2"]


def test_rotation_drains_unread_tail_of_old_file(tmp_path, monkeypatch):
    log_path = make_collector(tmp_path, monkeypatch)
    append_to_file(log_path, "old 1\n")
    read(log_path)
    append_to_file(log_path, "old 2 unread\n")      # written before rotation, never read
    simulate_logrotate(str(tmp_path), "auth.log")
    append_to_file(log_path, "new 1\n")
    assert read(log_path) == ["old 2 unread", "new 1"]


def test_rotation_with_old_file_deleted_still_reads_new_file(tmp_path, monkeypatch):
    log_path = make_collector(tmp_path, monkeypatch)
    append_to_file(log_path, "old 1\n")
    read(log_path)
    rotated_path = simulate_logrotate(str(tmp_path), "auth.log")
    os.remove(rotated_path)                          # data-loss path
    append_to_file(log_path, "new 1\n")
    assert read(log_path) == ["new 1"]


def test_new_file_bigger_than_saved_offset_is_not_skipped(tmp_path, monkeypatch):
    log_path = make_collector(tmp_path, monkeypatch)
    append_to_file(log_path, "tiny\n")               # saved offset will be small
    read(log_path)
    rotated_path = simulate_logrotate(str(tmp_path), "auth.log")
    os.remove(rotated_path)
    append_to_file(log_path, "a much longer first line in the new file\nsecond\n")
    assert read(log_path) == ["a much longer first line in the new file", "second"]


def test_old_format_state_resets_to_zero(tmp_path, monkeypatch):
    log_path = make_collector(tmp_path, monkeypatch)
    append_to_file(log_path, "line 1\nline 2\n")
    (tmp_path / "state.json").write_text('{"auth_log_position": 7}')  # offset, no inode
    assert read(log_path) == ["line 1", "line 2"]


def test_half_written_last_line_is_not_consumed(tmp_path, monkeypatch):
    log_path = make_collector(tmp_path, monkeypatch)
    append_to_file(log_path, "complete line\nhalf writ")
    assert read(log_path) == ["complete line"]
    append_to_file(log_path, "ten now\n")
    assert read(log_path) == ["half written now"]


def test_formfeed_inside_a_line_does_not_split_it(tmp_path, monkeypatch):
    log_path = make_collector(tmp_path, monkeypatch)
    append_to_file(log_path, "before\x0cafter\nnext\n")
    assert read(log_path) == ["before\x0cafter", "next"]


def test_other_state_keys_survive_a_read(tmp_path, monkeypatch):
    log_path = make_collector(tmp_path, monkeypatch)
    (tmp_path / "state.json").write_text(
        '{"cloudtrail_last_file": "abc.json", "cowrie_position": 5545}'
    )
    append_to_file(log_path, "line 1\n")
    read(log_path)
    import json
    saved = json.loads((tmp_path / "state.json").read_text())
    assert saved["cloudtrail_last_file"] == "abc.json"
    assert saved["cowrie_position"] == 5545
    assert "auth_log_position_inode" in saved
