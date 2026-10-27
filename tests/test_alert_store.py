# tests/test_alert_store.py
# alerts.json must survive crashes, concurrent writers and unreadable content.
import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from detection import engine
from rules.rule_001_ssh_brute_force import detect as detect_ssh_burst

START = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def alerts_file(tmp_path, monkeypatch):
    path = tmp_path / "alerts.json"
    monkeypatch.setattr(engine, "ALERTS_FILE", str(path))
    return path


@pytest.fixture
def make_alert(make_auth_event):
    def _make(source_ip):
        events = [
            make_auth_event(
                timestamp=START + timedelta(seconds=index * 2),
                source_ip=source_ip,
                auth_result="failed",
            )
            for index in range(5)
        ]
        return detect_ssh_burst(events)[0]
    return _make


def test_missing_file_means_no_alerts(alerts_file):
    assert engine.load_existing_alerts() == []


def test_save_then_load_round_trip(alerts_file, make_alert):
    saved = [make_alert("1.1.1.1"), make_alert("2.2.2.2")]
    engine.save_alerts(saved)
    loaded = engine.load_existing_alerts()
    assert [a.dedup_key for a in loaded] == [a.dedup_key for a in saved]


def test_crash_during_write_keeps_the_original_file(alerts_file, make_alert, monkeypatch):
    engine.save_alerts([make_alert("1.1.1.1"), make_alert("2.2.2.2")])

    def dump_that_dies_halfway(data, file, **kwargs):
        file.write('[{"half": ')
        raise RuntimeError("process killed mid-write")

    monkeypatch.setattr(engine.json, "dump", dump_that_dies_halfway)
    with pytest.raises(RuntimeError):
        engine.save_alerts([make_alert("3.3.3.3")])
    monkeypatch.undo()

    monkeypatch.setattr(engine, "ALERTS_FILE", str(alerts_file))
    assert len(engine.load_existing_alerts()) == 2
    leftovers = [name for name in os.listdir(alerts_file.parent) if name.endswith(".tmp")]
    assert leftovers == []


def test_reader_never_sees_a_half_written_file(alerts_file, make_alert, monkeypatch):
    engine.save_alerts([make_alert("1.1.1.1"), make_alert("2.2.2.2")])
    half_written = threading.Event()
    let_writer_finish = threading.Event()
    real_dump = json.dump

    def slow_dump(data, file, **kwargs):
        file.write("[")                      # the file is now half-written ...
        file.flush()
        half_written.set()
        assert let_writer_finish.wait(timeout=5)
        file.seek(0)
        file.truncate()
        real_dump(data, file, **kwargs)

    monkeypatch.setattr(engine.json, "dump", slow_dump)
    writer = threading.Thread(target=engine.save_alerts, args=([make_alert("3.3.3.3")],))
    writer.start()
    assert half_written.wait(timeout=5)
    with open(alerts_file) as reader:        # a reader arrives in the middle of the write
        visible = json.load(reader)
    let_writer_finish.set()
    writer.join()
    assert len(visible) == 2                 # the old, COMPLETE file


def test_unreadable_file_raises_and_is_preserved(alerts_file):
    alerts_file.write_text("{not valid json")
    with pytest.raises(engine.AlertStoreError):
        engine.load_existing_alerts()
    assert alerts_file.read_text() == "{not valid json"
    assert (alerts_file.parent / "alerts.json.corrupt").read_text() == "{not valid json"


def test_file_that_is_not_a_json_array_is_rejected(alerts_file):
    alerts_file.write_text('{"alerts": []}')
    with pytest.raises(engine.AlertStoreError):
        engine.load_existing_alerts()
    assert alerts_file.read_text() == '{"alerts": []}'


def test_preflight_check_counts_entries_and_rejects_bad_files(alerts_file, make_alert):
    assert engine.check_alert_store() == 0
    engine.save_alerts([make_alert("1.1.1.1")])
    assert engine.check_alert_store() == 1
    alerts_file.write_text("not json")
    with pytest.raises(engine.AlertStoreError):
        engine.check_alert_store()


def test_merge_and_save_keeps_both_alerts_when_two_writers_overlap(alerts_file, make_alert, monkeypatch):
    original_load = engine.load_existing_alerts

    def slow_load():
        loaded = original_load()
        time.sleep(0.3)                      # widen the read-modify-write gap
        return loaded

    monkeypatch.setattr(engine, "load_existing_alerts", slow_load)
    first_writer = threading.Thread(target=engine.merge_and_save, args=([make_alert("1.1.1.1")],))
    second_writer = threading.Thread(target=engine.merge_and_save, args=([make_alert("2.2.2.2")],))
    first_writer.start(); second_writer.start()
    first_writer.join(); second_writer.join()
    monkeypatch.setattr(engine, "load_existing_alerts", original_load)
    keys = sorted(a.dedup_key for a in engine.load_existing_alerts())
    assert keys == ["1.1.1.1|2026-01-15", "2.2.2.2|2026-01-15"]


def test_merge_and_save_suppresses_duplicates(alerts_file, make_alert):
    engine.save_alerts([make_alert("1.1.1.1")])
    all_alerts, new_only = engine.merge_and_save([make_alert("1.1.1.1"), make_alert("2.2.2.2")])
    assert len(new_only) == 1
    assert len(all_alerts) == 2
    assert len(engine.load_existing_alerts()) == 2


def test_engine_stops_before_reading_any_logs_if_store_is_unreadable(alerts_file, monkeypatch):
    alerts_file.write_text("{broken")

    def must_not_run(*args, **kwargs):
        raise AssertionError("a collector ran although the alert store is unreadable")

    monkeypatch.setattr(engine, "collect_auth_logs", must_not_run)
    with pytest.raises(engine.AlertStoreError):
        engine.run_engine()
