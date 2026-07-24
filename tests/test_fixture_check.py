def test_make_auth_event_works(make_auth_event):
    event = make_auth_event(source_ip="1.2.3.4", auth_result="failed")
    assert event.source_ip == "1.2.3.4"
    assert event.auth_result == "failed"
    assert event.raw == "placeholder raw log line"  # unset field, got the default