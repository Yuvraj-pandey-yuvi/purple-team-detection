from rules.rule_003_new_user_created import detect

def test_new_user_created_alerts(make_auth_event):
    events=[
        make_auth_event(
            new_username="newuser",
        )
    ]
    alerts=detect(events)
    assert len(alerts) == 1
    assert alerts[0].severity.value == "HIGH"
def test_new_user_created_suspicious_name_alerts(make_auth_event):
    events=[
        make_auth_event(
            new_username="root",
        )
    ]
    alerts=detect(events)
    assert len(alerts) == 1
    assert alerts[0].severity.value == "CRITICAL"
def test_no_new_user_created_no_alert(make_auth_event):
    events=[
        make_auth_event(
            new_username=None,
        )
    ]
    alerts=detect(events)
    assert len(alerts) == 0