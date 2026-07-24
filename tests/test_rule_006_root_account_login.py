from rules.rule_006_root_account_login import detect

def test_detect_root_console_login(make_cloudtrail_event):
    event = make_cloudtrail_event(
       actor_type="Root",
       event_name="ConsoleLogin",
        login_success=True,
    ) 
    alerts = detect([event])
    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"
def test_detect_root_actor_type_with_non_console_login(make_cloudtrail_event):
    event = make_cloudtrail_event(
        actor_type="Root",
        event_name="SomeOtherEvent",
        login_success=True,
    )
    alerts = detect([event])
    assert len(alerts) == 0
def test_detect_non_root_actor_type_with_console_login(make_cloudtrail_event):
    event = make_cloudtrail_event(
        actor_type="IAMUser",
        event_name="ConsoleLogin",
        login_success=True,
    )
    alerts = detect([event])
    assert len(alerts) == 0
def test_root_actor_type_with_console_login_but_unsuccessful(make_cloudtrail_event):
    event = make_cloudtrail_event(
        actor_type="Root",
        event_name="ConsoleLogin",
        login_success=False,
    )
    alerts = detect([event])
    assert len(alerts) == 0
def test_root_actor_type_with_non_console_login_and_unsuccessful(make_cloudtrail_event):
    event = make_cloudtrail_event(
        actor_type="Root",
        event_name="SomeOtherEvent",
        login_success=False,
    )
    alerts = detect([event])
    assert len(alerts) == 0
