from datetime import datetime, timedelta, timezone
from rules.rule_002_no_mfa_login import detect

def test_no_mfa_login_fires_alert(make_cloudtrail_event):
    events = [
        make_cloudtrail_event(
            event_name="ConsoleLogin",
            mfa_authenticated="false",   # note: string now, not False
            login_success=True,
        )
    ]
    alerts = detect(events)
    assert len(alerts) == 1
    assert alerts[0].severity.value == "CRITICAL"
def test_console_login_with_mfa_no_alert(make_cloudtrail_event):
    events = [
        make_cloudtrail_event(
            event_name="ConsoleLogin",
            mfa_authenticated="true",   # note: string now, not True
            login_success=True,
        )
    ]
    alerts = detect(events)
    assert len(alerts) == 0
def test_api_call_without_mfa_fires_medium_alert(make_cloudtrail_event):
    events = [
        make_cloudtrail_event(
            event_name="DescribeMetricFilters",
            mfa_authenticated="false",   # note: string now, not False
            actor_type="IAMUser",
        )
    ]
    alerts = detect(events)
    assert len(alerts) == 1
    assert alerts[0].severity.value == "MEDIUM"
def test_errored_api_call_no_alert(make_cloudtrail_event):
    events = [
        make_cloudtrail_event(
            event_name="DescribeMetricFilters",
            mfa_authenticated="false",   # note: string now, not False
            actor_type="IAMUser",
            error_code="AccessDenied",
        )
    ]
    alerts = detect(events)
    assert len(alerts) == 0