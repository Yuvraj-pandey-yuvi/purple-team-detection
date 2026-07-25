from rules.rule_009_cloudtrail_disabled import detect, CRITICAL_EVENTS, HIGH_EVENTS

def test_detect_critical_event(make_cloudtrail_event):
    event = make_cloudtrail_event(event_name="DeleteTrail")
    alerts = detect([event])
    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"
    assert alerts[0].description.startswith("CloudTrail impaired: DeleteTrail")

def test_detect_critical_event2(make_cloudtrail_event):
    event = make_cloudtrail_event(event_name="StopLogging")
    alerts = detect([event])
    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"
    assert alerts[0].description.startswith("CloudTrail impaired: StopLogging")
def test_detect_high_event(make_cloudtrail_event):
    event = make_cloudtrail_event(event_name="UpdateTrail")
    alerts = detect([event])
    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].description.startswith("CloudTrail impaired: UpdateTrail")
def test_detect_high_event2(make_cloudtrail_event):
    event = make_cloudtrail_event(event_name="PutEventSelectors")
    alerts = detect([event])
    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].description.startswith("CloudTrail impaired: PutEventSelectors")
def test_detect_non_critical_event(make_cloudtrail_event):
    event = make_cloudtrail_event(event_name="SomeOtherEvent")
    alerts = detect([event])
    assert len(alerts) == 0
def test_detect_multiple_events(make_cloudtrail_event):
    events = [
        make_cloudtrail_event(event_name="DeleteTrail"),
        make_cloudtrail_event(event_name="StopLogging"),
        make_cloudtrail_event(event_name="UpdateTrail"),
        make_cloudtrail_event(event_name="PutEventSelectors"),
        make_cloudtrail_event(event_name="SomeOtherEvent"),
    ]
    alerts = detect(events)
    assert len(alerts) == 4
    assert any(alert.severity == "CRITICAL" for alert in alerts)
    assert any(alert.severity == "HIGH" for alert in alerts)
