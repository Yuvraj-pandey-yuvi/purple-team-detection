from rules.rule_013_system_discovery import detect,DISCOVERY_COMMANDS,THRESHOLD,WINDOW_SECONDS
from datetime import datetime, timezone,timedelta
def test_system_discovery(make_auditd_event):
    # Create a series of auditd events for the same auid
    auid = 1000
    base_time = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    events = [
        make_auditd_event(auid=auid, exe=cmd, timestamp=base_time)
        for cmd in list(DISCOVERY_COMMANDS)[:THRESHOLD]
    ]

    # Call the detect function
    alerts = detect(events)

    # Assert that an alert is generated
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "rule_013_system_discovery"
    assert alert.severity.name == "MEDIUM"
    assert alert.first_seen == base_time
    assert alert.last_seen == base_time
def test_system_discovery_outside_window(make_auditd_event):
    # Create a series of auditd events for the same auid, but spaced out in time
    auid = 1000
    base_time = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    events = [
        make_auditd_event(auid=auid, exe=cmd, timestamp=base_time + timedelta(seconds=i * (WINDOW_SECONDS + 1)))
        for i, cmd in enumerate(list(DISCOVERY_COMMANDS)[:THRESHOLD])
    ]

    # Call the detect function
    alerts = detect(events)

    # Assert that no alert is generated since events are outside the sliding window
    assert len(alerts) == 0
def test_system_discovery_excluded_auid(make_auditd_event):
    # Create a series of auditd events for an excluded auid
    auid = 0  # This is in EXCLUDED_AUIDS
    base_time = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    events = [
        make_auditd_event(auid=auid, exe=cmd, timestamp=base_time)
        for cmd in list(DISCOVERY_COMMANDS)[:THRESHOLD]
    ]

    # Call the detect function
    alerts = detect(events)

    # Assert that no alert is generated since the auid is excluded
    assert len(alerts) == 0
def test_system_discovery_below_threshold(make_auditd_event):
    # Create a series of auditd events for the same auid, but below the threshold
    auid = 1000
    base_time = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    events = [
        make_auditd_event(auid=auid, exe=cmd, timestamp=base_time)
        for cmd in list(DISCOVERY_COMMANDS)[:THRESHOLD - 1]
    ]

    # Call the detect function
    alerts = detect(events)

    # Assert that no alert is generated since the number of events is below the threshold
    assert len(alerts) == 0
def test_system_discovery_multiple_auids(make_auditd_event):
    # Create a series of auditd events for multiple auids
    base_time = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    events = []
    for auid in [1000, 1001]:
        events.extend([
            make_auditd_event(auid=auid, exe=cmd, timestamp=base_time)
            for cmd in list(DISCOVERY_COMMANDS)[:THRESHOLD]
        ])

    # Call the detect function
    alerts = detect(events)

    # Assert that an alert is generated for each auid
    assert len(alerts) == 2
    for alert in alerts:
        assert alert.rule_id == "rule_013_system_discovery"
        assert alert.severity.name == "MEDIUM"
        assert alert.first_seen == base_time
        assert alert.last_seen == base_time
def test_system_discovery_edge_case(make_auditd_event):
    # Create a series of auditd events for the same auid, with one event just outside the window
    auid = 1000
    base_time = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    events = [
        make_auditd_event(auid=auid, exe=cmd, timestamp=base_time + timedelta(seconds=i * (24)))
        for i, cmd in enumerate(list(DISCOVERY_COMMANDS)[:THRESHOLD])
    ]
    # Add one more event just outside the window
    events.append(make_auditd_event(auid=auid, exe="uname", timestamp=base_time + timedelta(seconds=WINDOW_SECONDS + 1)))

    # Call the detect function
    alerts = detect(events)

    # Assert that an alert is generated since there are still THRESHOLD events within the window
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "rule_013_system_discovery"
    assert alert.severity.name == "MEDIUM"  
def test_system_discovery_edge_case_below_threshold(make_auditd_event):
    # Create a series of auditd events for the same auid, with one event just outside the window
    auid = 1000
    base_time = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    events = [
        make_auditd_event(auid=auid, exe=cmd, timestamp=base_time + timedelta(seconds=i * (WINDOW_SECONDS - 1)))
        for i, cmd in enumerate(list(DISCOVERY_COMMANDS)[:THRESHOLD - 1])
    ]
    # Add one more event just outside the window
    events.append(make_auditd_event(auid=auid, exe="uname", timestamp=base_time + timedelta(seconds=WINDOW_SECONDS + 1)))

    # Call the detect function
    alerts = detect(events)

    # Assert that no alert is generated since there are not enough events within the window
    assert len(alerts) == 0
