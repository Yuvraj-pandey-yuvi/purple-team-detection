import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pytest 
from datetime import datetime, timezone
from schemas import AuthLogEvent, LogSource
from schemas import AuthLogEvent, LogSource, CloudTrailEvent

@pytest.fixture
def make_auth_event():
    def _make(**overrides):
        defaults = dict(
            timestamp=datetime(2026,1,15,10,30,0,tzinfo=timezone.utc),
            raw="placeholder raw log line",
        )
        defaults.update(overrides)
        return AuthLogEvent(**defaults)
    return _make

@pytest.fixture
def make_cloudtrail_event():
    """Builds a CloudTrailEvent via from_record(), using REAL AWS-shaped
    nested JSON (camelCase keys, nested userIdentity block) — NOT flat
    kwargs. Required because extract_actor_info() is a
    model_validator(mode="after") that runs on every construction and
    unconditionally derives actor_type/mfa_authenticated from
    user_identity_raw — it would silently overwrite anything set directly.
    """
    def _make(
        event_name: str = "ConsoleLogin",
        mfa_authenticated: str = "false",   # AWS sends this as a STRING
        source_ip: str = "203.0.113.5",
        username: str = "buddy",
        login_success: bool = True,
        actor_type: str = "IAMUser",
        error_code=None,
    ):
        record = {
            "eventVersion": "1.11",
            "userIdentity": {
                "type": actor_type,
                "userName": username,
                "sessionContext": {
                    "attributes": {"mfaAuthenticated": mfa_authenticated}
                },
            },
            "eventTime": "2026-01-15T10:30:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": event_name,
            "awsRegion": "us-east-1",
            "sourceIPAddress": source_ip,
            "responseElements": (
                {"ConsoleLogin": "Success"} if login_success else None
            ),
            "errorCode": error_code,
        }
        return CloudTrailEvent.from_record(record)
    return _make