import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pytest 
from datetime import datetime, timezone
from schemas import AuthLogEvent, LogSource

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
