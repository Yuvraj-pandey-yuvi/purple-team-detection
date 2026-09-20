# correlation/loader.py
# Stage 1 — Load & validate alerts.json into real Alert objects.
#
# Design recap (agreed in this project's Phase 5 design session):
#   - alerts.json is written by the engine's independent 5-minute loop.
#     This script is a SEPARATE process reading the same file, so a
#     lock is required to avoid reading mid-write (known, documented
#     project risk — no locking existed before this).
#   - Reconstruct into real Pydantic Alert objects, not raw dicts —
#     catches type mismatches loudly, at load time, not three steps
#     later inside matching logic.
#   - A malformed individual entry must NOT abort the whole run.
#     Skip it, log it to correlation_errors.log, print a stdout nudge.
#     (Same philosophy as rule_017's skip-and-log for unmapped tags.)

import json
import fcntl
import time
from datetime import datetime, timezone
from pathlib import Path

from schemas import Alert

# correlation/loader.py lives at /correlation/loader.py — same
# sibling-of-detection/ pattern as engine.py's own ALERTS_FILE computation,
# so this resolves to the exact same <repo_root>/reports/alerts.json engine.py
# writes to, regardless of what directory this script is run from.
ALERTS_PATH = str(Path(__file__).resolve().parent.parent / "reports" / "alerts.json")
ERROR_LOG_PATH = str(Path(__file__).resolve().parent / "correlation_errors.log")

LOCK_RETRY_ATTEMPTS = 5
LOCK_RETRY_DELAY_SECONDS = 0.5


class LockAcquisitionFailed(Exception):
    """Raised when the shared lock on alerts.json couldn't be acquired
    after LOCK_RETRY_ATTEMPTS — signals the caller to skip this run."""
    pass


def load_alerts() -> list[Alert]:
    """
    Read alerts.json under a shared (read) lock, reconstruct each
    entry into a real Alert object.

    Returns only the entries that parsed successfully. Anything that
    fails to validate is skipped, not fatal — see _handle_parse_error.

    If the lock can't be acquired (engine is mid-write for longer than
    the retry budget), this run is skipped entirely — the next
    scheduled run will just try again, since correlation is fully
    stateless/re-derived each time.
    """
    try:
        raw_entries = _read_locked(ALERTS_PATH)
    except LockAcquisitionFailed:
        print(f"  [SKIP] Could not acquire lock on {ALERTS_PATH} "
              f"after {LOCK_RETRY_ATTEMPTS} attempts — skipping this run.")
        return []

    alerts: list[Alert] = []
    for i, entry in enumerate(raw_entries):
        try:
            alert = Alert.model_validate(entry)
            alerts.append(alert)
        except Exception as e:
            _handle_parse_error(index=i, raw_entry=entry, error=e)

    return alerts


def _read_locked(path: str) -> list[dict]:
    """
    Open `path` under a SHARED lock (LOCK_SH) — this script only ever
    reads, and multiple readers may safely hold a shared lock at once.
    The engine's writer is expected to take an EXCLUSIVE lock (LOCK_EX)
    around its write, so a shared lock here correctly blocks against
    that, but not against other concurrent readers.

    Tries LOCK_RETRY_ATTEMPTS times, non-blocking, with a short sleep
    between attempts. Raises LockAcquisitionFailed if still unavailable
    after all attempts.
    """
    for attempt in range(1, LOCK_RETRY_ATTEMPTS + 1):
        try:
            with open(path) as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
                try:
                    return json.load(f)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except BlockingIOError:
            # Someone else (the engine, presumably) holds LOCK_EX right now.
            if attempt < LOCK_RETRY_ATTEMPTS:
                time.sleep(LOCK_RETRY_DELAY_SECONDS)
            continue

    raise LockAcquisitionFailed


def _handle_parse_error(index: int, raw_entry: dict, error: Exception) -> None:
    """
    One alerts.json entry failed to parse into an Alert.

    Appends a line to correlation_errors.log with enough context to
    debug later, and prints a short nudge to stdout so it's not
    silently missed.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    # raw_entry might not even be a dict (see the model_type error case
    # we tested — a stray string/null in the file). Don't assume
    # .get() works; fall back to repr() for anything else.
    if isinstance(raw_entry, dict):
        rule_id = raw_entry.get("rule_id", "<unknown>")
    else:
        rule_id = "<malformed entry, not a dict>"

    log_line = (
        f"[{timestamp}] entry_index={index} rule_id={rule_id} "
        f"error={error}\n"
        f"    raw_entry={raw_entry!r}\n"
    )

    with open(ERROR_LOG_PATH, "a") as f:
        f.write(log_line)

    print(f"  [WARN] Skipped malformed alert at index {index} "
          f"(rule_id={rule_id}) — see {ERROR_LOG_PATH}")


if __name__ == "__main__":
    # TODO: quick manual smoke test — load and print count of alerts
    # parsed successfully vs skipped, before wiring this into the
    # rest of the correlation pipeline.
    pass