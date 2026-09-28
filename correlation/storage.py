# correlation/storage.py
# Stage 5 — Save CorrelatedIncidents: read-merge-write against
# correlated_alerts.json, then move closed-and-aged incidents into
# archive.json.
#
# Design recap:
#   - NEVER blind-overwrite correlated_alerts.json — closed state must
#     survive re-runs. If an existing incident (by key) is closed,
#     don't resurrect it even if this run recomputed a matching
#     incident. If it's open, update it (fresh chain/severity/info).
#     If it's brand new, add it.
#   - closed_at is set the moment `closed` flips True — not implemented
#     here (that's an analyst-action API concern, out of scope for this
#     script) but honored: if an incoming incident is marked closed
#     with no closed_at yet, stamp it now.
#   - Closed incidents past ARCHIVE_DELAY_HOURS get moved out of
#     correlated_alerts.json into archive.json — both lock-guarded,
#     same fcntl pattern as loader.py.
#   - Real S3 push is explicitly out of scope — documented extension
#     point only, per project decision.

import json
import fcntl
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

from correlation.incident import CorrelatedIncident

CORRELATED_ALERTS_PATH = str(Path(__file__).resolve().parent.parent / "reports" / "correlated_alerts.json")
ARCHIVE_PATH = str(Path(__file__).resolve().parent.parent / "reports" / "archive.json")
ERROR_LOG_PATH = str(Path(__file__).resolve().parent / "correlation_errors.log")

ARCHIVE_DELAY_HOURS = 2  # deliberately a SEPARATE constant from
# CORRELATION_WINDOW_HOURS in matching.py, even though both currently
# equal 2 — they answer different questions (how far back an attacker's
# action is still relevant, vs how long after closing it's safe to
# archive) and could need different values later.

LOCK_RETRY_ATTEMPTS = 5
LOCK_RETRY_DELAY_SECONDS = 0.5


class LockAcquisitionFailed(Exception):
    pass


def _read_json_locked(path: str, lock_type: int) -> list[dict]:
    """
    Read a JSON file under an fcntl lock. Returns [] if the file
    doesn't exist yet (first run). Retries on lock contention, same
    pattern as loader.py's _read_locked.
    """
    if not Path(path).exists():
        return []

    for attempt in range(1, LOCK_RETRY_ATTEMPTS + 1):
        try:
            with open(path) as f:
                fcntl.flock(f.fileno(), lock_type | fcntl.LOCK_NB)
                try:
                    return json.load(f)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except BlockingIOError:
            if attempt < LOCK_RETRY_ATTEMPTS:
                time.sleep(LOCK_RETRY_DELAY_SECONDS)
            continue

    raise LockAcquisitionFailed(f"Could not acquire lock on {path}")


def _write_json_locked(path: str, data: list[dict]) -> None:
    """Write a JSON file under an EXCLUSIVE fcntl lock. Blocks (no
    LOCK_NB) — same reasoning as engine.py's save_alerts(): this write
    is brief and infrequent, not worth retry/skip complexity."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            json.dump(data, f, indent=2, default=str)
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def _load_incidents(path: str, lock_type: int) -> list[CorrelatedIncident]:
    """Load + parse existing incidents, skip-and-log malformed entries
    — same discipline as loader.py's load_alerts()."""
    raw_entries = _read_json_locked(path, lock_type)
    incidents = []
    for i, entry in enumerate(raw_entries):
        try:
            incidents.append(CorrelatedIncident.model_validate(entry))
        except Exception as e:
            timestamp = datetime.now(timezone.utc).isoformat()
            with open(ERROR_LOG_PATH, "a") as f:
                f.write(f"[{timestamp}] storage_parse_error path={path} "
                        f"index={i} error={e}\n    raw_entry={entry!r}\n")
            print(f"  [WARN] Skipped malformed incident at index {i} in "
                  f"{path} — see {ERROR_LOG_PATH}")
    return incidents


def merge_incidents(
    new_incidents: list[CorrelatedIncident],
    existing: list[CorrelatedIncident],
) -> list[CorrelatedIncident]:
    """
    Merge this run's freshly-computed incidents with whatever's
    already on disk, keyed by `key`.

      - existing + closed        -> keep the OLD one, never resurrect
      - existing + open          -> replace with the NEW one, but
                                     preserve the original created_at
      - not existing (brand new) -> add as-is
      - existing on disk but NOT recomputed this run (its key didn't
        appear in new_incidents) -> carry forward unchanged. This
        covers closed incidents (expected — closing doesn't require
        re-matching) and any open incident that simply wasn't
        recomputed this particular run.

    If an incoming incident is closed=True but has no closed_at yet
    (freshly closed by an analyst action, not yet timestamped), stamp
    it now — this is the one place closed_at actually gets set.
    """
    existing_by_key = {inc.key: inc for inc in existing}
    merged: dict[str, CorrelatedIncident] = {}

    for new in new_incidents:
        if new.closed and new.closed_at is None:
            new = new.model_copy(update={"closed_at": datetime.now(timezone.utc)})

        old = existing_by_key.get(new.key)
        if old is not None and old.closed:
            merged[new.key] = old  # don't resurrect a closed incident
        elif old is not None:
            merged[new.key] = new.model_copy(update={"created_at": old.created_at})
        else:
            merged[new.key] = new

    for key, old in existing_by_key.items():
        if key not in merged:
            merged[key] = old  # carry forward, unrecomputed this run

    # Whatever path an incident took to get here, if it's closed but was
    # never timestamped (e.g. an analyst/UI flipped only `closed` on the
    # saved file), stamp closed_at now. Without this it could never age
    # into the archive, since archiving is measured from closed_at.
    now = datetime.now(timezone.utc)
    for key, inc in merged.items():
        if inc.closed and inc.closed_at is None:
            merged[key] = inc.model_copy(update={"closed_at": now})

    return list(merged.values())


def split_active_and_archive(
    incidents: list[CorrelatedIncident],
    archive_delay_hours: float = ARCHIVE_DELAY_HOURS,
) -> tuple[list[CorrelatedIncident], list[CorrelatedIncident]]:
    """
    Split into (still-active, ready-to-archive). An incident archives
    once it's closed AND closed_at is at least archive_delay_hours in
    the past.
    """
    now = datetime.now(timezone.utc)
    cutoff = timedelta(hours=archive_delay_hours)

    active, archive = [], []
    for inc in incidents:
        if inc.closed and inc.closed_at is not None and (now - inc.closed_at) >= cutoff:
            archive.append(inc)
        else:
            active.append(inc)

    return active, archive


def save_incidents(new_incidents: list[CorrelatedIncident]) -> None:
    """
    The real Stage 5 entry point — call this once per correlation run
    with the freshly-built incidents from build_all_incidents().

    Reads existing correlated_alerts.json + archive.json, merges,
    splits by archive eligibility, writes both back.
    """
    existing_active = _load_incidents(CORRELATED_ALERTS_PATH, fcntl.LOCK_SH)
    existing_archive = _load_incidents(ARCHIVE_PATH, fcntl.LOCK_SH)

    # correlation is a full re-scan of alerts.json, and archiving removes
    # an incident from the active file — so without this, the very next
    # run would re-derive the same incident from the still-present
    # alerts and re-create it as a fresh OPEN incident. Anything already
    # archived stays archived. (If its chain later grows, the key
    # changes, and it correctly surfaces as a new incident.)
    archived_keys = {inc.key for inc in existing_archive}
    new_incidents = [inc for inc in new_incidents if inc.key not in archived_keys]

    merged = merge_incidents(new_incidents, existing_active)
    active, newly_archived = split_active_and_archive(merged)

    full_archive = existing_archive + newly_archived

    _write_json_locked(
        CORRELATED_ALERTS_PATH,
        [inc.model_dump(mode="json") for inc in active],
    )
    _write_json_locked(
        ARCHIVE_PATH,
        [inc.model_dump(mode="json") for inc in full_archive],
    )

    print(f"Saved {len(active)} active incident(s) to {CORRELATED_ALERTS_PATH}")
    if newly_archived:
        print(f"Archived {len(newly_archived)} closed incident(s) to {ARCHIVE_PATH}")


if __name__ == "__main__":
    from correlation.loader import load_alerts
    from correlation.matching import run_correlation
    from correlation.incident import build_all_incidents

    print("Loading real alerts...")
    alerts = load_alerts()
    print(f"Loaded {len(alerts)} alerts.\n")

    all_matches = run_correlation(alerts)
    print(f"AnchorMatches found: {len(all_matches)}")

    incidents = build_all_incidents(all_matches)
    print(f"CorrelatedIncidents built this run: {len(incidents)}\n")

    save_incidents(incidents)