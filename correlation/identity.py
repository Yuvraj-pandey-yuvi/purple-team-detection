# correlation/identity.py
# Stage 2 — Resolve auid -> username, lazily, from /etc/passwd.
#
# Design recap (agreed in this project's Phase 5 design session):
#   - NO eager bootstrap. Only look up /etc/passwd when an unfamiliar
#     auid is actually encountered — avoids the staleness problem
#     entirely, since it always asks the live system at time of need.
#   - Cache lookups in memory for the lifetime of a single run (not
#     persisted across runs — next run re-resolves fresh, matching
#     the project's full-rescan/stateless design).
#   - auid=None is the COMMON, EXPECTED case right now (most rules
#     don't populate Alert.auid yet — see decisions-and-learnings.md).
#     This must be a SILENT skip, no log entry — logging it would
#     drown out real failures in noise.
#   - A real lookup failure (auid is a genuine int, but no longer in
#     /etc/passwd — e.g. user was deleted after the alert fired) IS
#     logged + printed, same pattern as loader.py's malformed-entry
#     handling.

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

PASSWD_PATH = "/etc/passwd"
ERROR_LOG_PATH = str(Path(__file__).resolve().parent / "correlation_errors.log")


def resolve_uid_to_username(auid: Optional[int], cache: dict[int, str]) -> Optional[str]:
    """
    Resolve a Linux auid to its username, via /etc/passwd, lazily.

    Returns None if:
      - auid is None (silent — this is the expected case for most
        alerts right now, not a failure)
      - auid is a real int but not found in /etc/passwd (logged —
        this IS worth knowing about)

    `cache` is expected to be a plain dict the CALLER owns and passes
    in fresh at the start of each correlation run — see the note in
    the module docstring on why this isn't persisted internally.
    """
    if auid is None:
        return None  # silent skip — no log call, on purpose (see module docstring)

    if auid in cache:
        return cache[auid]

    username = _lookup_passwd(auid)

    if username is None:
        _log_lookup_failure(auid)
    else:
        cache[auid] = username

    return username


def _log_lookup_failure(auid: int) -> None:
    """
    A real /etc/passwd lookup failure — auid was a genuine int, but no
    matching entry exists (e.g. the user was deleted after the alert
    fired). Distinct from the auid=None case, which is silent.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    log_line = (
        f"[{timestamp}] identity_lookup_failed auid={auid} "
        f"reason=\"not found in {PASSWD_PATH}\"\n"
    )

    with open(ERROR_LOG_PATH, "a") as f:
        f.write(log_line)

    print(f"  [WARN] auid={auid} not found in {PASSWD_PATH} "
          f"— see {ERROR_LOG_PATH}")


def _lookup_passwd(auid: int) -> Optional[str]:
    """
    Search /etc/passwd for a line whose UID field (3rd colon-separated
    field) matches `auid`. Returns the username (1st field) if found,
    None otherwise.

    /etc/passwd line format:
      username:x:uid:gid:comment:home_dir:shell
                 ^^^ this is what we're matching against

    No locking — /etc/passwd changes rarely (only on useradd/usermod/
    userdel), unlike alerts.json's constant 5-minute rewrite cycle, so
    a real race here is negligible and not worth the added complexity.

    A malformed line (fewer than 7 fields) is skipped, not fatal — the
    rest of the file is still searched.
    """
    try:
        with open(PASSWD_PATH) as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue

                fields = line.split(":")
                if len(fields) < 7:
                    # Malformed line — skip it, keep searching. Not
                    # logged: this is about /etc/passwd's own integrity,
                    # not a correlation-specific failure worth tracking
                    # the same way a failed lookup is.
                    continue

                username, _, uid_str = fields[0], fields[1], fields[2]

                try:
                    uid = int(uid_str)
                except ValueError:
                    continue  # malformed uid field — skip this line too

                if uid == auid:
                    return username

    except FileNotFoundError:
        # Extremely unlikely on a real Linux box, but don't let a
        # missing /etc/passwd crash the whole correlation run.
        return None

    return None  # searched the whole file, no match


if __name__ == "__main__":
    # Manual smoke test — run this directly on purple-project.
    # Resolves a couple of real, known uids on the box, and repeats
    # one lookup to confirm the cache actually short-circuits a
    # second /etc/passwd read (harmless either way, but worth
    # eyeballing that the cache path is really being hit).
    test_cache: dict[int, str] = {}

    # 1000 is ubuntu's real uid on this box per rule_004's own
    # ADMIN_AUIDS set — a good known-good case to test against.
    known_uid = 1000
    print(f"Resolving auid={known_uid} (first lookup, should hit /etc/passwd)...")
    result = resolve_uid_to_username(known_uid, test_cache)
    print(f"  -> {result}")

    print(f"\nResolving auid={known_uid} again (should come from cache)...")
    result = resolve_uid_to_username(known_uid, test_cache)
    print(f"  -> {result}")
    print(f"  Cache contents: {test_cache}")

    print(f"\nResolving auid=None (should be silent, no log entry)...")
    result = resolve_uid_to_username(None, test_cache)
    print(f"  -> {result}")

    fake_uid = 999999
    print(f"\nResolving auid={fake_uid} (shouldn't exist — should log a failure)...")
    result = resolve_uid_to_username(fake_uid, test_cache)
    print(f"  -> {result}")
    print(f"  Check {ERROR_LOG_PATH} — should have exactly ONE new "
          f"entry for auid={fake_uid}, nothing for the auid=None case above.")
