# correlation/matching.py
# Stage 3 — Build entity-centric indices, then match alerts via
# explicitly author-defined CORRELATION_PAIRS / CORRELATION_CHAINS.
#
# Design recap (agreed in this project's Phase 5 design session):
#   - Two separate indices: {username: [alerts]} and {source_ip: [alerts]}.
#     Some rules (e.g. rule_006, CloudTrail) only ever have source_ip,
#     never username/auid — a username-only index can't reach them.
#   - Built FRESH each run, from the alerts loader.py already loaded —
#     matches the stateless, full-rescan design (no persisted state).
#   - An auid-bearing alert (e.g. rule_008, once fixed) must be resolved
#     to a username via identity.py BEFORE it can enter the username
#     index — the index itself only ever stores by username, never auid.
#   - Direct alert-to-alert comparison only (see GraphWeaver discussion
#     in decisions-and-learnings.md) — no separate entity-graph model.

from datetime import timedelta
from typing import Optional
from schemas import Alert
from correlation.identity import resolve_uid_to_username


def build_username_index(alerts: list[Alert], uid_cache: dict[int, str]) -> dict[str, list[Alert]]:
    """
    Build {username: [alerts]} from the full loaded alert list.

    For each alert:
      - if alert.username is already set, use it directly (preferred —
        it's the rule's own direct claim, not a resolved/derived value)
      - elif alert.auid is set, resolve it via resolve_uid_to_username()
        (silent skip if that returns None — see identity.py's own
        silent-skip design for auid=None / failed lookups)
      - else, this alert has no username-shaped identity at all —
        does NOT enter this index (it may still enter the source_ip
        index, if it has one)

    A single alert can never realistically have BOTH a real username
    AND a resolvable auid at once, given how the rules are structured
    today — each rule's detect() takes exactly one event type
    (AuthLogEvent, AuditdEvent, or CloudTrailEvent), so an Alert only
    ever carries the identity shape native to its own source. The
    username-first ordering below is just a safe default in case that
    ever changes, not a guard against a currently-real scenario.
    """
    index: dict[str, list[Alert]] = {}

    for alert in alerts:
        username = alert.username

        if username is None and alert.auid is not None:
            username = resolve_uid_to_username(alert.auid, uid_cache)

        if username is None:
            continue  # no username-shaped identity — sits out of this index

        index.setdefault(username, []).append(alert)

    return index


def build_source_ip_index(alerts: list[Alert]) -> dict[str, list[Alert]]:
    """
    Build {source_ip: [alerts]} from the full loaded alert list.

    Simpler than the username index — source_ip is always a direct
    field on Alert already (no resolution step needed, no Stage 2
    dependency). An alert with source_ip=None simply doesn't enter
    this index.
    """
    index: dict[str, list[Alert]] = {}

    for alert in alerts:
        if alert.source_ip is None:
            continue
        index.setdefault(alert.source_ip, []).append(alert)

    return index


def build_indices(
    alerts: list[Alert],
) -> tuple[dict[str, list[Alert]], dict[str, list[Alert]]]:
    """
    Convenience wrapper — builds both indices in one call, sharing one
    uid_cache across the whole run (per Stage 2's per-run caching design).

    Returns (username_index, source_ip_index).
    """
    uid_cache: dict[int, str] = {}
    username_index = build_username_index(alerts, uid_cache)
    source_ip_index = build_source_ip_index(alerts)
    return username_index, source_ip_index


# ── Correlation config — explicitly author-defined, never inferred ─────────
# Each entry: (anchor_rule_id, candidate_rule_id).
# The anchor is the "later" alert (e.g. rule_008 cron persistence); the
# candidate is what we search BACKWARD for (e.g. rule_007 breach).
CORRELATION_WINDOW_HOURS = 2

CORRELATION_PAIRS: list[tuple[str, str]] = [
    ("rule_008_cron_persistence", "rule_007_brute_force_success"),
    # TODO: add more pairs as you wire more rules in, e.g.:
    # ("rule_008_cron_persistence", "rule_001_..."),  # the "attempts only" fallback tier
]


def get_identity(alert: Alert, uid_cache: dict[int, str]) -> Optional[str]:
    """
    Resolve a single alert's identity to a username — same logic as
    build_username_index() uses per-alert, but callable standalone for
    a single anchor alert rather than the whole list.
    """
    if alert.username is not None:
        return alert.username
    if alert.auid is not None:
        return resolve_uid_to_username(alert.auid, uid_cache)
    return None


def find_nearest_preceding_match(
    anchor: Alert,
    candidate_rule_id: str,
    username_index: dict[str, list[Alert]],
    uid_cache: dict[int, str],
    window_hours: float = CORRELATION_WINDOW_HOURS,
) -> Optional[Alert]:
    """
    Given an anchor alert, find the nearest-preceding alert of
    `candidate_rule_id` for the SAME resolved identity, within
    `window_hours` before the anchor's own timestamp.

    Returns None if:
      - the anchor's own identity can't be resolved at all (nothing
        to search by)
      - no candidate alerts exist for that identity
      - candidates exist for that identity, but none are BOTH the
        right rule_id AND within the time window before the anchor
    """
    identity = get_identity(anchor, uid_cache)
    if identity is None:
        return None  # no identity to search by — can't match at all

    same_person_alerts = username_index.get(identity, [])

    window = timedelta(hours=window_hours)

    valid_candidates = [
        alert for alert in same_person_alerts
        if alert.rule_id == candidate_rule_id
        and alert.timestamp < anchor.timestamp
        and (anchor.timestamp - alert.timestamp) <= window
    ]

    if not valid_candidates:
        return None

    return max(valid_candidates, key=lambda a: a.timestamp)


if __name__ == "__main__":
    from correlation.loader import load_alerts

    print("Loading real alerts...")
    alerts = load_alerts()
    print(f"Loaded {len(alerts)} alerts.\n")

    username_index, source_ip_index = build_indices(alerts)

    print(f"Username index: {len(username_index)} distinct usernames")
    for username, entries in sorted(username_index.items()):
        print(f"  {username}: {len(entries)} alert(s)")

    print(f"\nSource IP index: {len(source_ip_index)} distinct IPs")
    for ip, entries in sorted(source_ip_index.items()):
        print(f"  {ip}: {len(entries)} alert(s)")

    indexed_ids = set()
    for entries in username_index.values():
        indexed_ids.update(id(a) for a in entries)
    for entries in source_ip_index.values():
        indexed_ids.update(id(a) for a in entries)

    unindexed = [a for a in alerts if id(a) not in indexed_ids]
    print(f"\n{len(unindexed)} / {len(alerts)} alerts landed in NEITHER "
          f"index (no username, no resolvable auid, no source_ip).")
    if unindexed:
        from collections import Counter
        print("By rule_id:", dict(Counter(a.rule_id for a in unindexed)))