# correlation/incident.py
# Stage 4 — Build real CorrelatedIncident objects from AnchorMatches.
#
# Design recap (agreed across this project's Phase 5 design session):
#   - parent: rule_id:dedup_key ref to the triggering/most-recent alert.
#     Kept as a convenience field even though technically derivable
#     from chain — chain is the real source of truth.
#   - chain: list of rule_id:dedup_key refs, INCLUDING parent itself,
#     stored sorted by timestamp.
#   - key: dedup identity across runs = parent + full chain combined.
#     Changes if the chain grows on a later run (e.g. 2-link -> 3-link).
#   - severity: defaults to parent's own original severity; overwritten
#     only if parent.rule_id is in the severity opt-in list. When
#     multiple groups matched, use highest_severity() across them.
#   - severity_modified: True if severity was actually changed by
#     correlation, False if just copied through unchanged.
#   - info: deterministic, template-generated human-readable sentence
#     — written here, NOT by any future LLM layer.
#   - closed: bool, analyst-controlled lifecycle state (defaults False
#     for a freshly-built incident).

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field

from schemas import Alert, Severity
from correlation.matching import AnchorMatches, highest_severity, event_start, event_end


# Which anchor rule_ids are allowed to have their OWN severity
# overridden by correlation. Everything NOT in this set keeps its
# original rule-assigned severity untouched, even when matches exist —
# correlation only attaches chain/context metadata for those.
SEVERITY_OPT_IN_RULES: set[str] = {
    "rule_008_cron_persistence",
}


def _alert_ref(alert: Alert) -> str:
    """The rule_id:dedup_key reference format used throughout chain/parent/key."""
    return f"{alert.rule_id}:{alert.dedup_key}"


class CorrelatedIncident(BaseModel):
    parent: str
    chain: list[str]
    key: str
    severity: Severity
    severity_modified: bool
    info: str
    closed: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    closed_at: Optional[datetime] = None


def build_incident(anchor_matches: AnchorMatches) -> CorrelatedIncident:
    """
    Build ONE CorrelatedIncident from an AnchorMatches — combining
    every matched group into a single chain/story.
    """
    anchor = anchor_matches.anchor
    parent_ref = _alert_ref(anchor)

    # Pair each matched alert with its real Alert object so we can sort
    # by actual timestamp (not by ref string, which sorts alphabetically
    # and would be meaningless for ordering by time).
    chain_alerts: list[Alert] = [anchor] + [
        gm.matched for gm in anchor_matches.group_matches
    ]
    chain_alerts.sort(key=event_start)
    chain = [_alert_ref(a) for a in chain_alerts]

    key = parent_ref + "::" + "::".join(chain)

    if anchor.rule_id in SEVERITY_OPT_IN_RULES:
        severity = highest_severity(
            [gm.severity for gm in anchor_matches.group_matches]
        )
        severity_modified = True
    else:
        severity = anchor.severity
        severity_modified = False

    info = _build_info_sentence(anchor, anchor_matches.group_matches)

    return CorrelatedIncident(
        parent=parent_ref,
        chain=chain,
        key=key,
        severity=severity,
        severity_modified=severity_modified,
        info=info,
        closed=False,
    )


def _build_info_sentence(anchor: Alert, group_matches: list) -> str:
    """
    Plain-narrative sentence built from each alert's OWN description
    field — reuses what each rule already writes (human-authored, per
    rule) rather than inventing a second, separate "friendly name"
    mapping that could drift out of sync with the real descriptions.

    Told in chronological order (earliest event first), connected by
    the real time gap between consecutive events — reads as a story,
    not a technical dump.
    """
    chain_alerts = sorted(
        [gm.matched for gm in group_matches] + [anchor],
        key=event_start,
    )

    parts = [chain_alerts[0].description.rstrip(".")]
    for prev, curr in zip(chain_alerts, chain_alerts[1:]):
        # gap = when the previous activity ended -> when this one began
        gap_minutes = max(
            0, int((event_start(curr) - event_end(prev)).total_seconds() // 60)
        )
        parts.append(f"{gap_minutes} min later, {curr.description.rstrip('.')}")

    return ". ".join(parts) + "."


def build_all_incidents(all_anchor_matches: list[AnchorMatches]) -> list[CorrelatedIncident]:
    """Convenience wrapper — build a CorrelatedIncident for every AnchorMatches."""
    return [build_incident(am) for am in all_anchor_matches]


if __name__ == "__main__":
    from correlation.loader import load_alerts
    from correlation.matching import run_correlation

    print("Loading real alerts...")
    alerts = load_alerts()
    print(f"Loaded {len(alerts)} alerts.\n")

    all_matches = run_correlation(alerts)
    print(f"AnchorMatches found: {len(all_matches)}\n")

    incidents = build_all_incidents(all_matches)
    for incident in incidents:
        print(incident.model_dump_json(indent=2))
        print()