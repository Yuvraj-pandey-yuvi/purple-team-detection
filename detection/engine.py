# detection/engine.py
# Orchestrates the full detection pipeline
# Reads new logs → normalizes → runs rules → persists alerts

import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.expanduser('~/project'))

# ── Collectors ────────────────────────────────────────────────────────────────
from logs.log_collector import (
    collect_auth_logs,
    collect_auditd_logs,
    collect_cloudtrail_logs,
    BUCKET_NAME, ACCOUNT_ID, REGION
)

# ── Normalizer ────────────────────────────────────────────────────────────────
from schemas.normalizer import (
    parse_log_file,
    group_audit_lines,
)
from schemas import (
    LogSource,
    AuditdEvent, AuthLogEvent, CloudTrailEvent,
    Alert, AlertReport, CoverageSummary,
)

# ── Rules ─────────────────────────────────────────────────────────────────────
from rules.rule_001_ssh_brute_force  import detect as rule_ssh_brute
from rules.rule_002_no_mfa_login     import detect as rule_no_mfa
from rules.rule_003_new_user_created import detect as rule_new_user
from rules.rule_004_shadow_access    import detect as rule_shadow
from rules.rule_005_privilige_escalation   import detect as rule_privesc
from rules.rule_006_root_account_login       import detect as rule_root_login

# ── State files ───────────────────────────────────────────────────────────────
ALERTS_FILE = os.path.expanduser('~/project/reports/alerts.json')


# ── Alert persistence ─────────────────────────────────────────────────────────

def load_existing_alerts() -> list[Alert]:
    """
    Load accumulated alerts from previous runs.
    Returns empty list if no alerts file exists yet.
    
    WHY: Engine only processes new log lines each run.
    Old alerts must be loaded and merged with new ones
    so coverage report reflects full history, not just
    the last 5 minutes.
    """
    if not os.path.exists(ALERTS_FILE):
        return []
    try:
        with open(ALERTS_FILE) as f:
            raw = json.load(f)
        # Convert dicts back to Alert objects
        return [Alert(**a) for a in raw]
    except (json.JSONDecodeError, Exception) as e:
        print(f"  [WARN] Could not load alerts.json: {e}")
        return []


def save_alerts(alerts: list[Alert]) -> None:
    """
    Persist alerts to disk as JSON.
    Overwrites with full merged list — not just new alerts.
    """
    os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)
    with open(ALERTS_FILE, "w") as f:
        # Alert is a Pydantic model — .model_dump() converts to dict
        json.dump(
            [a.model_dump(mode="json") for a in alerts],
            f,
            indent=2,
            default=str
        )


# ── Deduplication ─────────────────────────────────────────────────────────────

def deduplicate_alerts(
    existing: list[Alert],
    new: list[Alert]
) -> list[Alert]:
    """
    Prevent same alert firing repeatedly for same attacker.
    
    Dedup key: rule_id + source_ip + username
    If same key already exists in existing alerts — skip.
    
    WHY: Without this, a brute force attack running for 2 hours
    generates one alert every 5 minutes = 24 identical alerts.
    Analyst gets paged 24 times for the same attacker.
    """
    existing_keys = {
        f"{a.rule_id}:{a.source_ip}:{a.username}"
        for a in existing
    }

    deduped = []
    for alert in new:
        key = f"{alert.rule_id}:{alert.source_ip}:{alert.username}"
        if key not in existing_keys:
            deduped.append(alert)
            existing_keys.add(key)  # prevent dupes within new batch too

    return deduped


# ── Main engine ───────────────────────────────────────────────────────────────

def run_engine() -> AlertReport:
    """
    Full detection pipeline — incremental processing.
    
    Flow:
      1. Load existing alerts from alerts.json
      2. Collect only NEW log lines (seek pointer in log_collector)
      3. Normalize raw lines into typed events
      4. Run rules against typed events
      5. Deduplicate new alerts against existing
      6. Merge and save
      7. Build and return AlertReport
    """
    print("=" * 55)
    print("  Purple Detection Engine")
    print(f"  Run time: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 55)

    # ── Step 1: Load existing alerts ─────────────────────────
    existing_alerts = load_existing_alerts()
    print(f"\n  Loaded {len(existing_alerts)} existing alerts")

    new_alerts: list[Alert] = []
    parse_errors = 0
    lines_processed = {"auth_log": 0, "auditd": 0, "cloudtrail": 0}

    # ── Step 2 & 3: Collect + Normalize auth.log ─────────────
    print("\n[1/3] Processing auth.log...")
    auth_raw_lines = collect_auth_logs()  # returns list[str] of new lines
    lines_processed["auth_log"] = len(auth_raw_lines)

    auth_events: list[AuthLogEvent] = []
    for line in auth_raw_lines:
        try:
            auth_events.append(AuthLogEvent.from_raw(line))
        except Exception:
            parse_errors += 1

    print(f"  New lines: {len(auth_raw_lines)}, "
          f"parsed: {len(auth_events)}, "
          f"errors: {parse_errors}")

    # ── Step 4: Run auth.log rules ────────────────────────────
    brute_alerts  = rule_ssh_brute(auth_events)
    user_alerts   = rule_new_user(auth_events)
    new_alerts.extend(brute_alerts)
    new_alerts.extend(user_alerts)
    print(f"  SSH brute force: {len(brute_alerts)} alerts")
    print(f"  New user:        {len(user_alerts)} alerts")

    # ── Step 2 & 3: Collect + Normalize auditd ───────────────
    print("\n[2/3] Processing auditd...")
    auditd_raw = collect_auditd_logs()   # returns new raw text
    lines_processed["auditd"] = len(auditd_raw.splitlines())

    # group_audit_lines handles the multi-record correlation
    auditd_groups  = group_audit_lines(auditd_raw)
    auditd_events: list[AuditdEvent] = []
    for group in auditd_groups:
        try:
            auditd_events.append(AuditdEvent.from_dict(group))
        except Exception:
            parse_errors += 1

    print(f"  New events: {len(auditd_events)}")

    # ── Step 4: Run auditd rules ──────────────────────────────
    shadow_alerts  = rule_shadow(auditd_events)
    privesc_alerts = rule_privesc(auditd_events)
    new_alerts.extend(shadow_alerts)
    new_alerts.extend(privesc_alerts)
    print(f"  Shadow access:        {len(shadow_alerts)} alerts")
    print(f"  Privilege escalation: {len(privesc_alerts)} alerts")

    # ── Step 2 & 3: Collect + Normalize CloudTrail ───────────
    print("\n[3/3] Processing CloudTrail...")
    ct_raw = collect_cloudtrail_logs(BUCKET_NAME, ACCOUNT_ID, REGION)
    lines_processed["cloudtrail"] = len(ct_raw)

    ct_events: list[CloudTrailEvent] = []
    for record in ct_raw:
        try:
            ct_events.append(CloudTrailEvent.from_record(record))
        except Exception:
            parse_errors += 1

    print(f"  New events: {len(ct_events)}")

    # ── Step 4: Run CloudTrail rules ─────────────────────────
    mfa_alerts  = rule_no_mfa(ct_events)
    root_alerts = rule_root_login(ct_events)
    new_alerts.extend(mfa_alerts)
    new_alerts.extend(root_alerts)
    print(f"  No MFA:      {len(mfa_alerts)} alerts")
    print(f"  Root login:  {len(root_alerts)} alerts")

    # ── Step 5: Deduplicate ───────────────────────────────────
    deduped_new = deduplicate_alerts(existing_alerts, new_alerts)
    print(f"\n  New alerts: {len(new_alerts)} "
          f"({len(new_alerts) - len(deduped_new)} duplicates suppressed)")

    # ── Step 6: Merge and save ────────────────────────────────
    all_alerts = existing_alerts + deduped_new
    save_alerts(all_alerts)
    print(f"  Total accumulated alerts: {len(all_alerts)}")

    # ── Step 7: Build report ──────────────────────────────────
    report = AlertReport(
        alerts      = all_alerts,
        coverage    = CoverageSummary.from_alerts(all_alerts),
        log_lines_processed = lines_processed,
        parse_errors = parse_errors,
    )

    # ── Print coverage ────────────────────────────────────────
    print(f"\n{'=' * 55}")
    print(f"  COVERAGE: {report.coverage.coverage_pct}% "
          f"({report.coverage.detected_count}/"
          f"{report.coverage.total_techniques} techniques)")
    print(f"  Parse errors: {parse_errors}")
    print(f"{'=' * 55}\n")

    return report


if __name__ == "__main__":
    run_engine()