# detection/engine.py
# Orchestrates the full detection pipeline
# Reads new logs → normalizes → runs rules → persists alerts

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
import fcntl

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ── Collectors ────────────────────────────────────────────────────────────────
from logs.log_collector import (
    collect_auth_logs,
    collect_auditd_logs,
    collect_cloudtrail_logs,
    collect_falco_logs,  
    collect_cowrie_logs,
    BUCKET_NAME, ACCOUNT_ID, REGION,
    FALCO_BUCKET_NAME                       
)

# ── Normalizer ────────────────────────────────────────────────────────────────
from schemas.normalizer import (
    parse_log_file,
    group_audit_lines,
)
from schemas import (
    LogSource,
    AuditdEvent, AuthLogEvent, CloudTrailEvent,FalcoEvent,
    Alert, AlertReport, CoverageSummary, parse_cowrie_sessions
)
from storage.cowrie_store import init_db, store_session

# ── Rules — auth.log ──────────────────────────────────────────────────────────
from rules.rule_001_ssh_brute_force    import detect as rule_ssh_brute
from rules.rule_003_new_user_created   import detect as rule_new_user
from rules.rule_007_brute_force_success import detect as rule_brute_success

# ── Rules — auditd ───────────────────────────────────────────────────────────
from rules.rule_004_shadow_access      import detect as rule_shadow
from rules.rule_014_masquerading       import detect as rule_masquerading
from rules.rule_008_cron_persisitence  import detect as rule_cron  # fix typo later
from rules.rule_010_auditd_disabled    import detect as rule_auditd_disabled
from rules.rule_011_sudoers_tamper     import detect as rule_sudoers
from rules.rule_012_account_enumeration import detect as rule_enum
from rules.rule_013_system_discovery   import detect as rule_discovery
from rules.rule_005_privilige_escalation import detect as rule_privesc
# ── Rules — CloudTrail ───────────────────────────────────────────────────────
from rules.rule_002_no_mfa_login       import detect as rule_no_mfa
from rules.rule_006_root_account_login import detect as rule_root_login
from rules.rule_009_cloudtrail_disabled import detect as rule_ct_disabled
from rules.rule_016_canary_credential_used import detect as rule_canary


# ── Rules — Cowrie ──────────────────────────────────────────────────────────
from rules.rule_015_cowrie_login import detect as rule_cowrie_login

#------falco-rules--------------
from rules.rule_017_falco_default_passthrough import detect as rule_falco_passthrough

# ── State files ───────────────────────────────────────────────────────────────
ALERTS_FILE = str(Path(__file__).resolve().parent.parent / "reports" / "alerts.json")

# Real path inside the engine container — cowrie-var named volume mounted
# read-only at /mnt/cowrie-data (see docker-compose.yml). Cowrie itself
# writes to <volume_root>/log/cowrie/cowrie.json, so from engine's side
# that's /mnt/cowrie-data/log/cowrie/cowrie.json.
COWRIE_LOG_FILE = '/mnt/cowrie-data/log/cowrie/cowrie.json'


# ── Alert persistence ─────────────────────────────────────────────────────────

def load_existing_alerts() -> list[Alert]:
    if not os.path.exists(ALERTS_FILE):
        return []

    with open(ALERTS_FILE) as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_SH)   # NEW — block until safe to read
        try:
            try:
                raw = json.load(f)
            except json.JSONDecodeError as e:
                print(f"  [WARN] alerts.json is not valid JSON: {e}")
                return []
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)   # NEW — always release

    alerts: list[Alert] = []
    for i, entry in enumerate(raw):
        try:
            alerts.append(Alert.model_validate(entry))
        except Exception as e:
            print(f"  [WARN] Skipped malformed alert at index {i}: {e}")

    return alerts


def save_alerts(alerts: list[Alert]) -> None:
    os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)
    with open(ALERTS_FILE, "w") as f:
        fcntl.flock(f.fileno(),fcntl.LOCK_EX)
        try:
            json.dump(
            [a.model_dump(mode="json") for a in alerts],
            f,
            indent=2,
            default=str
            )
        finally:
            fcntl.flock(f.fileno(),fcntl.LOCK_UN)
        


# ── Deduplication ─────────────────────────────────────────────────────────────

def deduplicate_alerts(existing, new):
    def _key(a):
        if a.dedup_key:
            return f"{a.rule_id}:{a.dedup_key}"
        # fallback for rules not yet migrated to dedup_key
        return f"{a.rule_id}:{a.source_ip}:{a.username}:{a.extra.get('auid', '')}"

    existing_keys = {_key(a) for a in existing}
    deduped = []
    for alert in new:
        key = _key(alert)
        if key not in existing_keys:
            deduped.append(alert)
            existing_keys.add(key)
    return deduped

# ── Main engine ───────────────────────────────────────────────────────────────

def run_engine() -> AlertReport:
    print("=" * 55)
    print("  Purple Detection Engine")
    print(f"  Run time: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 55)

    existing_alerts = load_existing_alerts()
    print(f"\n  Loaded {len(existing_alerts)} existing alerts")

    new_alerts: list[Alert] = []
    parse_errors = 0
    lines_processed = {"auth_log": 0, "auditd": 0, "cloudtrail": 0, "cowrie": 0,"falco":0}

    # ── auth.log ──────────────────────────────────────────────
    print("\n[1/5] Processing auth.log...")
    auth_raw_lines = collect_auth_logs()
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

    # Run auth.log rules
    brute_alerts   = rule_ssh_brute(auth_events)
    user_alerts    = rule_new_user(auth_events)
    success_alerts = rule_brute_success(auth_events)
    new_alerts.extend(brute_alerts)
    new_alerts.extend(user_alerts)
    new_alerts.extend(success_alerts)
    print(f"  SSH brute force:         {len(brute_alerts)} alerts")
    print(f"  New user:                {len(user_alerts)} alerts")
    print(f"  Brute force success:     {len(success_alerts)} alerts")

    # ── auditd ────────────────────────────────────────────────
    print("\n[2/5] Processing auditd...")
    auditd_raw = collect_auditd_logs()
    lines_processed["auditd"] = len(auditd_raw.splitlines())

    auditd_groups = group_audit_lines(auditd_raw)
    auditd_events: list[AuditdEvent] = []
    for group in auditd_groups:
        try:
            auditd_events.append(AuditdEvent.from_dict(group))
        except Exception:
            parse_errors += 1

    print(f"  New events: {len(auditd_events)}")

    # Run auditd rules
    shadow_alerts   = rule_shadow(auditd_events)
    cron_alerts     = rule_cron(auditd_events)
    auditd_alerts   = rule_auditd_disabled(auditd_events)
    sudoers_alerts  = rule_sudoers(auditd_events)
    enum_alerts     = rule_enum(auditd_events)
    discovery_alerts = rule_discovery(auditd_events)
    privesc_alerts = rule_privesc(auditd_events)
    masquerading_alerts = rule_masquerading(auditd_events)

    new_alerts.extend(shadow_alerts)
    new_alerts.extend(cron_alerts)
    new_alerts.extend(auditd_alerts)
    new_alerts.extend(sudoers_alerts)
    new_alerts.extend(enum_alerts)
    new_alerts.extend(discovery_alerts)
    new_alerts.extend(privesc_alerts)
    new_alerts.extend(masquerading_alerts)

    print(f"  Shadow access:           {len(shadow_alerts)} alerts")
    print(f"  Cron persistence:        {len(cron_alerts)} alerts")
    print(f"  auditd disabled:         {len(auditd_alerts)} alerts")
    print(f"  Sudoers tamper:          {len(sudoers_alerts)} alerts")
    print(f"  Account enumeration:     {len(enum_alerts)} alerts")
    print(f"  System discovery:        {len(discovery_alerts)} alerts")
    print(f"  Privilege escalation:    {len(privesc_alerts)} alerts")
    print(f"  Masquerading:             {len(masquerading_alerts)} alerts")

    # ── CloudTrail ────────────────────────────────────────────
    print("\n[3/5] Processing CloudTrail...")
    ct_raw = collect_cloudtrail_logs(BUCKET_NAME, ACCOUNT_ID, REGION)
    lines_processed["cloudtrail"] = len(ct_raw)

    ct_events: list[CloudTrailEvent] = []
    for record in ct_raw:
        try:
            ct_events.append(CloudTrailEvent.from_record(record))
        except Exception:
            parse_errors += 1

    print(f"  New events: {len(ct_events)}")

    # Run CloudTrail rules
    mfa_alerts    = rule_no_mfa(ct_events)
    root_alerts   = rule_root_login(ct_events)
    ct_dis_alerts = rule_ct_disabled(ct_events)
    canary_alerts=rule_canary(ct_events)
    new_alerts.extend(mfa_alerts)
    new_alerts.extend(root_alerts)
    new_alerts.extend(ct_dis_alerts)
    new_alerts.extend(canary_alerts)
    print(f"  No MFA:                  {len(mfa_alerts)} alerts")
    print(f"  Root login:              {len(root_alerts)} alerts")
    print(f"  CloudTrail disabled:     {len(ct_dis_alerts)} alerts")
    print(f"  Canary crendtial used:   {len(canary_alerts)}alerts")

        # ── Cowrie ────────────────────────────────────────────────
    print("\n[4/5] Processing Cowrie honeypot...")
    init_db()

    cowrie_raw_lines = collect_cowrie_logs(COWRIE_LOG_FILE)
    lines_processed["cowrie"] = len(cowrie_raw_lines)

    try:
        cowrie_sessions = parse_cowrie_sessions(cowrie_raw_lines)
    except Exception:
        parse_errors += 1
        cowrie_sessions = []

    for session in cowrie_sessions:
        store_session(session)

    cowrie_login_alerts = rule_cowrie_login(cowrie_sessions)
    new_alerts.extend(cowrie_login_alerts)
    print(f"  New/updated sessions: {len(cowrie_sessions)}")
    print(f"  Cowrie honeypot logins:  {len(cowrie_login_alerts)} alerts")
        # ── Falco ─────────────────────────────────────────────────
    print("\n[5/5] Processing Falco...")
    falco_raw = collect_falco_logs(FALCO_BUCKET_NAME)
    lines_processed["falco"] = len(falco_raw)

    falco_events: list[FalcoEvent] = []
    for record in falco_raw:
        try:
            falco_events.append(FalcoEvent.from_alert(record))
        except Exception:
            parse_errors += 1

    print(f"  New events: {len(falco_events)}")

    falco_default_alerts = rule_falco_passthrough(falco_events)
    new_alerts.extend(falco_default_alerts)
    print(f"  Default rule passthrough: {len(falco_default_alerts)} alerts")
    # ── Deduplicate + merge + save ────────────────────────────
    deduped_new = deduplicate_alerts(existing_alerts, new_alerts)
    print(f"\n  New alerts: {len(new_alerts)} "
          f"({len(new_alerts) - len(deduped_new)} duplicates suppressed)")

    all_alerts = existing_alerts + deduped_new
    save_alerts(all_alerts)
    print(f"  Total accumulated alerts: {len(all_alerts)}")

    # ── Build report ──────────────────────────────────────────
    report = AlertReport(
        alerts              = all_alerts,
        coverage            = CoverageSummary.from_alerts(all_alerts),
        log_lines_processed = lines_processed,
        parse_errors        = parse_errors,
    )

    print(f"\n{'=' * 55}")
    print(f"  COVERAGE: {report.coverage.coverage_pct}% "
          f"({report.coverage.detected_count}/"
          f"{report.coverage.total_techniques} techniques)")
    print(f"  Parse errors: {parse_errors}")
    print(f"{'=' * 55}\n")

    return report


if __name__ == "__main__":
    run_engine()
