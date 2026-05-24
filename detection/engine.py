# engine.py
# The core detection engine
# Loads all rules, runs them against all log sources
# Outputs alerts with coverage statistics

import sys 
import os
sys.path.insert(0,os.path.expanduser('~/Purple-Detection-Project'))

from logs.log_collector import (
    collect_auth_logs,
    collect_all_auditd_logs,
    collect_cloudtrail_logs ,
    BUCKET_NAME,ACCOUNT_ID,REGION
)
# Load all rules
from rules.rule_001_ssh_brute_force  import detect as rule_ssh_brute
from rules.rule_002_no_mfa_login     import detect as rule_no_mfa
from rules.rule_003_new_user_created import detect as rule_new_user
from rules.rule_004_shadow_access    import detect as rule_shadow
from rules.rule_005_cron_persistence import detect as rule_cron

# Technique registry - tracks what you're monitoring
TECHNIQUES = {
    'T1110.001': 'Brute Force - Password Guessing',
    'T1078':     'Valid Accounts - Console Login',
    'T1136.001': 'Create Local Account',
    'T1003.008': 'OS Credential Dumping',
    'T1053.003': 'Scheduled Task - Cron',
}


def run_engine():
    all_alerts=[]
    detected_techniques=set()

    print("="*55)
    print(" Purple Detection Engine - Running Detection Rules")
    print("="*55)

    #auth.log rules
    print("\n[1/3] Processing auth.log rules...")
    auth_logs=collect_auth_logs()
    
    #run brute force rule
    brute_alerts=rule_ssh_brute(auth_logs)
    all_alerts.extend(brute_alerts)
    if brute_alerts:
        detected_techniques.add('T1110.001')
    print (f"  - SSH Brute Force: {len(brute_alerts)} alerts")

    #new user rule
    user_alerts = rule_new_user(auth_logs)
    all_alerts.extend(user_alerts)
    if user_alerts:
        detected_techniques.add('T1136.001')
    print(f"  - New User Creation: {len(user_alerts)} alerts")

    #auditd rules
    print("\n[2/3] Processing auditd rules...")
    auditd_logs=collect_all_auditd_logs()
    #run rules against each key
    auditd_rule_map={
        
        'shadow_access': (rule_shadow,'T1003.008'), 
        'cron_modification':(rule_cron,'T1053.003')
    }
    auditd_alert_count = 0
    for key, (rule_fn, technique) in auditd_rule_map.items():
        log_text = auditd_logs.get(key, '')
        blocks = log_text.split('----')
        for block in blocks:
            if not block.strip():
                continue
            result = rule_fn(block)
            if result:
                all_alerts.append(result)
                detected_techniques.add(technique)
                auditd_alert_count += 1

    print(f"      auditd rules: {auditd_alert_count} alert(s)")

    # ── CLOUDTRAIL RULES ─────────────────────────────────
    print("\n[3/3] Collecting CloudTrail logs...")
    ct_events = collect_cloudtrail_logs(
        BUCKET_NAME, ACCOUNT_ID, REGION
    )
    print(f"      {len(ct_events)} events loaded")

    ct_alert_count = 0
    for event in ct_events:
        result = rule_no_mfa(event)
        if result:
            all_alerts.append(result)
            detected_techniques.add('T1078')
            ct_alert_count += 1

    print(f"      CloudTrail rules: {ct_alert_count} alert(s)")

    # ── COVERAGE REPORT ──────────────────────────────────
    print("\n" + "=" * 55)
    print("  COVERAGE REPORT")
    print("=" * 55)
    print(f"\n  Techniques monitored : {len(TECHNIQUES)}")
    print(f"  Techniques detected  : {len(detected_techniques)}")
    coverage = (len(detected_techniques) / len(TECHNIQUES)) * 100
    print(f"  Detection coverage   : {coverage:.0f}%\n")

    for tid, tname in TECHNIQUES.items():
        status = '✅ DETECTED' if tid in detected_techniques \
                               else '❌ NOT DETECTED'
        print(f"  {status}  {tid}  {tname}")

    # ── ALERTS ───────────────────────────────────────────
    print(f"\n{'=' * 55}")
    print(f"  ALERTS ({len(all_alerts)} total)")
    print(f"{'=' * 55}\n")

    all_alerts = deduplicate_alerts(all_alerts)
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
    all_alerts.sort(
        key=lambda x: severity_order.get(x.get('severity'), 9)
    )

    for i, alert in enumerate(all_alerts, 1):
        sev = alert.get('severity', 'UNKNOWN')
        colors = {
            'CRITICAL': '\033[91m',
            'HIGH':     '\033[93m',
            'MEDIUM':   '\033[94m'
        }
        color = colors.get(sev, '')
        reset = '\033[0m'

        print(f"  Alert #{i}")
        print(f"  {color}[{sev}]{reset} {alert.get('rule_name')}")
        print(f"  Technique  : {alert.get('technique')}")
        print(f"  Log source : {alert.get('log_source')}")
        print(f"  Reason     : {alert.get('reason')}")
        print()

    return all_alerts, detected_techniques


def deduplicate_alerts(alerts):
    seen = set()
    unique = []
    for alert in alerts:
        key = (alert.get('technique'), alert.get('reason'))
        if key not in seen:
            seen.add(key)
            unique.append(alert)
    return unique

if __name__ == "__main__":
    run_engine()