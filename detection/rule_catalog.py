# detection/rule_catalog.py
"""Plain-English catalogue of every detection rule, joined with how often each has fired.
tests/test_public_attackers.py checks that every file in rules/ has an entry, so this list
cannot silently fall behind the code."""

CATALOG = [
    ("rule_001_ssh_brute_force", "SSH brute force and probing", "T1110.001", "auth_log", "Medium to Critical", "Many failed or probing SSH connections from one IP in a short window."),
    ("rule_002_console_login_no_mfa", "AWS console login without MFA", "T1078", "cloudtrail", "Medium to Critical", "Someone signs in to the AWS console with no second factor."),
    ("rule_003_new_user_created", "New user account created", "T1136.001", "auth_log", "High to Critical", "A new local account appears, a common way to keep access."),
    ("rule_004_shadow_access", "Password-hash file read", "T1003.008", "auditd", "Critical", "A process that should not touch /etc/shadow reads it."),
    ("rule_005_privilege_escalation", "Privilege escalation", "T1548", "auditd", "Critical", "A normal user suddenly runs something as root."),
    ("rule_006_root_account_login", "AWS root account login", "T1078.001", "cloudtrail", "Critical", "The all-powerful AWS root account is used to sign in."),
    ("rule_007_brute_force_success", "Brute force that succeeded", "T1110.001", "auth_log", "Critical", "Repeated failures followed by a successful login from the same IP."),
    ("rule_008_cron_persistence", "Scheduled-job persistence", "T1053.003", "auditd", "High to Critical", "A cron job is written, a classic way to survive reboots."),
    ("rule_009_cloudtrail_disabled", "AWS audit logging switched off", "T1562.002", "cloudtrail", "High to Critical", "CloudTrail is stopped, deleted or changed so actions stop being recorded."),
    ("rule_010_auditd_tamper", "Linux audit system tampered with", "T1562.001", "auditd", "High to Critical", "The audit daemon or its rules are disabled or changed."),
    ("rule_011_sudoers_tamper", "sudo permissions modified", "T1548", "auditd", "Critical", "The sudoers file is edited, which can grant silent root access."),
    ("rule_012_account_enumeration", "Account enumeration", "T1087.001", "auditd", "High", "A burst of commands that list users and groups."),
    ("rule_013_system_discovery", "System discovery", "T1082", "auditd", "Medium", "A burst of commands that map out the machine."),
    ("rule_014_masquerading", "Process name mismatch", "T1036", "auditd", "Critical", "A process whose name does not match its program, which can hide malware but also trips on harmless tools."),
    ("rule_015_cowrie_login", "Honeypot login", "T1110.001", "cowrie", "Critical", "An attacker gets into the honeypot with a guessed password."),
    ("rule_016_canary_credential_used", "Canary credential used", "T1078", "cloudtrail", "Critical", "A decoy AWS key that nobody should use is used."),
    ("rule_017_falco_default_passthrough", "Container runtime alert (Falco)", "T1053.003 / T1548", "falco", "Info to Critical", "Falco's own alerts from the Kubernetes lab, passed through."),
    ("rule_018_collector_heartbeat", "Log source went silent", "T1562.001", "pipeline", "Medium to High", "Watches the pipeline itself. Not listed with the public alerts."),
]


def with_counts(rule_counts: dict) -> list[dict]:
    """Every rule, including the ones that have never fired, with total / last 24 h / last fired."""
    rows = []
    for rule_id, name, technique, source, severity, what in CATALOG:
        c = rule_counts.get(rule_id) or {}
        rows.append({"id": rule_id, "name": name, "technique": technique, "source": source, "severity": severity,
                     "what": what, "total": c.get("total", 0), "last_24h": c.get("last_24h", 0) or 0,
                     "last_seen": c.get("last_seen")})
    return rows
