# rule_004_shadow_access.py
# ATT&CK T1003.008 - OS Credential Dumping
# ATT&CK T1036     - Masquerading
# ATT&CK T1136.001 - Create Local Account (passwd write)
#
# Logic:
# 1. /etc/shadow accessed by non-whitelisted process
# 2. Whitelisted process running from unexpected path (masquerading)
# 3. /etc/passwd written to by non-legitimate process
#
# Log source: auditd (keys: shadow_access, passwd_write)

import re
from datetime import datetime, timezone


# ── CONSTANTS ────────────────────────────────────────────

# Process name → expected executable path
# If name matches but path doesn't = masquerading attack
EXE_WHITELIST = {
    'unix_chkpwd': '/usr/sbin/unix_chkpwd',
    'passwd':      '/usr/bin/passwd',
    'sshd-session': '/usr/lib/openssh/sshd-session',  # fix this
    'su':          '/usr/bin/su',
    'sudo':        '/usr/bin/sudo',
    'useradd':     '/usr/sbin/useradd',
    'login':       '/usr/bin/login',
    'chkexpiry':   '/usr/sbin/chkexpiry',
}

# Process names that are noisy but don't need path verification
# These are package manager / system tools we fully trust
NOISE_WHITELIST = [
    'dpkg-preconfigu',
    'frontend',
    '(systemd)',
    'systemd',
    'needrestart',
    'auditctl',
    'grep',
]

# Only these processes should ever write to /etc/passwd
LEGITIMATE_PASSWD_WRITERS = [
    'useradd',
    'usermod',
    'userdel',
    'vipw',
    'pwconv',
    'pwunconv',
    'chfn',
    'chsh',
]


# ── HELPERS ──────────────────────────────────────────────

def parse_block(audit_block):
    """Extract all useful fields from an auditd block"""
    def get(pattern, text, default='unknown'):
        m = re.search(pattern, text)
        return m.group(1) if m else default

    comm    = get(r'comm="([^"]+)"',    audit_block)
    exe     = get(r'exe="([^"]+)"',     audit_block)
    auid    = get(r'\bauid=(\d+)',       audit_block)
    uid     = get(r'\buid=(\d+)',        audit_block)
    euid    = get(r'\beuid=(\d+)',       audit_block)
    pid     = get(r'\bpid=(\d+)',        audit_block)
    ppid    = get(r'ppid=(\d+)',         audit_block)
    success = get(r'success=(\w+)',      audit_block)
    tty     = get(r'tty=(\S+)',          audit_block)
    ts_raw  = get(r'msg=audit\((\d+)',   audit_block)

    # Convert unix timestamp to readable
    timestamp = 'unknown'
    if ts_raw != 'unknown':
        try:
            ts = float(ts_raw)
            timestamp = datetime.fromtimestamp(
                ts, tz=timezone.utc
            ).strftime('%Y-%m-%dT%H:%M:%SZ')
        except Exception:
            timestamp = ts_raw

    # Map auid to human readable name
    auid_map = {
        '1000':       'ubuntu',
        '0':          'root',
        '4294967295': 'unset/system',
    }
    auid_human = auid_map.get(auid, f'uid_{auid}')

    # Privilege escalation: normal user running as root
    privilege_escalated = (
        auid not in ('0', '4294967295', 'unknown')
        and euid == '0'
    )

    return {
        'comm':               comm,
        'exe':                exe,
        'auid':               auid,
        'auid_human':         auid_human,
        'uid':                uid,
        'euid':               euid,
        'pid':                pid,
        'ppid':               ppid,
        'success':            success,
        'tty':                tty,
        'timestamp':          timestamp,
        'privilege_escalated': privilege_escalated,
    }


def build_alert(rule_id, rule_name, technique,
                severity, parsed, reason, extra=None):
    """Build a standardized alert dict"""
    alert = {
        'rule_id':   rule_id,
        'rule_name': rule_name,
        'technique': technique,
        'severity':  severity,
        'log_source': 'auditd',

        # Process
        'comm':  parsed['comm'],
        'exe':   parsed['exe'],
        'pid':   parsed['pid'],
        'ppid':  parsed['ppid'],

        # Identity
        'auid':               parsed['auid'],
        'auid_human':         parsed['auid_human'],
        'uid':                parsed['uid'],
        'euid':               parsed['euid'],
        'tty':                parsed['tty'],

        # Context
        'success':             parsed['success'],
        'privilege_escalated': parsed['privilege_escalated'],
        'timestamp':           parsed['timestamp'],

        'reason': reason,
    }
    if extra:
        alert.update(extra)
    return alert


# ── DETECTION LOGIC ──────────────────────────────────────

def detect(audit_block):
    """
    Main detection function.
    Handles shadow_access and passwd_write keys.
    Returns single alert or None.
    """

    # ── PASSWD WRITE DETECTION ───────────────────────────
    if 'key="passwd_write"' in audit_block:
        parsed = parse_block(audit_block)
        comm   = parsed['comm']

        if comm not in LEGITIMATE_PASSWD_WRITERS:
            return build_alert(
                rule_id   = 'RULE-004b',
                rule_name = 'Unauthorized /etc/passwd Modification',
                technique = 'T1136.001',
                severity  = 'CRITICAL',
                parsed    = parsed,
                reason    = (
                    f"Process '{comm}' wrote directly to /etc/passwd "
                    f"— possible backdoor account creation"
                ),
                extra = {'file': '/etc/passwd'}
            )
        return None

    # ── SHADOW ACCESS DETECTION ──────────────────────────
    if 'key="shadow_access"' not in audit_block:
        return None

    parsed = parse_block(audit_block)
    comm   = parsed['comm']
    exe    = parsed['exe']

    # Check 1: pure noise - skip entirely
    if comm in NOISE_WHITELIST:
        return None

    # Check 2: whitelisted process - verify exe path
    if comm in EXE_WHITELIST:
        expected_exe = EXE_WHITELIST[comm]
        if exe == expected_exe:
            return None  # legitimate - correct name AND path

        # Name matches but path is wrong = masquerading
        return build_alert(
            rule_id   = 'RULE-004c',
            rule_name = 'Process Masquerading Detected',
            technique = 'T1036',
            severity  = 'CRITICAL',
            parsed    = parsed,
            reason    = (
                f"Process named '{comm}' running from "
                f"'{exe}' instead of expected '{expected_exe}' "
                f"— possible masquerading attack (T1036)"
            ),
            extra = {
                'expected_exe': expected_exe,
                'actual_exe':   exe,
            }
        )

    # Check 3: unknown process accessing shadow
    return build_alert(
        rule_id   = 'RULE-004',
        rule_name = 'Credential Dump via /etc/shadow',
        technique = 'T1003.008',
        severity  = 'CRITICAL',
        parsed    = parsed,
        reason    = (
            f"Process '{comm}' accessed /etc/shadow "
            f"as {parsed['auid_human']} (euid={parsed['euid']}) "
            f"{'[PRIVILEGE ESCALATED]' if parsed['privilege_escalated'] else ''}"
        )
    )
