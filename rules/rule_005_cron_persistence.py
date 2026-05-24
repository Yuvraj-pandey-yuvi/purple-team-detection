# rule_005_cron_persistence.py
# ATT&CK T1053.003 - Scheduled Task: Cron
#
# Logic: cron directory modified
# Attackers add cron jobs to maintain persistence
#
# Log source: auditd (key: cron_modification)

import re

def detect(audit_block):
    """
    Takes one auditd block (text between ---- separators)
    Returns alert if new cron job created
    """

    if 'key="cron_modification"' not in audit_block:
        return None

    # Extract all fields
    comm_match    = re.search(r'comm="([^"]+)"',    audit_block)
    fpath_match   = re.search(r'name="([^"]+)"',    audit_block)
    exe_match     = re.search(r'exe="([^"]+)"',     audit_block)
    auid_match    = re.search(r'\bauid=(\d+)',       audit_block)
    uid_match     = re.search(r'\buid=(\d+)',        audit_block)
    euid_match    = re.search(r'\beuid=(\d+)',       audit_block)
    pid_match     = re.search(r'\bpid=(\d+)',        audit_block)
    ppid_match    = re.search(r'ppid=(\d+)',         audit_block)
    success_match = re.search(r'success=(\w+)',      audit_block)
    tty_match     = re.search(r'tty=(\S+)',          audit_block)
    time_match    = re.search(r'msg=audit\((\d+)',   audit_block)

    comm      = comm_match.group(1)  if comm_match  else ''
    file_path = fpath_match.group(1) if fpath_match else ''
    auid      = auid_match.group(1)  if auid_match  else 'unknown'
    euid      = euid_match.group(1)  if euid_match  else 'unknown'

    # Filter out noise
    IGNORE_COMMS = ['auditctl', 'needrestart', 'cron','systemd-tmpfile']
    if comm in IGNORE_COMMS:
        return None

    # Only alert on file creation not directory access
    cron_dirs = ['/etc/cron.d', '/var/spool/cron', '/etc/crontab']
    if file_path in cron_dirs:
        return None
    
    # Must be an absolute path to a file, not a directory name
    if not file_path.startswith('/'):
         return None

    # Filter deletions
    if comm == 'rm':
        return None

    # Convert unix timestamp to readable
    timestamp = 'unknown'
    if time_match:
        try:
            from datetime import datetime, timezone
            ts = float(time_match.group(1))
            timestamp = datetime.fromtimestamp(
                ts, tz=timezone.utc
            ).strftime('%Y-%m-%dT%H:%M:%SZ')
        except Exception:
            timestamp = time_match.group(1)

    # Map auid to human readable
    auid_map = {
        '1000':       'ubuntu',
        '0':          'root',
        '4294967295': 'unset/system',
    }
    auid_human = auid_map.get(auid, f'uid_{auid}')

    # Privilege escalation check
    privilege_escalated = (auid != euid and euid == '0')

    # Assess suspicion level based on filename
    suspicious_names = [
        'backdoor', 'hack', 'shell', 'reverse',
        'payload', 'exploit', 'tmp', 'test'
    ]
    name_suspicious = any(
        s in file_path.lower() for s in suspicious_names
    )
    severity = 'CRITICAL' if name_suspicious else 'HIGH'

    # Extract just the filename from full path
    cron_filename = file_path.split('/')[-1] if file_path else 'unknown'

    return {
        'rule_id':   'RULE-005',
        'rule_name': 'Cron Job Created',
        'technique': 'T1053.003',
        'severity':  severity,
        'log_source': 'auditd',

        # What was created
        'cron_file':      cron_filename,
        'cron_file_path': file_path,

        # Process that created it
        'comm': comm,
        'exe':  exe_match.group(1)  if exe_match  else 'unknown',
        'pid':  pid_match.group(1)  if pid_match  else 'unknown',
        'ppid': ppid_match.group(1) if ppid_match else 'unknown',

        # Identity
        'auid':          auid,
        'auid_human':    auid_human,
        'uid':           uid_match.group(1) if uid_match else 'unknown',
        'euid':          euid,
        'tty':           tty_match.group(1) if tty_match else 'unknown',

        # Context
        'success':             success_match.group(1) if success_match else 'unknown',
        'privilege_escalated': privilege_escalated,
        'name_suspicious':     name_suspicious,
        'timestamp':           timestamp,

        'reason': (
            f"Cron job '{cron_filename}' created at '{file_path}' "
            f"by {auid_human} via '{comm}' "
            f"{'[PRIVILEGE ESCALATED]' if privilege_escalated else ''}"
            f"{'[SUSPICIOUS NAME]' if name_suspicious else ''}"
        )
    }