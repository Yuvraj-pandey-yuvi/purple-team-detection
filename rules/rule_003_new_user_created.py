# rule_003_new_user_created.py
# ATT&CK T1136.001 - Create Local Account
#
# Logic: detect new user creation from auth.log
# auth.log reliably captures useradd events
#
# Log source: auth.log

import re

def detect(auth_log_text):
    """
    Scans auth.log for new user creation events.
    Returns list of alerts.
    """
    alerts = []

    # Pattern 1: matches the new user creation line
    # useradd[26960]: new user: name=atomic_test_user, UID=1002
    user_pattern = re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*'
        r'useradd\[\d+\]: new user: name=(\w+).*'
        r'UID=(\d+).*GID=(\d+)'
    )

    # Pattern 2: matches the sudo line showing WHO ran useradd
    # sudo: ubuntu : TTY=pts/1 ... COMMAND=/usr/sbin/useradd ...
    sudo_pattern = re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*'
        r'sudo:.*?(\w+)\s*:.*'
        r'COMMAND=.*useradd.*?(\w[\w-]+)\s*$'
    )

    SYSTEM_UID_THRESHOLD = 1000
    KNOWN_USERS          = ['ubuntu', 'testuser', 'root']

    # Build a lookup of who ran useradd and when
    # key: username_created, value: who_ran_it
    created_by_map = {}
    lines = auth_log_text.split('\n')

    for line in lines:
        sudo_match = sudo_pattern.search(line)
        if sudo_match:
            executor = sudo_match.group(2)  # who ran sudo
            target   = sudo_match.group(3)  # username being created
            created_by_map[target] = executor

    # Now find all user creation events
    for line in lines:
        match = user_pattern.search(line)
        if not match:
            continue

        timestamp = match.group(1)
        username  = match.group(2)
        uid       = int(match.group(3))
        gid       = match.group(4)

        # Skip system accounts
        if uid < SYSTEM_UID_THRESHOLD:
            continue

        # Skip known legitimate users
        if username in KNOWN_USERS:
            continue

        # Who created this user
        created_by = created_by_map.get(username, 'unknown')

        # Is this suspicious?
        # More suspicious if created by unexpected account
        # or at unusual naming pattern
        suspicious_names = ['admin', 'root2', 'test',
                            'backdoor', 'hack', 'tmp']
        name_suspicious = any(
            s in username.lower() for s in suspicious_names
        )

        severity = 'CRITICAL' if name_suspicious else 'HIGH'

        alerts.append({
            'rule_id':    'RULE-003',
            'rule_name':  'New Local User Account Created',
            'technique':  'T1136.001',
            'severity':   severity,
            'log_source': 'auth.log',

            # Who was created
            'new_username': username,
            'uid':          uid,
            'gid':          gid,

            # Who created them
            'created_by':   created_by,

            # When
            'timestamp':    timestamp,

            # Extra context
            'name_suspicious': name_suspicious,

            'reason': (
                f"New user '{username}' (UID {uid}) created "
                f"by '{created_by}' at {timestamp}"
            )
        })

    return alerts