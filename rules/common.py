"""
rules/common.py
-----------------
Shared constants used across multiple detection rules.

This exists specifically to avoid two near-identical lists silently
drifting apart over time (add a new sensitive service to one rule,
forget the other). See the discussion that led to this file: it
started as a question of whether rule_004's SHADOW_WHITELIST and a new
masquerading check should share one list. They don't — they answer two
different questions — but the pieces that DO answer the same question
across multiple rules belong here, once.

SENSITIVE_PROCESS_NAMES
    "Is this process name valuable enough for an attacker to
    impersonate?" — an identity worth protecting, independent of what
    the process is currently doing. NOT the same question as "is this
    process allowed to do X" (that's what a rule-specific whitelist
    like SHADOW_WHITELIST answers).

TRUSTED_BIN_DIRS
    Standard Linux locations where legitimate installed binaries live.
    Deliberately a short, stable list — real system binaries don't
    move around, unlike the near-infinite set of individual binary
    names you'd otherwise have to enumerate.

comm_is_truncated_prefix_of()
    The kernel's `comm` field (/proc/PID/comm) is hard-limited to 15
    characters. A legitimately long process name (e.g.
    "unattended-upgrades") gets truncated to "unattended-upgr" — this
    is NOT masquerading, it's just how the kernel works. This helper
    tells the difference between "genuinely truncated" and "actually
    doesn't match at all".
"""

SENSITIVE_PROCESS_NAMES = {
    # Authentication / access control
    "sshd", "sshd-session", "sudo", "su", "passwd", "unix_chkpwd",
    "polkitd",
    # Persistence
    "cron", "crond", "systemd",
    # System integrity / logging / auditing
    "auditd", "rsyslogd", "systemd-journald",
    # Networking
    "NetworkManager", "systemd-resolved", "sshd-session",
    # IPC / core services
    "dbus-daemon",
}

TRUSTED_BIN_DIRS = (
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/lib/",
    "/usr/libexec/",
)

COMM_MAX_LEN = 15  # hard kernel limit on /proc/PID/comm


def exe_in_trusted_dir(exe: str) -> bool:
    """True if exe's path starts with one of TRUSTED_BIN_DIRS.

    NOTE the trailing slash on every entry in TRUSTED_BIN_DIRS — without
    it, "/usr/bin-evil/malware".startswith("/usr/bin") would incorrectly
    return True. The trailing slash makes this a real directory-boundary
    check, not just a string-prefix check.
    """
    if not exe:
        return False
    return exe.startswith(TRUSTED_BIN_DIRS)


def comm_is_truncated_prefix_of(comm: str, exe_basename: str) -> bool:
    """True if `comm` looks like a legitimate kernel truncation of
    exe_basename, rather than an unrelated/fabricated name.

    Both conditions must hold:
      1. comm is exactly COMM_MAX_LEN chars — truncation can only ever
         produce a name at exactly the limit. A shorter comm that still
         doesn't match exe_basename was never truncated; it's just wrong.
      2. comm is an exact prefix of exe_basename — the kernel truncates
         by cutting the end off, nothing else.
    """
    if len(comm) != COMM_MAX_LEN:
        return False
    return exe_basename.startswith(comm)