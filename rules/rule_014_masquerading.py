import os
from datetime import datetime, timezone
from schemas import AuditdEvent, Alert, ATTCKTechnique, Severity, LogSource
from rules.common import (
    SENSITIVE_PROCESS_NAMES,
    exe_in_trusted_dir,
    comm_is_truncated_prefix_of,
)

# Symlink-driven, known-legitimate comm/exe pairs — same idea as
# rule_004's COMM_EXE_WHITELIST, kept local since it's specific to the
# general masquerading check, not shared.
COMM_EXE_WHITELIST = {
    ("sh", "/usr/bin/dash"),
    ("sh", "/bin/dash"),
}


def detect(events: list[AuditdEvent]) -> list[Alert]:
    """T1036 Masquerading — general-purpose, runs against every auditd
    event (not gated behind a specific `key`, unlike rule_004's original
    scoped-to-shadow-access version this replaces).

    Two independent signals, either one alone is enough to fire:
      1. Name mismatch: comm doesn't match exe's basename, and the
         mismatch isn't explained by kernel truncation or a known
         symlink pair.
      2. Path mismatch: comm claims to be a well-known sensitive
         service (SENSITIVE_PROCESS_NAMES), but exe is running from
         outside the standard trusted binary directories.

    An attacker can defeat signal 1 alone by naming their binary
    exactly like a trusted process (e.g. renaming malware to
    "unattended-upgrades") — the name check has nothing to catch in
    that case, since comm and exe genuinely agree. Signal 2 is what
    catches that: the NAME matches, but the LOCATION doesn't, which is
    much harder for an attacker to fake without already having deep
    system access.
    """
    alerts = []

    for event in events:
        if not event.exe or not event.comm:
            continue

        exe_basename = os.path.basename(event.exe)

        # --- Signal 1: name mismatch ---------------------------------
        name_mismatches = exe_basename != event.comm
        is_legit_truncation = comm_is_truncated_prefix_of(
            event.comm, exe_basename
        )
        is_known_symlink = (event.comm, event.exe) in COMM_EXE_WHITELIST

        if name_mismatches and not is_legit_truncation and not is_known_symlink:
            alerts.append(Alert(
                rule_id     = "rule_014_masquerading",
                technique   = ATTCKTechnique.T1036,
                severity    = Severity.CRITICAL,
                timestamp   = datetime.now(timezone.utc),
                first_seen  = event.timestamp,
                log_source  = LogSource.AUDITD,
                description = (
                    f"Process name mismatch: comm='{event.comm}' "
                    f"but exe='{event.exe}' — possible masquerading"
                ),
                extra = {
                    "exe":    event.exe,
                    "comm":   event.comm,
                    "auid":   event.auid,
                    "pid":    event.pid,
                    "signal": "name_mismatch",
                }
            ))

        # --- Signal 2: sensitive name running from an untrusted path -
        if event.comm in SENSITIVE_PROCESS_NAMES and not exe_in_trusted_dir(event.exe):
            alerts.append(Alert(
                rule_id     = "rule_014_masquerading",
                technique   = ATTCKTechnique.T1036,
                severity    = Severity.CRITICAL,
                timestamp   = datetime.now(timezone.utc),
                first_seen  = event.timestamp,
                log_source  = LogSource.AUDITD,
                description = (
                    f"Process claims to be sensitive service "
                    f"'{event.comm}' but is running from an untrusted "
                    f"location: {event.exe}"
                ),
                extra = {
                    "exe":    event.exe,
                    "comm":   event.comm,
                    "auid":   event.auid,
                    "pid":    event.pid,
                    "signal": "untrusted_path",
                }
            ))

    return alerts