from datetime import datetime, timezone
from schemas import (
    CloudTrailEvent, Alert, ATTCKTechnique,
    Severity, LogSource
)

# The 3 canary IAM usernames (see terraform/canary.tf). Each is a real IAM
# user with ZERO attached permissions - every API call they attempt is
# denied by AWS's own default-deny posture, but CloudTrail still logs the
# attempt regardless of success/failure. Nothing legitimate should EVER
# use these identities - same "100% confidence, no tuning needed" design
# as rule_015's honeypot login detection, applied to real host compromise
# instead of honeypot interaction.
#
# Each username is planted in a different location on the real EC2 host
# (not the honeypot - a canary INSIDE Cowrie would be redundant with
# rule_015, since any honeypot login is already 100% confidence malicious;
# this one specifically catches undetected compromise of the REAL system,
# which existing pattern-based rules structurally cannot guarantee catching):
#   bashrc  -> /root/.bashrc              (requires full root to find)
#   storage -> ~/backups/aws_backup_credentials.txt  (readable by any user)
#   cron    -> ~/scripts/check_engine_health.sh      (readable by any user,
#              credential is planted but deliberately never executed by
#              the real script - see script's own comments)
CANARY_USERNAMES = {
    "jenkins-deploy-temp": "bashrc",
    "backup-user": "storage",
    "s3-backup-cron": "cron",
}


def detect(events: list[CloudTrailEvent]) -> list[Alert]:
    """One CRITICAL alert per canary identity, ever - not per event.
    Given the near-zero legitimate-use base rate (should be exactly zero),
    a single hit already means real host compromise; alerting per-event
    would only add noise without adding confidence."""
    alerts = []

    for event in events:
        if event.actor_username not in CANARY_USERNAMES:
            continue

        plant_location = CANARY_USERNAMES[event.actor_username]

        alerts.append(Alert(
            rule_id     = "rule_016_canary_credential_used",
            technique   = ATTCKTechnique.T1078,
            severity    = Severity.CRITICAL,
            timestamp   = datetime.now(timezone.utc),
            first_seen  = event.timestamp,
            dedup_key   = event.actor_username,
            log_source  = LogSource.CLOUDTRAIL,
            description = (
                f"Canary credential '{event.actor_username}' was used — "
                f"this identity has zero real permissions and exists only "
                f"as bait planted at: {plant_location}. Its use means "
                f"someone with real filesystem access to the EC2 host "
                f"found and attempted to reuse this credential. Real "
                f"system compromise, independent of whether any other "
                f"detection rule fired."
            ),
            extra = {
                "canary_username": event.actor_username,
                "plant_location": plant_location,
                "event_name": event.event_name,
                "event_source": event.event_source,
                "source_ip": event.source_ip,
                "user_agent": event.user_agent,
                "aws_region": event.aws_region,
            }
        ))

    return alerts
