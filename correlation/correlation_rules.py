# correlation/correlation_rules.py
#
# Pure correlation config — no logic lives here, only data. Matches
# the existing project pattern of rules/rule_XXX.py being separate
# from detection/engine.py's orchestration: adding a new correlation
# relationship means editing THIS file only, never matching.py.
#
# Explicitly author-defined, never auto-inferred — this project
# deliberately chose to require a human decision for every correlation
# relationship, rather than guessing connections from shared fields.
#
# Structure, per anchor rule_id: a list of GROUPS. Each group is a
# list of (candidate_rule_id, severity) fallback tiers — within one
# group, first successful match wins (same confidence question, at
# different strength, e.g. "confirmed breach" vs "attempts only").
#
# Groups themselves are INDEPENDENT of each other — every group is
# checked regardless of whether another group already matched, since
# they represent genuinely different questions (e.g. "was there a
# breach?" vs "did they also create a persistence account?"). A single
# anchor can match zero, one, or several groups; all matched groups
# get combined into ONE CorrelatedIncident (Stage 4's job), not one
# per group.

from schemas import Severity

CORRELATION_RULES: dict[str, list[list[tuple[str, Severity]]]] = {
    "rule_008_cron_persistence": [
        # Group 1: "was there a breach on this account?" — fallback tiers
        [
            ("rule_007_brute_force_success", Severity.CRITICAL),
            ("rule_001_ssh_brute_force", Severity.MEDIUM),
        ],
        # Group 2: "did they also create a persistence account?" —
        # independent question, checked regardless of Group 1's result
        # TODO: uncomment once ready to wire this in for real
        # [
        #     ("rule_003_new_user_created", Severity.HIGH),
        # ],
    ],
}