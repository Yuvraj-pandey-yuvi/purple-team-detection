"""
schemas/cloudtrail.py
---------------------
Schema for AWS CloudTrail events — your source for:
  T1078  Valid Accounts / Console login without MFA

Based on REAL log structure from your EC2:
  userIdentity.sessionContext.attributes.mfaAuthenticated = "false"
  (NOT additionalEventData.MFAUsed as AWS docs suggest for console logins)

Real CloudTrail record structure:
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAVCX2MQYBU5QCZQYAT",
    "arn": "arn:aws:iam::349491201539:user/buddy",
    "accountId": "349491201539",
    "accessKeyId": "ASIAVCX2MQYBZ65M6RDH",
    "userName": "buddy",
    "sessionContext": {
      "attributes": {
        "creationDate": "2026-05-21T12:17:33Z",
        "mfaAuthenticated": "false"   <-- THIS is where MFA status lives
      }
    }
  },
  "eventTime": "2026-05-21T13:08:38Z",
  "eventSource": "logs.amazonaws.com",
  "eventName": "DescribeMetricFilters",
  "awsRegion": "eu-north-1",
  "sourceIPAddress": "47.15.34.78",
  "responseElements": null,           <-- null for read-only calls
  ...
}
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator, model_validator

from .base import BaseLogEvent, LogSource


class CloudTrailEvent(BaseLogEvent):
    """A parsed AWS CloudTrail record.

    Input is a dict (already parsed JSON) — not a raw string like
    auditd or auth.log. The .raw field stores the original JSON string
    for forensic preservation.
    """

    source: LogSource = LogSource.CLOUDTRAIL

    # ── Standard CloudTrail fields ────────────────────────────────────────────
    event_version: str = Field(default="", alias="eventVersion")
    event_time: Optional[datetime] = Field(default=None, alias="eventTime")
    event_source: str = Field(default="", alias="eventSource")
    event_name: str = Field(default="", alias="eventName")
    aws_region: str = Field(default="", alias="awsRegion")
    source_ip: Optional[str] = Field(default=None, alias="sourceIPAddress")
    user_agent: Optional[str] = Field(default=None, alias="userAgent")
    read_only: Optional[bool] = Field(default=None, alias="readOnly")
    event_type: Optional[str] = Field(default=None, alias="eventType")

    # ── Identity — raw block kept, typed fields extracted in model_validator ──
    user_identity_raw: dict = Field(default_factory=dict, alias="userIdentity")
    """
    Raw userIdentity block preserved in full.
    Typed fields below are extracted from it in extract_actor_info().
    We keep the raw block because userIdentity structure varies by
    identity type (IAMUser vs AssumedRole vs Root) and we don't want
    to lose fields during extraction.
    """

    # Extracted from user_identity_raw by model_validator
    actor_username: Optional[str] = None
    actor_type: str = ""
    actor_arn: Optional[str] = None
    actor_account_id: Optional[str] = None

    # ── MFA status — extracted from userIdentity.sessionContext ───────────────
    mfa_authenticated: Optional[bool] = None
    """
    Extracted from userIdentity.sessionContext.attributes.mfaAuthenticated.

    WHY HERE AND NOT additionalEventData:
    AWS docs mention additionalEventData.MFAUsed for ConsoleLogin events.
    But your real logs show mfaAuthenticated lives in sessionContext for
    IAMUser API calls. We check both locations for maximum coverage.
    """

    # ── Response ──────────────────────────────────────────────────────────────
    response_elements: Optional[dict] = Field(default=None, alias="responseElements")
    """
    null for read-only API calls (DescribeMetricFilters, ListBuckets etc).
    Contains result data for write operations.
    Always guard with 'if self.response_elements' before accessing.
    """

    additional_event_data: Optional[dict] = Field(
        default=None, alias="additionalEventData"
    )
    error_code: Optional[str] = Field(default=None, alias="errorCode")
    error_message: Optional[str] = Field(default=None, alias="errorMessage")

    model_config = {
        "populate_by_name": True,   # accept both alias and field name
        "frozen": True,
        "extra": "allow",
    }

    # ── Validators ───────────────────────────────────────────────────────────

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_cloudtrail_ts(cls, v):
        """
        CloudTrail uses ISO-8601 with Z suffix: '2026-05-21T13:08:38Z'
        Python < 3.11 fromisoformat() doesn't handle Z — replace with +00:00
        """
        if isinstance(v, str):
            cleaned = v.replace("Z", "+00:00")
            try:
                return datetime.fromisoformat(cleaned)
            except ValueError:
                pass
        return v

    @model_validator(mode="after")
    def extract_actor_info(self) -> "CloudTrailEvent":
        """
        Pull typed fields out of the raw userIdentity block.

        WHY model_validator AND NOT field_validator:
        We need to set multiple fields (actor_username, actor_type, etc.)
        from one source (user_identity_raw). field_validator only handles
        one field at a time. model_validator runs after all fields are set
        and can modify multiple fields at once.

        WHY object.__setattr__:
        frozen=True makes the model immutable — normal assignment raises.
        object.__setattr__ bypasses Pydantic's frozen check, which is
        acceptable here because we're still inside __init__ territory
        (model_validator runs during construction, not after).

        USERNAME EXTRACTION CASCADE:
        Different identity types store username differently:
          IAMUser:     userIdentity.userName = "buddy"
          AssumedRole: userIdentity.sessionIssuer.userName = "admin-role"
          Root:        no userName field — use "root"
          AWSService:  no userName — use principalId
        We try each location in order, take first non-None value.
        """
        uid = self.user_identity_raw

        # Actor type
        object.__setattr__(self, "actor_type", uid.get("type", ""))
        object.__setattr__(self, "actor_arn", uid.get("arn"))
        object.__setattr__(self, "actor_account_id", uid.get("accountId"))

        # Username cascade
        username = (
            uid.get("userName")                                    # IAMUser
            or uid.get("sessionIssuer", {}).get("userName")        # AssumedRole
            or ("root" if uid.get("type") == "Root" else None)     # Root account
            or uid.get("principalId", "").split(":")[-1]           # fallback
            or None
        )
        object.__setattr__(self, "actor_username", username)

        # MFA status — check sessionContext first (your real log format)
        # then fall back to additionalEventData (ConsoleLogin format)
        mfa = None
        session_ctx = uid.get("sessionContext", {})
        attributes = session_ctx.get("attributes", {})
        mfa_str = attributes.get("mfaAuthenticated")
        if mfa_str is not None:
            mfa = mfa_str.lower() == "true"
        elif self.additional_event_data:
            # ConsoleLogin format: additionalEventData.MFAUsed = "Yes"/"No"
            mfa_used = self.additional_event_data.get("MFAUsed")
            if mfa_used is not None:
                mfa = mfa_used == "Yes"

        object.__setattr__(self, "mfa_authenticated", mfa)

        return self

    # ── Detection properties ──────────────────────────────────────────────────

    @property
    def mfa_used(self) -> bool:
        """
        True if MFA was used. Conservative default: True when unknown.

        WHY DEFAULT TRUE (not False):
        If mfa_authenticated is None — we couldn't determine MFA status.
        Defaulting to True means we don't alert on events where we simply
        lack the information. False positives on every service call that
        doesn't log MFA status would drown out real alerts.
        This is the 'fail safe' principle in detection engineering.
        """
        if self.mfa_authenticated is None:
            return True
        return self.mfa_authenticated

    @property
    def is_console_login(self) -> bool:
        return self.event_name == "ConsoleLogin"

    @property
    def login_success(self) -> bool:
        """
        True if ConsoleLogin succeeded.
        Guards against responseElements being null (read-only calls).
        """
        if not self.response_elements:
            return False
        return self.response_elements.get("ConsoleLogin") == "Success"

    @property
    def is_api_call_without_mfa(self) -> bool:
        """
        T1078 signal for API calls (not just console login).

        YOUR REAL LOGS show buddy making API calls with mfaAuthenticated=false.
        This is a broader signal than just ConsoleLogin — any API call
        from an IAMUser without MFA is a risk.
        """
        return (
            self.actor_type == "IAMUser"
            and self.mfa_authenticated is False
            and not self.error_code   # successful call, not a failed attempt
        )

    @property
    def is_suspicious_login(self) -> bool:
        """T1078 composite: successful console login without MFA."""
        return self.is_console_login and self.login_success and not self.mfa_used

    # ── Factory ──────────────────────────────────────────────────────────────

    @classmethod
    def from_record(cls, record: dict) -> "CloudTrailEvent":
        """
        Parse a single CloudTrail record dict into a validated CloudTrailEvent.

        WHY dict input NOT string:
        CloudTrail events are already JSON. Parsing JSON twice (string→dict→object)
        wastes time and can lose precision on numbers. The normalizer calls
        json.loads() once, then passes the dict here.

        Usage:
            data = json.loads(cloudtrail_file_content)
            events = [CloudTrailEvent.from_record(r) for r in data["Records"]]
        """
        raw_str = json.dumps(record, default=str)

        return cls(
            source=LogSource.CLOUDTRAIL,
            timestamp=record.get("eventTime", ""),
            raw=raw_str,
            **record,
        )

    @classmethod
    def from_s3_json(cls, json_str: str) -> list["CloudTrailEvent"]:
        """
        Parse an entire CloudTrail JSON file from S3.

        CloudTrail S3 objects always have {"Records": [...]} wrapper.
        Returns list of events, skips records that fail validation.
        """
        data = json.loads(json_str)
        records = data.get("Records", [])

        events = []
        for record in records:
            try:
                events.append(cls.from_record(record))
            except Exception as exc:
                import logging
                logging.getLogger(__name__).debug(
                    "CloudTrail record parse error: %s", exc
                )
        return events