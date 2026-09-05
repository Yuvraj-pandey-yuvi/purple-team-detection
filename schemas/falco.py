"""
schemas/falco.py
-----------------
Schema for Falco alerts — your source for:
  Container/pod runtime detection (5th log source, joins auditd,
  auth_log, CloudTrail, Cowrie)

Based on a REAL captured alert from your kubeadm-cluster-lab, json_output: true:
{
  "hostname":"ip-172-31-40-76",
  "output":"...",
  "output_fields":{
    "container.id":"host","container.name":"host","evt.type":"openat",
    "fd.name":"/etc/shadow","k8s.ns.name":null,"k8s.pod.name":null,
    "proc.cmdline":"cat /etc/shadow","proc.exepath":"/usr/bin/cat",
    "proc.name":"cat","proc.pname":"sudo","user.loginuid":1000,
    "user.name":"root","user.uid":0
  },
  "priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall",
  "tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],
  "time":"2026-09-01T06:47:31.554672538Z"
}

WHY hostname/tags/source ARE REQUIRED (unlike output_fields-derived fields):
Every alert captured from this pipeline's own Falco deployment has had
all three present. Falco's own json_output_properties config (falco.yaml)
makes these individually togglable, so a different Falco config COULD
omit them -- but this pipeline's config always includes them. If that
config ever changes, this will fail loudly with a ValidationError rather
than silently producing incomplete alerts -- which is the correct
failure mode (see _parse_kv empty-string bug precedent in Phase 2).

WHY output_fields-DERIVED fields ARE ALL Optional:
Confirmed via Falco's own GitHub issues -- output_fields is populated
per-rule, not a fixed guaranteed set. A "Container Entrypoint Seen"
alert (falcosecurity/falco#560) has a completely different field subset
than the shadow-read alert above (no user.uid, no proc.name, no
k8s.pod.name at all). No exceptions to Optional here.

WHY 'source' NEEDS SPECIAL HANDLING:
Falco's own JSON has a top-level "source" key ("syscall" vs "k8s_audit")
-- its classification of which event source produced this alert.
BaseLogEvent ALSO has a "source" field, meaning something totally
different: which collector in this pipeline produced the event.
Same name, unrelated meanings -- passing both raises
"got multiple values for keyword argument 'source'" (confirmed via a
real test). Falco's own value is preserved under event_source instead,
and this pipeline's source is hardcoded to LogSource.FALCO, same
pattern as CloudTrailEvent hardcoding LogSource.CLOUDTRAIL.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Optional

from pydantic import Field, field_validator

from .base import BaseLogEvent, LogSource

logger = logging.getLogger(__name__)


class FalcoEvent(BaseLogEvent):
    """A parsed Falco alert (json_output: true).

    Input is a dict (already parsed JSON) -- not a raw string.
    The .raw field stores the original JSON string for forensic
    preservation, same as CloudTrailEvent.
    """

    source: LogSource = LogSource.FALCO

    # ── Structurally guaranteed by Falco's alert envelope (required) ──────────
    hostname: str
    output: str
    priority: str
    rule: str
    tags: list[str]

    # Falco's OWN source classification ("syscall" / "k8s_audit" / plugin name).
    # NOT the same thing as BaseLogEvent.source -- see module docstring.
    event_source: Optional[str] = Field(default=None, alias="falco_event_source")

    # ── output_fields-derived (NEVER required -- see module docstring) ────────
    user_uid: Optional[int] = Field(default=None, alias="user.uid")
    user_name: Optional[str] = Field(default=None, alias="user.name")
    user_loginuid: Optional[int] = Field(default=None, alias="user.loginuid")
    proc_pname: Optional[str] = Field(default=None, alias="proc.pname")
    proc_name: Optional[str] = Field(default=None, alias="proc.name")
    proc_exepath: Optional[str] = Field(default=None, alias="proc.exepath")
    proc_cmdline: Optional[str] = Field(default=None, alias="proc.cmdline")
    k8s_pod_name: Optional[str] = Field(default=None, alias="k8s.pod.name")
    k8s_ns_name: Optional[str] = Field(default=None, alias="k8s.ns.name")
    fd_name: Optional[str] = Field(default=None, alias="fd.name")
    evt_type: Optional[str] = Field(default=None, alias="evt.type")
    container_name: Optional[str] = Field(default=None, alias="container.name")
    container_image_repository: Optional[str] = Field(
        default=None, alias="container.image.repository"
    )
    container_id: Optional[str] = Field(default=None, alias="container.id")

    model_config = {
        "populate_by_name": True,   # accept both alias and field name
        "frozen": True,
        "extra": "allow",
    }

    # ── Validators ───────────────────────────────────────────────────────────

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_falco_ts(cls, v):
        """
        Falco's 'time' field is ISO-8601 with nanosecond precision:
        '2026-09-01T06:47:31.554672538Z'. Python's datetime has no
        nanosecond resolution -- fromisoformat() silently truncates to
        microseconds (confirmed: .554672538 -> .554672, no error, no
        rounding). Own validator kept separate from CloudTrail's
        identical-looking one deliberately -- same reasoning as every
        other per-source validator in this repo: a future Falco-specific
        quirk (different output mode, different chart version) shouldn't
        risk touching CloudTrail's parsing.
        """
        if isinstance(v, str):
            cleaned = v.replace("Z", "+00:00")
            try:
                return datetime.fromisoformat(cleaned)
            except ValueError:
                pass
        return v

    # ── Factory ──────────────────────────────────────────────────────────────

    @classmethod
    def from_alert(cls, record: dict) -> "FalcoEvent":
        """
        Parse a single Falco alert dict into a validated FalcoEvent.

        Steps (confirmed against real captured data, not assumed):
          1. Rename Falco's own 'source' key to 'falco_event_source' --
             prevents the keyword collision with BaseLogEvent.source.
          2. Flatten output_fields onto the top level, so dotted keys
             like 'user.uid' can be matched by Field(alias=...).
          3. Compute extra_fields = anything not modeled -- confirmed
             via real test that unmodeled keys (evt.time, proc.tty,
             container.image.tag, proc.aname[2]) land here correctly.
          4. Pop 'time' after extracting it into timestamp, so it isn't
             duplicated as a stray top-level attribute alongside its
             copy already sitting in extra.

        Usage:
            record = json.loads(line)
            event = FalcoEvent.from_alert(record)
        """
        flat = dict(record)

        if "source" in flat:
            flat["falco_event_source"] = flat.pop("source")

        output_fields = flat.pop("output_fields", {})
        flat.update(output_fields)

        known_aliases = {
            f.alias for f in cls.model_fields.values() if f.alias is not None
        }
        known_top_level = {"hostname", "output", "priority", "rule", "tags", "time"}
        known_keys = known_aliases | known_top_level

        extra_fields = {k: v for k, v in flat.items() if k not in known_keys}

        raw_str = json.dumps(record, default=str)
        time_val = flat.pop("time", None)

        return cls(
            source=LogSource.FALCO,
            timestamp=time_val,
            raw=raw_str,
            extra=extra_fields,
            **flat,
        )

    @classmethod
    def from_jsonl(cls, jsonl_str: str) -> list["FalcoEvent"]:
        """
        Parse a whole Falco shipper .jsonl object (one JSON alert per line,
        the format your S3 shipper script produces).

        Same skip-and-log-on-failure pattern as
        CloudTrailEvent.from_s3_json -- one malformed line shouldn't
        drop the rest of the file.

        Usage:
            obj_body = s3_client.get_object(...)["Body"].read().decode()
            events = FalcoEvent.from_jsonl(obj_body)
        """
        events: list["FalcoEvent"] = []
        for lineno, line in enumerate(jsonl_str.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                events.append(cls.from_alert(record))
            except Exception as exc:
                logger.debug("Falco alert parse error at line %d: %s", lineno, exc)
        return events

    # ── Detection properties ────────────────────────────────────────────────
    # (placeholder -- populate once custom ATT&CK-mapped Falco rules exist;
    #  MITRE technique IDs already arrive for free in `tags`, e.g. "T1555")