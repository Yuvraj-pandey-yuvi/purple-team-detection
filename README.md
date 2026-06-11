<img width="1298" height="625" alt="brave_screenshot (1)" src="https://github.com/user-attachments/assets/dbb442b1-1d37-4101-8db5-46972fc55b3e" /># Purple Team Detection Pipeline

An automated threat detection system that simulates real MITRE ATT&CK techniques on AWS infrastructure and measures detection coverage in real time.

Built as a demonstration of detection engineering principles — not a tutorial project, but a working system detecting real attacks on a live server.

---

## What It Does

1. **Simulates attacks** using Atomic Red Team mapped to MITRE ATT&CK techniques on an AWS EC2 instance
2. **Collects logs incrementally** from three sources: Linux auditd, auth.log, and AWS CloudTrail — using seek pointers to process only new lines each run
3. **Normalizes events** through a Pydantic schema layer — typed, validated Python objects before any rule sees the data
4. **Detects attacks** using 13 custom Python detection rules with intelligent false positive filtering
5. **Generates coverage reports** showing which techniques were detected, which were missed, and why
6. **Visualizes results** on a real-time dashboard with ATT&CK matrix, attacker geolocation map, and user activity charts
7. **Documents detection logic** with Sigma rules (portable to any SIEM) and analyst playbooks for each technique

---

## Architecture



<img width="111" height="150" alt="purple_team_pipeline_flow" src="https://github.com/user-attachments/assets/113897df-e4cb-4012-866a-456b9022bb86" />


## ATT&CK Techniques Covered

| # | Technique | Name | Log Source | Detection Method | Status |
|---|-----------|------|------------|-----------------|--------|
| 001 | T1110.001 | Brute Force: Password Guessing | auth.log | Sliding window 300s, attack speed classification | ✅ |
| 002 | T1078 | Valid Accounts: No MFA | CloudTrail | sessionContext.mfaAuthenticated + ConsoleLogin | ✅ |
| 003 | T1136.001 | Create Local Account | auth.log | useradd pattern, suspicious username detection | ✅ |
| 004 | T1003.008 | OS Credential Dumping | auditd | shadow_access key + exe whitelist | ✅ |
| 005 | T1548 | Privilege Escalation | auditd | euid=0 + auid≥1000 + auid≠4294967295 | ✅ |
| 006 | T1036.005 | Masquerading | auditd | exe path vs comm mismatch | ✅ |
| 007 | T1078.001 | Valid Accounts: Root Login | CloudTrail | userIdentity.type = Root | ✅ |
| 008 | T1110.001 | Brute Force Success | auth.log | Failures + accepted login from same IP ≤600s | ✅ |
| 009 | T1053.003 | Cron Persistence | auditd | cron_modification key + write syscalls only | ✅ |
| 010 | T1562.002 | CloudTrail Disabled | CloudTrail | DeleteTrail, StopLogging, UpdateTrail | ✅ |
| 011 | T1562.001 | auditd Disabled | auditd | auditd_tamper key on auditctl execution | ✅ |
| 012 | T1087.001 | Account Enumeration | auditd | /etc/passwd reads + id/whoami in burst | ✅ |
| 013 | T1082 | System Discovery | auditd | 5+ discovery commands in 120s sliding window | ✅ |

**Detection coverage: 13 techniques across 7 ATT&CK tactics**

---

## Schema Layer

All log sources are normalized through a Pydantic validation layer before reaching detection rules. Raw log bytes become typed Python objects at the boundary — no rule ever parses strings or handles missing keys.

```
/var/log/auth.log     →  AuthLogEvent    (source_ip, auth_result, username, port)
/var/log/audit.log    →  AuditdEvent     (auid, uid, euid, exe, comm, key, name)
S3 CloudTrail JSON    →  CloudTrailEvent (actor_username, mfa_authenticated, event_name)
```

Key design decisions:
- `frozen=True` — events are immutable after parsing, rules cannot corrupt shared state
- UTC normalization — all timestamps converted to UTC-aware datetime before any rule runs
- auditd multi-record correlation — SYSCALL + PATH records grouped by serial number before parsing
- `extra: allow` — unknown fields preserved for forensics without crashing the pipeline

---

## Sigma Rules

Every detection rule has a corresponding Sigma rule in `/sigma/` — portable to Splunk, Elastic, Microsoft Sentinel via `sigma-cli`.

```bash
# Convert to Splunk SPL
sigma convert -t splunk sigma/rule_001_ssh_brute_force.yml

# Convert to Elasticsearch
sigma convert -t elasticsearch sigma/rule_004_shadow_access.yml
```

Note: Sigma rules match single events. Threshold/window correlation (e.g. 5 failures in 300s) is handled by the Python detection rules.

---

## Analyst Playbooks

Each detection rule has a corresponding playbook in `/playbooks/` documenting:
- Immediate actions (0–15 mins)
- Investigation questions
- Containment steps
- Evidence to collect
- How to prevent recurrence

---

## Incremental Log Processing

The pipeline uses seek pointers to avoid reprocessing old log lines:

```json
// reports/state.json — updated after every run
{
  "auth_log_position": 48392,
  "auditd_position": 129841,
  "cloudtrail_last_file": "349491201539_CloudTrail_eu-north-1_20260604T1310Z.json.gz",
  "last_run": "2026-06-04T10:30:00Z"
}
```

- **auth.log / auditd**: byte-position seek — reads only lines written since last run
- **CloudTrail**: last-filename tracking — alphabetical order equals chronological order
- **Log rotation detection**: resets position if file size < last position

---

## Alert Persistence and Deduplication

Alerts accumulate across runs in `reports/alerts.json`. New alerts are deduplicated before appending:

```python
dedup_key = f"{rule_id}:{source_ip}:{username}"
```

Same attacker triggering the same rule suppresses duplicate pages to analysts.

---

## Real Findings During Development

This system detected real attacks — not just simulated ones:

- **178.175.167.68 (Moldova)** — 26 SSH brute force attempts over 59 seconds, classified as aggressive
- **47.251.122.241** — 55 failed SSH attempts detected automatically without simulation
- **139.19.117.129** — Repeated login attempts across multiple days, identified as persistent scanner

These appeared naturally on the internet-facing EC2 instance within 24 hours of deployment.

---

## Detection Rules

**auth.log rules (Initial Access, Persistence)**
- `rule_001` — SSH brute force: sliding window, attack speed classification (aggressive/moderate/slow)
- `rule_003` — New user creation: suspicious username detection, creator attribution via sudo logs
- `rule_008` — Brute force success: confirmed breach when failures followed by accepted login ≤600s

**auditd rules (Execution, Privilege Escalation, Defense Evasion, Discovery)**
- `rule_004` — Shadow file access: exe whitelist, catches masquerading via path mismatch
- `rule_005` — Privilege escalation: euid=0 with auid≥1000, excludes system processes (4294967295)
- `rule_009` — Cron persistence: write syscalls only {257,2,82,86}, ignores ls/stat false positives
- `rule_010` — auditd tamper: auditctl execution detected before logging goes silent
- `rule_012` — Account enumeration: burst detection on /etc/passwd reads and id/whoami
- `rule_013` — System discovery: 5+ fingerprinting commands in 120s = post-exploitation recon

**CloudTrail rules (Initial Access, Defense Evasion)**
- `rule_002` — No MFA login: sessionContext.attributes.mfaAuthenticated from real log structure
- `rule_006` — Root account login: any ConsoleLogin where userIdentity.type = Root
- `rule_007` — CloudTrail disabled: DeleteTrail (CRITICAL), StopLogging (CRITICAL), UpdateTrail (HIGH)
- `rule_011` — auditd tamper (secondary): service stop detection via auditd before silence

---

## Detection Coverage Analysis

### What We Detect Well
- SSH brute force with attack speed classification and confirmed breach detection
- Privilege escalation via auid/euid trinity — 4294967295 exclusion eliminates system daemon noise
- Process masquerading via exe path verification — catches prctl() name spoofing
- CloudTrail impairment across four event types with severity tiering

### Known Blind Spots
- Attackers who kill auditd instantly before any log is written (heartbeat monitoring partially mitigates)
- Living-off-the-land techniques using only whitelisted binaries
- CloudTrail propagation delay (15-minute S3 lag) for AWS detections
- Lateral movement to other AWS accounts not yet monitored
- EXECVE record parsing not yet implemented — command arguments unavailable
- auditd killed via kill -9 or SIGKILL — process cannot log its own death
- systemctl stop auditd — partially caught by auditd_tamper key,
  but only if auditctl was also used

Documenting blind spots is intentional — understanding what your detection system misses is as important as what it catches.

---

## Technical Stack

- **Detection Engine**: Python 3.11, Pydantic v2
- **Log Sources**: Linux auditd, /var/log/auth.log, AWS CloudTrail (S3)
- **Schema Layer**: Pydantic models — AuditdEvent, AuthLogEvent, CloudTrailEvent, Alert
- **Sigma Rules**: 13 rules, portable via sigma-cli to Splunk/Elastic/Sentinel
- **Attack Simulation**: Atomic Red Team (MITRE ATT&CK mapped)
- **Cloud**: AWS EC2, S3, CloudTrail, SNS
- **API**: FastAPI with typed response_model schemas
- **Dashboard**: HTML/CSS/JavaScript, Leaflet.js, Chart.js
- **Container**: Docker
- **Infrastructure**: AWS VPC, Security Groups, IAM

---

## How to Run

### Prerequisites
- AWS account with EC2, CloudTrail, S3 configured
- Ubuntu EC2 instance with auditd installed
- Python 3.11+
- Docker (optional)

### Setup

```bash
git clone https://github.com/Yuvraj-pandey-yuvi/purple-team-detection
cd purple-team-detection

pip install -r requirements.txt

aws configure

# Run detection engine
python3 detection/engine.py

# Start API server
python3 -m uvicorn dashboard.api:app --host 0.0.0.0 --port 8000
```

### Docker

```bash
docker build -t purpleteam .
docker run -p 8000:8000 purpleteam
```

---

## Dashboard
<img width="1300" height="564" alt="brave_screenshot (3)" src="https://github.com/user-attachments/assets/48be3527-ef38-4abf-8898-adbf446b238d" />
<img width="1296" height="394" alt="brave_screenshot (2)" src="https://github.com/user-attachments/assets/9f559fc2-e0de-423a-979c-356f2f765df8" />
<img width="1298" height="625" alt="brave_screenshot (1)" src="https://github.com/user-attachments/assets/eff084e2-494f-40ca-8cf0-c457f582f211" />
<img width="1295" height="631" alt="brave_screenshot" src="https://github.com/user-attachments/assets/d13d5055-5f39-4b68-90e9-830668bbfa9a" />
<img width="1296" height="394" alt="brave_screenshot (2)" src="https://github.com/user-attachments/assets/9920bede-e765-4ada-b61e-3f28a6296453" />
<img width="1298" height="625" alt="brave_screenshot (1)" src="https://github.com/user-attachments/assets/bc6af3c0-ab82-4726-9d41-473d7d291aed" />
<img width="1295" height="631" alt="brave_screenshot" src="https://github.com/user-attachments/assets/6c82d8cd-4553-459d-b48c-03cbda6fe9f7" />
<img width="1300" height="564" alt="brave_screenshot (3)" src="https://github.com/user-attachments/assets/ade59f67-e945-4d91-8b61-bea95158a352" />
<img width="1298" height="625" alt="brave_screenshot (1)" src="https://github.com/user-attachments/assets/3790b43f-d8d0-448d-a085-4761bc99c15d" />
<img width="1295" height="631" alt="brave_screenshot" src="https://github.com/user-attachments/assets/f0895252-6589-4965-94a5-fd32e043c51a" />
<img width="1300" height="564" alt="brave_screenshot (3)" src="https://github.com/user-attachments/assets/fe01870e-8505-48d4-9c97-f75e4582e87a" />
<img width="1296" height="394" alt="brave_screenshot (2)" src="https://github.com/user-attachments/assets/01b20476-fcf8-44b6-9d37-e699bff00b05" />
<img width="1295" height="631" alt="brave_screenshot" src="https://github.com/user-attachments/assets/ef243d58-09d2-4a35-9873-07feebbd3189" />
<img width="1300" height="564" alt="brave_screenshot (3)" src="https://github.com/user-attachments/assets/af86a022-6353-4912-8cbe-225defed5caa" />
<img width="1296" height="394" alt="brave_screenshot (2)" src="https://github.com/user-attachments/assets/83491f3b-d2aa-4093-b710-326914ec064e" />
<img width="1298" height="625" alt="brave_screenshot (1)" src="https://github.com/user-attachments/assets/5ea1ee0c-3558-4168-b3aa-f8fca8ddfa57" />


---

## What I Learned

**False positives are the real problem.** `unix_chkpwd` accesses `/etc/shadow` on every SSH login. Getting from 68 noisy alerts to 5 clean ones required understanding legitimate system behavior — which you only learn by reading actual logs.

**Schema design matters before rule design.** Building a Pydantic validation layer first meant every rule received typed, validated objects. Rules contain only detection logic — no string parsing, no key existence guards, no type coercion.

**auditd multi-record correlation is non-obvious.** A single syscall generates SYSCALL + PATH + EXECVE records sharing a serial number. Treating each line independently loses the filename from PATH records. Grouping by serial before parsing solved this.

**Log silence is a detection signal.** If auditd stops writing, the pipeline runs fine but detects nothing. The correct response is heartbeat monitoring — treat silence itself as a T1562.001 alert.

**Real attackers appear faster than expected.** Within 24 hours of exposing an EC2 instance, real bots were scanning it. That turned a simulated detection project into one with real validation.

---

## Author

Yuvraj Pandey
B.Tech Computer Science, JNU (2024–2028)<img width="111" height="150" alt="purple_team_pipeline_flow" src="https://github.com/user-attachments/assets/1dc6f9c4-7f0e-4fe3-91eb-a2906b60d709" />
