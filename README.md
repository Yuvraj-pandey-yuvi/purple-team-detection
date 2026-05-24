# Purple Team Detection Pipeline

An automated threat detection system that simulates real MITRE 
ATT&CK techniques on AWS infrastructure and measures detection 
coverage in real time.

Built as a demonstration of detection engineering principles — 
not a tutorial project, but a working system detecting real 
attacks on a live server.

---

## What It Does

1. **Simulates attacks** using Atomic Red Team mapped to MITRE 
   ATT&CK techniques on an AWS EC2 instance
2. **Collects logs** from three sources: Linux auditd, auth.log, 
   and AWS CloudTrail
3. **Detects attacks** using custom Python detection rules with 
   intelligent false positive filtering
4. **Generates coverage reports** showing which techniques were 
   detected, which were missed, and why
5. **Visualizes results** on a real-time dashboard with ATT&CK 
   matrix, attacker geolocation map, and user activity charts

---

## Architecture

[Add your architecture diagram image here]

---

## ATT&CK Techniques Covered

| Technique | Name | Detection Method | Status |
|-----------|------|-----------------|--------|
| T1110.001 | Brute Force: Password Guessing | Sliding window on auth.log | ✅ Detected |
| T1136.001 | Create Local Account | useradd pattern in auth.log | ✅ Detected |
| T1003.008 | OS Credential Dumping | auditd shadow_access key | ✅ Detected |
| T1036     | Masquerading | exe path verification | ✅ Detected |
| T1053.003 | Scheduled Task: Cron | auditd cron_modification key | ✅ Detected |
| T1078     | Valid Accounts: No MFA | CloudTrail ConsoleLogin | ⚠ Implemented |

**Current detection coverage: 80%**

---

## Real Findings During Development

This system detected real attacks — not just simulated ones:

- **178.175.167.68 (Moldova)** — 26 SSH brute force attempts 
  over 59 seconds, classified as aggressive
- **47.251.122.241** — 55 failed SSH attempts detected 
  automatically without simulation
- **139.19.117.129** — Repeated login attempts across multiple 
  days, identified as a persistent scanner

These appeared naturally on the internet-facing EC2 instance 
within 24 hours of deployment — demonstrating that the detection 
system works against real-world threat actors, not just lab 
simulations.

---

## Detection Rules

Each rule is a standalone Python module mapping to a specific 
ATT&CK technique:

**rule_001_ssh_brute_force.py** — Sliding window detection on 
auth.log. Classifies attacks as aggressive/moderate/slow_scan 
based on attempt frequency. Tracks first/last seen timestamps 
per attacker IP.

**rule_003_new_user_created.py** — Correlates two auth.log 
entries: the sudo invocation and the useradd confirmation. 
Escalates severity for suspicious usernames. Identifies who 
created the account.

**rule_004_shadow_access.py** — Three-layer detection:
- Unknown process accessing /etc/shadow → T1003.008
- Known process from unexpected path → T1036 (Masquerading)  
- Direct write to /etc/passwd → T1136.001
Uses exe path verification to catch renamed malicious binaries.

**rule_005_cron_persistence.py** — Detects new cron job file 
creation, filters out deletions and system maintenance. 
Escalates suspicious filenames to CRITICAL.

---

## Detection Coverage Analysis

### What We Detect Well
- SSH brute force with attack speed classification
- Privilege escalation (auid ≠ euid pattern)
- Process masquerading via exe path verification
- New user creation with creator attribution

### Known Blind Spots
- Attackers who disable auditd before acting
- Techniques that don't touch monitored files
- T1078 ConsoleLogin requires CloudTrail propagation delay
- Container escape techniques not yet monitored

Documenting blind spots is intentional — understanding what 
your detection system misses is as important as what it catches.

---

## Technical Stack

- **Detection Engine**: Python 3.11
- **Log Sources**: Linux auditd, /var/log/auth.log, AWS CloudTrail
- **Attack Simulation**: Atomic Red Team (MITRE ATT&CK mapped)
- **Cloud**: AWS EC2, S3, CloudTrail, SNS
- **API**: FastAPI
- **Dashboard**: HTML/CSS/JavaScript, Leaflet.js, Chart.js
- **Container**: Docker
- **Infrastructure**: AWS VPC, Security Groups, IAM

---

## Dashboard

The dashboard provides:
- ATT&CK coverage matrix (green = detected, red = missed)
- Alerts by technique bar chart
- Alerts by user account (auid) bar chart  
- Real-time attacker geolocation map
- Privilege escalation timeline
- Active alerts with full context (process, user, timestamp)

[Add dashboard screenshot here]

---

## How to Run

### Prerequisites
- AWS account with EC2, CloudTrail, S3 configured
- Ubuntu EC2 instance with auditd installed
- Python 3.11+
- Docker (optional)

### Setup

```bash
# Clone the repository
git clone https://github.com/YOURUSERNAME/purple-team-detection
cd purple-team-detection

# Install dependencies
pip install -r requirements.txt

# Configure AWS credentials
aws configure

# Generate detection report
python3 reports/report_generator.py

# Start the API server
python3 -m uvicorn dashboard.api:app --host 0.0.0.0 --port 8000
```

### Docker

```bash
docker build -t purpleteam .
docker run -p 8000:8000 purpleteam
```

---

## What I Learned

Building this system taught me several things that reading 
about detection engineering doesn't:

**False positives are the real problem.** `unix_chkpwd` 
accesses `/etc/shadow` on every SSH login. `dpkg-preconfigu` 
touches it during package installs. Getting from 68 noisy 
alerts to 5 clean ones required understanding what legitimate 
system behavior looks like — which you only learn by seeing 
the actual logs.

**Name-based whitelists aren't enough.** Adding exe path 
verification (T1036 masquerading detection) came from asking 
"what if an attacker just renames their binary?" That question 
led to a meaningfully better detection rule.

**Real attackers appear faster than expected.** Within 24 hours 
of exposing an EC2 instance, real bots were scanning it. That 
turned a simulated detection project into one with real 
validation.

---

## Author

Yuvraj Pandey  
B.Tech Computer Science, JNU (2024–2028)  
[LinkedIn] | [GitHub]
