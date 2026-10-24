# logs/log_collector.py
# Collects logs from three sources — incremental only
# Uses seek pointer for auth.log and auditd
# Uses last-filename tracking for CloudTrail S3

import subprocess
import json
import glob
import os
from datetime import datetime, timezone

# ── State file ────────────────────────────────────────────────────────────────
# Tracks how far we've read into each log file between runs
# So we never reprocess lines we've already seen
STATE_FILE = os.environ.get(
    'PURPLE_STATE_FILE',
    os.path.expanduser('~/project/reports/state.json')
)

# Log locations: env vars let the pod point at the directory mounts
AUTH_LOG_PATH  = os.environ.get('AUTH_LOG_PATH',  '/var/log/auth.log')
AUDIT_LOG_PATH = os.environ.get('AUDIT_LOG_PATH', '/var/log/audit/audit.log')

BUCKET_NAME = 'aws-cloudtrail-logs-349491201539-1a4abf05'
ACCOUNT_ID  = '349491201539'
REGION      = 'eu-north-1'


# ── State helpers ─────────────────────────────────────────────────────────────

def load_state() -> dict:
    """
    Load pipeline state from state.json.
    Returns empty dict if file doesn't exist yet (first run).
    
    State contains:
      auth_log_position:    byte offset in /var/log/auth.log
      auditd_position:      byte offset in /var/log/audit/audit.log  
      cloudtrail_last_file: filename of last processed CloudTrail file
    """
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_state(state: dict) -> None:
    """Save state atomically: write a temp file, then rename over the real one."""
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    temp_path = STATE_FILE + '.tmp'
    with open(temp_path, 'w') as f:
        json.dump(state, f, indent=2)
    os.replace(temp_path, STATE_FILE)


# ── Core seek-pointer reader (rotation-aware) ─────────────────────────────────

def find_file_by_inode(directory: str, base_name: str, inode: int):
    """Find base_name or base_name.N (uncompressed) in directory with this inode."""
    for name in os.listdir(directory):
        if name != base_name and not name.startswith(base_name + '.'):
            continue
        if name.endswith('.gz'):
            continue   # compressed files can't be read as plain text
        path = os.path.join(directory, name)
        try:
            if os.stat(path).st_ino == inode:
                return path
        except FileNotFoundError:
            continue   # vanished between listdir and stat
    return None


def read_from_offset(path: str, offset: int, read_partial_tail: bool = False):
    """
    Read from byte `offset`; return (lines, new_offset).
    Only COMPLETE lines (ending in newline) are consumed, so a line still
    being written is left for the next run. A rotated file is finished, so
    for it read_partial_tail=True also takes a last line without newline.
    Lines are split on \n only (str.splitlines would also split on odd
    characters like form-feed, which can appear inside log messages).
    """
    with open(path, 'rb') as f:
        f.seek(offset)
        data = f.read()

    last_newline = data.rfind(b'\n')
    if read_partial_tail:
        consumed = data
    elif last_newline == -1:
        consumed = b''
    else:
        consumed = data[:last_newline + 1]

    decoded = consumed.decode('utf-8', errors='replace')
    lines = [line for line in decoded.split('\n') if line.strip()]
    return lines, offset + len(consumed)


def read_new_lines(filepath: str, state_key: str) -> list[str]:
    """
    Read new lines since last run, surviving log rotation.
    State per file: <state_key> = byte offset, <state_key>_inode = which file.
    Shared by auth.log, auditd and Cowrie collectors.
    """
    state = load_state()
    inode_key = state_key + '_inode'
    saved_offset = state.get(state_key)
    saved_inode = state.get(inode_key)

    if not os.path.exists(filepath):
        print(f"  [WARN] Log file not found: {filepath}")
        return []

    file_stat = os.stat(filepath)
    directory, base_name = os.path.split(filepath)
    lines = []

    if saved_inode is None:
        # First run, or old state format (offset without inode): replay from 0.
        if saved_offset is not None:
            print(f"  [INFO] Old-format state for {filepath}, replaying from 0")
        offset = 0
    elif saved_inode != file_stat.st_ino:
        # The file we were reading was rotated away: finish it, then the new one.
        old_path = find_file_by_inode(directory, base_name, saved_inode)
        if old_path:
            tail_lines, _ = read_from_offset(
                old_path, saved_offset or 0, read_partial_tail=True
            )
            lines += tail_lines
            print(f"  [INFO] Rotation: drained {len(tail_lines)} lines from {old_path}")
        else:
            print(f"  [WARN] Rotation: old file for {filepath} is gone, lines may be lost")
        offset = 0
    else:
        offset = saved_offset or 0
        if offset > file_stat.st_size:
            print(f"  [INFO] {filepath} was truncated, resetting position")
            offset = 0

    new_lines, new_offset = read_from_offset(filepath, offset)
    lines += new_lines

    state[state_key] = new_offset
    state[inode_key] = file_stat.st_ino
    state['last_run'] = datetime.now(timezone.utc).isoformat()
    save_state(state)
    return lines


# ── auth.log collector ────────────────────────────────────────────────────────

def collect_auth_logs() -> list[str]:
    """
    Read new lines from /var/log/auth.log since last run.
    
    BEFORE: subprocess.run(['sudo', 'cat', '/var/log/auth.log'])
            → read entire file every time, returns one big string
    
    AFTER:  read_new_lines() with seek pointer
            → read only new lines, returns list[str]
    
    WHY THE CHANGE:
    - No subprocess overhead
    - No sudo requirement for Python process
    - Incremental — doesn't reprocess 50,000 old lines every 5 minutes
    - Returns list[str] which engine normalizes into list[AuthLogEvent]
    """
    return read_new_lines(
        filepath  = AUTH_LOG_PATH,
        state_key = 'auth_log_position'
    )


# ── auditd collector ──────────────────────────────────────────────────────────

def collect_auditd_logs() -> str:
    """
    Read new lines from /var/log/audit/audit.log since last run.
    
    BEFORE: subprocess.run(['sudo', 'ausearch', '-k', key])
            → queried auditd daemon directly, filtered by key
            → returned text split by '----' separator
    
    AFTER:  read_new_lines() with seek pointer
            → reads raw audit.log file directly
            → returns raw text for group_audit_lines() in normalizer
    
    WHY THE CHANGE:
    ausearch filters by key before your code sees the events.
    Reading raw audit.log gives you ALL events — your detection
    rules decide what's relevant via the key field, not ausearch.
    Also: ausearch can't be used with historical log files or tests.
    
    Returns:
        Raw auditd log text — passed to group_audit_lines() in engine
    """
    new_lines = read_new_lines(
        filepath  = AUDIT_LOG_PATH,
        state_key = 'auditd_position'
    )
    # group_audit_lines() expects a single string with newlines
    return '\n'.join(new_lines)


# ── CloudTrail collector ──────────────────────────────────────────────────────

def collect_cloudtrail_logs(
    bucket_name: str,
    account_id: str,
    region: str
) -> list[dict]:
    """
    Download and parse new CloudTrail files from S3.
    
    WHY NOT SEEK POINTER:
    CloudTrail doesn't write to one continuous file like auth.log.
    Every few minutes AWS creates a NEW file in S3:
      349491201539_CloudTrail_eu-north-1_20260604T1310Z_abc.json.gz
      349491201539_CloudTrail_eu-north-1_20260604T1315Z_xyz.json.gz
    
    Instead of seek pointer, we track the LAST FILENAME we processed.
    Any file with a name alphabetically greater than that = new file.
    This works because filenames contain timestamps — alphabetical
    order equals chronological order.
    
    Returns:
        list of CloudTrail record dicts — NOT yet CloudTrailEvent objects.
        Engine passes these to CloudTrailEvent.from_record() in normalizer.
    """
    state = load_state()
    last_file = state.get('cloudtrail_last_file', '')

    # Build S3 path for today
    today = datetime.utcnow().strftime('%Y/%m/%d')
    s3_path = (
        f's3://{bucket_name}/AWSLogs/{account_id}/'
        f'CloudTrail/{region}/{today}/'
    )

    # Download new files from S3
    local_dir = '/tmp/cloudtrail'
    os.makedirs(local_dir, exist_ok=True)

    subprocess.run(
        ['aws', 's3', 'sync', s3_path, local_dir],
        capture_output=True,
        text=True
    )

    # Decompress .gz files
    for gz_file in glob.glob(f'{local_dir}/*.gz'):
        json_equivalent = gz_file.replace('.gz', '')
        if not os.path.exists(json_equivalent):
            subprocess.run(
                ['gunzip', '-k', gz_file],  # -k keeps original .gz
                capture_output=True,
                text=True
            )

    # Process only files newer than last_file
    events = []
    newest_file = last_file

    json_files = sorted(glob.glob(f'{local_dir}/*.json'))

    for filepath in json_files:
        filename = os.path.basename(filepath)

        # Skip already-processed files
        # Alphabetical comparison works because filename contains timestamp
        if filename <= last_file:
            continue

        try:
            with open(filepath) as f:
                data = json.load(f)
                records = data.get('Records', [])
                events.extend(records)
                print(f"  Processed: {filename} ({len(records)} events)")

            # Track newest file processed this run
            if filename > newest_file:
                newest_file = filename

        except json.JSONDecodeError:
            print(f"  [WARN] Could not parse: {filename}")

    # Save state
    if newest_file != last_file:
        state['cloudtrail_last_file'] = newest_file
        save_state(state)

    return events

#-------cowrie-collector---------------------------------------------------------
def collect_cowrie_logs(filepath: str) -> list[str]:
    """
    Read only NEW lines from Cowrie's cowrie.json since the last run --
    same byte-offset/rotation-safe pattern as collect_auth_logs(), via
    the shared read_new_lines() helper. Replaces the old full-file
    re-read every run, which OOM'd once the file grew past ~70MB
    (rotation had silently stopped -- see Phase 4 findings).
    """
    return read_new_lines(
        filepath=filepath,
        state_key='cowrie_position'
    )

# ── Falco collector ──────────────────────────────────────────────────────────

FALCO_BUCKET_NAME = 'purple-falco-logs-yuvraj2026'


def collect_falco_logs(bucket_name: str) -> list[dict]:
    """
    Download and parse new Falco alert files from S3.

    S3 layout (per-hostname, NOT one flat stream like CloudTrail):
      falco/<hostname>/<date>/<time>.jsonl
      e.g. falco/ip-172-31-38-178/2026-09-02/063001.jsonl

    WHY PER-HOSTNAME TRACKING (not one global 'last_file' like CloudTrail):
    Multiple nodes write independently. Comparing filenames across
    DIFFERENT hostname prefixes alphabetically doesn't mean anything --
    'ip-172-31-41-127/...' vs 'ip-172-31-38-178/...' sorts by IP string,
    not by time. Track a dict instead: {hostname: last_seen_sortable_id}.

    Returns:
        list of raw Falco alert dicts (already json.loads'd) -- NOT yet
        FalcoEvent objects. Engine passes these to FalcoEvent.from_alert()
        in the normalizer, same handoff pattern as collect_cloudtrail_logs().
    """
    state = load_state()
    last_files = state.get('falco_last_files', {})

    local_dir = '/tmp/falco'
    os.makedirs(local_dir, exist_ok=True)

    # Sync the WHOLE falco/ prefix in one shot. We don't know hostnames
    # in advance (nodes can be replaced, IPs change on restart), so
    # syncing per-host doesn't make sense -- one sync call, then we
    # discover hostnames from the resulting local directory structure.
    subprocess.run(
        ['aws', 's3', 'sync', f's3://{bucket_name}/falco/', local_dir],
        capture_output=True,
        text=True
    )

    events = []
    updated_last_files = dict(last_files)  # working copy, mutated as we go

    # Recursive glob -- '**' matches any depth of subdirectories, but
    # ONLY if recursive=True is passed explicitly (glob.glob defaults
    # to non-recursive even with '**' in the pattern -- an easy silent
    # bug if you forget the flag: it would just silently match nothing
    # nested and you'd never see an error, just zero files found).
    jsonl_files = sorted(
        glob.glob(f'{local_dir}/**/*.jsonl', recursive=True)
    )

    for filepath in jsonl_files:
        # relpath gives us: 'ip-172-31-38-178/2026-09-02/063001.jsonl'
        rel = os.path.relpath(filepath, local_dir)
        parts = rel.split(os.sep)
        hostname = parts[0]

        # THE TRAP: if we tracked/compared just the bare filename
        # ('063001.jsonl'), a file from 2026-09-02 would sort BEFORE a
        # file from 2026-08-30 ('110501.jsonl') on pure string
        # comparison, because '06' < '11' -- even though 09-02 is
        # chronologically LATER. The fix: track date+time together as
        # one string, e.g. '2026-09-02/063001.jsonl'. Since the date
        # portion is YYYY-MM-DD (sorts correctly) and the time portion
        # is HH MM SS with no separators (sorts correctly), the
        # concatenated string sorts in true chronological order.
        sortable_id = '/'.join(parts[1:])   # '2026-09-02/063001.jsonl'

        host_last = last_files.get(hostname, '')
        if sortable_id <= host_last:
            continue

        try:
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    events.append(json.loads(line))
            print(f"  Processed: {hostname}/{sortable_id}")
        except json.JSONDecodeError:
            print(f"  [WARN] Could not parse: {filepath}")
            continue

        if sortable_id > updated_last_files.get(hostname, ''):
            updated_last_files[hostname] = sortable_id

    if updated_last_files != last_files:
        state['falco_last_files'] = updated_last_files
        save_state(state)

    return events


# ── Entry point for manual testing ───────────────────────────────────────────

if __name__ == "__main__":
    print("Testing log collectors...\n")

    print("[1/3] auth.log")
    auth_lines = collect_auth_logs()
    print(f"  New lines: {len(auth_lines)}")
    if auth_lines:
        print(f"  Sample: {auth_lines[-1][:80]}")

    print("\n[2/3] auditd")
    auditd_text = collect_auditd_logs()
    auditd_lines = [l for l in auditd_text.splitlines() if l.strip()]
    print(f"  New lines: {len(auditd_lines)}")

    print("\n[3/3] CloudTrail")
    ct_events = collect_cloudtrail_logs(BUCKET_NAME, ACCOUNT_ID, REGION)
    print(f"  New events: {len(ct_events)}")
    if ct_events:
        print(f"  Sample: {ct_events[0].get('eventName')}")

    print("\nDone. Check ~/project/reports/state.json for positions.")

    