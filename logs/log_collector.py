#logss collector
# collect from three sorces
# 1 auth.log - authentication logs
# 2 auditd - os level files/process activity
# 3 CLoudtrail - aws api calls 
import subprocess
import json
import glob
import os
from datetime import datetime,timezone

def collect_auth_logs():
    """
    Pull /var/log/aut.log
    Returns raw log text
    """
    result=subprocess.run(
        ['sudo','cat','/var/log/auth.log'],
         capture_output=True,
         text=True
    
    )
    return result.stdout

def collect_auditd_logs(key):
    """
    Pull auditd logs filtered by rule key"""
    result=subprocess.run(
        ['sudo','ausearch','-k',key,'--start','yesterday'],
         capture_output=True,
         text=True
    )
    return result.stdout
def collect_all_auditd_logs():
    """
    Pull all auditd keys at once
    """
    keys=['shadow_access','passwd_access','user_creation','cron_modification','sudo_usage','command_execution']
    all_logs={}
    for key in keys:
        all_logs[key]=collect_auditd_logs(key)
    return all_logs

def collect_cloudtrail_logs(bucket_name, account_id, region):
    today = datetime.now(timezone.utc).strftime('%Y/%m/%d')
    s3_path = (
        f's3://{bucket_name}/AWSLogs/{account_id}/'
        f'CloudTrail/{region}/{today}/'
    )

    os.makedirs('/tmp/cloudtrail', exist_ok=True)

    # Check if files already downloaded
    existing = glob.glob('/tmp/cloudtrail/*.json')
    if not existing:
        print("      Downloading from S3...")
        subprocess.run(
            ['aws', 's3', 'sync', s3_path, '/tmp/cloudtrail/'],
            capture_output=True
        )
        # Decompress
        for f in glob.glob('/tmp/cloudtrail/*.gz'):
            subprocess.run(['gunzip', '-f', f])
    else:
        print(f"      Using cached files ({len(existing)} found)")

    # Parse
    events = []
    for f in glob.glob('/tmp/cloudtrail/*.json'):
        try:
            with open(f) as fp:
                data = json.load(fp)
                events.extend(data.get('Records', []))
        except Exception as e:
            print(f"      Error reading {f}: {e}")

    return events

BUCKET_NAME = 'aws-cloudtrail-logs-349491201539-1a4abf05'
ACCOUNT_ID  = '349491201539'
REGION      = 'us-east-1'

if __name__ == "__main__":
    print("Collecting auth.log...")
    auth = collect_auth_logs()
    auth_lines = auth.strip().split('\n')
    print(f"  auth.log lines collected: {len(auth_lines)}")
    print(f"  Sample: {auth_lines[-1]}\n")

    print("Collecting auditd logs...")
    auditd = collect_all_auditd_logs()
    for key, value in auditd.items():
        count = value.count('----')
        print(f"  {key}: {count} entries")

    print("\nCollecting CloudTrail logs...")
    ct_events = collect_cloudtrail_logs(BUCKET_NAME, ACCOUNT_ID, REGION)
    print(f"  CloudTrail events collected: {len(ct_events)}")
    if ct_events:
        names = [e.get('eventName') for e in ct_events[:5]]
        print(f"  Sample eventNames: {names}")