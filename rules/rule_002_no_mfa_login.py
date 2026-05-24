# rule_002_no_mfa_login.py
# ATT&CK T1078 - Valid Accounts
#
# Logic: AWS console login where MFA was not used
# This catches attackers using stolen credentials
#
# Log source: CloudTrail

def detect(event):
    """
    Takes one CloudTrail event dict.
    Returns alert if console login without MFA.
    """
    if event.get('eventName') != 'ConsoleLogin':
        return None

    # Extract MFA status
    additional_data = event.get('additionalEventData', {})
    mfa_used        = additional_data.get('MFAUsed', 'No')

    if mfa_used == 'Yes':
        return None  # MFA used - legitimate login

    # Extract identity fields
    user_identity = event.get('userIdentity', {})
    username      = user_identity.get('userName', 'unknown')
    user_arn      = user_identity.get('arn', 'unknown')
    account_id    = user_identity.get('accountId', 'unknown')
    user_type     = user_identity.get('type', 'unknown')

    # Extract login context
    source_ip    = event.get('sourceIPAddress', 'unknown')
    event_time   = event.get('eventTime', 'unknown')
    user_agent   = event.get('userAgent', 'unknown')
    aws_region   = event.get('awsRegion', 'unknown')

    # Login result - was it successful?
    login_result = (
        event
        .get('responseElements', {})
        .get('ConsoleLogin', 'unknown')
    )

    # Browser detection from user agent
    if 'Mozilla' in user_agent:
        client_type = 'browser'
    elif 'Boto' in user_agent or 'aws-cli' in user_agent:
        client_type = 'cli_or_sdk'
    else:
        client_type = 'unknown_client'

    return {
        'rule_id':      'RULE-002',
        'rule_name':    'AWS Console Login Without MFA',
        'technique':    'T1078',
        'severity':     'HIGH',
        'log_source':   'CloudTrail',

        # Who
        'username':     username,
        'user_arn':     user_arn,
        'account_id':   account_id,
        'user_type':    user_type,

        # Where from
        'source_ip':    source_ip,
        'aws_region':   aws_region,
        'user_agent':   user_agent,
        'client_type':  client_type,

        # When
        'event_time':   event_time,

        # What happened
        'mfa_used':     mfa_used,
        'login_result': login_result,

        'reason': (
            f"User '{username}' logged into AWS console "
            f"without MFA from {source_ip} "
            f"using {client_type} at {event_time}"
        )
    }