"""AWS client initialization."""

import sys
import boto3
from utils import log_print


def init_aws_clients(aws_config):
    """
    Initialize AWS clients (SES, IAM, STS).
    
    Args:
        aws_config: Dict with access_key_id, secret_access_key, and region
        
    Returns:
        tuple: (ses_client, iam_client, sts_client, aws_account_id)
    """
    try:
        ses_client = boto3.client(
            "ses", 
            region_name=aws_config['region'],
            aws_access_key_id=aws_config['access_key_id'],
            aws_secret_access_key=aws_config['secret_access_key']
        )
        iam_client = boto3.client(
            "iam",
            aws_access_key_id=aws_config['access_key_id'],
            aws_secret_access_key=aws_config['secret_access_key']
        )
        sts_client = boto3.client(
            "sts",
            aws_access_key_id=aws_config['access_key_id'],
            aws_secret_access_key=aws_config['secret_access_key']
        )
        aws_account_id = sts_client.get_caller_identity()["Account"]
        log_print("Successfully initialized AWS (SES, IAM, STS) clients.")
        log_print(f"  > Using AWS Account ID: {aws_account_id}")
        log_print(f"  > Using AWS Region: {aws_config['region']}")
        
        return ses_client, iam_client, sts_client, aws_account_id
            
    except Exception as e:
        log_print(f"\nError initializing clients: {e}", file=sys.stderr)
        sys.exit(1)

