"""IAM user and policy operations."""

import json
import sys
from botocore.exceptions import ClientError
from utils import log_print


def create_iam_user_and_policy(iam_client, domain_name, aws_region, aws_account_id):
    """
    Create IAM user and policy for SES email sending.
    
    Args:
        iam_client: Boto3 IAM client
        domain_name: Domain name
        aws_region: AWS region
        aws_account_id: AWS account ID
        
    Returns:
        str: IAM user name
    """
    log_print(f"\n[Step 4/7] Creating dedicated IAM user and policy...")
    iam_user_name = f"ses-sender-{domain_name.replace('.', '-')}"
    policy_name = f"ses-send-only-{domain_name.replace('.', '-')}"
    policy_arn = f"arn:aws:iam::{aws_account_id}:policy/{policy_name}"

    try:
        iam_client.create_user(UserName=iam_user_name)
        log_print(f"  > IAM User '{iam_user_name}' created.")
    except iam_client.exceptions.EntityAlreadyExistsException:
        log_print(f"  > Info: IAM User '{iam_user_name}' already exists. Skipping creation.")

    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ses:SendRawEmail",
                    "ses:SendEmail"
                ],
                "Resource": f"arn:aws:ses:{aws_region}:{aws_account_id}:identity/{domain_name}"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ses:ListIdentities",
                    "ses:GetIdentityVerificationAttributes",
                    "ses:GetIdentityDkimAttributes",
                    "ses:SetIdentityFeedbackForwardingEnabled"
                ],
                "Resource": "*"
            }
        ]
    }
    
    try:
        policy_response = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document),
            Description=f"Allows sending email only via SES for the domain {domain_name}"
        )
        iam_client.attach_user_policy(UserName=iam_user_name, PolicyArn=policy_response['Policy']['Arn'])
        log_print(f"  > IAM Policy '{policy_name}' created and attached to user.")
    except iam_client.exceptions.EntityAlreadyExistsException:
        log_print(f"  > Info: IAM Policy '{policy_name}' already exists. Attaching to user.")
        iam_client.attach_user_policy(UserName=iam_user_name, PolicyArn=policy_arn)

    return iam_user_name


def create_smtp_credentials(iam_client, iam_user_name):
    """
    Generate SMTP credentials for an IAM user.
    
    Args:
        iam_client: Boto3 IAM client
        iam_user_name: IAM user name
        
    Returns:
        tuple: (access_key_id, secret_access_key)
    """
    log_print(f"\n[Step 5/7] Generating SMTP credentials for user '{iam_user_name}'...")
    try:
        keys = iam_client.create_access_key(UserName=iam_user_name)
        smtp_user = keys['AccessKey']['AccessKeyId']
        smtp_pass = keys['AccessKey']['SecretAccessKey']
        log_print("  > Success: SMTP credentials generated.")
        return smtp_user, smtp_pass
    except ClientError as e:
        log_print(f"  > Error creating access key: {e}", file=sys.stderr)
        log_print("  > Cannot proceed. No credentials to output.", file=sys.stderr)
        sys.exit(1)


def remove_iam_user_and_policy(iam_client, domain_name, aws_account_id):
    """
    Remove IAM user and policy for a domain.
    
    Args:
        iam_client: Boto3 IAM client
        domain_name: Domain name
        aws_account_id: AWS account ID
        
    Returns:
        tuple: (user_removed, policy_removed) - boolean values indicating success
    """
    log_print(f"\n[Cleanup] Removing IAM user and policy for '{domain_name}'...")
    
    iam_user_name = f"ses-sender-{domain_name.replace('.', '-')}"
    policy_name = f"ses-send-only-{domain_name.replace('.', '-')}"
    policy_arn = f"arn:aws:iam::{aws_account_id}:policy/{policy_name}"
    
    user_removed = False
    policy_removed = False
    
    # Step 1: Detach policy from user (if user exists)
    try:
        iam_client.detach_user_policy(UserName=iam_user_name, PolicyArn=policy_arn)
        log_print(f"  > Detached policy '{policy_name}' from user '{iam_user_name}'.")
    except iam_client.exceptions.NoSuchEntityException:
        log_print(f"  > Info: Policy '{policy_name}' not attached to user '{iam_user_name}' (may not exist).")
    except Exception as e:
        log_print(f"  > Warning: Could not detach policy: {e}")
    
    # Step 2: Delete all access keys for the user
    try:
        access_keys = iam_client.list_access_keys(UserName=iam_user_name)
        for key_metadata in access_keys.get('AccessKeyMetadata', []):
            try:
                iam_client.delete_access_key(
                    UserName=iam_user_name,
                    AccessKeyId=key_metadata['AccessKeyId']
                )
                log_print(f"  > Deleted access key '{key_metadata['AccessKeyId']}' for user '{iam_user_name}'.")
            except Exception as e:
                log_print(f"  > Warning: Could not delete access key '{key_metadata['AccessKeyId']}': {e}")
    except iam_client.exceptions.NoSuchEntityException:
        log_print(f"  > Info: User '{iam_user_name}' does not exist (access keys may not exist).")
    except Exception as e:
        log_print(f"  > Warning: Could not list/delete access keys: {e}")
    
    # Step 3: Delete the user
    try:
        iam_client.delete_user(UserName=iam_user_name)
        log_print(f"  > Success: IAM User '{iam_user_name}' deleted.")
        user_removed = True
    except iam_client.exceptions.NoSuchEntityException:
        log_print(f"  > Info: User '{iam_user_name}' does not exist.")
    except Exception as e:
        log_print(f"  > Error deleting user '{iam_user_name}': {e}")
    
    # Step 4: Delete the policy (only if no entities are using it)
    try:
        # First, check if policy exists and get its version
        policy_versions = iam_client.list_policy_versions(PolicyArn=policy_arn)
        
        # Delete all non-default policy versions first
        for version in policy_versions.get('Versions', []):
            if not version['IsDefaultVersion']:
                try:
                    iam_client.delete_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=version['VersionId']
                    )
                    log_print(f"  > Deleted policy version '{version['VersionId']}'.")
                except Exception as e:
                    log_print(f"  > Warning: Could not delete policy version '{version['VersionId']}': {e}")
        
        # Now delete the policy itself
        iam_client.delete_policy(PolicyArn=policy_arn)
        log_print(f"  > Success: IAM Policy '{policy_name}' deleted.")
        policy_removed = True
    except iam_client.exceptions.NoSuchEntityException:
        log_print(f"  > Info: Policy '{policy_name}' does not exist.")
    except iam_client.exceptions.DeleteConflictException:
        log_print(f"  > Warning: Policy '{policy_name}' is still attached to other entities. Skipping deletion.")
    except Exception as e:
        log_print(f"  > Error deleting policy '{policy_name}': {e}")
    
    return user_removed, policy_removed

