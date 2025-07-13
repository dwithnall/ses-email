#!/usr/bin/env python3

import os
import sys
import argparse
import configparser
import json
import boto3
from botocore.exceptions import ClientError
from cloudflare import Cloudflare
from datetime import datetime

# Global variable to hold the log file
log_file = None

def log_print(*args, **kwargs):
    """Print to both console and log file"""
    print(*args, **kwargs)
    if log_file:
        # Convert args to string and write to log file
        message = ' '.join(str(arg) for arg in args)
        log_file.write(message + '\n')
        log_file.flush()  # Ensure immediate writing

def create_cf_record(cf_client, zone_id, record_type, name, content, ttl=3600, proxied=False, priority=None):
    """Helper function to create a DNS record in CloudFlare, skipping if it exists."""
    # Ensure TXT record content is wrapped in quotes
    if record_type == 'TXT' and not (content.startswith('"') and content.endswith('"')):
        content = f'"{content}"'
    
    record_data = {
        'zone_id': zone_id, 
        'type': record_type,
        'name': name,
        'content': content,
        'ttl': ttl,
        'comment': 'Provisioned by SES'
    }
    if record_type in ['A', 'AAAA', 'CNAME']:
        record_data['proxied'] = proxied
    if record_type == 'MX' and priority is not None:
        record_data['priority'] = priority
        
    try:
        log_print(f"  > Creating {record_type} record: {name} -> {content[:70]}...")
        cf_client.dns.records.create(**record_data)
        log_print(f"    - Success: Record '{name}' created.")
        return True
    except Exception as e:
        # Error codes for duplicate records 
        if "81057" in str(e) or "1009" in str(e):
            log_print(f"    - Info: Record '{name}' already exists. Skipping.")
            return True
        else:
            log_print(f"    - Error creating record '{name}': {e}")
            return False

def main():
    """
    Main function to provision a domain with SES, create a dedicated IAM user,
    and configure all necessary DNS records in CloudFlare.
    """
    global log_file
    
    parser = argparse.ArgumentParser(
        description="Provision a domain for Amazon SES, create a sending user, and configure CloudFlare DNS.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("domain", help="The domain name to provision (e.g., example.com)")
    parser.add_argument("--config", default="config.ini", help="Path to the configuration file (default: config.ini)")
    parser.add_argument("--mail-from-subdomain", default="mail", help="Subdomain for the custom MAIL FROM address (e.g., 'mail' for mail.example.com)")
    args = parser.parse_args()

    domain_name = args.domain
    mail_from_subdomain = f"{args.mail_from_subdomain}.{domain_name}"
    
    # Set up log file
    log_filename = f"ses-provision-{domain_name.replace('.', '-')}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"
    try:
        log_file = open(log_filename, 'w', encoding='utf-8')
        log_print(f"--- Starting full SES & IAM provisioning for: {domain_name} ---")
        log_print(f"Log file: {log_filename}")
    except Exception as e:
        print(f"Error creating log file: {e}", file=sys.stderr)
        sys.exit(1)

    # --- 1. Load Configuration from File ---
    log_print(f"\n[Step 1/7] Loading configuration from '{args.config}'...")
    if not os.path.exists(args.config):
        log_print(f"  > Error: Configuration file not found at '{args.config}'", file=sys.stderr)
        log_print("  > Please create it or use the --config flag to specify the correct path.", file=sys.stderr)
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(args.config)
    
    try:
        # Load AWS credentials
        aws_access_key = config['AWS']['access_key_id']
        aws_secret_key = config['AWS']['secret_access_key']
        aws_region = config['AWS']['region']
        
        # Load CloudFlare credentials
        cf_api_token = config['Cloudflare']['api_token']
        log_print("  > Configuration loaded successfully.")
    except KeyError as e:
        log_print(f"  > Error: Missing key {e} in the configuration file.", file=sys.stderr)
        log_print("  > Please ensure your config file has [AWS] and [Cloudflare] sections with all required keys.", file=sys.stderr)
        sys.exit(1)

    # --- 2. Initialize Clients ---
    try:
        ses_client = boto3.client(
            "ses", 
            region_name=aws_region,
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key
        )
        iam_client = boto3.client(
            "iam",
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key
        )
        sts_client = boto3.client(
            "sts",
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key
        )
        cf_client = Cloudflare(api_token=cf_api_token)
        aws_account_id = sts_client.get_caller_identity()["Account"]
        log_print("Successfully initialized AWS (SES, IAM, STS) and CloudFlare clients.")
        log_print(f"  > Using AWS Account ID: {aws_account_id}")
        log_print(f"  > Using AWS Region: {aws_region}")
    except Exception as e:
        log_print(f"\nError initializing clients: {e}", file=sys.stderr)
        sys.exit(1)

    # --- 3. Validate Domain in CloudFlare ---
    log_print(f"\n[Step 2/7] Validating domain '{domain_name}' in CloudFlare...")
    # (The rest of the script logic is identical to the previous version)
    try:
        zones_response = cf_client.zones.list(name=domain_name)
        zones = zones_response.result
        
        if not zones:
            log_print(f"  > Error: Domain '{domain_name}' not found in your CloudFlare account.", file=sys.stderr)
            log_print("  > Please ensure the domain is added to CloudFlare before running this script.", file=sys.stderr)
            sys.exit(1)
        zone_id = zones[0].id
        log_print(f"  > Success: Found CloudFlare Zone ID: {zone_id}")
    except Exception as e:
        log_print(f"  > Error fetching CloudFlare Zone ID: {e}", file=sys.stderr)
        sys.exit(1)

    # --- 4. Set up SES Identities (Domain, DKIM, MAIL FROM) ---
    log_print(f"\n[Step 3/7] Configuring SES Identities for '{domain_name}'...")
    try:
        ver_identity_resp = ses_client.verify_domain_identity(Domain=domain_name)
        ses_txt_token = ver_identity_resp['VerificationToken']
        log_print("  > SES domain verification token received.")

        ver_dkim_resp = ses_client.verify_domain_dkim(Domain=domain_name)
        dkim_tokens = ver_dkim_resp['DkimTokens']
        log_print("  > SES DKIM tokens received.")

        ses_client.set_identity_mail_from_domain(
            Identity=domain_name,
            MailFromDomain=mail_from_subdomain,
            BehaviorOnMXFailure='UseDefaultValue'
        )
        log_print(f"  > SES MAIL FROM domain configured for '{mail_from_subdomain}'.")
    except ClientError as e:
        log_print(f"  > Error during SES configuration: {e}", file=sys.stderr)
        sys.exit(1)

    # --- 5. Create Dedicated IAM User and Policy ---
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
                    "ses:GetIdentityDkimAttributes"
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

    # --- 6. Generate SMTP Credentials for the new User ---
    log_print(f"\n[Step 5/7] Generating SMTP credentials for user '{iam_user_name}'...")
    try:
        keys = iam_client.create_access_key(UserName=iam_user_name)
        smtp_user = keys['AccessKey']['AccessKeyId']
        smtp_pass = keys['AccessKey']['SecretAccessKey']
        log_print("  > Success: SMTP credentials generated.")
    except ClientError as e:
        log_print(f"  > Error creating access key: {e}", file=sys.stderr)
        log_print("  > Cannot proceed. No credentials to output.", file=sys.stderr)
        sys.exit(1)

    # --- 7. Create All DNS Records in CloudFlare ---
    log_print(f"\n[Step 6/7] Creating all required DNS records in CloudFlare...")
    create_cf_record(cf_client, zone_id, 'TXT', f"_amazonses.{domain_name}", ses_txt_token)
    for token in dkim_tokens:
        create_cf_record(cf_client, zone_id, 'CNAME', f"{token}._domainkey.{domain_name}", f"{token}.dkim.amazonses.com")
    create_cf_record(cf_client, zone_id, 'MX', mail_from_subdomain, f"feedback-smtp.{aws_region}.amazonses.com", priority=10)
    create_cf_record(cf_client, zone_id, 'TXT', mail_from_subdomain, '"v=spf1 include:amazonses.com ~all"')
    create_cf_record(cf_client, zone_id, 'TXT', f"_dmarc.{domain_name}", f"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain_name};")
    log_print("  > Note: DMARC record created with a 'none' policy. You can strengthen this to 'quarantine' or 'reject' later.")

    # --- 8. Output Final Credentials and Instructions ---
    log_print("\n--- ✅ Provisioning Complete! ✅ ---")
    log_print("\n[Step 7/7] Your application credentials are listed below.")
    log_print("\n" + "="*60)
    log_print("      SAVE THESE CREDENTIALS NOW. YOU CANNOT RETRIEVE THE      ")
    log_print("             SECRET KEY AGAIN AFTER THIS.                      ")
    log_print("="*60)
    log_print()
    log_print("AWS ACCESS KEYS (for programmatic access):")
    log_print(f"  AWS_ACCESS_KEY_ID:     {smtp_user}")
    log_print(f"  AWS_SECRET_ACCESS_KEY: {smtp_pass}")
    log_print(f"  AWS_REGION:            {aws_region}")
    log_print()
    log_print("SES SMTP CREDENTIALS (for email sending):")
    log_print(f"  SES SMTP Endpoint:     smtp.mail.{aws_region}.amazonaws.com")
    log_print(f"  SMTP Username:         {smtp_user}")
    log_print(f"  SMTP Password:         {smtp_pass}")
    log_print()
    log_print("Fluentmail credentials (paste into WordPress Config):")
    log_print(f"define('FLUENTMAIL_AWS_ACCESS_KEY_ID', '{smtp_user}');")
    log_print(f"define('FLUENTMAIL_AWS_SECRET_ACCESS_KEY', '{smtp_pass}');")
    log_print()
    log_print("="*60)

    log_print("\n### What To Do Next ###")
    log_print("1.  **DNS Propagation**: Wait 5-30 minutes for the DNS records to become active globally.")
    log_print("2.  **AWS Verification**: AWS will automatically detect the records. Check the 'Identity Status' in the SES Console for your domain. You'll get an email when it is complete.")
    log_print(f"4.  **DMARC Reports**: Ensure the mailbox `dmarc-reports@{domain_name}` exists to receive reports. By default DMARC is set to 'none'.")
    
    # Log the filename and close the log file
    log_print(f"\nLog file saved: {log_filename}")
    if log_file:
        log_file.close()

if __name__ == "__main__":
    main()