#!/usr/bin/env python3
"""Main entry point for SES domain provisioning tool."""

import sys
import argparse
from utils import init_log_file, close_log_file, log_print
from config import load_config
from aws_clients import init_aws_clients
from cloudflare_ops import (
    init_cloudflare_client,
    get_zone_id,
    create_ses_dns_records,
    remove_ses_records_from_cloudflare
)
from ses_ops import configure_ses_identity
from iam_ops import create_iam_user_and_policy, create_smtp_credentials, remove_iam_user_and_policy
from output import print_credentials, print_manual_dns_records


def main():
    """
    Main function to provision a domain with SES, create a dedicated IAM user,
    and configure all necessary DNS records in CloudFlare.
    """
    parser = argparse.ArgumentParser(
        description="Provision a domain for Amazon SES, create a sending user, and configure CloudFlare DNS.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("domain", help="The domain name to provision (e.g., example.com)")
    parser.add_argument("--config", default="config.ini", help="Path to the configuration file (default: config.ini)")
    parser.add_argument("--mail-from-subdomain", default="mail", help="Subdomain for the custom MAIL FROM address (e.g., 'mail' for mail.example.com)")
    parser.add_argument("--no-cloudflare", action="store_true", help="Skip CloudFlare DNS record creation (you'll need to manually create DNS records)")
    parser.add_argument("--enable-feedback", action="store_true", help="Enable SES feedback email forwarding for bounces and complaints")
    parser.add_argument("--remove-cloudflare-records", action="store_true", help="Remove all SES-related DNS records from CloudFlare for this domain")
    parser.add_argument("--remove-aws-resources", action="store_true", help="Remove IAM user and policy for this domain")
    parser.add_argument("--skip-ses", action="store_true", help="Skip SES identity setup, IAM user creation, and SMTP credential generation")
    parser.add_argument("--skip-cloudflare", action="store_true", help="Skip Cloudflare DNS record creation")
    parser.add_argument("--skip-mx", action="store_true", help="Skip MX record creation (optional for outgoing-only transactional email)")
    args = parser.parse_args()

    domain_name = args.domain
    mail_from_subdomain = f"{args.mail_from_subdomain}.{domain_name}"
    
    # Initialize logging
    log_filename = init_log_file(domain_name)

    # Load configuration
    aws_config, cf_api_token = load_config(args.config, require_cloudflare=not args.no_cloudflare)

    # Initialize AWS clients
    ses_client, iam_client, _, aws_account_id = init_aws_clients(aws_config)
    
    # Handle cleanup operations if requested
    cleanup_performed = False
    
    # Handle AWS resource cleanup if requested
    if args.remove_aws_resources:
        user_removed, policy_removed = remove_iam_user_and_policy(
            iam_client, domain_name, aws_account_id
        )
        log_print("\n--- ✅ AWS Resource Cleanup Complete! ✅ ---")
        if user_removed:
            log_print(f"Removed IAM user for domain '{domain_name}'.")
        if policy_removed:
            log_print(f"Removed IAM policy for domain '{domain_name}'.")
        if not user_removed and not policy_removed:
            log_print("No AWS resources found to remove.")
        cleanup_performed = True
    
    # Initialize CloudFlare client if needed for cleanup
    cf_client = None
    zone_id = None
    if args.remove_cloudflare_records:
        if args.no_cloudflare:
            log_print("\n  > Error: Cannot remove CloudFlare records when --no-cloudflare is set.", file=sys.stderr)
            close_log_file()
            sys.exit(1)
        cf_client = init_cloudflare_client(cf_api_token)
        zone_id = get_zone_id(cf_client, domain_name)
    
    # Handle CloudFlare record cleanup if requested
    if args.remove_cloudflare_records:
        removed = remove_ses_records_from_cloudflare(
            cf_client, zone_id, domain_name, mail_from_subdomain, aws_config['region']
        )
        log_print("\n--- ✅ CloudFlare Cleanup Complete! ✅ ---")
        log_print(f"Removed {removed} SES-related DNS record(s) from CloudFlare.")
        cleanup_performed = True
    
    # Exit if cleanup was performed
    if cleanup_performed:
        log_print(f"\nLog file saved: {log_filename}")
        close_log_file()
        sys.exit(0)
    
    # Initialize CloudFlare client for normal provisioning
    if not args.no_cloudflare:
        cf_client = init_cloudflare_client(cf_api_token)
        zone_id = get_zone_id(cf_client, domain_name)
    else:
        log_print("\n[Step 2/7] Skipping CloudFlare domain validation (--no-cloudflare flag).")

    # Configure SES identity
    ses_txt_token, dkim_tokens = configure_ses_identity(
        ses_client, domain_name, mail_from_subdomain, args.enable_feedback
    )

    # Create IAM user and policy
    iam_user_name = create_iam_user_and_policy(
        iam_client, domain_name, aws_config['region'], aws_account_id
    )

    # Generate SMTP credentials
    smtp_user, smtp_pass = create_smtp_credentials(iam_client, iam_user_name)

    # Create DNS records in CloudFlare or print manual instructions
    if not args.no_cloudflare:
        create_ses_dns_records(
            cf_client, zone_id, domain_name, mail_from_subdomain,
            aws_config['region'], ses_txt_token, dkim_tokens
        )
    else:
        print_manual_dns_records(
            domain_name, mail_from_subdomain, aws_config['region'],
            ses_txt_token, dkim_tokens
        )

    # Print credentials and instructions
    print_credentials(
        smtp_user, smtp_pass, aws_config['region'], domain_name,
        args.enable_feedback, args.no_cloudflare
    )
    
    # Close log file
    log_print(f"\nLog file saved: {log_filename}")
    close_log_file()


if __name__ == "__main__":
    main()
