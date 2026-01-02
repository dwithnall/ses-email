"""Output formatting for credentials and instructions."""

from utils import log_print


def print_credentials(smtp_user, smtp_pass, aws_region, domain_name, enable_feedback, no_cloudflare):
    """Print all credentials and final instructions."""
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
    
    if enable_feedback:
        log_print("\n📧 SES Feedback Email: ENABLED")
        log_print("  > You will receive notifications for bounces and complaints")
        log_print("  > Monitor your feedback email address to maintain good sending reputation")
    else:
        log_print("\n📧 SES Feedback Email: DISABLED (default)")
        log_print("  > Use --enable-feedback flag to receive bounce/complaint notifications")

    log_print("\n### What To Do Next ###")
    if not no_cloudflare:
        log_print("1.  **DNS Propagation**: Wait 5-30 minutes for the DNS records to become active globally.")
        log_print("2.  **AWS Verification**: AWS will automatically detect the records. Check the 'Identity Status' in the SES Console for your domain. You'll get an email when it is complete.")
        log_print(f"3.  **DMARC Reports**: Ensure the mailbox `dmarc-reports@{domain_name}` exists to receive reports. By default DMARC is set to 'none'.")
    else:
        log_print("1.  **Manual DNS Setup**: Create the DNS records listed above in your DNS provider.")
        log_print("2.  **DNS Propagation**: Wait 5-30 minutes for the DNS records to become active globally.")
        log_print("3.  **AWS Verification**: AWS will automatically detect the records. Check the 'Identity Status' in the SES Console for your domain. You'll get an email when it is complete.")
        log_print(f"4.  **DMARC Reports**: Ensure the mailbox `dmarc-reports@{domain_name}` exists to receive reports. By default DMARC is set to 'none'.")


def print_manual_dns_records(domain_name, mail_from_subdomain, aws_region, ses_txt_token, dkim_tokens, skip_mx=False):
    """Print manual DNS record instructions when CloudFlare is disabled."""
    log_print("\n[Step 6/7] Skipping CloudFlare DNS record creation (--no-cloudflare or --skip-cloudflare flag).")
    log_print("  > You will need to manually create the following DNS records:")
    log_print(f"  > TXT Record: _amazonses.{domain_name} = {ses_txt_token}")
    for token in dkim_tokens:
        log_print(f"  > CNAME Record: {token}._domainkey.{domain_name} = {token}.dkim.amazonses.com")
    
    # MX record is optional
    if not skip_mx:
        log_print(f"  > MX Record: {mail_from_subdomain} = feedback-smtp.{aws_region}.amazonses.com (Priority: 10)")
    else:
        log_print(f"  > MX Record: {mail_from_subdomain} = feedback-smtp.{aws_region}.amazonses.com (Priority: 10) [SKIPPED - optional for outgoing-only email]")
    
    log_print(f"  > TXT Record: {mail_from_subdomain} = \"v=spf1 include:amazonses.com ~all\"")
    log_print(f"  > TXT Record: _dmarc.{domain_name} = \"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain_name};\"")

