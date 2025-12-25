"""SES (Simple Email Service) operations."""

import sys
from botocore.exceptions import ClientError
from utils import log_print


def configure_ses_identity(ses_client, domain_name, mail_from_subdomain, enable_feedback=False):
    """
    Configure SES identity for a domain.
    
    Args:
        ses_client: Boto3 SES client
        domain_name: Domain name to configure
        mail_from_subdomain: MAIL FROM subdomain
        enable_feedback: Whether to enable feedback forwarding
        
    Returns:
        tuple: (ses_txt_token, dkim_tokens)
    """
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
        
        # Configure SES feedback forwarding
        ses_client.set_identity_feedback_forwarding_enabled(
            Identity=domain_name,
            ForwardingEnabled=enable_feedback
        )
        if enable_feedback:
            log_print("  > SES feedback forwarding enabled for bounces and complaints.")
        else:
            log_print("  > SES feedback forwarding disabled (default).")
            
        return ses_txt_token, dkim_tokens
        
    except ClientError as e:
        log_print(f"  > Error during SES configuration: {e}", file=sys.stderr)
        sys.exit(1)

