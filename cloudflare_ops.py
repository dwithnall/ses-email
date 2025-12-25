"""CloudFlare DNS operations for SES domain provisioning."""

import sys
from cloudflare import Cloudflare
from utils import log_print


def init_cloudflare_client(api_token):
    """Initialize CloudFlare client."""
    try:
        cf_client = Cloudflare(api_token=api_token)
        log_print("  > CloudFlare client initialized.")
        return cf_client
    except Exception as e:
        log_print(f"  > Error initializing CloudFlare client: {e}", file=sys.stderr)
        raise


def get_zone_id(cf_client, domain_name):
    """Get CloudFlare zone ID for a domain."""
    log_print(f"\n[Step 2/7] Validating domain '{domain_name}' in CloudFlare...")
    try:
        zones_response = cf_client.zones.list(name=domain_name)
        zones = zones_response.result
        
        if not zones:
            log_print(f"  > Error: Domain '{domain_name}' not found in your CloudFlare account.", file=sys.stderr)
            log_print("  > Please ensure the domain is added to CloudFlare before running this script.", file=sys.stderr)
            sys.exit(1)
        zone_id = zones[0].id
        log_print(f"  > Success: Found CloudFlare Zone ID: {zone_id}")
        return zone_id
    except Exception as e:
        log_print(f"  > Error fetching CloudFlare Zone ID: {e}", file=sys.stderr)
        sys.exit(1)


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


def create_ses_dns_records(cf_client, zone_id, domain_name, mail_from_subdomain, aws_region, ses_txt_token, dkim_tokens):
    """Create all required SES DNS records in CloudFlare."""
    log_print(f"\n[Step 6/7] Creating all required DNS records in CloudFlare...")
    
    create_cf_record(cf_client, zone_id, 'TXT', f"_amazonses.{domain_name}", ses_txt_token)
    for token in dkim_tokens:
        create_cf_record(cf_client, zone_id, 'CNAME', f"{token}._domainkey.{domain_name}", f"{token}.dkim.amazonses.com")
    create_cf_record(cf_client, zone_id, 'MX', mail_from_subdomain, f"feedback-smtp.{aws_region}.amazonses.com", priority=10)
    create_cf_record(cf_client, zone_id, 'TXT', mail_from_subdomain, '"v=spf1 include:amazonses.com ~all"')
    create_cf_record(cf_client, zone_id, 'TXT', f"_dmarc.{domain_name}", f"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain_name};")
    log_print("  > Note: DMARC record created with a 'none' policy. You can strengthen this to 'quarantine' or 'reject' later.")


def remove_ses_records_from_cloudflare(cf_client, zone_id, domain_name, mail_from_subdomain, aws_region):
    """Remove all SES-related DNS records from CloudFlare for a domain."""
    log_print(f"\n[Cleanup] Removing SES-related DNS records from CloudFlare for '{domain_name}'...")
    
    # Patterns to identify SES-related records
    ses_patterns = [
        # SES verification record
        ('TXT', f'_amazonses.{domain_name}'),
        # DKIM records (CNAME records with _domainkey subdomain)
        ('CNAME', f'_domainkey.{domain_name}'),
        # MAIL FROM MX record
        ('MX', mail_from_subdomain),
        # MAIL FROM SPF record
        ('TXT', mail_from_subdomain),
        # DMARC record
        ('TXT', f'_dmarc.{domain_name}'),
    ]
    
    try:
        # Get all DNS records for the zone
        records_response = cf_client.dns.records.list(zone_id=zone_id)
        all_records = records_response.result
        
        removed_count = 0
        
        for record in all_records:
            record_name = record.name
            record_type = record.type
            record_content = record.content
            
            # Check if this record matches any SES pattern
            should_remove = False
            
            # Check exact matches for specific records
            if (record_type, record_name) in ses_patterns:
                should_remove = True
            # Check for DKIM CNAME records (they have token._domainkey.domain format)
            elif record_type == 'CNAME' and f'._domainkey.{domain_name}' in record_name:
                # Also verify it points to amazonses.com
                if 'dkim.amazonses.com' in record_content:
                    should_remove = True
            # Check for MAIL FROM MX record pointing to SES
            elif record_type == 'MX' and record_name == mail_from_subdomain:
                if f'feedback-smtp.{aws_region}.amazonses.com' in record_content:
                    should_remove = True
            # Check for SPF record on MAIL FROM subdomain
            elif record_type == 'TXT' and record_name == mail_from_subdomain:
                if 'amazonses.com' in record_content or 'v=spf1' in record_content:
                    should_remove = True
            
            if should_remove:
                try:
                    log_print(f"  > Removing {record_type} record: {record_name} -> {record_content[:70]}...")
                    cf_client.dns.records.delete(zone_id=zone_id, dns_record_id=record.id)
                    log_print(f"    - Success: Record '{record_name}' removed.")
                    removed_count += 1
                except Exception as e:
                    log_print(f"    - Error removing record '{record_name}': {e}")
        
        if removed_count == 0:
            log_print("  > No SES-related DNS records found to remove.")
        else:
            log_print(f"  > Removed {removed_count} SES-related DNS record(s).")
        
        return removed_count
        
    except Exception as e:
        log_print(f"  > Error listing/removing DNS records: {e}", file=sys.stderr)
        return 0

