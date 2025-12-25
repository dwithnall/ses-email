"""Configuration loading and validation."""

import os
import sys
import configparser
from utils import log_print


def load_config(config_path, require_cloudflare=True):
    """
    Load configuration from INI file.
    
    Args:
        config_path: Path to the configuration file
        require_cloudflare: Whether CloudFlare credentials are required
        
    Returns:
        tuple: (aws_config, cf_api_token) where aws_config is a dict with
               access_key_id, secret_access_key, and region
    """
    log_print(f"\n[Step 1/7] Loading configuration from '{config_path}'...")
    
    if not os.path.exists(config_path):
        log_print(f"  > Error: Configuration file not found at '{config_path}'", file=sys.stderr)
        log_print("  > Please create it or use the --config flag to specify the correct path.", file=sys.stderr)
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(config_path)
    
    # Load AWS credentials
    try:
        aws_config = {
            'access_key_id': config['AWS']['access_key_id'],
            'secret_access_key': config['AWS']['secret_access_key'],
            'region': config['AWS']['region']
        }
        log_print("  > AWS configuration loaded successfully.")
    except KeyError as e:
        log_print(f"  > Error: Missing AWS key {e} in the configuration file.", file=sys.stderr)
        log_print("  > Please ensure your config file has [AWS] section with all required keys.", file=sys.stderr)
        sys.exit(1)
    
    # Load CloudFlare credentials if required
    cf_api_token = None
    if require_cloudflare:
        try:
            cf_api_token = config['Cloudflare']['api_token']
            log_print("  > CloudFlare configuration loaded successfully.")
        except KeyError as e:
            log_print(f"  > Error: Missing CloudFlare key {e} in the configuration file.", file=sys.stderr)
            log_print("  > Please ensure your config file has [Cloudflare] section with api_token, or use --no-cloudflare flag.", file=sys.stderr)
            sys.exit(1)
    else:
        log_print("  > CloudFlare integration disabled via --no-cloudflare flag.")
    
    return aws_config, cf_api_token

