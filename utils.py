"""Utility functions for logging and common operations."""

import sys
from datetime import datetime

# Global variable to hold the log file
log_file = None


def init_log_file(domain_name):
    """Initialize the log file for a domain."""
    global log_file
    log_filename = f"ses-provision-{domain_name.replace('.', '-')}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"
    try:
        log_file = open(log_filename, 'w', encoding='utf-8')
        log_print(f"--- Starting full SES & IAM provisioning for: {domain_name} ---")
        log_print(f"Log file: {log_filename}")
        return log_filename
    except Exception as e:
        print(f"Error creating log file: {e}", file=sys.stderr)
        sys.exit(1)


def close_log_file():
    """Close the log file if it's open."""
    global log_file
    if log_file:
        log_file.close()
        log_file = None


def log_print(*args, **kwargs):
    """Print to both console and log file."""
    print(*args, **kwargs)
    global log_file
    if log_file:
        # Convert args to string and write to log file
        message = ' '.join(str(arg) for arg in args)
        log_file.write(message + '\n')
        log_file.flush()  # Ensure immediate writing

