"""Configuration file handling."""

import argparse
import configparser
from typing import Any, Dict, Optional

from .scheduling import BusinessHoursWindow, DAYS_OF_WEEK


DEFAULT_CONFIG_TEMPLATE = """\
# ADSpray Configuration File
# --------------------------
# Use 'auto' for users_file, lockout_threshold, lockout_window, min_length,
# and complexity to automatically fetch values from Active Directory.
# IMPORTANT: 'auto' settings REQUIRE valid AD credentials in [target].
# If any setting is 'auto' and credentials are missing, the spray will fail.

[target]
# Domain controller FQDN or IP address
dc = 10.0.0.1
# NetBIOS domain/workgroup name
workgroup = CORP
# AD credentials for enumeration (REQUIRED for any 'auto' settings)
username = admin
password = P@ssw0rd!
# Use LDAPS (SSL/TLS)
ssl = false
# Override port number (optional, leave empty for default)
port =
# Override LDAP base DN (optional, leave empty for auto-detect)
base_dn =

[spray]
# File containing passwords to spray
passwords_file = passwords.txt
# File containing usernames, or 'auto' to enumerate from AD (requires credentials)
users_file = auto
# Output file for valid credentials
output = valid_creds.txt
# Try username as password
userpass = false
# Verbosity level (0=silent, 1=minimal, 2=normal, 3=verbose)
verbose = 3

[policy]
# Lockout threshold, or 'auto' to fetch from AD (requires credentials)
# 0 = no lockout policy
lockout_threshold = auto
# Lockout observation window in minutes, or 'auto' to fetch from AD (requires credentials)
lockout_window = auto
# Minimum password length, or 'auto' to fetch from AD (requires credentials)
min_length = auto
# Require password complexity, or 'auto' to fetch from AD (requires credentials)
complexity = auto

[schedule]
# Timezone for business hours (IANA format, e.g., America/New_York, Europe/London)
# Leave empty to disable business hours feature
timezone =
# Number of attempts to reduce during business hours
# Formula: attempts_allowed = lockout_threshold - business_hours_reduction
# e.g., if threshold=5 and reduction=3, then 5-3=2 attempts allowed during business hours
# If the result is 0 or negative, spray pauses entirely during business hours
business_hours_reduction = 3
# Force use of system clock instead of external time verification
# WARNING: Only set to 'true' if you cannot access external time sources
# If enabled, ensure your system clock is accurate to avoid spraying during business hours
force_system_time = false
# Business hours for each day (HH:MM-HH:MM format, 24-hour)
# Use 'off' to indicate no restrictions (full speed spraying)
# Use 'pause' to pause entirely on that day
monday = 09:00-17:00
tuesday = 09:00-17:00
wednesday = 09:00-17:00
thursday = 09:00-17:00
friday = 09:00-17:00
saturday = off
sunday = off
"""


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from INI file.

    Returns a dict with all config values, using None for unset values.
    """
    config = configparser.ConfigParser()
    config.read(config_path)

    result: Dict[str, Any] = {}

    # [target] section
    if config.has_section('target'):
        result['dc'] = config.get('target', 'dc', fallback=None)
        result['workgroup'] = config.get('target', 'workgroup', fallback=None)
        result['username'] = config.get('target', 'username', fallback=None)
        result['password'] = config.get('target', 'password', fallback=None)
        result['ssl'] = config.getboolean('target', 'ssl', fallback=False)
        port_str = config.get('target', 'port', fallback='')
        result['port'] = int(port_str) if port_str.strip() else None
        base_dn = config.get('target', 'base_dn', fallback='')
        result['base_dn'] = base_dn if base_dn.strip() else None

    # [spray] section
    if config.has_section('spray'):
        result['passwords_file'] = config.get('spray', 'passwords_file', fallback=None)
        result['users_file'] = config.get('spray', 'users_file', fallback=None)
        result['output'] = config.get('spray', 'output', fallback='valid_creds.txt')
        result['userpass'] = config.getboolean('spray', 'userpass', fallback=False)
        result['verbose'] = config.getint('spray', 'verbose', fallback=3)

    # [policy] section - support 'auto' keyword
    if config.has_section('policy'):
        for key in ['lockout_threshold', 'lockout_window', 'min_length']:
            val = config.get('policy', key, fallback='auto')
            result[key] = 'auto' if val.lower() == 'auto' else int(val)

        complexity_val = config.get('policy', 'complexity', fallback='auto')
        if complexity_val.lower() == 'auto':
            result['complexity'] = 'auto'
        else:
            result['complexity'] = config.getboolean('policy', 'complexity', fallback=False)

    # [schedule] section
    if config.has_section('schedule'):
        timezone = config.get('schedule', 'timezone', fallback='')
        result['timezone'] = timezone if timezone.strip() else None
        result['business_hours_reduction'] = config.getint('schedule', 'business_hours_reduction', fallback=3)
        result['force_system_time'] = config.getboolean('schedule', 'force_system_time', fallback=False)

        result['daily_hours'] = {}
        for day in DAYS_OF_WEEK:
            hours_str = config.get('schedule', day, fallback='off')
            result['daily_hours'][day] = BusinessHoursWindow.parse(hours_str)

    return result


def merge_config_with_args(config: Dict[str, Any], args: argparse.Namespace) -> argparse.Namespace:
    """
    Merge config file values with CLI args. CLI args take precedence.
    """
    # Map of config keys to arg names (where they differ)
    key_mapping = {
        'passwords_file': 'spray_passwords',
        'lockout_threshold': 'lockout_threshold',
        'lockout_window': 'lockout_window',
        'min_length': 'min_length',
    }

    for config_key, config_value in config.items():
        if config_value is None:
            continue

        arg_key = key_mapping.get(config_key, config_key)

        # Skip if CLI arg was explicitly provided (not default)
        # We check against None for optional args and check hasattr for safety
        if hasattr(args, arg_key):
            current_value = getattr(args, arg_key)
            # If CLI provided a value (not None and not the argparse default), keep it.
            if current_value is not None:
                if isinstance(current_value, bool) and not current_value and config_value:
                    setattr(args, arg_key, config_value)
                # Preserve explicit CLI values (including False) unless config is True.
                continue

        setattr(args, arg_key, config_value)

    return args


def generate_config_file(output_path: Optional[str] = None) -> str:
    """Generate a template configuration file."""
    if output_path:
        with open(output_path, 'w') as f:
            f.write(DEFAULT_CONFIG_TEMPLATE)
        return f"Configuration template written to: {output_path}"
    else:
        return DEFAULT_CONFIG_TEMPLATE
