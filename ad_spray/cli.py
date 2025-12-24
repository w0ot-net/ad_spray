"""Command-line interface for AD Spray."""

import argparse
import json
import sys
from pathlib import Path
from zoneinfo import ZoneInfo

from .config import load_config, merge_config_with_args
from .constants import (
    Colors,
    DEFAULT_SESSION_PATH,
    ERROR_SUCCESS,
    VALID_CREDENTIAL_STATUSES,
)
from .engine import SprayEngine
from .models import PasswordPolicy
from .scheduling import (
    BusinessHoursWindow,
    DAYS_OF_WEEK,
    Schedule,
    TimeVerifier,
    TimeVerificationError,
)
from .session import (
    create_session,
    delete_session,
    fetch_policy,
    fetch_users,
    list_sessions,
    load_session,
    resolve_session_id,
    save_session,
)


def prompt_session_selection(session_path: Path, filter_completed: bool = None) -> str:
    """
    Display numbered list of sessions and prompt user to select one.

    Args:
        session_path: Path to session storage
        filter_completed: If True, only show completed. If False, only incomplete. If None, show all.

    Returns:
        Selected session ID, or None if no sessions or user cancels.
    """
    sessions = list_sessions(session_path)

    if filter_completed is not None:
        sessions = [s for s in sessions if s["completed"] == filter_completed]

    if not sessions:
        return None

    print(f"\n{Colors.BLUE}Available sessions:{Colors.NC}\n", file=sys.stderr)

    for i, s in enumerate(sessions, 1):
        name_display = s.get('name') or s['session_id']
        status = f"{Colors.GREEN}completed{Colors.NC}" if s["completed"] else f"{Colors.ORANGE}in progress{Colors.NC}"
        valid = s.get('valid', 0)
        print(f"  {Colors.LBLUE}[{i}]{Colors.NC} {name_display} ({status}, {valid} valid)", file=sys.stderr)

    print(file=sys.stderr)

    while True:
        try:
            choice = input("Select session number: ").strip()
            if not choice:
                return None
            idx = int(choice) - 1
            if 0 <= idx < len(sessions):
                return sessions[idx]["session_id"]
            print(f"{Colors.RED}[!] Invalid selection{Colors.NC}", file=sys.stderr)
        except ValueError:
            print(f"{Colors.RED}[!] Enter a number{Colors.NC}", file=sys.stderr)
        except (EOFError, KeyboardInterrupt):
            return None


def build_password_policy(args) -> PasswordPolicy:
    """Build the password policy from args."""
    return PasswordPolicy(
        min_password_length=args.min_length if args.min_length is not None else 0,
        complexity_enabled=args.complexity if args.complexity is not None else False,
    )


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
    for key in ['dc', 'workgroup', 'ssl', 'port',
                'spray_passwords', 'users_file', 'output', 'userpass', 'verbose',
                'lockout_window', 'attempts', 'attempts_business',
                'min_length', 'complexity', 'timezone', 'daily_hours']:
        if not hasattr(args, key):
            setattr(args, key, None)

    args = merge_config_with_args(config_values, args)

    # Handle --get-creds mode (just show credentials and exit)
    if getattr(args, 'get_creds', None) is not None:
        session_id = args.get_creds
        if session_id is True:
            # No session specified, prompt for selection
            session_id = prompt_session_selection(session_path)
            if not session_id:
                print(f"{Colors.ORANGE}[!] No sessions available.{Colors.NC}", file=sys.stderr)
                return 1
        else:
            # Resolve by ID or name
            resolved = resolve_session_id(session_path, session_id)
            if not resolved:
                print(f"{Colors.RED}[!] Session not found: {session_id}{Colors.NC}", file=sys.stderr)
                return 1
            session_id = resolved

        try:
            session = load_session(session_path, session_id)
        except FileNotFoundError:
            print(f"{Colors.RED}[!] Session not found: {session_id}{Colors.NC}", file=sys.stderr)
            return 1

        # Print valid credentials
        found_any = False
        for attempt in session.attempts:
            if attempt.status in VALID_CREDENTIAL_STATUSES:
                found_any = True
                suffix = "" if attempt.status == ERROR_SUCCESS else f" # {attempt.status.replace('ERROR_', '')}"
                print(f"{attempt.username}:{attempt.password}{suffix}")

        if not found_any:
            print(f"{Colors.ORANGE}[!] No valid credentials found.{Colors.NC}", file=sys.stderr)
        return 0

    if args.resume:
        # Resume existing session
        session_id = args.resume
        if session_id is True:
            # No session specified, prompt for selection (only incomplete sessions)
            session_id = prompt_session_selection(session_path, filter_completed=False)
            if not session_id:
                print(f"{Colors.ORANGE}[!] No incomplete sessions to resume.{Colors.NC}", file=sys.stderr)
                return 1
        else:
            # Resolve by ID or name
            resolved = resolve_session_id(session_path, session_id)
            if not resolved:
                print(f"{Colors.RED}[!] Session not found: {session_id}{Colors.NC}", file=sys.stderr)
                return 1
            session_id = resolved

        try:
            session = load_session(session_path, session_id)
            if session.config.completed:
                print(f"{Colors.ORANGE}[!] Session already completed.{Colors.NC}", file=sys.stderr)
                return 1
            print(f"{Colors.GREEN}[+] Resuming session: {session.config.name} ({session_id}){Colors.NC}", file=sys.stderr)
        except FileNotFoundError:
            print(f"{Colors.RED}[!] Session not found: {session_id}{Colors.NC}", file=sys.stderr)
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
        if not args.users_file:
            print(f"{Colors.RED}[!] Users file is required (--users){Colors.NC}", file=sys.stderr)
            return 1
        if args.lockout_window is None:
            print(f"{Colors.RED}[!] Lockout window is required (--lockout-window){Colors.NC}", file=sys.stderr)
            return 1
        if args.attempts is None:
            print(f"{Colors.RED}[!] Attempts per window is required (--attempts){Colors.NC}", file=sys.stderr)
            return 1
        # If timezone is set, require --attempts-business
        if args.timezone and args.attempts_business is None:
            print(f"{Colors.RED}[!] --attempts-business is required when using --timezone{Colors.NC}", file=sys.stderr)
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

        # Load users
        try:
            with open(args.users_file) as f:
                users = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}[!] Users file not found: {args.users_file}{Colors.NC}", file=sys.stderr)
            return 1

        if not users:
            print(f"{Colors.RED}[!] Users file is empty{Colors.NC}", file=sys.stderr)
            return 1

        print(f"{Colors.GREEN}[+] Loaded {len(users)} users from file{Colors.NC}", file=sys.stderr)

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
                    daily_hours=daily_hours,
                )
            except Exception as e:
                print(f"{Colors.RED}[!] Invalid timezone: {args.timezone}: {e}{Colors.NC}", file=sys.stderr)
                return 1

        # Build policy from args
        policy = build_password_policy(args)

        # Print timing info
        print(f"{Colors.BLUE}[+] Timing: {args.attempts} attempts / {args.lockout_window}min window{Colors.NC}", file=sys.stderr)
        if args.timezone:
            print(f"{Colors.BLUE}[+] Business hours ({args.timezone}): {args.attempts_business} attempts{Colors.NC}", file=sys.stderr)
        if policy.min_password_length > 0:
            print(f"{Colors.BLUE}[+] Min password length: {policy.min_password_length}{Colors.NC}", file=sys.stderr)
        if policy.complexity_enabled:
            print(f"{Colors.BLUE}[+] Complexity required: {policy.complexity_enabled}{Colors.NC}", file=sys.stderr)

        # Get session name (prompt if not provided)
        session_name = getattr(args, 'name', None)
        if not session_name:
            while True:
                session_name = input("Session name: ").strip()
                if session_name:
                    break
                print(f"{Colors.RED}[!] Session name is required{Colors.NC}", file=sys.stderr)

        session = create_session(
            dc_host=args.dc,
            workgroup=args.workgroup,
            users=users,
            passwords=passwords,
            policy=policy,
            schedule=schedule,
            lockout_window=args.lockout_window,
            attempts_allowed=args.attempts,
            attempts_allowed_business=args.attempts_business if args.timezone else args.attempts,
            user_as_pass=args.userpass or False,
            use_ssl=args.ssl or False,
            port=args.port,
            output_file=args.output or 'valid_creds.txt',
            verbose=args.verbose or 3,
            name=session_name,
            session_path=session_path,
        )
        # Note: create_session now handles saving with new storage format
        print(f"{Colors.GREEN}[+] Created session: {session.config.name} ({session.config.session_id}){Colors.NC}", file=sys.stderr)

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

    # Print each session in a readable format
    print(f"\n{Colors.BLUE}{'═' * 80}{Colors.NC}")
    print(f"{Colors.ORANGE} Sessions ({len(sessions)} total){Colors.NC}")
    print(f"{Colors.BLUE}{'═' * 80}{Colors.NC}\n")

    for s in sessions:
        # Status indicator
        if s["completed"]:
            status = f"{Colors.GREEN}✓ Completed{Colors.NC}"
        else:
            status = f"{Colors.ORANGE}○ In Progress{Colors.NC}"

        # Session identifier (name or ID)
        name_display = s.get('name') or s['session_id']

        print(f"  {Colors.LBLUE}{name_display}{Colors.NC}")

        # Show ID if we have a name
        if s.get('name'):
            print(f"    ID: {s['session_id']}")

        # Target info
        print(f"    Target: {s['workgroup']}@{s['dc_host']}")

        # Progress
        users = s.get('users', 0)
        passwords = s.get('passwords', 0)
        attempts = s.get('total', 0)
        valid = s.get('valid', 0)
        locked = s.get('locked', 0)

        print(f"    Progress: {attempts:,} attempts ({users:,} users × {passwords:,} passwords)")
        print(f"    Results: {Colors.GREEN}{valid} valid{Colors.NC}, {Colors.RED}{locked} locked{Colors.NC}")

        # Timestamps
        created = s["created_at"][:19].replace("T", " ")
        print(f"    Created: {created}")
        print(f"    Status: {status}")

        print()

    print(f"{Colors.BLUE}{'═' * 80}{Colors.NC}\n")
    return 0


def cmd_delete(args) -> int:
    """Delete a session."""
    session_path = Path(args.session_path)
    session_id = resolve_session_id(session_path, args.session_id)
    if not session_id:
        print(f"{Colors.RED}[!] Session not found: {args.session_id}{Colors.NC}", file=sys.stderr)
        return 1
    if delete_session(session_path, session_id):
        print(f"{Colors.GREEN}[+] Deleted session: {session_id}{Colors.NC}", file=sys.stderr)
        return 0
    else:
        print(f"{Colors.RED}[!] Failed to delete session: {session_id}{Colors.NC}", file=sys.stderr)
        return 1


def cmd_export(args) -> int:
    """Export session results."""
    session_path = Path(args.session_path)
    session_id = resolve_session_id(session_path, args.session_id)
    if not session_id:
        print(f"{Colors.RED}[!] Session not found: {args.session_id}{Colors.NC}", file=sys.stderr)
        return 1
    try:
        session = load_session(session_path, session_id)
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Session not found: {session_id}{Colors.NC}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(session.to_dict(), indent=2))
    else:  # credentials format
        for attempt in session.attempts:
            if attempt.status in VALID_CREDENTIAL_STATUSES:
                suffix = "" if attempt.status == ERROR_SUCCESS else f" # {attempt.status.replace('ERROR_', '')}"
                print(f"{attempt.username}:{attempt.password}{suffix}")

    return 0


def cmd_get_policy(args) -> int:
    """Fetch and display the domain lockout policy."""
    if not args.dc:
        print(f"{Colors.RED}[!] Domain controller is required (-d){Colors.NC}", file=sys.stderr)
        return 1
    if not args.workgroup:
        print(f"{Colors.RED}[!] Workgroup is required (-w){Colors.NC}", file=sys.stderr)
        return 1
    if not args.username:
        print(f"{Colors.RED}[!] Username is required (-u){Colors.NC}", file=sys.stderr)
        return 1
    if not args.password:
        print(f"{Colors.RED}[!] Password is required (-p){Colors.NC}", file=sys.stderr)
        return 1

    try:
        policy = fetch_policy(
            dc_host=args.dc,
            username=args.username,
            password=args.password,
            workgroup=args.workgroup,
            use_ssl=args.ssl or False,
            port=args.port,
            base_dn=args.base_dn,
        )

        print(f"\n{Colors.BLUE}{'═' * 50}{Colors.NC}")
        print(f"{Colors.ORANGE} Domain Password Policy{Colors.NC}")
        print(f"{Colors.BLUE}{'═' * 50}{Colors.NC}\n")

        print(f"  {Colors.LBLUE}Lockout Threshold:{Colors.NC}      {policy.lockout_threshold}")
        print(f"  {Colors.LBLUE}Observation Window:{Colors.NC}     {policy.lockout_observation_window_minutes} minutes")
        print(f"  {Colors.LBLUE}Lockout Duration:{Colors.NC}       {policy.lockout_duration_minutes} minutes")
        print(f"  {Colors.LBLUE}Min Password Length:{Colors.NC}    {policy.min_password_length}")
        print(f"  {Colors.LBLUE}Complexity Required:{Colors.NC}    {policy.complexity_enabled}")

        print(f"\n{Colors.BLUE}{'═' * 50}{Colors.NC}\n")

        # Provide guidance
        if policy.lockout_threshold == 0:
            print(f"  {Colors.GREEN}No lockout policy - unlimited attempts allowed{Colors.NC}")
        else:
            safe_attempts = policy.lockout_threshold - 1
            sleep_time = policy.lockout_observation_window_minutes + 1
            print(f"  {Colors.ORANGE}Suggested spray settings:{Colors.NC}")
            print(f"    --lockout-threshold {policy.lockout_threshold}")
            print(f"    --lockout-window {policy.lockout_observation_window_minutes}")
            print(f"\n  {Colors.BLUE}This means:{Colors.NC}")
            print(f"    - {safe_attempts} password attempt(s) per user before sleeping")
            print(f"    - {sleep_time} minute sleep between password batches")

        print()
        return 0

    except Exception as e:
        print(f"{Colors.RED}[!] Failed to fetch policy: {e}{Colors.NC}", file=sys.stderr)
        return 1


def cmd_get_users(args) -> int:
    """Fetch users from AD and save to file."""
    if not args.dc:
        print(f"{Colors.RED}[!] Domain controller is required (-d){Colors.NC}", file=sys.stderr)
        return 1
    if not args.workgroup:
        print(f"{Colors.RED}[!] Workgroup is required (-w){Colors.NC}", file=sys.stderr)
        return 1
    if not args.username:
        print(f"{Colors.RED}[!] Username is required (-u){Colors.NC}", file=sys.stderr)
        return 1
    if not args.password:
        print(f"{Colors.RED}[!] Password is required (-p){Colors.NC}", file=sys.stderr)
        return 1

    output_file = args.output or "users.txt"

    try:
        print(f"{Colors.BLUE}[+] Connecting to {args.dc}...{Colors.NC}", file=sys.stderr)
        users = fetch_users(
            dc_host=args.dc,
            username=args.username,
            password=args.password,
            workgroup=args.workgroup,
            use_ssl=args.ssl or False,
            port=args.port,
            base_dn=args.base_dn,
        )

        if not users:
            print(f"{Colors.ORANGE}[!] No users found{Colors.NC}", file=sys.stderr)
            return 1

        # Write to file
        with open(output_file, 'w') as f:
            for user in users:
                f.write(f"{user}\n")

        print(f"{Colors.GREEN}[+] Found {len(users)} users{Colors.NC}", file=sys.stderr)
        print(f"{Colors.GREEN}[+] Saved to: {output_file}{Colors.NC}", file=sys.stderr)
        return 0

    except Exception as e:
        print(f"{Colors.RED}[!] Failed to fetch users: {e}{Colors.NC}", file=sys.stderr)
        return 1


def main() -> int:
    """Main entry point for the CLI."""
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
  # Basic spray (no business hours consideration)
  %(prog)s -d 10.0.0.1 -w CORP --users users.txt --passwords pwds.txt \\
      --lockout-window 30 --attempts 4

  # With business hours (different attempts during/outside business hours)
  %(prog)s -d 10.0.0.1 -w CORP --users users.txt --passwords pwds.txt \\
      --lockout-window 30 --attempts 4 --timezone America/New_York --attempts-business 2

  # Pause during business hours (0 attempts)
  %(prog)s -d 10.0.0.1 -w CORP --users users.txt --passwords pwds.txt \\
      --lockout-window 30 --attempts 4 --timezone America/New_York --attempts-business 0

  # Resume existing spray
  %(prog)s --resume 1

  # Get credentials from a session
  %(prog)s --get-creds 1
        """,
    )
    spray_parser.add_argument("-c", "--config", help="Configuration file (INI format)")
    spray_parser.add_argument("-d", "--dc", help="Domain controller FQDN or IP address")
    spray_parser.add_argument("-w", "--workgroup", help="NetBIOS domain/workgroup name (e.g., CORP)")
    spray_parser.add_argument("--passwords", dest="spray_passwords", help="File containing passwords to spray")
    spray_parser.add_argument("--users", dest="users_file", help="File containing usernames to spray")
    spray_parser.add_argument("-o", "--output", help="Output file for valid credentials (default: valid_creds.txt)")
    spray_parser.add_argument("-v", "--verbose", type=int, choices=[0, 1, 2, 3],
                              help="Verbosity level (0=silent, 3=max, default: 3)")
    spray_parser.add_argument("--userpass", action="store_true", help="Try username as password")
    spray_parser.add_argument("--ssl", action="store_true", help="Use LDAPS (SSL/TLS)")
    spray_parser.add_argument("--port", type=int, help="Override port number")
    spray_parser.add_argument("--resume", nargs="?", const=True, metavar="SESSION_ID",
                              help="Resume an existing session (prompts for selection if no ID given)")
    spray_parser.add_argument("--get-creds", nargs="?", const=True, metavar="SESSION_ID",
                              help="Show valid credentials from a session (prompts for selection if no ID given)")
    spray_parser.add_argument("--session-path", default=str(DEFAULT_SESSION_PATH),
                              help=f"Session storage path (default: {DEFAULT_SESSION_PATH})")
    # Timing flags
    spray_parser.add_argument("--lockout-window", type=int,
                              help="Lockout observation window in minutes (use get-policy to fetch from AD)")
    spray_parser.add_argument("--attempts", type=int,
                              help="Attempts per user per window (required if no --timezone)")
    # Business hours scheduling
    spray_parser.add_argument("--timezone", help="Timezone for business hours (IANA format, e.g., America/New_York)")
    spray_parser.add_argument("--attempts-business", type=int,
                              help="Attempts during business hours (required with --timezone, 0 = pause)")
    spray_parser.add_argument("--force-system-time", action="store_true",
                              help="Use system clock instead of external time verification (not recommended)")
    # Password filtering
    spray_parser.add_argument("--min-length", type=int,
                              help="Minimum password length for filtering")
    spray_parser.add_argument("--complexity", action="store_true",
                              help="Enable password complexity filtering")
    # Session naming options
    spray_parser.add_argument("--name", help="Human-readable session name (e.g., 'Q1 External Audit')")
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

    # Get-policy subcommand
    policy_parser = subparsers.add_parser(
        "get-policy",
        help="Fetch and display the domain lockout policy",
        epilog="""
Examples:
  %(prog)s -d 10.0.0.1 -w CORP -u admin -p 'P@ss'
  %(prog)s -d dc01.corp.local -w CORP -u admin -p 'P@ss' --ssl
        """,
    )
    policy_parser.add_argument("-d", "--dc", help="Domain controller FQDN or IP address")
    policy_parser.add_argument("-w", "--workgroup", help="NetBIOS domain/workgroup name (e.g., CORP)")
    policy_parser.add_argument("-u", "--username", help="Username for AD authentication")
    policy_parser.add_argument("-p", "--password", help="Password for AD authentication")
    policy_parser.add_argument("--base-dn", dest="base_dn", help="Override LDAP base DN")
    policy_parser.add_argument("--ssl", action="store_true", help="Use LDAPS (SSL/TLS)")
    policy_parser.add_argument("--port", type=int, help="Override port number")
    policy_parser.set_defaults(func=cmd_get_policy)

    # Get-users subcommand
    users_parser = subparsers.add_parser(
        "get-users",
        help="Fetch users from AD and save to file",
        epilog="""
Examples:
  %(prog)s -d 10.0.0.1 -w CORP -u admin -p 'P@ss'
  %(prog)s -d dc01.corp.local -w CORP -u admin -p 'P@ss' -o targets.txt
        """,
    )
    users_parser.add_argument("-d", "--dc", help="Domain controller FQDN or IP address")
    users_parser.add_argument("-w", "--workgroup", help="NetBIOS domain/workgroup name (e.g., CORP)")
    users_parser.add_argument("-u", "--username", help="Username for AD authentication")
    users_parser.add_argument("-p", "--password", help="Password for AD authentication")
    users_parser.add_argument("-o", "--output", help="Output file (default: users.txt)")
    users_parser.add_argument("--base-dn", dest="base_dn", help="Override LDAP base DN")
    users_parser.add_argument("--ssl", action="store_true", help="Use LDAPS (SSL/TLS)")
    users_parser.add_argument("--port", type=int, help="Override port number")
    users_parser.set_defaults(func=cmd_get_users)

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
