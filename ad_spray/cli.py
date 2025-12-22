"""Command-line interface for AD Spray."""

import argparse
import json
import sys
from pathlib import Path
from zoneinfo import ZoneInfo

from .config import load_config, generate_config_file
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
    fetch_domain_info,
    fetch_policy_only,
    list_sessions,
    load_session,
    save_session,
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
            session = load_session(session_path, args.resume)
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
        save_session(session, session_path)
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
    session_path = Path(args.session_path)
    if delete_session(session_path, args.session_id):
        print(f"{Colors.GREEN}[+] Deleted session: {args.session_id}{Colors.NC}", file=sys.stderr)
        return 0
    else:
        print(f"{Colors.RED}[!] Session not found: {args.session_id}{Colors.NC}", file=sys.stderr)
        return 1


def cmd_export(args) -> int:
    """Export session results."""
    session_path = Path(args.session_path)
    try:
        session = load_session(session_path, args.session_id)
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
