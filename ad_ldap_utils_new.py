#!/usr/bin/env python3
"""
Wrapper script for backward compatibility.
Entry point for AD LDAP utilities.
"""

import argparse
import sys
from contextlib import contextmanager
from typing import Iterable

from ad_spray.ldap import ADConnection, check_auth, is_ip_address
from ad_spray.constants import Colors


def _write_text_lines(path: str, lines: Iterable[str]) -> None:
    """Write newline-terminated text lines to a file."""
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(f"{line}\n" for line in lines)


def _write_json(path: str, obj) -> None:
    """Write JSON with indentation and trailing newline."""
    import json
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")


def add_common_args(parser: argparse.ArgumentParser) -> None:
    """Add common connection arguments to a parser."""
    parser.add_argument("-u", "--username", required=True, help="Username for authentication")
    parser.add_argument("-p", "--password", required=True, help="Password for authentication")
    parser.add_argument("-d", "--dc", required=True, help="Domain controller FQDN or IP address")
    parser.add_argument("-w", "--workgroup", default=None, help="NetBIOS domain/workgroup name (e.g., CORP)")
    parser.add_argument("--base-dn", dest="base_dn", default=None, help="Override the LDAP search base DN")
    parser.add_argument("--ssl", action="store_true", help="Use LDAPS (SSL/TLS on port 636)")
    parser.add_argument("--port", type=int, default=None, help="Override the port number")


@contextmanager
def open_ad_from_args(args) -> Iterable[ADConnection]:
    """Open an ADConnection from parsed CLI arguments."""
    host_type = "IP" if is_ip_address(args.dc) else "FQDN"
    print(f"[*] Connecting to {args.dc} ({host_type})...", file=sys.stderr)

    with ADConnection(
        dc_host=args.dc,
        username=args.username,
        password=args.password,
        workgroup=args.workgroup,
        base_dn=args.base_dn,
        use_ssl=args.ssl,
        port=args.port,
    ) as ad:
        auth_display = f"{args.workgroup}\\{ad.username}" if args.workgroup else ad.username
        auth_method = "NTLM" if args.workgroup else "SIMPLE"
        print(f"[*] Authenticated as: {auth_display} ({auth_method})", file=sys.stderr)
        print(f"[*] Base DN: {ad.base_dn}", file=sys.stderr)
        yield ad


def cmd_users(args) -> None:
    """Handle the 'users' subcommand."""
    with open_ad_from_args(args) as ad:
        users = ad.get_users()
        print(f"[+] Found {len(users)} users", file=sys.stderr)
        _write_text_lines(args.output, users)
        print(f"[+] Users written to {args.output}", file=sys.stderr)


def cmd_lockout_policy(args) -> None:
    """Handle the 'lockout-policy' subcommand."""
    with open_ad_from_args(args) as ad:
        policy = ad.get_lockout_policy()
        _write_json(args.output, policy)
        print(f"[+] Lockout policy written to {args.output}", file=sys.stderr)

        # Also print a summary
        print(f"[+] Lockout threshold: {policy['lockout_threshold']} attempts", file=sys.stderr)
        print(f"[+] Lockout duration: {policy['lockout_duration_minutes']} minutes", file=sys.stderr)
        print(f"[+] Observation window: {policy['lockout_observation_window_minutes']} minutes", file=sys.stderr)


def cmd_check_auth(args) -> None:
    """Handle the 'check-auth' subcommand."""
    host_type = "IP" if is_ip_address(args.dc) else "FQDN"
    print(f"[*] Checking auth against {args.dc} ({host_type})...", file=sys.stderr)

    result = check_auth(
        dc_host=args.dc,
        username=args.username,
        password=args.password,
        workgroup=args.workgroup,
        use_ssl=args.ssl,
        port=args.port,
    )

    if args.output:
        _write_json(args.output, result)
        print(f"[+] Result written to {args.output}", file=sys.stderr)

    # Print result summary
    status_symbol = "+" if result["success"] else "-"
    print(f"[{status_symbol}] {result['status']}", file=sys.stderr)
    if result.get("status_code"):
        print(f"[*] Code: 0x{result['status_code']:x}", file=sys.stderr)

    # Exit with appropriate code
    sys.exit(0 if result["success"] else 1)


# Subcommand definitions: (help, default_output, handler, epilog_examples)
SUBCOMMANDS = {
    "users": (
        "Enumerate all domain users",
        "users.txt",
        cmd_users,
        """
Examples:
  %(prog)s -u admin -p 'P@ssw0rd' -d dc01.corp.local
  %(prog)s -u admin -p 'P@ssw0rd' -d 192.168.1.10 -w CORP
  %(prog)s -u admin -p 'P@ssw0rd' -d example.com -w EXAMPLE -o domain_users.txt
        """,
    ),
    "lockout-policy": (
        "Retrieve domain lockout policy",
        "lockout_policy.json",
        cmd_lockout_policy,
        """
Examples:
  %(prog)s -u admin -p 'P@ssw0rd' -d dc01.corp.local
  %(prog)s -u admin -p 'P@ssw0rd' -d 192.168.1.10 -w CORP -o policy.json
        """,
    ),
    "check-auth": (
        "Test authentication and return status code",
        None,  # Output is optional for this command
        cmd_check_auth,
        """
Tests credentials against AD and returns the authentication status code.
Exits with code 0 on success, 1 on failure.

Status codes include:
  ERROR_SUCCESS              - Authentication successful
  ERROR_LOGON_FAILURE        - Invalid username or password
  ERROR_ACCOUNT_DISABLED     - Account is disabled
  ERROR_ACCOUNT_LOCKED_OUT   - Account is locked out
  ERROR_PASSWORD_EXPIRED     - Password has expired
  ERROR_PASSWORD_MUST_CHANGE - Password must be changed at next logon
  ERROR_ACCOUNT_EXPIRED      - Account has expired

Examples:
  %(prog)s -u testuser -p 'password' -d dc01.corp.local -w CORP
  %(prog)s -u admin -p 'P@ssw0rd' -d 192.168.1.10 -w CORP -o result.json
        """,
    ),
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Active Directory LDAP utilities.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Command to run")

    for name, (help_text, default_output, handler, epilog) in SUBCOMMANDS.items():
        sub = subparsers.add_parser(
            name,
            help=help_text,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=epilog,
        )
        add_common_args(sub)
        if default_output:
            sub.add_argument("-o", "--output", default=default_output, help=f"Output filename (default: {default_output})")
        else:
            sub.add_argument("-o", "--output", default=None, help="Output filename (optional)")
        sub.set_defaults(func=handler)

    args = parser.parse_args()

    try:
        args.func(args)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
