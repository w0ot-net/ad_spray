#!/usr/bin/env python3
"""
Active Directory LDAP Utilities

A module for interacting with Active Directory via LDAP.
Can be imported as a module or run standalone for user enumeration and policy retrieval.

Requires: pip install ldap3
"""

import argparse
import ipaddress
import json
import sys
from contextlib import contextmanager
from datetime import timedelta
from typing import Any, Dict, Iterable, List, Optional

from ldap3 import ALL, BASE, NTLM, SUBTREE, Connection, Server
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError

import re

# AD sub-error codes extracted from LDAP error messages (hex values after "data")
# These are Windows System Error Codes (Win32)
# Reference: https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes
AD_ERROR_CODES = {
    0x525: "ERROR_NO_SUCH_USER",           # 1317 - The specified account does not exist
    0x52e: "ERROR_LOGON_FAILURE",          # 1326 - Unknown user name or bad password
    0x530: "ERROR_INVALID_LOGON_HOURS",    # 1328 - Account logon time restriction violation
    0x531: "ERROR_INVALID_WORKSTATION",    # 1329 - Account not allowed to log on from this computer
    0x532: "ERROR_PASSWORD_EXPIRED",       # 1330 - The password has expired
    0x533: "ERROR_ACCOUNT_DISABLED",       # 1331 - Account currently disabled
    0x534: "ERROR_LOGON_TYPE_NOT_GRANTED", # 1332 - Logon type not granted
    0x701: "ERROR_ACCOUNT_EXPIRED",        # 1793 - The user's account has expired
    0x773: "ERROR_PASSWORD_MUST_CHANGE",   # 1907 - User must change password before first logon
    0x775: "ERROR_ACCOUNT_LOCKED_OUT",     # 1909 - Account is currently locked out
}

# Regex to extract AD-specific error code from LDAP bind error messages
# Matches patterns like: "data 52e," or "data 775,"
AD_ERROR_CODE_RE = re.compile(r"data\s+([0-9a-fA-F]+)")


def parse_ad_error_code(error_message: str) -> Optional[int]:
    """Extract the AD-specific error code from an LDAP error message."""
    match = AD_ERROR_CODE_RE.search(error_message)
    return int(match.group(1), 16) if match else None


def is_ip_address(value: str) -> bool:
    """Check if a string is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def fqdn_to_base_dn(fqdn: str) -> str:
    """Convert FQDN to LDAP base DN (e.g., 'corp.example.com' -> 'DC=corp,DC=example,DC=com')"""
    return ",".join(f"DC={part}" for part in fqdn.split("."))


def to_minutes(value: Any) -> Optional[int]:
    """Convert a time value to minutes. Handles Windows FILETIME (negative int) or timedelta."""
    if value is None:
        return None
    if isinstance(value, timedelta):
        return int(value.total_seconds() // 60)
    if isinstance(value, int):
        # Windows FILETIME: 100-nanosecond intervals, negative for duration
        return abs(value) // (10_000_000 * 60)
    return None


def _write_text_lines(path: str, lines: Iterable[str]) -> None:
    """Write newline-terminated text lines to a file."""
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(f"{line}\n" for line in lines)


def _write_json(path: str, obj: Any) -> None:
    """Write JSON with indentation and trailing newline."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")


def check_auth(
    dc_host: str,
    username: str,
    password: str,
    workgroup: str = None,
    use_ssl: bool = False,
    port: int = None,
) -> Dict[str, Any]:
    """
    Attempt to authenticate against AD and return the result status.

    This function attempts a bind and returns the authentication result,
    including any AD-specific error codes for failed attempts.

    Args:
        dc_host: Domain controller FQDN or IP address
        username: Username to test (with or without domain prefix)
        password: Password to test
        workgroup: NetBIOS domain/workgroup name for NTLM auth
        use_ssl: Use LDAPS (SSL/TLS)
        port: Override the port (default: 636 for SSL, 389 otherwise)

    Returns:
        Dictionary containing:
        - success: True if authentication succeeded
        - status: Status code name (e.g., 'STATUS_SUCCESS', 'STATUS_ACCOUNT_DISABLED')
        - status_code: Numeric status code (0 for success, AD error code for failure)
        - message: Human-readable description
        - raw_error: Raw error message (only on failure)
    """
    port = port or (636 if use_ssl else 389)

    # Clean username and build auth user string
    if "\\" in username:
        clean_user = username.partition("\\")[2]
    else:
        clean_user = username.partition("@")[0] or username

    if workgroup:
        auth_user = f"{workgroup}\\{clean_user}"
        auth_params = {"user": auth_user, "password": password, "authentication": NTLM}
    else:
        auth_user = username
        auth_params = {"user": auth_user, "password": password}

    try:
        server = Server(dc_host, port=port, use_ssl=use_ssl, get_info=ALL)
        conn = Connection(server, auto_bind=True, **auth_params)
        conn.unbind()
        return {
            "success": True,
            "status": "ERROR_SUCCESS",
            "status_code": 0,
            "message": "Authentication successful",
        }
    except LDAPBindError as e:
        error_msg = str(e)
        ad_code = parse_ad_error_code(error_msg)
        status_name = AD_ERROR_CODES.get(ad_code, "ERROR_LOGON_FAILURE") if ad_code else "ERROR_LOGON_FAILURE"
        return {
            "success": False,
            "status": status_name,
            "status_code": ad_code or 0x52e,
            "message": f"Authentication failed: {status_name}",
            "raw_error": error_msg,
        }
    except LDAPSocketOpenError as e:
        return {
            "success": False,
            "status": "ERROR_HOST_UNREACHABLE",
            "status_code": None,
            "message": f"Could not connect to server: {e}",
            "raw_error": str(e),
        }
    except Exception as e:
        return {
            "success": False,
            "status": "ERROR_GEN_FAILURE",
            "status_code": None,
            "message": f"Unexpected error: {e}",
            "raw_error": str(e),
        }


class ADConnection:
    """
    A connection manager for Active Directory LDAP operations.

    Attributes:
        server: The ldap3 Server object
        connection: The ldap3 Connection object (None until connect() is called)
        base_dn: The base DN for LDAP searches

    Example:
        with ADConnection('dc01.corp.local', 'admin', 'password', workgroup='CORP') as ad:
            users = ad.get_users()
            policy = ad.get_lockout_policy()
    """

    def __init__(
        self,
        dc_host: str,
        username: str,
        password: str,
        workgroup: str = None,
        base_dn: str = None,
        use_ssl: bool = False,
        port: int = None,
    ):
        """
        Initialize an AD connection configuration.

        Args:
            dc_host: Domain controller FQDN or IP address
            username: Username for authentication
            password: Password for authentication
            workgroup: NetBIOS domain/workgroup name (e.g., 'CORP')
            base_dn: Override the LDAP search base DN
            use_ssl: Use LDAPS (SSL/TLS)
            port: Override the port (default: 636 for SSL, 389 otherwise)
        """
        self.dc_host = dc_host
        self.username = self._clean_username(username)
        self.password = password
        self.workgroup = workgroup
        self._base_dn_override = base_dn
        self.use_ssl = use_ssl
        self.port = port or (636 if use_ssl else 389)

        self.server: Optional[Server] = None
        self.connection: Optional[Connection] = None
        self.base_dn: Optional[str] = None

    def _clean_username(self, username: str) -> str:
        """Strip any existing domain prefix from username."""
        if "\\" in username:
            return username.partition("\\")[2]
        return username.partition("@")[0] or username

    def _auth_params(self) -> Dict[str, Any]:
        """Build Connection() authentication parameters."""
        if self.workgroup:
            # Use NetBIOS domain/workgroup for NTLM.
            return {
                "user": f"{self.workgroup}\\{self.username}",
                "password": self.password,
                "authentication": NTLM,
            }
        # SIMPLE bind (or default) if no workgroup specified.
        return {"user": self.username, "password": self.password}

    def _resolve_base_dn(self) -> str:
        """Determine the base DN from override, server info, or FQDN."""
        if self._base_dn_override:
            return self._base_dn_override

        # Try to get from server info
        if self.server and self.server.info and self.server.info.other.get("defaultNamingContext"):
            return self.server.info.other["defaultNamingContext"][0]

        # Fall back to deriving from FQDN (won't work for IP addresses)
        if not is_ip_address(self.dc_host):
            return fqdn_to_base_dn(self.dc_host)

        raise ValueError(
            "Cannot determine base DN. When using an IP address, either provide "
            "--base-dn or ensure the server exposes defaultNamingContext."
        )

    def connect(self) -> "ADConnection":
        """Establish the LDAP connection. Returns self for chaining."""
        self.server = Server(self.dc_host, port=self.port, use_ssl=self.use_ssl, get_info=ALL)
        self.connection = Connection(self.server, auto_bind=True, **self._auth_params())
        self.base_dn = self._resolve_base_dn()
        return self

    def disconnect(self) -> None:
        """Close the LDAP connection."""
        if self.connection:
            self.connection.unbind()
            self.connection = None

    def __enter__(self) -> "ADConnection":
        """Context manager entry."""
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Context manager exit."""
        self.disconnect()
        return False

    def search(
        self,
        search_filter: str,
        attributes: List[str],
        search_base: str = None,
        scope=SUBTREE,
    ) -> List[Any]:
        """
        Perform an LDAP search.

        Args:
            search_filter: LDAP filter string
            attributes: List of attributes to retrieve
            search_base: Override the search base (defaults to self.base_dn)
            scope: Search scope (SUBTREE, BASE, LEVEL)

        Returns:
            List of ldap3 Entry objects
        """
        if not self.connection:
            raise RuntimeError("Not connected. Call connect() first or use as context manager.")

        self.connection.search(
            search_base=search_base or self.base_dn,
            search_filter=search_filter,
            search_scope=scope,
            attributes=attributes,
        )
        return list(self.connection.entries)

    def _get_samaccountnames(self, search_filter: str) -> List[str]:
        """Common implementation for enumerating sAMAccountName values."""
        entries = self.search(search_filter, ["sAMAccountName"])
        return sorted(
            entry.sAMAccountName.value for entry in entries
            if hasattr(entry, "sAMAccountName") and entry.sAMAccountName.value
        )

    def get_users(self) -> List[str]:
        """
        Retrieve all user sAMAccountNames from the domain.

        Returns:
            Sorted list of usernames (without domain prefix)
        """
        # objectClass=user and objectCategory=person excludes computer accounts
        return self._get_samaccountnames("(&(objectClass=user)(objectCategory=person))")

    def get_groups(self) -> List[str]:
        """
        Retrieve all group sAMAccountNames from the domain.

        Returns:
            Sorted list of group names
        """
        return self._get_samaccountnames("(objectClass=group)")

    def get_computers(self) -> List[str]:
        """
        Retrieve all computer sAMAccountNames from the domain.

        Returns:
            Sorted list of computer names (includes trailing $)
        """
        return self._get_samaccountnames("(objectClass=computer)")

    def get_lockout_policy(self) -> Dict[str, Any]:
        """
        Retrieve the domain's account lockout and password policy.

        Returns:
            Dictionary containing lockout policy settings:
            - lockout_threshold: Number of failed attempts before lockout (0 = never)
            - lockout_duration_minutes: How long account stays locked (0 = until admin unlocks)
            - lockout_observation_window_minutes: Time window for counting failed attempts
            - min_password_length: Minimum password length
            - password_history_length: Number of previous passwords remembered
            - complexity_enabled: Whether password complexity is required
            - raw: Raw attribute values from AD

        Password complexity (when enabled) requires:
            - At least 3 of 4 categories: uppercase, lowercase, digits, special chars
            - Cannot contain username or parts of display name (>2 consecutive chars)
        """
        attributes = [
            "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow",
            # Also grab password policy while we're here
            "minPwdLength", "minPwdAge", "maxPwdAge", "pwdHistoryLength", "pwdProperties",
        ]

        entries = self.search("(objectClass=domain)", attributes, self.base_dn, BASE)
        if not entries:
            raise RuntimeError("Could not retrieve domain policy")

        entry = entries[0]

        def get(attr: str) -> Any:
            """Safely read an attribute value from an ldap3 Entry."""
            return entry[attr].value if hasattr(entry, attr) and entry[attr].value is not None else None

        def raw_value(val: Any) -> Any:
            """Convert value to JSON-serializable format for raw output."""
            return val.total_seconds() if isinstance(val, timedelta) else val

        raw = {attr: get(attr) for attr in attributes}

        # Parse pwdProperties bitmask
        # Bit 0 (1): DOMAIN_PASSWORD_COMPLEX - complexity required
        # Bit 3 (8): DOMAIN_LOCKOUT_ADMINS - lock out admins too
        # Bit 4 (16): DOMAIN_PASSWORD_STORE_CLEARTEXT - reversible encryption
        # Bit 5 (32): DOMAIN_REFUSE_PASSWORD_CHANGE - refuse password changes
        pwd_properties = raw["pwdProperties"] or 0
        complexity_enabled = bool(pwd_properties & 1)

        return {
            "lockout_threshold": raw["lockoutThreshold"] or 0,
            "lockout_duration_minutes": to_minutes(raw["lockoutDuration"]) or 0,
            "lockout_observation_window_minutes": to_minutes(raw["lockOutObservationWindow"]) or 0,
            "min_password_length": raw["minPwdLength"] or 0,
            "password_history_length": raw["pwdHistoryLength"] or 0,
            "min_password_age_minutes": to_minutes(raw["minPwdAge"]) or 0,
            "max_password_age_minutes": to_minutes(raw["maxPwdAge"]) or 0,
            "complexity_enabled": complexity_enabled,
            "raw": {k: raw_value(v) for k, v in raw.items()},
        }


# ---------------------------------------------------------------------------
# CLI Interface
# ---------------------------------------------------------------------------


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
    """
    Open an ADConnection from parsed CLI arguments.

    This consolidates repeated connection banner and common setup logic across subcommands.
    """
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