"""ADConnection class for LDAP operations."""

import ipaddress
from datetime import timedelta
from typing import Any, Dict, List, Optional

from ldap3 import ALL, BASE, NTLM, SUBTREE, Connection, Server


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
