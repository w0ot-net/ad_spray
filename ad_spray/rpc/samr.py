"""SAMR RPC functions for null-session AD enumeration."""

from typing import List

from impacket.dcerpc.v5 import samr, transport
from impacket.smbconnection import SMBConnection

from ..constants import to_minutes
from ..models import DomainPolicy


def _connect(dc_host: str, port: int):
    """Establish a null SMB session and bind to the SAMR pipe.

    Returns (dce, domain_handle) for the first non-Builtin domain.
    """
    smb = SMBConnection(dc_host, dc_host, sess_port=port)
    smb.login("", "")

    rpc = transport.SMBTransport(dc_host, filename=r"\samr", smb_connection=smb)
    dce = rpc.get_dce_rpc()
    dce.connect()
    dce.bind(samr.MSRPC_UUID_SAMR)

    # Open server -> find the real domain (skip Builtin)
    server_handle = samr.hSamrConnect(dce)["ServerHandle"]
    domains = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
    domain_name = None
    for entry in domains["Buffer"]["Buffer"]:
        name = entry["Name"]
        if name.upper() != "BUILTIN":
            domain_name = name
            break
    if domain_name is None:
        raise RuntimeError("No non-Builtin domain found via SAMR")

    domain_sid = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)["DomainId"]
    domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)["DomainHandle"]
    return dce, domain_handle


def _ndrhyper_to_minutes(value) -> int:
    """Convert an NDRHYPER duration field (100-ns intervals, negative) to minutes."""
    raw = value["Data"] if hasattr(value, "__getitem__") else int(value)
    return to_minutes(raw) or 0


def fetch_policy_rpc(dc_host: str, port: int = 445) -> DomainPolicy:
    """Fetch domain password/lockout policy via SAMR null session."""
    dce, domain_handle = _connect(dc_host, port)

    # Password info (level 1)
    pwd_info = samr.hSamrQueryInformationDomain(
        dce, domain_handle,
        domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation,
    )["Buffer"]["Buffer"]

    min_pwd_length = pwd_info["MinPasswordLength"]
    pwd_properties = pwd_info["PasswordProperties"]
    complexity_enabled = bool(pwd_properties & 1)

    # Lockout info (level 12)
    lockout_info = samr.hSamrQueryInformationDomain(
        dce, domain_handle,
        domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation,
    )["Buffer"]["Buffer"]

    lockout_threshold = lockout_info["LockoutThreshold"]
    lockout_duration = _ndrhyper_to_minutes(lockout_info["LockoutDuration"])
    observation_window = _ndrhyper_to_minutes(lockout_info["LockoutObservationWindow"])

    return DomainPolicy(
        lockout_threshold=lockout_threshold,
        lockout_duration_minutes=lockout_duration,
        lockout_observation_window_minutes=observation_window,
        min_password_length=min_pwd_length,
        complexity_enabled=complexity_enabled,
    )


def fetch_users_rpc(dc_host: str, port: int = 445) -> List[str]:
    """Enumerate domain users via SAMR null session.

    Uses UF_NORMAL_ACCOUNT (0x10) mask to exclude machine accounts.
    """
    dce, domain_handle = _connect(dc_host, port)

    users = []
    enumeration_context = 0
    while True:
        resp = samr.hSamrEnumerateUsersInDomain(
            dce, domain_handle,
            userAccountControl=samr.USER_NORMAL_ACCOUNT,
            enumerationContext=enumeration_context,
        )
        for entry in resp["Buffer"]["Buffer"]:
            users.append(entry["Name"])
        enumeration_context = resp["EnumerationContext"]
        # STATUS_MORE_ENTRIES = 0x00000105
        if resp["ErrorCode"] != 0x00000105:
            break

    return sorted(users)
