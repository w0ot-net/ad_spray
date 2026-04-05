"""SMB-based authentication checking via impacket."""

from typing import Any, Dict

from impacket.smbconnection import SMBConnection, SessionError

from ..constants import (
    ERROR_SUCCESS,
    ERROR_LOGON_FAILURE,
    ERROR_ACCOUNT_DISABLED,
    ERROR_ACCOUNT_LOCKED_OUT,
    ERROR_PASSWORD_EXPIRED,
    ERROR_PASSWORD_MUST_CHANGE,
    ERROR_ACCOUNT_EXPIRED,
    ERROR_INVALID_LOGON_HOURS,
    ERROR_INVALID_WORKSTATION,
    ERROR_LOGON_TYPE_NOT_GRANTED,
    ERROR_HOST_UNREACHABLE,
    ERROR_GEN_FAILURE,
)

# NT status code → our ERROR_* constant
# Reference: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-25e5c5eb9b46
NT_STATUS_MAP = {
    0xC000006D: ERROR_LOGON_FAILURE,           # STATUS_LOGON_FAILURE
    0xC0000072: ERROR_ACCOUNT_DISABLED,        # STATUS_ACCOUNT_DISABLED
    0xC0000234: ERROR_ACCOUNT_LOCKED_OUT,      # STATUS_ACCOUNT_LOCKED_OUT
    0xC0000071: ERROR_PASSWORD_EXPIRED,        # STATUS_PASSWORD_EXPIRED
    0xC0000224: ERROR_PASSWORD_MUST_CHANGE,    # STATUS_PASSWORD_MUST_CHANGE
    0xC0000193: ERROR_ACCOUNT_EXPIRED,         # STATUS_ACCOUNT_EXPIRED
    0xC000006F: ERROR_INVALID_LOGON_HOURS,     # STATUS_INVALID_LOGON_HOURS
    0xC0000070: ERROR_INVALID_WORKSTATION,     # STATUS_INVALID_WORKSTATION
    0xC000015B: ERROR_LOGON_TYPE_NOT_GRANTED,  # STATUS_LOGON_TYPE_NOT_GRANTED
    # STATUS_NO_SUCH_USER → LOGON_FAILURE (not NO_SUCH_USER) to avoid
    # unreliable user-skip signal over SMB
    0xC0000064: ERROR_LOGON_FAILURE,           # STATUS_NO_SUCH_USER
}


def check_auth(
    dc_host: str,
    username: str,
    password: str,
    workgroup: str = "",
    port: int = 445,
) -> Dict[str, Any]:
    """
    Attempt SMB authentication against a domain controller.

    Args:
        dc_host: Domain controller FQDN or IP address
        username: Username to test (with or without domain prefix)
        password: Password to test
        workgroup: NetBIOS domain/workgroup name
        port: SMB port (default: 445)

    Returns:
        Dictionary with success, status, status_code, message keys.
    """
    # Strip domain prefixes (DOMAIN\user or user@domain)
    if "\\" in username:
        username = username.partition("\\")[2]
    else:
        username = username.partition("@")[0] or username

    smb = None
    try:
        smb = SMBConnection(dc_host, dc_host, sess_port=port)
        smb.login(username, password, domain=workgroup)
        return {
            "success": True,
            "status": ERROR_SUCCESS,
            "status_code": 0,
            "message": "Authentication successful",
        }
    except SessionError as e:
        nt_code = e.getErrorCode()
        status = NT_STATUS_MAP.get(nt_code, ERROR_LOGON_FAILURE)
        return {
            "success": False,
            "status": status,
            "status_code": nt_code,
            "message": f"Authentication failed: {status}",
            "raw_error": str(e),
        }
    except OSError as e:
        return {
            "success": False,
            "status": ERROR_HOST_UNREACHABLE,
            "status_code": None,
            "message": f"Could not connect to {dc_host}:{port}",
            "raw_error": str(e),
        }
    except Exception as e:
        return {
            "success": False,
            "status": ERROR_GEN_FAILURE,
            "status_code": None,
            "message": f"Unexpected error: {e}",
            "raw_error": str(e),
        }
    finally:
        if smb is not None:
            try:
                smb.close()
            except Exception:
                pass
