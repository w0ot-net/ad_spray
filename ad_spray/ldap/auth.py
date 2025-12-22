"""Authentication checking functions."""

from typing import Any, Dict

from ldap3 import ALL, NTLM, Connection, Server
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError

from .errors import AD_ERROR_CODES, parse_ad_error_code


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
