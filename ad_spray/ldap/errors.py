"""AD error code mappings and parsing utilities."""

import re
from typing import Optional

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
