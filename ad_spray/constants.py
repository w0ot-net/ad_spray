"""Constants used throughout the application."""

from pathlib import Path


class Colors:
    """ANSI color codes for terminal output."""
    NC = '\033[0m'
    RED = '\033[0;31m'
    BLUE = '\033[0;34m'
    GREEN = '\033[0;32m'
    LBLUE = '\033[1;34m'
    ORANGE = '\033[0;33m'

    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY output)."""
        cls.NC = cls.RED = cls.BLUE = cls.GREEN = cls.LBLUE = cls.ORANGE = ''


# Microsoft Win32 Error Codes - used directly, no custom mapping
# Reference: https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes
ERROR_SUCCESS = "ERROR_SUCCESS"
ERROR_NO_SUCH_USER = "ERROR_NO_SUCH_USER"
ERROR_LOGON_FAILURE = "ERROR_LOGON_FAILURE"
ERROR_INVALID_LOGON_HOURS = "ERROR_INVALID_LOGON_HOURS"
ERROR_INVALID_WORKSTATION = "ERROR_INVALID_WORKSTATION"
ERROR_PASSWORD_EXPIRED = "ERROR_PASSWORD_EXPIRED"
ERROR_ACCOUNT_DISABLED = "ERROR_ACCOUNT_DISABLED"
ERROR_LOGON_TYPE_NOT_GRANTED = "ERROR_LOGON_TYPE_NOT_GRANTED"
ERROR_ACCOUNT_EXPIRED = "ERROR_ACCOUNT_EXPIRED"
ERROR_PASSWORD_MUST_CHANGE = "ERROR_PASSWORD_MUST_CHANGE"
ERROR_ACCOUNT_LOCKED_OUT = "ERROR_ACCOUNT_LOCKED_OUT"
ERROR_HOST_UNREACHABLE = "ERROR_HOST_UNREACHABLE"
ERROR_GEN_FAILURE = "ERROR_GEN_FAILURE"

# Statuses that indicate valid credentials (even if account has issues)
VALID_CREDENTIAL_STATUSES = {
    ERROR_SUCCESS,
    ERROR_ACCOUNT_DISABLED,
    ERROR_PASSWORD_EXPIRED,
    ERROR_PASSWORD_MUST_CHANGE,
    ERROR_ACCOUNT_EXPIRED,
    ERROR_INVALID_LOGON_HOURS,
    ERROR_INVALID_WORKSTATION,
    ERROR_LOGON_TYPE_NOT_GRANTED,
}

# Statuses that should cause a user to be skipped for remaining attempts
SKIP_USER_STATUSES = {
    ERROR_SUCCESS,
    ERROR_ACCOUNT_DISABLED,
    ERROR_ACCOUNT_LOCKED_OUT,
    ERROR_ACCOUNT_EXPIRED,
    ERROR_NO_SUCH_USER,
}

# Default session storage path
DEFAULT_SESSION_PATH = Path.home() / ".adspray" / "sessions"
