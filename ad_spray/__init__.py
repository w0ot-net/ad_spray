"""
AD Spray - Active Directory Password Spraying Tool

A Python implementation of internal password spraying, using LDAP authentication
to test credentials against Active Directory.
"""

__version__ = "1.0.0"

from .constants import Colors, DEFAULT_SESSION_PATH
from .models import PasswordPolicy, Attempt, SprayConfig, SpraySession
from .scheduling import (
    TimeVerifier,
    TimeVerificationError,
    TimeVerificationResult,
    BusinessHoursWindow,
    Schedule,
    DAYS_OF_WEEK,
)
from .ldap import ADConnection, check_auth, AD_ERROR_CODES
from .engine import SprayEngine
from .session import (
    create_session,
    save_session,
    load_session,
    list_sessions,
    delete_session,
    fetch_domain_info,
    fetch_policy_only,
)
from .config import load_config, generate_config_file
from .policy import password_meets_policy, password_contains_username
from .storage import SessionStore, SessionManager, AttemptRecord, SessionState, SessionMetadata
from .cli import main

__all__ = [
    # Version
    "__version__",
    # Constants
    "Colors",
    "DEFAULT_SESSION_PATH",
    # Models
    "PasswordPolicy",
    "Attempt",
    "SprayConfig",
    "SpraySession",
    # Scheduling
    "TimeVerifier",
    "TimeVerificationError",
    "TimeVerificationResult",
    "BusinessHoursWindow",
    "Schedule",
    "DAYS_OF_WEEK",
    # LDAP
    "ADConnection",
    "check_auth",
    "AD_ERROR_CODES",
    # Engine
    "SprayEngine",
    # Session
    "create_session",
    "save_session",
    "load_session",
    "list_sessions",
    "delete_session",
    "fetch_domain_info",
    "fetch_policy_only",
    # Config
    "load_config",
    "generate_config_file",
    # Policy
    "password_meets_policy",
    "password_contains_username",
    # CLI
    "main",
]
