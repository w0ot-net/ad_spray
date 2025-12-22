"""Password policy validation utilities."""

from typing import Tuple, Optional

from .models import PasswordPolicy


def password_meets_policy(
    password: str,
    policy: PasswordPolicy,
    username: str = None
) -> Tuple[bool, Optional[str]]:
    """
    Check if a password meets the policy requirements.

    Args:
        password: The password to check
        policy: The password policy to check against
        username: Optional username to check for inclusion in password

    Returns:
        Tuple of (meets_policy: bool, reason: str or None)
    """
    # Check minimum length
    if len(password) < policy.min_password_length:
        return False, f"below min length ({policy.min_password_length})"

    # Check complexity if enabled
    if policy.complexity_enabled:
        # Must contain characters from at least 3 of 4 categories
        categories = 0
        if any(c.isupper() for c in password):
            categories += 1
        if any(c.islower() for c in password):
            categories += 1
        if any(c.isdigit() for c in password):
            categories += 1
        if any(not c.isalnum() for c in password):
            categories += 1

        if categories < 3:
            return False, "doesn't meet complexity (need 3 of: upper, lower, digit, special)"

        # Cannot contain username (case-insensitive)
        # Note: Windows also checks display name tokens, but we don't have display names
        if username and len(username) > 2:
            if username.lower() in password.lower():
                return False, "contains username"

    return True, None


def password_contains_username(
    password: str,
    username: str,
    policy: PasswordPolicy
) -> bool:
    """
    Check if password contains username (case-insensitive).

    Windows complexity rule: password cannot contain the sAMAccountName.
    Note: The "3+ char token" rule applies to display name tokens, not username.
    Since we don't have display names, we only check for full username.

    Args:
        password: The password to check
        username: The username to check for
        policy: The password policy (used to check if complexity is enabled)

    Returns:
        True if password contains username and complexity is enabled
    """
    if not policy.complexity_enabled:
        return False
    if len(username) <= 2:
        return False

    return username.lower() in password.lower()
