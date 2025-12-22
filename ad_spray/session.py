"""Session management for spray operations."""

import hashlib
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .constants import Colors, DEFAULT_SESSION_PATH
from .ldap import ADConnection
from .models import PasswordPolicy, SprayConfig, SpraySession
from .scheduling import Schedule
from .storage import (
    SessionStore,
    SessionManager,
    SessionState,
    AttemptRecord,
    SessionMetadata,
    migrate_old_session,
)


def generate_session_id() -> str:
    """Generate a unique session ID."""
    data = f"{time.time()}-{os.getpid()}-{os.urandom(8).hex()}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def create_session(
    dc_host: str,
    workgroup: str,
    users: List[str],
    passwords: List[str],
    policy: PasswordPolicy,
    schedule: Schedule,
    user_as_pass: bool = False,
    use_ssl: bool = False,
    port: Optional[int] = None,
    output_file: Optional[str] = None,
    verbose: int = 3,
    name: Optional[str] = None,
    tags: Optional[List[str]] = None,
    session_path: Path = DEFAULT_SESSION_PATH,
) -> SpraySession:
    """Create a new spray session with the new storage format."""
    session_id = generate_session_id()

    config = SprayConfig(
        session_id=session_id,
        dc_host=dc_host,
        workgroup=workgroup,
        use_ssl=use_ssl,
        port=port,
        output_file=output_file,
        verbose=verbose,
        user_as_pass=user_as_pass,
        created_at=datetime.now().isoformat(),
        name=name,
        tags=tags or [],
    )

    # Create session using new storage format
    store = SessionStore(session_path, session_id)
    store.create(
        config=config.to_dict(),
        policy=policy.to_dict(),
        schedule=schedule.to_dict(),
        users=users,
        passwords=passwords,
    )

    # Return a SpraySession object for compatibility
    return SpraySession(
        config=config,
        policy=policy,
        schedule=schedule,
        users=users,
        passwords=passwords,
    )


def load_session(session_path: Path, session_id: str) -> SpraySession:
    """Load session from new storage format."""
    store = SessionStore(session_path, session_id)

    if not store.exists():
        # Try to find and migrate old format
        old_session_file = session_path / session_id / 'session.json'
        if old_session_file.exists():
            migrated_id = migrate_old_session(session_path / session_id, session_path)
            if migrated_id:
                store = SessionStore(session_path, migrated_id)
            else:
                raise FileNotFoundError(f"Session not found: {session_id}")
        else:
            raise FileNotFoundError(f"Session not found: {session_id}")

    config = SprayConfig.from_dict(store.load_config())
    policy = PasswordPolicy.from_dict(store.load_policy())
    schedule = Schedule.from_dict(store.load_schedule())
    users = store.load_users()
    passwords = store.load_passwords()
    state = store.load_state()
    attempts = store.load_all_attempts()

    # Convert AttemptRecord to Attempt for compatibility
    from .models import Attempt
    attempt_list = [
        Attempt(
            username=a.username,
            password=a.password,
            status=a.status,
            timestamp=a.timestamp,
        )
        for a in attempts
    ]

    # Update config.completed from state
    config.completed = state.completed

    return SpraySession(
        config=config,
        policy=policy,
        schedule=schedule,
        users=users,
        passwords=passwords,
        attempts=attempt_list,
        skipped_users=state.skipped_users,
        skipped_passwords=state.skipped_passwords,
        current_password_index=state.current_password_index,
        attempts_since_sleep=state.attempts_since_sleep,
    )


def save_session(session: SpraySession, session_path: Path) -> None:
    """Save session state (not attempts - those are appended individually)."""
    store = SessionStore(session_path, session.config.session_id)

    state = SessionState(
        current_password_index=session.current_password_index,
        attempts_since_sleep=session.attempts_since_sleep,
        skipped_users=session.skipped_users,
        skipped_passwords=session.skipped_passwords,
        completed=session.config.completed,
    )
    store.save_state(state)


def save_attempt(
    session_id: str,
    username: str,
    password: str,
    status: str,
    session_path: Path = DEFAULT_SESSION_PATH,
) -> None:
    """Append a single attempt to the session (fast, append-only)."""
    store = SessionStore(session_path, session_id)
    attempt = AttemptRecord(
        username=username,
        password=password,
        status=status,
        timestamp=datetime.now().isoformat(),
    )
    store.append_attempt(attempt)


def list_sessions(session_path: Path) -> List[Dict[str, Any]]:
    """List all available sessions with cached metadata."""
    manager = SessionManager(session_path)
    sessions = manager.list_sessions()

    # Convert to dict format for compatibility
    return [
        {
            "session_id": s.session_id,
            "name": s.name,
            "tags": s.tags,
            "workgroup": s.workgroup,
            "dc_host": s.dc_host,
            "completed": s.completed,
            "created_at": s.created_at,
            "total": s.total_attempts,
            "valid": s.valid_count,
            "disabled": s.disabled_count,
            "locked": s.locked_count,
            "users": s.total_users,
            "passwords": s.total_passwords,
        }
        for s in sessions
    ]


def delete_session(session_path: Path, session_id: str) -> bool:
    """Delete a session. Returns True if deleted, False if not found."""
    manager = SessionManager(session_path)
    return manager.delete_session(session_id)


def get_session_store(session_path: Path, session_id: str) -> SessionStore:
    """Get a SessionStore for direct access to session files."""
    return SessionStore(session_path, session_id)


def update_session_metadata(session_path: Path, session_id: str) -> None:
    """Update the cached metadata for a session."""
    store = SessionStore(session_path, session_id)
    store.update_metadata()


def mark_session_completed(session_path: Path, session_id: str) -> None:
    """Mark a session as completed."""
    store = SessionStore(session_path, session_id)
    store.mark_completed()


# ---------------------------------------------------------------------------
# AD Fetch Functions (unchanged)
# ---------------------------------------------------------------------------

def fetch_domain_info(
    dc_host: str,
    username: str,
    password: str,
    workgroup: str,
    use_ssl: bool = False,
    port: Optional[int] = None,
    base_dn: Optional[str] = None,
    verbose: int = 3,
) -> tuple:
    """
    Connect to AD and fetch users and policy.
    Returns (users, policy) tuple.
    """
    def _print(msg: str, level: int = 3):
        if verbose >= level:
            print(msg, file=sys.stderr)

    _print(f"{Colors.BLUE}[+] Connecting to {dc_host}...{Colors.NC}", level=1)

    with ADConnection(
        dc_host=dc_host,
        username=username,
        password=password,
        workgroup=workgroup,
        base_dn=base_dn,
        use_ssl=use_ssl,
        port=port,
    ) as ad:
        _print(f"{Colors.BLUE}[+] Connected. Base DN: {ad.base_dn}{Colors.NC}", level=2)

        # Fetch users
        _print(f"{Colors.BLUE}[+] Enumerating users...{Colors.NC}", level=1)
        users = ad.get_users()
        _print(f"{Colors.GREEN}[+] Found {len(users)} users{Colors.NC}", level=1)

        # Fetch lockout policy
        _print(f"{Colors.BLUE}[+] Fetching lockout policy...{Colors.NC}", level=1)
        policy_dict = ad.get_lockout_policy()
        policy = PasswordPolicy.from_dict(policy_dict)

        _print(f"{Colors.GREEN}[+] Lockout threshold: {policy.lockout_threshold}{Colors.NC}", level=1)
        _print(f"{Colors.GREEN}[+] Observation window: {policy.lockout_observation_window_minutes} min{Colors.NC}", level=1)
        _print(f"{Colors.GREEN}[+] Min password length: {policy.min_password_length}{Colors.NC}", level=1)
        _print(f"{Colors.GREEN}[+] Complexity required: {policy.complexity_enabled}{Colors.NC}", level=1)

        return users, policy


def fetch_policy_only(
    dc_host: str,
    username: str,
    password: str,
    workgroup: str,
    use_ssl: bool = False,
    port: Optional[int] = None,
    base_dn: Optional[str] = None,
    verbose: int = 3,
) -> PasswordPolicy:
    """
    Connect to AD and fetch only the policy.
    Returns PasswordPolicy.
    """
    def _print(msg: str, level: int = 3):
        if verbose >= level:
            print(msg, file=sys.stderr)

    _print(f"{Colors.BLUE}[+] Connecting to {dc_host} for policy...{Colors.NC}", level=1)

    with ADConnection(
        dc_host=dc_host,
        username=username,
        password=password,
        workgroup=workgroup,
        base_dn=base_dn,
        use_ssl=use_ssl,
        port=port,
    ) as ad:
        _print(f"{Colors.BLUE}[+] Fetching lockout policy...{Colors.NC}", level=1)
        policy_dict = ad.get_lockout_policy()
        policy = PasswordPolicy.from_dict(policy_dict)

        _print(f"{Colors.GREEN}[+] Lockout threshold: {policy.lockout_threshold}{Colors.NC}", level=1)
        _print(f"{Colors.GREEN}[+] Observation window: {policy.lockout_observation_window_minutes} min{Colors.NC}", level=1)
        _print(f"{Colors.GREEN}[+] Min password length: {policy.min_password_length}{Colors.NC}", level=1)
        _print(f"{Colors.GREEN}[+] Complexity required: {policy.complexity_enabled}{Colors.NC}", level=1)

        return policy
