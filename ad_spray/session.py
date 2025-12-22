"""Session management for spray operations."""

import hashlib
import json
import os
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .constants import Colors, ERROR_SUCCESS, ERROR_ACCOUNT_DISABLED, DEFAULT_SESSION_PATH
from .ldap import ADConnection
from .models import PasswordPolicy, SprayConfig, SpraySession
from .scheduling import Schedule


def generate_session_id() -> str:
    """Generate a unique session ID."""
    data = f"{time.time()}-{os.getpid()}"
    return hashlib.md5(data.encode()).hexdigest()


def save_session(session: SpraySession, session_path: Path) -> None:
    """Save session to disk."""
    session_dir = session_path / session.config.session_id
    session_dir.mkdir(parents=True, exist_ok=True)
    with open(session_dir / "session.json", "w") as f:
        json.dump(session.to_dict(), f, indent=2)


def load_session(session_path: Path, session_id: str) -> SpraySession:
    """Load session from disk."""
    session_file = session_path / session_id / "session.json"
    if not session_file.exists():
        raise FileNotFoundError(f"Session not found: {session_id}")
    with open(session_file) as f:
        return SpraySession.from_dict(json.load(f))


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
) -> SpraySession:
    """Create a new spray session."""
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
    )

    return SpraySession(
        config=config,
        policy=policy,
        schedule=schedule,
        users=users,
        passwords=passwords,
    )


def list_sessions(session_path: Path) -> List[Dict[str, Any]]:
    """List all available sessions."""
    sessions = []
    if not session_path.exists():
        return sessions

    for session_dir in session_path.iterdir():
        if not session_dir.is_dir():
            continue
        try:
            session = load_session(session_path, session_dir.name)
            stats = session.get_stats()
            sessions.append({
                "session_id": session.config.session_id,
                "workgroup": session.config.workgroup,
                "dc_host": session.config.dc_host,
                "completed": session.config.completed,
                "created_at": session.config.created_at,
                "total": len(session.attempts),
                "valid": stats.get(ERROR_SUCCESS, 0),
                "disabled": stats.get(ERROR_ACCOUNT_DISABLED, 0),
            })
        except Exception:
            continue

    return sorted(sessions, key=lambda x: x["created_at"], reverse=True)


def delete_session(session_path: Path, session_id: str) -> bool:
    """Delete a session. Returns True if deleted, False if not found."""
    session_dir = session_path / session_id
    if not session_dir.exists():
        return False
    shutil.rmtree(session_dir)
    return True
