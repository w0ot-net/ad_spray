"""
Session storage with separate files for efficient I/O.

Directory structure:
    ~/.adspray/sessions/{session_id}/
    ├── config.json         # SprayConfig (immutable after creation)
    ├── policy.json         # PasswordPolicy (immutable)
    ├── schedule.json       # Schedule (immutable)
    ├── users.txt           # One username per line
    ├── passwords.txt       # One password per line
    ├── state.json          # Mutable state (current_password_index, skipped_*, etc.)
    ├── attempts.jsonl      # Append-only JSON Lines
    ├── valid_creds.txt     # Quick access to valid credentials
    ├── spray_log.txt       # Detailed spray output log
    └── meta.json           # Cached metadata for fast listing
"""

import fcntl
import json
import os
import platform
import shutil
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, Iterator, List, Optional, Set, Tuple

from .constants import ERROR_SUCCESS, ERROR_ACCOUNT_DISABLED, VALID_CREDENTIAL_STATUSES


# ---------------------------------------------------------------------------
# Atomic File Operations
# ---------------------------------------------------------------------------

def atomic_write_json(path: Path, data: Any, indent: int = 2) -> None:
    """Write JSON atomically using temp file + rename."""
    temp_path = path.with_suffix('.tmp')
    try:
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        temp_path.rename(path)
    except Exception:
        if temp_path.exists():
            temp_path.unlink()
        raise


def atomic_write_text(path: Path, content: str) -> None:
    """Write text atomically using temp file + rename."""
    temp_path = path.with_suffix('.tmp')
    try:
        with open(temp_path, 'w', encoding='utf-8') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        temp_path.rename(path)
    except Exception:
        if temp_path.exists():
            temp_path.unlink()
        raise


def atomic_write_lines(path: Path, lines: List[str]) -> None:
    """Write lines atomically."""
    atomic_write_text(path, '\n'.join(lines) + '\n' if lines else '')


def append_jsonl(path: Path, obj: Dict[str, Any]) -> None:
    """Append a single JSON object as a line to a JSONL file."""
    with open(path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(obj, separators=(',', ':')) + '\n')
        f.flush()
        os.fsync(f.fileno())


def read_jsonl(path: Path) -> Iterator[Dict[str, Any]]:
    """Read JSONL file as iterator of dicts."""
    if not path.exists():
        return
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def count_jsonl_lines(path: Path) -> int:
    """Count lines in JSONL file without loading all into memory."""
    if not path.exists():
        return 0
    count = 0
    with open(path, 'r', encoding='utf-8') as f:
        for _ in f:
            count += 1
    return count


# ---------------------------------------------------------------------------
# File Locking (Unix only, no-op on Windows)
# ---------------------------------------------------------------------------

@contextmanager
def session_lock(session_dir: Path) -> Generator[None, None, None]:
    """Acquire exclusive lock on session directory."""
    if platform.system() == 'Windows':
        # Windows doesn't support fcntl, skip locking
        yield
        return

    lock_file = session_dir / '.lock'
    session_dir.mkdir(parents=True, exist_ok=True)

    with open(lock_file, 'w') as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError(f"Session {session_dir.name} is locked by another process")
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


# ---------------------------------------------------------------------------
# Data Classes for New Structure
# ---------------------------------------------------------------------------

@dataclass
class AttemptRecord:
    """Compact attempt record for JSONL storage."""
    username: str
    password: str
    status: str
    timestamp: str

    def to_jsonl_dict(self) -> Dict[str, str]:
        """Compact representation for JSONL."""
        return {
            'u': self.username,
            'p': self.password,
            's': self.status,
            't': self.timestamp,
        }

    @classmethod
    def from_jsonl_dict(cls, d: Dict[str, str]) -> 'AttemptRecord':
        return cls(
            username=d['u'],
            password=d['p'],
            status=d['s'],
            timestamp=d['t'],
        )

    def to_full_dict(self) -> Dict[str, str]:
        """Full representation for compatibility."""
        return {
            'username': self.username,
            'password': self.password,
            'status': self.status,
            'timestamp': self.timestamp,
        }


@dataclass
class SessionState:
    """Mutable session state (saved frequently)."""
    current_password_index: int = 0
    attempts_since_sleep: int = 0
    skipped_users: Set[str] = field(default_factory=set)
    skipped_passwords: Set[str] = field(default_factory=set)
    completed: bool = False
    last_updated: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'current_password_index': self.current_password_index,
            'attempts_since_sleep': self.attempts_since_sleep,
            'skipped_users': sorted(self.skipped_users),
            'skipped_passwords': sorted(self.skipped_passwords),
            'completed': self.completed,
            'last_updated': self.last_updated,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'SessionState':
        return cls(
            current_password_index=d.get('current_password_index', 0),
            attempts_since_sleep=d.get('attempts_since_sleep', 0),
            skipped_users=set(d.get('skipped_users', [])),
            skipped_passwords=set(d.get('skipped_passwords', [])),
            completed=d.get('completed', False),
            last_updated=d.get('last_updated'),
        )


@dataclass
class SessionMetadata:
    """Cached metadata for fast session listing."""
    session_id: str
    name: Optional[str]
    workgroup: str
    dc_host: str
    created_at: str
    completed: bool
    total_users: int
    total_passwords: int
    total_attempts: int
    valid_count: int
    disabled_count: int
    locked_count: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'SessionMetadata':
        return cls(**d)


# ---------------------------------------------------------------------------
# Session Store
# ---------------------------------------------------------------------------

class SessionStore:
    """
    Handles all session file I/O operations.

    Usage:
        store = SessionStore(session_path, session_id)

        # Create new session
        store.create(config, policy, schedule, users, passwords)

        # Load existing session
        config = store.load_config()
        state = store.load_state()

        # Append attempt (fast, append-only)
        store.append_attempt(attempt)

        # Update state (small file, atomic write)
        store.save_state(state)
    """

    def __init__(self, base_path: Path, session_id: str):
        self.base_path = Path(base_path)
        self.session_id = session_id
        self.session_dir = self.base_path / session_id

    @property
    def config_path(self) -> Path:
        return self.session_dir / 'config.json'

    @property
    def policy_path(self) -> Path:
        return self.session_dir / 'policy.json'

    @property
    def schedule_path(self) -> Path:
        return self.session_dir / 'schedule.json'

    @property
    def users_path(self) -> Path:
        return self.session_dir / 'users.txt'

    @property
    def passwords_path(self) -> Path:
        return self.session_dir / 'passwords.txt'

    @property
    def state_path(self) -> Path:
        return self.session_dir / 'state.json'

    @property
    def attempts_path(self) -> Path:
        return self.session_dir / 'attempts.jsonl'

    @property
    def valid_creds_path(self) -> Path:
        return self.session_dir / 'valid_creds.txt'

    @property
    def log_path(self) -> Path:
        return self.session_dir / 'spray_log.txt'

    @property
    def meta_path(self) -> Path:
        return self.session_dir / 'meta.json'

    def exists(self) -> bool:
        """Check if session exists."""
        return self.session_dir.exists() and self.config_path.exists()

    def create(
        self,
        config: Dict[str, Any],
        policy: Dict[str, Any],
        schedule: Dict[str, Any],
        users: List[str],
        passwords: List[str],
    ) -> None:
        """Create a new session with all initial files."""
        self.session_dir.mkdir(parents=True, exist_ok=True)

        with session_lock(self.session_dir):
            # Write immutable config files
            atomic_write_json(self.config_path, config)
            atomic_write_json(self.policy_path, policy)
            atomic_write_json(self.schedule_path, schedule)

            # Write user/password lists
            atomic_write_lines(self.users_path, users)
            atomic_write_lines(self.passwords_path, passwords)

            # Initialize empty state
            initial_state = SessionState(last_updated=datetime.now().isoformat())
            atomic_write_json(self.state_path, initial_state.to_dict())

            # Create empty attempts file
            self.attempts_path.touch()

            # Create empty valid creds file
            self.valid_creds_path.touch()

            # Write initial metadata
            self._update_metadata()

    def load_config(self) -> Dict[str, Any]:
        """Load session config."""
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def load_policy(self) -> Dict[str, Any]:
        """Load password policy."""
        with open(self.policy_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def load_schedule(self) -> Dict[str, Any]:
        """Load schedule."""
        with open(self.schedule_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def load_users(self) -> List[str]:
        """Load user list."""
        if not self.users_path.exists():
            return []
        with open(self.users_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]

    def load_passwords(self) -> List[str]:
        """Load password list."""
        if not self.passwords_path.exists():
            return []
        with open(self.passwords_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]

    def load_state(self) -> SessionState:
        """Load mutable state."""
        if not self.state_path.exists():
            return SessionState()
        with open(self.state_path, 'r', encoding='utf-8') as f:
            return SessionState.from_dict(json.load(f))

    def save_state(self, state: SessionState) -> None:
        """Save mutable state atomically."""
        state.last_updated = datetime.now().isoformat()
        atomic_write_json(self.state_path, state.to_dict())

    def append_attempt(self, attempt: AttemptRecord) -> None:
        """Append a single attempt to the JSONL file."""
        append_jsonl(self.attempts_path, attempt.to_jsonl_dict())

        # Also append to valid_creds.txt if valid
        if attempt.status in VALID_CREDENTIAL_STATUSES:
            suffix = '' if attempt.status == ERROR_SUCCESS else f' # {attempt.status.replace("ERROR_", "")}'
            with open(self.valid_creds_path, 'a', encoding='utf-8') as f:
                f.write(f'{attempt.username}:{attempt.password}{suffix}\n')

    def iter_attempts(self) -> Iterator[AttemptRecord]:
        """Iterate over all attempts without loading into memory."""
        for d in read_jsonl(self.attempts_path):
            yield AttemptRecord.from_jsonl_dict(d)

    def load_all_attempts(self) -> List[AttemptRecord]:
        """Load all attempts into memory (for compatibility)."""
        return list(self.iter_attempts())

    def get_attempted_pairs(self) -> Set[Tuple[str, str]]:
        """Get set of (username, password) pairs already attempted."""
        return {(a.username, a.password) for a in self.iter_attempts()}

    def count_attempts(self) -> int:
        """Count total attempts without loading."""
        return count_jsonl_lines(self.attempts_path)

    def get_stats(self) -> Dict[str, int]:
        """Get attempt statistics by status."""
        stats: Dict[str, int] = {'total': 0}
        for attempt in self.iter_attempts():
            stats['total'] += 1
            stats[attempt.status] = stats.get(attempt.status, 0) + 1
        return stats

    def _update_metadata(self) -> None:
        """Update cached metadata file."""
        config = self.load_config()
        state = self.load_state()
        stats = self.get_stats()

        meta = SessionMetadata(
            session_id=self.session_id,
            name=config.get('name'),
            workgroup=config.get('workgroup', ''),
            dc_host=config.get('dc_host', ''),
            created_at=config.get('created_at', ''),
            completed=state.completed,
            total_users=len(self.load_users()),
            total_passwords=len(self.load_passwords()),
            total_attempts=stats.get('total', 0),
            valid_count=stats.get(ERROR_SUCCESS, 0),
            disabled_count=stats.get(ERROR_ACCOUNT_DISABLED, 0),
            locked_count=stats.get('ERROR_ACCOUNT_LOCKED_OUT', 0),
        )
        atomic_write_json(self.meta_path, meta.to_dict())

    def update_metadata(self) -> None:
        """Public method to update metadata."""
        self._update_metadata()

    def load_metadata(self) -> Optional[SessionMetadata]:
        """Load cached metadata (fast)."""
        if not self.meta_path.exists():
            return None
        try:
            with open(self.meta_path, 'r', encoding='utf-8') as f:
                return SessionMetadata.from_dict(json.load(f))
        except Exception:
            return None

    def mark_completed(self) -> None:
        """Mark session as completed and update metadata."""
        state = self.load_state()
        state.completed = True
        self.save_state(state)
        self._update_metadata()

    def delete(self) -> bool:
        """Delete this session. Returns True if deleted."""
        if not self.session_dir.exists():
            return False
        shutil.rmtree(self.session_dir)
        return True


# ---------------------------------------------------------------------------
# Session Manager (higher-level operations)
# ---------------------------------------------------------------------------

class SessionManager:
    """Manages multiple sessions."""

    def __init__(self, base_path: Path):
        self.base_path = Path(base_path)

    def get_store(self, session_id: str) -> SessionStore:
        """Get a store for a specific session."""
        return SessionStore(self.base_path, session_id)

    def list_sessions(self) -> List[SessionMetadata]:
        """List all sessions with cached metadata (fast)."""
        sessions = []
        if not self.base_path.exists():
            return sessions

        for session_dir in self.base_path.iterdir():
            if not session_dir.is_dir():
                continue

            store = SessionStore(self.base_path, session_dir.name)
            if not store.exists():
                continue

            # Try to load cached metadata first (fast)
            meta = store.load_metadata()
            if meta:
                sessions.append(meta)
            else:
                # Fall back to regenerating metadata
                try:
                    store.update_metadata()
                    meta = store.load_metadata()
                    if meta:
                        sessions.append(meta)
                except Exception:
                    continue

        return sorted(sessions, key=lambda x: x.created_at, reverse=True)

    def session_exists(self, session_id: str) -> bool:
        """Check if a session exists."""
        return self.get_store(session_id).exists()

    def delete_session(self, session_id: str) -> bool:
        """Delete a session."""
        return self.get_store(session_id).delete()


# ---------------------------------------------------------------------------
# Migration from Old Format
# ---------------------------------------------------------------------------

def migrate_old_session(old_session_path: Path, new_base_path: Path) -> Optional[str]:
    """
    Migrate a session from the old monolithic JSON format to the new structure.

    Args:
        old_session_path: Path to old session directory (containing session.json)
        new_base_path: Base path for new sessions

    Returns:
        New session ID if successful, None if failed
    """
    old_session_file = old_session_path / 'session.json'
    if not old_session_file.exists():
        return None

    try:
        with open(old_session_file, 'r', encoding='utf-8') as f:
            old_data = json.load(f)

        session_id = old_data['config']['session_id']
        store = SessionStore(new_base_path, session_id)

        if store.exists():
            # Already migrated
            return session_id

        # Extract components
        config = old_data['config']
        policy = old_data['policy']
        schedule = old_data.get('schedule', {'timezone': None, 'business_hours_reduction': 0, 'daily_hours': {}})
        users = old_data.get('users', [])
        passwords = old_data.get('passwords', [])
        attempts = old_data.get('attempts', [])
        skipped_users = set(old_data.get('skipped_users', []))
        skipped_passwords = set(old_data.get('skipped_passwords', []))

        # Create new session structure
        store.create(config, policy, schedule, users, passwords)

        # Write attempts
        for attempt_dict in attempts:
            attempt = AttemptRecord(
                username=attempt_dict['username'],
                password=attempt_dict['password'],
                status=attempt_dict.get('status', ''),
                timestamp=attempt_dict.get('timestamp', ''),
            )
            store.append_attempt(attempt)

        # Write state
        state = SessionState(
            current_password_index=old_data.get('current_password_index', 0),
            attempts_since_sleep=old_data.get('attempts_since_sleep', 0),
            skipped_users=skipped_users,
            skipped_passwords=skipped_passwords,
            completed=config.get('completed', False),
        )
        store.save_state(state)
        store.update_metadata()

        return session_id

    except Exception:
        return None
