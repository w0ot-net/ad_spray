"""Data models for spray sessions."""

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from .storage import SessionStore

from .scheduling import Schedule


@dataclass
class PasswordPolicy:
    """Password filtering policy."""
    min_password_length: int
    complexity_enabled: bool  # Windows password complexity rules

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PasswordPolicy":
        return cls(
            min_password_length=d.get("min_password_length", 0),
            complexity_enabled=d.get("complexity_enabled", False),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Attempt:
    """A single credential attempt."""
    username: str
    password: str
    status: Optional[str] = None  # Microsoft error code string
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Attempt":
        return cls(**d)


@dataclass
class SprayConfig:
    """Configuration for a spray session."""
    session_id: str
    dc_host: str
    workgroup: str
    use_ssl: bool
    port: Optional[int]
    output_file: Optional[str]
    verbose: int
    user_as_pass: bool
    created_at: str
    name: str  # Human-readable session name (required)
    completed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SprayConfig":
        return cls(**d)


@dataclass
class SpraySession:
    """A complete spray session with config, attempts, and policy."""
    config: SprayConfig
    policy: PasswordPolicy
    schedule: Schedule = field(default_factory=Schedule.disabled)
    users: List[str] = field(default_factory=list)
    passwords: List[str] = field(default_factory=list)
    attempts: List[Attempt] = field(default_factory=list)
    skipped_users: Set[str] = field(default_factory=set)
    skipped_passwords: Set[str] = field(default_factory=set)
    current_password_index: int = 0
    attempts_since_sleep: int = 0
    # Spray timing settings
    lockout_window: int = 30  # minutes
    attempts_allowed: int = 1  # attempts per window (non-business hours / no schedule)
    attempts_allowed_business: int = 0  # attempts during business hours (0 = pause)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "config": self.config.to_dict(),
            "policy": self.policy.to_dict(),
            "schedule": self.schedule.to_dict(),
            "users": self.users,
            "passwords": self.passwords,
            "attempts": [a.to_dict() for a in self.attempts],
            "skipped_users": list(self.skipped_users),
            "skipped_passwords": list(self.skipped_passwords),
            "current_password_index": self.current_password_index,
            "attempts_since_sleep": self.attempts_since_sleep,
            "lockout_window": self.lockout_window,
            "attempts_allowed": self.attempts_allowed,
            "attempts_allowed_business": self.attempts_allowed_business,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SpraySession":
        return cls(
            config=SprayConfig.from_dict(d["config"]),
            policy=PasswordPolicy.from_dict(d["policy"]),
            schedule=Schedule.from_dict(d["schedule"]) if "schedule" in d else Schedule.disabled(),
            users=d.get("users", []),
            passwords=d.get("passwords", []),
            attempts=[Attempt.from_dict(a) for a in d.get("attempts", [])],
            skipped_users=set(d.get("skipped_users", [])),
            skipped_passwords=set(d.get("skipped_passwords", [])),
            current_password_index=d.get("current_password_index", 0),
            attempts_since_sleep=d.get("attempts_since_sleep", 0),
            lockout_window=d.get("lockout_window", 30),
            attempts_allowed=d.get("attempts_allowed", 1),
            attempts_allowed_business=d.get("attempts_allowed_business", 0),
        )

    def get_stats(self) -> Dict[str, int]:
        """Get statistics about the session."""
        stats: Dict[str, int] = {"total": len(self.attempts), "pending": 0}
        for attempt in self.attempts:
            if attempt.status is None:
                stats["pending"] = stats.get("pending", 0) + 1
            else:
                stats[attempt.status] = stats.get(attempt.status, 0) + 1
        return stats

    def get_safe_attempts_per_window(
        self,
        time_verifier: Optional[Any] = None
    ) -> int:
        """
        Get the number of attempts allowed per observation window.

        Args:
            time_verifier: Optional TimeVerifier to use for accurate time

        Returns:
            Number of attempts allowed. Returns 0 if should pause.
        """
        # If schedule is enabled, check if we're in business hours
        if self.schedule.is_enabled():
            if time_verifier:
                current_time = time_verifier.get_current_time(self.schedule.timezone)
                is_business, should_pause = self.schedule.get_current_status_with_time(current_time)
            else:
                is_business, should_pause = self.schedule.get_current_status()

            if should_pause:
                return 0
            if is_business:
                return self.attempts_allowed_business

        return self.attempts_allowed

    def get_sleep_time_seconds(self) -> int:
        """
        Get the sleep time needed between password batches.

        Returns (lockout_window + 1) minutes in seconds.
        e.g., window=30 min -> sleep 31 min (1860 seconds)
        """
        return (self.lockout_window + 1) * 60
