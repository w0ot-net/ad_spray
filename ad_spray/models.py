"""Data models for spray sessions."""

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from .storage import SessionStore

from .scheduling import Schedule


@dataclass
class PasswordPolicy:
    """Domain password and lockout policy."""
    lockout_threshold: int  # 0 = no lockout
    lockout_duration_minutes: int
    lockout_observation_window_minutes: int
    min_password_length: int
    password_history_length: int
    complexity_enabled: bool  # Windows password complexity rules

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PasswordPolicy":
        return cls(
            lockout_threshold=d.get("lockout_threshold", 0),
            lockout_duration_minutes=d.get("lockout_duration_minutes", 30),
            lockout_observation_window_minutes=d.get("lockout_observation_window_minutes", 30),
            min_password_length=d.get("min_password_length", 0),
            password_history_length=d.get("password_history_length", 0),
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
    completed: bool = False
    name: Optional[str] = None  # Human-readable session name
    tags: List[str] = field(default_factory=list)  # Session tags for organization

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SprayConfig":
        # Handle missing fields for backward compatibility
        d = d.copy()
        d.setdefault('name', None)
        d.setdefault('tags', [])
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
        apply_schedule: bool = True,
        time_verifier: Optional[Any] = None
    ) -> int:
        """
        Calculate the maximum attempts per user within the observation window
        that won't trigger lockout.

        Args:
            apply_schedule: If True, apply business hours reduction if applicable
            time_verifier: Optional TimeVerifier to use for accurate time

        Returns:
            n-1 where n is the lockout threshold (possibly reduced for business hours).
            Returns 0 or negative if should pause entirely.
            e.g., threshold=5 -> 4 attempts allowed
                  threshold=1 -> 0 attempts (cannot spray safely!)
                  threshold=0 -> unlimited (no lockout policy)
        """
        if self.policy.lockout_threshold == 0:
            # No lockout policy
            return 100

        # Base: exactly n-1 to guarantee no lockout
        base_attempts = self.policy.lockout_threshold - 1

        # Apply schedule reduction if enabled and in business hours
        if apply_schedule and self.schedule.is_enabled():
            # Get current time from verifier if available, otherwise use system time
            if time_verifier:
                current_time = time_verifier.get_current_time(self.schedule.timezone)
                is_business, should_pause = self.schedule.get_current_status_with_time(current_time)
            else:
                is_business, should_pause = self.schedule.get_current_status()

            if should_pause:
                return 0  # Pause day
            if is_business:
                # During business hours: threshold - reduction
                # e.g., threshold=5, reduction=3 -> 2 attempts
                return self.schedule.get_reduced_attempts(self.policy.lockout_threshold)

        return base_attempts

    def get_sleep_time_seconds(self) -> int:
        """
        Get the sleep time needed between password batches.

        Returns m+1 minutes (in seconds) where m is the observation window.
        e.g., window=30 min -> sleep 31 min (1860 seconds)
        """
        if self.policy.lockout_threshold == 0:
            return 0

        # Exactly m+1 minutes to guarantee counter reset
        return (self.policy.lockout_observation_window_minutes + 1) * 60
