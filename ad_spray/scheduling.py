"""Time verification and business hours scheduling."""

import json
import sys
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, time as dt_time
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

# Days of week for schedule parsing
DAYS_OF_WEEK = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']

# External time sources for verification
EXTERNAL_TIME_SOURCES = [
    # Primary: Major tech companies with reliable servers
    ("https://www.google.com", "Google"),
    ("https://www.cloudflare.com", "Cloudflare"),
    ("https://www.microsoft.com", "Microsoft"),
    # Fallback: Time API
    ("https://worldtimeapi.org/api/ip", "WorldTimeAPI"),
]

# Maximum allowed drift between system time and external time (seconds)
MAX_TIME_DRIFT_SECONDS = 60

# How often to re-verify external time during spray (seconds)
TIME_REVERIFICATION_INTERVAL = 300  # 5 minutes


class TimeVerificationError(Exception):
    """Raised when external time cannot be verified."""
    pass


@dataclass
class TimeVerificationResult:
    """Result of time verification."""
    verified_time: datetime
    source: str
    system_time: datetime
    offset_seconds: float  # positive = system ahead, negative = system behind

    @property
    def drift_acceptable(self) -> bool:
        """Check if the drift is within acceptable limits."""
        return abs(self.offset_seconds) <= MAX_TIME_DRIFT_SECONDS


class TimeVerifier:
    """
    Verifies current time against external sources.

    This ensures the spray operates on accurate time, critical for
    respecting business hours schedules.
    """

    def __init__(self, force_system_time: bool = False, verbose: int = 3):
        self.force_system_time = force_system_time
        self.verbose = verbose
        self._offset_seconds: Optional[float] = None
        self._last_verification: Optional[datetime] = None
        self._source: Optional[str] = None
        self._verified = False

    def _print(self, message: str, level: int = 3):
        """Print message if verbosity level is high enough."""
        if self.verbose >= level:
            print(message, file=sys.stderr)

    def _fetch_http_time(self, url: str, source_name: str) -> Optional[datetime]:
        """
        Fetch time from HTTP Date header.

        Returns UTC datetime or None if failed.
        """
        try:
            req = urllib.request.Request(url, method='HEAD')
            req.add_header('User-Agent', 'ADSpray-TimeCheck/1.0')

            with urllib.request.urlopen(req, timeout=5) as response:
                date_header = response.headers.get('Date')
                if date_header:
                    # Parse RFC 2822 date format
                    return parsedate_to_datetime(date_header)
        except Exception:
            pass
        return None

    def _fetch_api_time(self, url: str) -> Optional[datetime]:
        """
        Fetch time from WorldTimeAPI.

        Returns UTC datetime or None if failed.
        """
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'ADSpray-TimeCheck/1.0')

            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode('utf-8'))
                # WorldTimeAPI returns ISO format datetime
                utc_datetime = data.get('utc_datetime')
                if utc_datetime:
                    # Parse ISO format, handle 'Z' suffix
                    utc_datetime = utc_datetime.replace('Z', '+00:00')
                    return datetime.fromisoformat(utc_datetime)
        except Exception:
            pass
        return None

    def verify(self) -> TimeVerificationResult:
        """
        Verify current time against external sources.

        Returns TimeVerificationResult with verified time.
        Raises TimeVerificationError if verification fails and not forcing system time.
        """
        system_time = datetime.now(ZoneInfo('UTC'))

        if self.force_system_time:
            self._verified = True
            self._offset_seconds = 0.0
            self._source = "System Clock (forced)"
            self._last_verification = system_time
            return TimeVerificationResult(
                verified_time=system_time,
                source=self._source,
                system_time=system_time,
                offset_seconds=0.0,
            )

        # Try each external source
        external_time: Optional[datetime] = None
        source_name: Optional[str] = None

        # Import Colors here to avoid circular import
        from .constants import Colors

        for url, name in EXTERNAL_TIME_SOURCES:
            self._print(f"{Colors.BLUE}[+] Checking time from {name}...{Colors.NC}", level=2)

            if 'worldtimeapi' in url:
                external_time = self._fetch_api_time(url)
            else:
                external_time = self._fetch_http_time(url, name)

            if external_time:
                source_name = name
                self._print(f"{Colors.GREEN}[+] Got time from {name}{Colors.NC}", level=2)
                break
            else:
                self._print(f"{Colors.ORANGE}[!] Failed to get time from {name}{Colors.NC}", level=2)

        if external_time is None:
            raise TimeVerificationError(
                "Could not verify time from any external source. "
                "Use --force-system-time to proceed with system clock (not recommended)."
            )

        # Ensure external_time is UTC
        if external_time.tzinfo is None:
            external_time = external_time.replace(tzinfo=ZoneInfo('UTC'))
        else:
            external_time = external_time.astimezone(ZoneInfo('UTC'))

        # Calculate offset
        offset = (system_time - external_time).total_seconds()

        self._verified = True
        self._offset_seconds = offset
        self._source = source_name
        self._last_verification = datetime.now()

        return TimeVerificationResult(
            verified_time=external_time,
            source=source_name,
            system_time=system_time,
            offset_seconds=offset,
        )

    def get_current_time(self, timezone: Optional[str] = None) -> datetime:
        """
        Get the current verified time.

        If timezone is provided, returns time in that timezone.
        Otherwise returns UTC.

        Re-verifies if the last verification was too long ago.
        """
        # Re-verify periodically
        if (self._last_verification is None or
            (datetime.now() - self._last_verification).total_seconds() > TIME_REVERIFICATION_INTERVAL):
            try:
                self.verify()
            except TimeVerificationError:
                if not self.force_system_time:
                    raise

        # Get system time and apply offset
        if self.force_system_time or self._offset_seconds is None:
            now_utc = datetime.now(ZoneInfo('UTC'))
        else:
            system_now = datetime.now(ZoneInfo('UTC'))
            # Subtract offset to get true time (offset is system - external)
            now_utc = system_now - timedelta(seconds=self._offset_seconds)

        if timezone:
            try:
                tz = ZoneInfo(timezone)
                return now_utc.astimezone(tz)
            except Exception:
                return now_utc

        return now_utc

    def needs_reverification(self) -> bool:
        """Check if time should be re-verified."""
        if self._last_verification is None:
            return True
        elapsed = (datetime.now() - self._last_verification).total_seconds()
        return elapsed > TIME_REVERIFICATION_INTERVAL

    @property
    def source(self) -> str:
        """Get the time source name."""
        return self._source or "Unknown"

    @property
    def is_verified(self) -> bool:
        """Check if time has been verified."""
        return self._verified


@dataclass
class BusinessHoursWindow:
    """Represents business hours for a single day."""
    start: Optional[dt_time]  # None means 'off' (no restrictions)
    end: Optional[dt_time]
    pause_all_day: bool = False  # True means 'pause' (no spraying this day)

    @classmethod
    def parse(cls, value: str) -> "BusinessHoursWindow":
        """Parse a business hours string like '09:00-17:00', 'off', or 'pause'."""
        value = value.strip().lower()

        if value == 'off' or value == '':
            return cls(start=None, end=None, pause_all_day=False)

        if value == 'pause':
            return cls(start=None, end=None, pause_all_day=True)

        if '-' not in value:
            raise ValueError(f"Invalid business hours format: {value}. Use HH:MM-HH:MM, 'off', or 'pause'")

        try:
            start_str, end_str = value.split('-')
            start_parts = start_str.strip().split(':')
            end_parts = end_str.strip().split(':')

            start = dt_time(int(start_parts[0]), int(start_parts[1]))
            end = dt_time(int(end_parts[0]), int(end_parts[1]))

            return cls(start=start, end=end, pause_all_day=False)
        except (ValueError, IndexError) as e:
            raise ValueError(f"Invalid business hours format: {value}. Use HH:MM-HH:MM format") from e

    def is_within_hours(self, current_time: dt_time) -> bool:
        """Check if the given time falls within business hours."""
        if self.pause_all_day:
            return True  # Treat pause days as "always in business hours" for reduction logic

        if self.start is None or self.end is None:
            return False  # 'off' means no business hours restriction

        # Handle overnight spans (e.g., 22:00-06:00)
        if self.start <= self.end:
            return self.start <= current_time <= self.end
        else:
            return current_time >= self.start or current_time <= self.end

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "pause_all_day": self.pause_all_day,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "BusinessHoursWindow":
        return cls(
            start=dt_time.fromisoformat(d["start"]) if d.get("start") else None,
            end=dt_time.fromisoformat(d["end"]) if d.get("end") else None,
            pause_all_day=d.get("pause_all_day", False),
        )


@dataclass
class Schedule:
    """Business hours schedule with timezone."""
    timezone: Optional[str]  # IANA timezone name, None means disabled
    business_hours_reduction: int
    daily_hours: Dict[str, BusinessHoursWindow]  # day name -> hours

    def is_enabled(self) -> bool:
        """Check if schedule feature is enabled."""
        return self.timezone is not None and self.timezone.strip() != ''

    def get_current_status(self) -> Tuple[bool, bool]:
        """
        Get current schedule status using system time.

        Returns:
            Tuple of (is_business_hours: bool, should_pause: bool)
        """
        if not self.is_enabled():
            return False, False

        try:
            tz = ZoneInfo(self.timezone)
        except Exception:
            return False, False

        now = datetime.now(tz)
        return self.get_current_status_with_time(now)

    def get_current_status_with_time(self, current_datetime: datetime) -> Tuple[bool, bool]:
        """
        Get schedule status for a specific time.

        Args:
            current_datetime: The datetime to check (should be in the schedule's timezone)

        Returns:
            Tuple of (is_business_hours: bool, should_pause: bool)
        """
        if not self.is_enabled():
            return False, False

        day_name = DAYS_OF_WEEK[current_datetime.weekday()]
        current_time = current_datetime.time()

        hours = self.daily_hours.get(day_name)
        if hours is None:
            return False, False

        if hours.pause_all_day:
            return True, True

        is_business = hours.is_within_hours(current_time)
        return is_business, False

    def get_reduced_attempts(self, lockout_threshold: int) -> int:
        """
        Calculate reduced attempts during business hours.

        Args:
            lockout_threshold: The lockout threshold from policy

        Returns:
            Reduced attempt count (may be 0 or negative, meaning pause)
            e.g., threshold=5, reduction=3 -> 2 attempts allowed
        """
        return lockout_threshold - self.business_hours_reduction

    def get_time_until_business_hours_end(self) -> Optional[int]:
        """
        Get seconds until business hours end using system time.

        Returns:
            Seconds until end, or None if not in business hours or schedule disabled
        """
        if not self.is_enabled():
            return None

        try:
            tz = ZoneInfo(self.timezone)
        except Exception:
            return None

        now = datetime.now(tz)
        return self.get_time_until_business_hours_end_with_time(now)

    def get_time_until_business_hours_end_with_time(self, current_datetime: datetime) -> Optional[int]:
        """
        Get seconds until business hours end for a specific time.

        Args:
            current_datetime: The datetime to check (should be in the schedule's timezone)

        Returns:
            Seconds until end, or None if not in business hours or schedule disabled
        """
        if not self.is_enabled():
            return None

        day_name = DAYS_OF_WEEK[current_datetime.weekday()]
        current_time = current_datetime.time()

        hours = self.daily_hours.get(day_name)
        if hours is None or hours.start is None:
            return None

        if hours.pause_all_day:
            # Calculate time until midnight
            tomorrow = current_datetime.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
            return int((tomorrow - current_datetime).total_seconds())

        if not hours.is_within_hours(current_time):
            return None

        # Calculate time until end
        end_dt = current_datetime.replace(hour=hours.end.hour, minute=hours.end.minute, second=0, microsecond=0)
        if end_dt <= current_datetime:
            end_dt += timedelta(days=1)

        return int((end_dt - current_datetime).total_seconds())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timezone": self.timezone,
            "business_hours_reduction": self.business_hours_reduction,
            "daily_hours": {k: v.to_dict() for k, v in self.daily_hours.items()},
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Schedule":
        return cls(
            timezone=d.get("timezone"),
            business_hours_reduction=d.get("business_hours_reduction", 3),
            daily_hours={k: BusinessHoursWindow.from_dict(v) for k, v in d.get("daily_hours", {}).items()},
        )

    @classmethod
    def disabled(cls) -> "Schedule":
        """Create a disabled schedule."""
        return cls(
            timezone=None,
            business_hours_reduction=0,
            daily_hours={},
        )


def format_schedule_display(schedule: Schedule, time_verifier: TimeVerifier) -> str:
    """
    Format the weekly schedule for display.

    Shows each day with its hours and current status.
    """
    # Import Colors here to avoid circular import
    from .constants import Colors

    lines = []

    if not schedule.is_enabled():
        return "  Schedule: Disabled (no timezone set)"

    try:
        tz = ZoneInfo(schedule.timezone)
        current_time = time_verifier.get_current_time(schedule.timezone)
        current_day = DAYS_OF_WEEK[current_time.weekday()]
    except Exception:
        current_day = None
        current_time = None

    lines.append(f"  Timezone: {schedule.timezone}")
    lines.append(f"  Business hours reduction: {schedule.business_hours_reduction} attempts")
    lines.append("")
    lines.append("  Weekly Schedule:")

    for day in DAYS_OF_WEEK:
        hours = schedule.daily_hours.get(day)
        if hours is None:
            hours_str = "off"
        elif hours.pause_all_day:
            hours_str = "PAUSE (no spraying)"
        elif hours.start is None:
            hours_str = "off (full speed)"
        else:
            hours_str = f"{hours.start.strftime('%H:%M')}-{hours.end.strftime('%H:%M')} (reduced attempts)"

        # Mark current day
        marker = " <-- TODAY" if day == current_day else ""
        is_current = "*" if day == current_day else " "

        lines.append(f"   {is_current} {day.capitalize():9}: {hours_str}{marker}")

    # Show current status
    if current_time:
        is_business, should_pause = schedule.get_current_status_with_time(current_time)
        lines.append("")
        if should_pause:
            lines.append(f"  Current status: PAUSED (schedule dictates no spraying now)")
        elif is_business:
            lines.append(f"  Current status: BUSINESS HOURS (reduced attempts active)")
        else:
            lines.append(f"  Current status: Outside business hours (full speed)")

    return "\n".join(lines)
