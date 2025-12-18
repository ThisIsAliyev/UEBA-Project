"""
Restricted Hours Login Behavior Detector.

Detects successful logins that occur during restricted hours (13:00-20:00).
This can indicate:
- Unauthorized access attempts
- Policy violations
- Potential insider threats during off-hours

Uses Windows Security event 4624 (successful logon).

Rules:
- Event ID 4624 (successful logon)
- Login timestamp falls between 13:00 (1pm) and 20:00 (8pm) local time
- 30 minute debounce per (host, user) to avoid alert flooding
- Risk score: 60
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional
from collections import defaultdict

from ..models import NormalizedEvent, Alert, EventCategory, AuthResult, BehaviorType

logger = logging.getLogger(__name__)

# Configuration constants
RESTRICTED_START_HOUR = 18  # 6:00 PM (18:00) - start of restricted hours
RESTRICTED_END_HOUR = 8     # 8:00 AM (08:00) - end of restricted hours (next day)
DEBOUNCE_MINUTES = 30       # Cooldown after alert before raising another for same user/host
RISK_SCORE = 60             # Medium risk score

# Service accounts to ignore
SERVICE_ACCOUNTS = {
    "nt authority\\system",
    "nt authority\\local service",
    "nt authority\\network service",
    "local service",
    "network service",
    "system",
    "dwm-1",
    "dwm-2",
    "umfd-0",
    "umfd-1",
}


class RestrictedHoursLoginDetector:
    """
    Detects successful logins during restricted hours (13:00-20:00).
    
    Monitors event ID 4624 and triggers an alert when a user logs in
    during the specified time window.
    """
    
    def __init__(self):
        """Initialize the detector."""
        # Track recent alerts: key = (user, host) -> last_alert_timestamp
        self._recent_alerts: Dict[tuple, datetime] = {}
    
    def _cleanup_old_records(self):
        """Remove expired alert records."""
        cutoff = datetime.utcnow() - timedelta(minutes=DEBOUNCE_MINUTES)
        self._recent_alerts = {
            k: v for k, v in self._recent_alerts.items() 
            if v > cutoff
        }
    
    def _is_service_account(self, user: str) -> bool:
        """Check if the user is a built-in service account."""
        if not user:
            return False
        return user.lower() in SERVICE_ACCOUNTS
    
    def _is_restricted_hours(self, timestamp: datetime) -> bool:
        """
        Check if the timestamp falls within restricted hours (18:00-08:00) LOCAL TIME.
        This is an overnight period (6 PM to 8 AM next day).
        
        Args:
            timestamp: The event timestamp (may be UTC)
            
        Returns:
            True if within restricted hours, False otherwise
        """
        # Convert to local time if timestamp is in UTC
        local_time = timestamp
        if timestamp.tzinfo is None:
            # Assume UTC and convert to local
            local_time = timestamp.replace(tzinfo=timezone.utc).astimezone()
        elif timestamp.tzinfo == timezone.utc:
            local_time = timestamp.astimezone()
        
        hour = local_time.hour
        logger.debug(f"Checking restricted hours: UTC={timestamp.hour}:00, Local={hour}:00, restricted={RESTRICTED_START_HOUR}:00-{RESTRICTED_END_HOUR}:00")
        
        # Overnight period: 18:00-08:00 means hour >= 18 OR hour < 8
        return hour >= RESTRICTED_START_HOUR or hour < RESTRICTED_END_HOUR
    
    def _format_time(self, timestamp: datetime) -> str:
        """Format timestamp to show time in HH:MM format."""
        return timestamp.strftime("%H:%M")
    
    def detect(self, event: NormalizedEvent, db=None, config: dict = None) -> List[Alert]:
        """
        Analyze an event for restricted hours login pattern.
        
        Args:
            event: Normalized event to analyze
            db: Database connection (not used currently)
            config: Additional configuration
            
        Returns:
            List of Alert objects (0 or 1 alert)
        """
        # Cleanup old records periodically
        self._cleanup_old_records()
        
        # Debug: Log all events for troubleshooting
        logger.debug(
            f"RestrictedHours checking event: id={event.event_id}, "
            f"category={event.category}, user={event.user}, "
            f"provider={event.provider}, timestamp={event.timestamp}"
        )
        
        # Only process auth events
        if event.category != EventCategory.AUTH:
            logger.debug(f"Skipping: not AUTH category (is {event.category})")
            return []
        
        # Require auth_result to be present
        if not event.has_auth_info():
            logger.debug(f"Skipping event {event.event_id}: missing auth_result")
            return []
        
        # Only process successful login events (4624)
        if event.event_id != 4624:
            logger.debug(f"Skipping: event_id {event.event_id} != 4624")
            return []
        
        # Skip if not a success event
        if event.auth_result and event.auth_result != AuthResult.SUCCESS:
            logger.debug(f"Skipping: auth_result is {event.auth_result}, not SUCCESS")
            return []
        
        # Skip service accounts
        if self._is_service_account(event.user):
            logger.debug(f"Skipping: service account {event.user}")
            return []
        
        # Skip certain logon types (e.g., type 5 = service logon)
        if event.logon_type in (5,):  # Service logon
            logger.debug(f"Skipping: logon_type {event.logon_type} is service logon")
            return []
        
        # Check if login is within restricted hours
        if not self._is_restricted_hours(event.timestamp):
            logger.debug(f"Skipping: timestamp {event.timestamp} not in restricted hours")
            return []
        
        logger.info(f"MATCH! User {event.user} logged in during restricted hours at {event.timestamp}")
        
        # NOTE: In-memory debounce removed.
        # Storage layer now handles aggregation via upsert_or_update_alert().
        # Each detection will either create a new alert or increment occurrence_count
        # on an existing open alert within the 30-minute merge window.
        
        # Build summary
        login_time = self._format_time(event.timestamp)
        user_display = event.user.replace("\\", "\\\\")
        summary = (
            f"User {user_display} logged in at {login_time} during restricted hours "
            f"(18:00-08:00) on host {event.host}"
        )
        
        # Build details
        details_dict = {
            "user": event.user,
            "host": event.host,
            "login_time": event.timestamp.isoformat(),
            "login_hour": event.timestamp.hour,
            "login_minute": event.timestamp.minute,
            "restricted_window": f"{RESTRICTED_START_HOUR}:00 - {RESTRICTED_END_HOUR}:00 (overnight)",
            "source_ip": event.source_ip,
            "logon_type": event.logon_type,
            "workstation": event.workstation,
            "event_id": event.event_id,
            "rule": "Login detected during restricted hours (18:00-08:00 overnight)"
        }
        
        details = json.dumps(details_dict, indent=2)
        
        alert = Alert(
            timestamp=event.timestamp,
            behavior=BehaviorType.RESTRICTED_HOURS_LOGIN.value,
            risk_score=RISK_SCORE,
            host=event.host,
            user=event.user,
            source_ip=event.source_ip,
            summary=summary,
            details=details
        )
        
        logger.info(
            "Alert[%s] host=%s user=%s time=%s risk=%d summary=%s",
            alert.behavior, alert.host, alert.user, 
            self._format_time(event.timestamp), alert.risk_score, alert.summary
        )
        
        return [alert]


# Global detector instance
_detector = RestrictedHoursLoginDetector()


def detect_restricted_hours_login(
    event: NormalizedEvent,
    db=None,
    config: dict = None
) -> List[Alert]:
    """
    Detect login during restricted hours (13:00-20:00).
    
    This is the main entry point for this behavior detector.
    
    Args:
        event: Normalized event to analyze
        db: Database connection
        config: Detection configuration
        
    Returns:
        List of Alert objects
    """
    return _detector.detect(event, db, config)

