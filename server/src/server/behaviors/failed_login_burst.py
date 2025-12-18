"""
Failed Login Burst Behavior Detector.

Detects patterns where multiple consecutive failed login attempts occur
without any successful login in between. This is a classic indicator of:
- Brute force attacks
- Password spraying
- Credential stuffing

Uses Windows Security events 4624 (success) and 4625 (failure).

Rules:
- 5 consecutive failed logons (event_id = 4625) for the same (host, user)
- Within a 5 minute window
- No successful logon (4624) between the first and fifth failure
- 15 minute debounce after raising an alert for the same (host, user)
- Risk score: 70
"""

import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from collections import defaultdict

from ..models import NormalizedEvent, Alert, EventCategory, AuthResult, BehaviorType

logger = logging.getLogger(__name__)

# Configuration constants
CONSECUTIVE_FAILURES_THRESHOLD = 5  # Number of consecutive failures to trigger
FAILURE_WINDOW_MINUTES = 5          # Time window to look for failures
DEBOUNCE_MINUTES = 15               # Cooldown after alert before raising another
RISK_SCORE = 70                     # Medium-high risk score


class FailedLoginBurstDetector:
    """
    Tracks failed login attempts and detects consecutive failure bursts.
    
    Maintains state about recent failures per (user, host) combination.
    An alert is raised when 5+ consecutive failures occur without any
    intervening success.
    """
    
    def __init__(self):
        """Initialize the detector."""
        # Track failures: key = (user, host) -> list of (timestamp, source_ip, event_id)
        self._failures: Dict[tuple, List[tuple]] = defaultdict(list)
        
        # Track recent alerts: key = (user, host) -> last_alert_timestamp
        self._recent_alerts: Dict[tuple, datetime] = {}
        
        # Track last success: key = (user, host) -> timestamp of last success
        self._last_success: Dict[tuple, datetime] = {}
    
    def _cleanup_old_records(self):
        """Remove expired records older than the failure window."""
        cutoff = datetime.utcnow() - timedelta(minutes=FAILURE_WINDOW_MINUTES + 1)
        alert_cutoff = datetime.utcnow() - timedelta(minutes=DEBOUNCE_MINUTES)
        
        # Clean failure records
        for key in list(self._failures.keys()):
            self._failures[key] = [
                record for record in self._failures[key] 
                if record[0] > cutoff
            ]
            if not self._failures[key]:
                del self._failures[key]
        
        # Clean alert records
        self._recent_alerts = {
            k: v for k, v in self._recent_alerts.items() 
            if v > alert_cutoff
        }
        
        # Clean success records (keep last hour)
        success_cutoff = datetime.utcnow() - timedelta(hours=1)
        self._last_success = {
            k: v for k, v in self._last_success.items()
            if v > success_cutoff
        }
    
    def _record_failure(self, event: NormalizedEvent):
        """Record a failed login attempt."""
        key = (event.user.lower(), event.host.lower())
        source_ip = event.source_ip or "unknown"
        self._failures[key].append((event.timestamp, source_ip, event.event_id))
        
        logger.debug(
            f"Recorded failed login: user={event.user}, host={event.host}, "
            f"source_ip={source_ip}, total_failures={len(self._failures[key])}"
        )
    
    def _record_success(self, event: NormalizedEvent):
        """Record a successful login (resets failure tracking for this user/host)."""
        key = (event.user.lower(), event.host.lower())
        self._last_success[key] = event.timestamp
        
        # Clear failures for this user/host since they successfully logged in
        if key in self._failures:
            logger.debug(
                f"Clearing {len(self._failures[key])} failures after success: "
                f"user={event.user}, host={event.host}"
            )
            del self._failures[key]
    
    def _check_for_burst(self, event: NormalizedEvent) -> Optional[Alert]:
        """
        Check if this failed login creates a burst condition.
        
        A burst is detected when:
        - 5+ consecutive failed logins for the same (host, user)
        - Within a 5 minute window
        - No successful login between the first and latest failure
        
        Args:
            event: The failed login event
            
        Returns:
            Alert if burst detected, None otherwise
        """
        key = (event.user.lower(), event.host.lower())
        
        if key not in self._failures:
            return None
        
        # Get failures within the time window
        window_start = event.timestamp - timedelta(minutes=FAILURE_WINDOW_MINUTES)
        
        recent_failures = [
            record for record in self._failures[key]
            if record[0] >= window_start
        ]
        
        failure_count = len(recent_failures)
        
        # Not enough failures yet
        if failure_count < CONSECUTIVE_FAILURES_THRESHOLD:
            return None
        
        # Check if there was a success between the first failure and now
        if key in self._last_success:
            first_failure_time = recent_failures[0][0]
            if self._last_success[key] >= first_failure_time:
                # There was a success after the first failure - not consecutive
                logger.debug(
                    f"Success event breaks the failure chain for {key}"
                )
                return None
        
        # NOTE: In-memory debounce removed.
        # Storage layer now handles aggregation via upsert_or_update_alert().
        # Each burst detection will either create a new alert or increment occurrence_count
        # on an existing open alert within the 30-minute merge window.
        
        # Clear the failures for this key after alerting (to reset burst tracking)
        del self._failures[key]
        
        # Collect source IPs
        source_ips = list(set(record[1] for record in recent_failures if record[1] != "unknown"))
        primary_ip = source_ips[0] if source_ips else None
        
        # Build summary
        user_display = event.user.replace("\\", "\\\\")  # Escape backslashes for display
        summary = (
            f"{failure_count} consecutive failed logons for user {user_display} "
            f"on host {event.host} (no success in between)"
        )
        
        # Build details
        details_dict = {
            "user": event.user,
            "host": event.host,
            "failure_count": failure_count,
            "time_window_minutes": FAILURE_WINDOW_MINUTES,
            "source_ips": source_ips,
            "failures": [
                {
                    "timestamp": ts.isoformat(),
                    "source_ip": ip,
                    "event_id": eid
                }
                for ts, ip, eid in recent_failures[-10:]  # Last 10 failures
            ],
            "logon_type": event.logon_type,
        }
        
        details = json.dumps(details_dict, indent=2)
        
        alert = Alert(
            timestamp=event.timestamp,  # Timestamp of the last failed event
            behavior=BehaviorType.FAILED_LOGIN_BURST.value,
            risk_score=RISK_SCORE,
            host=event.host,
            user=event.user,
            source_ip=primary_ip,
            fail_count=failure_count,
            summary=summary,
            details=details
        )
        
        logger.info(
            "Alert[%s] host=%s user=%s risk=%d summary=%s",
            alert.behavior, alert.host, alert.user, alert.risk_score, alert.summary
        )
        
        return alert
    
    def detect(self, event: NormalizedEvent, db=None, config: dict = None) -> List[Alert]:
        """
        Analyze an event for failed login burst pattern.
        
        Args:
            event: Normalized event to analyze
            db: Database connection (for future persistence)
            config: Additional configuration
            
        Returns:
            List of Alert objects (0 or 1 alert)
        """
        # Cleanup old records periodically
        self._cleanup_old_records()
        
        # Only process auth events (Security log)
        if event.category != EventCategory.AUTH:
            return []
        
        # Require auth_result to be present for reliable detection
        if not event.has_auth_info():
            logger.debug(f"Skipping event {event.event_id}: missing auth_result")
            return []
        
        # Only process login events (4624 = success, 4625 = failure)
        if event.event_id not in (4624, 4625):
            return []
        
        # Also check provider for Security events
        if event.provider and "Security-Auditing" not in event.provider:
            # Not a security event, skip
            return []
        
        # Handle successful login - resets failure tracking
        if event.event_id == 4624 or event.auth_result == AuthResult.SUCCESS:
            self._record_success(event)
            return []
        
        # Handle failed login
        if event.event_id == 4625 or event.auth_result == AuthResult.FAILED:
            self._record_failure(event)
            
            # Check if we've hit the burst threshold
            alert = self._check_for_burst(event)
            if alert:
                return [alert]
        
        return []


# Global detector instance
_detector = FailedLoginBurstDetector()


def detect_failed_login_burst(
    event: NormalizedEvent,
    db=None,
    config: dict = None
) -> List[Alert]:
    """
    Detect failed login burst (5+ consecutive failures without success).
    
    This is the main entry point for this behavior detector.
    
    Args:
        event: Normalized event to analyze
        db: Database connection
        config: Detection configuration
        
    Returns:
        List of Alert objects
    """
    return _detector.detect(event, db, config)
