"""
Windows Firewall Disabled Behavior Detector.

Detects when Windows Firewall service is stopped/disabled.
This is a critical security event that can indicate:
- Malware attempting to disable security controls
- Unauthorized configuration changes
- Preparation for lateral movement or data exfiltration

Uses Windows Firewall event 5025 (Windows Firewall Service has been stopped).

Rules:
- Event ID 5025 from Windows Firewall with Advanced Security
- Triggers alert immediately when firewall is stopped
- 5 minute debounce per host to avoid alert flooding
- Risk score: 85 (High - critical security control disabled)
"""

import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from collections import defaultdict

from ..models import NormalizedEvent, Alert, EventCategory, BehaviorType

logger = logging.getLogger(__name__)

# Configuration constants
DEBOUNCE_MINUTES = 5    # Cooldown after alert before raising another for same host
RISK_SCORE = 85         # High risk - disabling firewall is serious

# Windows Firewall event IDs
FIREWALL_STOPPED_EVENT_ID = 5025   # Windows Firewall Service has been stopped
FIREWALL_STARTED_EVENT_ID = 5024   # Windows Firewall Service has been started

# Provider names for Windows Firewall events
FIREWALL_PROVIDERS = {
    "microsoft-windows-security-auditing",
    "microsoft-windows-windows firewall with advanced security",
    "windows firewall with advanced security",
    "security-auditing",
}


class FirewallDisabledDetector:
    """
    Detects when Windows Firewall is turned off.
    
    Monitors for Event ID 5025 which indicates the Windows Firewall
    service has been stopped.
    """
    
    def __init__(self):
        """Initialize the detector."""
        # Track recent alerts: key = host -> last_alert_timestamp
        self._recent_alerts: Dict[str, datetime] = {}
    
    def _cleanup_old_records(self):
        """Remove expired alert records."""
        cutoff = datetime.utcnow() - timedelta(minutes=DEBOUNCE_MINUTES)
        self._recent_alerts = {
            k: v for k, v in self._recent_alerts.items() 
            if v > cutoff
        }
    
    def _is_firewall_event(self, event: NormalizedEvent) -> bool:
        """
        Check if this is a Windows Firewall event.
        
        Args:
            event: The normalized event
            
        Returns:
            True if this is a firewall-related event
        """
        # Check provider
        if event.provider:
            provider_lower = event.provider.lower()
            for fw_provider in FIREWALL_PROVIDERS:
                if fw_provider in provider_lower:
                    return True
        
        # Also check by event ID range (5024-5040 are firewall events)
        if 5024 <= event.event_id <= 5040:
            return True
        
        return False
    
    def detect(self, event: NormalizedEvent, db=None, config: dict = None) -> List[Alert]:
        """
        Analyze an event for firewall disabled pattern.
        
        Args:
            event: Normalized event to analyze
            db: Database connection (not used currently)
            config: Additional configuration
            
        Returns:
            List of Alert objects (0 or 1 alert)
        """
        # Cleanup old records periodically
        self._cleanup_old_records()
        
        # Debug logging
        logger.debug(
            f"FirewallDisabled checking event: id={event.event_id}, "
            f"provider={event.provider}, user={event.user}, host={event.host}"
        )
        
        # Check if this is event ID 5025 (Firewall stopped)
        if event.event_id != FIREWALL_STOPPED_EVENT_ID:
            return []
        
        # Verify it's a firewall event (by provider or event ID range)
        if not self._is_firewall_event(event):
            logger.debug(f"Event 5025 but not from firewall provider: {event.provider}")
            # Still process it - event ID 5025 is specific enough
        
        logger.info(f"FIREWALL DISABLED detected on host {event.host} by user {event.user}")
        
        # NOTE: In-memory debounce removed.
        # Storage layer now handles aggregation via upsert_or_update_alert().
        # Each detection will either create a new alert or increment occurrence_count
        # on an existing open alert within the 30-minute merge window.
        
        # Build summary
        user_display = event.user.replace("\\", "\\\\") if event.user else "SYSTEM"
        summary = f"Windows Firewall was turned off on {event.host}"
        if event.user and event.user.lower() not in ("system", "nt authority\\system"):
            summary += f" by {user_display}"
        
        # Build details
        details_dict = {
            "event_id": event.event_id,
            "event_description": "Windows Firewall Service has been stopped",
            "host": event.host,
            "user": event.user or "SYSTEM",
            "timestamp": event.timestamp.isoformat(),
            "provider": event.provider,
            "message": event.message,
            "severity": "HIGH",
            "recommendation": "Investigate why firewall was disabled. Re-enable immediately if unauthorized."
        }
        
        details = json.dumps(details_dict, indent=2)
        
        alert = Alert(
            timestamp=event.timestamp,
            behavior=BehaviorType.FIREWALL_DISABLED.value,
            risk_score=RISK_SCORE,
            host=event.host,
            user=event.user or "SYSTEM",
            summary=summary,
            details=details
        )
        
        logger.info(
            "Alert[%s] host=%s user=%s risk=%d summary=%s",
            alert.behavior, alert.host, alert.user, alert.risk_score, alert.summary
        )
        
        return [alert]


# Global detector instance
_detector = FirewallDisabledDetector()


def detect_firewall_disabled(
    event: NormalizedEvent,
    db=None,
    config: dict = None
) -> List[Alert]:
    """
    Detect Windows Firewall being disabled (Event ID 5025).
    
    This is the main entry point for this behavior detector.
    
    Args:
        event: Normalized event to analyze
        db: Database connection
        config: Detection configuration
        
    Returns:
        List of Alert objects
    """
    return _detector.detect(event, db, config)

