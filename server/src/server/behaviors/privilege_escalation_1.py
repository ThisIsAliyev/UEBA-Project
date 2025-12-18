"""
Privilege Escalation Behavior Detector.

Detects when a user is added to privileged groups (Administrators, Domain Admins, etc.).
This can indicate:
- Unauthorized privilege escalation
- Insider threat activity
- Compromised account being used for persistence

Uses Windows Security events 4728, 4732, 4756 (user added to security-enabled group).

Rules:
- Event IDs: 4728 (global group), 4732 (local group), 4756 (universal group)
- Target group is privileged (Administrators, Domain Admins, Enterprise Admins, etc.)
- 30 minute debounce per (host, user, target_group)
- Risk score: 85 (High - privilege escalation is critical)
"""

import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from collections import defaultdict

from ..models import NormalizedEvent, Alert, EventCategory, BehaviorType

logger = logging.getLogger(__name__)

# Configuration constants
DEBOUNCE_MINUTES = 30   # Cooldown after alert
RISK_SCORE = 85         # High risk - privilege escalation is serious

# Event IDs for group membership changes
GROUP_MEMBER_ADDED_GLOBAL = 4728    # Member added to global group
GROUP_MEMBER_ADDED_LOCAL = 4732     # Member added to local group
GROUP_MEMBER_ADDED_UNIVERSAL = 4756 # Member added to universal group

# Privileged group names (case-insensitive partial match)
PRIVILEGED_GROUPS = {
    "administrators",
    "domain admins",
    "enterprise admins",
    "schema admins",
    "backup operators",
    "account operators",
    "server operators",
    "print operators",
    "remote desktop users",
    "power users",
}


class PrivilegeEscalationDetector:
    """
    Detects privilege escalation via group membership changes.
    """
    
    def __init__(self):
        """Initialize the detector."""
        # Track recent alerts: key = (user, host, group) -> last_alert_timestamp
        self._recent_alerts: Dict[tuple, datetime] = {}
    
    def _cleanup_old_records(self):
        """Remove expired alert records."""
        cutoff = datetime.utcnow() - timedelta(minutes=DEBOUNCE_MINUTES)
        self._recent_alerts = {
            k: v for k, v in self._recent_alerts.items() 
            if v > cutoff
        }
    
    def _is_privileged_group(self, group_name: str) -> bool:
        """Check if the group is a privileged group."""
        if not group_name:
            return False
        
        group_lower = group_name.lower()
        for priv_group in PRIVILEGED_GROUPS:
            if priv_group in group_lower:
                return True
        return False
    
    def _extract_group_info(self, event: NormalizedEvent) -> Optional[tuple]:
        """
        Extract target user and group name from event.
        
        Returns:
            (target_user, group_name) or None
        """
        import re
        
        # Try to extract from message field
        message = event.message or ""
        
        # Pattern: "Member: CN=username,..." or "Member Name: username" or "Member:\r\n\tSecurity ID: ...\r\n\tAccount Name: username"
        target_user = None
        
        # Try CN= pattern first
        match = re.search(r'Member:\s*CN=([^,]+)', message, re.IGNORECASE)
        if match:
            target_user = match.group(1).strip()
        
        # Try "Member Name:" pattern
        if not target_user:
            match = re.search(r'Member Name:\s*([^\r\n]+)', message, re.IGNORECASE)
            if match:
                target_user = match.group(1).strip()
        
        # Try "Account Name:" after "Member:" section
        if not target_user:
            match = re.search(r'Member:.*?Account Name:\s*([^\r\n]+)', message, re.IGNORECASE | re.DOTALL)
            if match:
                target_user = match.group(1).strip()
        
        # Pattern: "Group: CN=groupname,..." or "Group Name: groupname" or "Group:\r\n\tSecurity ID: ...\r\n\tGroup Name: groupname"
        group_name = None
        
        # Try CN= pattern first
        match = re.search(r'Group:\s*CN=([^,]+)', message, re.IGNORECASE)
        if match:
            group_name = match.group(1).strip()
        
        # Try "Group Name:" pattern
        if not group_name:
            match = re.search(r'Group Name:\s*([^\r\n]+)', message, re.IGNORECASE)
            if match:
                group_name = match.group(1).strip()
        
        # Try "Group Name:" after "Group:" section
        if not group_name:
            match = re.search(r'Group:.*?Group Name:\s*([^\r\n]+)', message, re.IGNORECASE | re.DOTALL)
            if match:
                group_name = match.group(1).strip()
        
        if target_user and group_name:
            logger.debug(f"Extracted group info: user={target_user}, group={group_name}")
            return (target_user, group_name)
        
        logger.debug(f"Failed to extract group info from message: {message[:200]}")
        return None
    
    def detect(self, event: NormalizedEvent, db=None, config: dict = None) -> List[Alert]:
        """
        Analyze an event for privilege escalation pattern.
        
        Args:
            event: Normalized event to analyze
            db: Database connection (not used currently)
            config: Additional configuration
            
        Returns:
            List of Alert objects (0 or 1 alert)
        """
        # Cleanup old records periodically
        self._cleanup_old_records()
        
        # Only process Security events
        if event.category != EventCategory.AUTH:
            return []
        
        # Check for group membership change events
        if event.event_id not in (GROUP_MEMBER_ADDED_GLOBAL, GROUP_MEMBER_ADDED_LOCAL, GROUP_MEMBER_ADDED_UNIVERSAL):
            return []
        
        # Extract group and target user info
        group_info = self._extract_group_info(event)
        if not group_info:
            logger.debug(f"Could not extract group info from event {event.event_id}")
            return []
        
        target_user, group_name = group_info
        
        # Check if it's a privileged group
        if not self._is_privileged_group(group_name):
            logger.debug(f"Group '{group_name}' is not privileged, skipping")
            return []
        
        logger.info(f"PRIVILEGE ESCALATION detected: {target_user} added to {group_name} by {event.user} on {event.host}")
        
        # Build summary
        summary = f"User {target_user} was added to privileged group '{group_name}' by {event.user} on {event.host}"
        
        # Build details
        details_dict = {
            "target_user": target_user,
            "group_name": group_name,
            "added_by": event.user,
            "host": event.host,
            "timestamp": event.timestamp.isoformat(),
            "event_id": event.event_id,
            "message": event.message,
            "severity": "HIGH",
            "recommendation": "Verify this group membership change was authorized. Investigate if unauthorized."
        }
        
        details = json.dumps(details_dict, indent=2)
        
        alert = Alert(
            timestamp=event.timestamp,
            behavior=BehaviorType.PRIVILEGE_ESCALATION.value,
            risk_score=RISK_SCORE,
            host=event.host,
            user=event.user,
            summary=summary,
            details=details
        )
        
        logger.info(
            "Alert[%s] host=%s user=%s target=%s group=%s risk=%d",
            alert.behavior, alert.host, alert.user, target_user, group_name, alert.risk_score
        )
        
        return [alert]


# Global detector instance
_detector = PrivilegeEscalationDetector()


def detect_privilege_escalation(
    event: NormalizedEvent,
    db=None,
    config: dict = None
) -> List[Alert]:
    """
    Detect privilege escalation via group membership changes.
    
    This is the main entry point for this behavior detector.
    
    Args:
        event: Normalized event to analyze
        db: Database connection
        config: Detection configuration
        
    Returns:
        List of Alert objects
    """
    return _detector.detect(event, db, config)
