"""
Suspicious EXE Execution from Downloads Behavior Detector.

Detects execution of executables/scripts from the Downloads folder.
This is a common vector for malware and unauthorized software execution.

Rules:
- Path contains \\users\\ AND \\downloads\\
- Extension is one of: .exe, .msi, .ps1, .bat, .cmd, .vbs, .js, .hta
- User is NOT a service account (NT AUTHORITY\\SYSTEM, LOCAL SERVICE, NETWORK SERVICE)
- 1 hour debounce for the same (host, user, path) combination
- Risk score: 65
"""

import re
import json
import hashlib
import logging
from datetime import datetime, timedelta
from typing import List, Optional
from collections import defaultdict

from ..models import NormalizedEvent, Alert, BehaviorType

logger = logging.getLogger(__name__)

# Configuration constants
DEBOUNCE_HOURS = 1  # Raise at most one alert per hour for same (host, user, path)
# Note: Different files will generate separate alerts, but the same file
# executed multiple times within 1 hour will only generate one alert
RISK_SCORE = 65     # Medium risk score

# Suspicious executable extensions (must be from Downloads folder)
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"
}

# Built-in service accounts to ignore (case-insensitive)
SERVICE_ACCOUNTS = {
    "nt authority\\system",
    "nt authority\\local service",
    "nt authority\\network service",
    "local service",
    "network service",
    "system",
}


class SuspiciousPathDetector:
    """
    Detects execution of executables from the Downloads folder.
    Tracks recent alerts to avoid flooding.
    """
    
    def __init__(self):
        """Initialize the detector."""
        self.dedup_window = timedelta(hours=DEBOUNCE_HOURS)
        # Track: (host, user, path_normalized) -> last_alert_time
        self._recent_alerts: dict = defaultdict(lambda: datetime.min)
    
    def _cleanup_old_alerts(self):
        """Remove expired entries from the dedup cache."""
        cutoff = datetime.utcnow() - self.dedup_window
        expired = [k for k, v in self._recent_alerts.items() if v < cutoff]
        for k in expired:
            del self._recent_alerts[k]
    
    def _normalize_path(self, path: str) -> str:
        """Normalize path to lowercase for comparison and deduplication."""
        if not path:
            return ""
        return path.lower().strip()
    
    def _is_downloads_folder(self, path: str) -> bool:
        """
        Check if the path is in a Downloads folder.
        
        Must contain both \\users\\ and \\downloads\\ (case-insensitive).
        """
        if not path:
            return False
        
        lower_path = path.lower()
        return "\\users\\" in lower_path and "\\downloads\\" in lower_path
    
    def _has_suspicious_extension(self, path: str) -> bool:
        """Check if the file has one of the suspicious extensions."""
        if not path:
            return False
        
        lower_path = path.lower()
        for ext in SUSPICIOUS_EXTENSIONS:
            if lower_path.endswith(ext):
                return True
        return False
    
    def _is_service_account(self, user: str) -> bool:
        """Check if the user is a built-in service account."""
        if not user:
            return False
        return user.lower() in SERVICE_ACCOUNTS
    
    def detect(self, event: NormalizedEvent, db=None, config: dict = None) -> List[Alert]:
        """
        Check if the event represents suspicious execution from Downloads folder.
        
        Args:
            event: Normalized event to analyze
            db: Database connection (for future state queries)
            config: Detection configuration
            
        Returns:
            List of Alert objects (0 or 1 alert)
        """
        # Must be from Sysmon provider
        if not event.provider or "Sysmon" not in event.provider:
            return []
        
        # Must be Sysmon source
        source_val = event.source if isinstance(event.source, str) else event.source.value
        if source_val not in ("sysmon", "Sysmon"):
            return []
        
        # Only accept event_id 1 (Process Create) - we want to alert on execution, not termination
        if event.event_id != 1:
            return []
        
        # Get path from image_path or target_filename (whichever is available)
        path = (event.image_path or event.target_filename or "").strip()
        if not path:
            logger.debug(f"Skipping event {event.event_id}: no path found (image_path={event.image_path}, target_filename={event.target_filename})")
            return []
        
        # Skip service accounts
        if self._is_service_account(event.user):
            logger.debug(f"Skipping event {event.event_id}: service account {event.user}")
            return []
        
        # Check for suspicious extension
        if not self._has_suspicious_extension(path):
            logger.debug(f"Skipping event {event.event_id}: no suspicious extension in path {path}")
            return []
        
        # Check if path is in Downloads folder
        if not self._is_downloads_folder(path):
            logger.debug(f"Skipping event {event.event_id}: path not in Downloads folder: {path}")
            return []
        
        # Normalize path for consistent comparison (use full path to allow different files)
        # This ensures different files generate separate alerts
        normalized_path = self._normalize_path(path)
        
        # NOTE: In-memory deduplication removed.
        # Storage layer now handles aggregation via upsert_or_update_alert().
        # Each detection will either create a new alert or increment occurrence_count
        # on an existing open alert within the 30-minute merge window.
        
        # Debug logging for successful detection
        logger.info(
            f"✅ Downloads folder execution detected: event_id={event.event_id}, user={event.user}, "
            f"host={event.host}, process={event.process_name}, path={path}, normalized={normalized_path}"
        )
        
        # Build summary
        summary = f"Executable started from Downloads folder: {path} by {event.user}"
        
        # Build details
        details_dict = {
            "image_path": path,
            "process_name": event.process_name,
            "process_id": event.process_id,
            "parent_process_name": event.parent_process_name,
            "parent_process_id": event.parent_process_id,
            "command_line": event.command_line,
            "user": event.user,
            "host": event.host,
            "event_id": event.event_id,
        }
        
        details = json.dumps(details_dict, indent=2)
        
        alert = Alert(
            timestamp=event.timestamp,
            behavior=BehaviorType.SUSPICIOUS_PATH_EXECUTION.value,
            risk_score=RISK_SCORE,
            host=event.host,
            user=event.user,
            target_path=normalized_path,
            file_event_count=1,  # Consistent value as specified
            summary=summary,
            details=details
        )
        
        logger.info(
            "Alert[%s] host=%s user=%s risk=%d summary=%s",
            alert.behavior, alert.host, alert.user, alert.risk_score, alert.summary
        )
        
        return [alert]


# Global detector instance
_detector = SuspiciousPathDetector()


def detect_suspicious_path_execution(
    event: NormalizedEvent,
    db=None,
    config: dict = None
) -> List[Alert]:
    """
    Detect execution from Downloads folder.
    
    This is the main entry point for this behavior detector.
    
    Args:
        event: Normalized event to analyze
        db: Database connection
        config: Detection configuration
        
    Returns:
        List of Alert objects
    """
    return _detector.detect(event, db, config)
