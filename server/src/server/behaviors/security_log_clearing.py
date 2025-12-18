"""
Security Log Clearing Attempt Behavior Detector.

Detects attempts to clear Windows event logs using tools like:
- wevtutil.exe cl <LogName>
- PowerShell Clear-EventLog / Clear-Log

This is a high-severity indicator of anti-forensics activity, often used by
attackers to cover their tracks after compromise.

Rules:
- Process name is wevtutil.exe, powershell.exe, or pwsh.exe
- Command line indicates log clearing operation
- Target logs: Security, System, Application, Setup
- Risk score: 90 (very high)
- Debounce: 1 alert per 10 minutes for same (host, user, process_name, command_line)
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
DEBOUNCE_MINUTES = 10   # Raise at most one alert per 10 minutes for same command
RISK_SCORE = 90         # Very high risk score

# Target log names that indicate security-sensitive log clearing
TARGET_LOGS = {"security", "system", "application", "setup"}

# wevtutil patterns
WEVTUTIL_CLEAR_PATTERN = re.compile(
    r'wevtutil\s+cl\s+',
    re.IGNORECASE
)

# PowerShell Clear-EventLog patterns
POWERSHELL_CLEAR_PATTERNS = [
    re.compile(r'Clear-EventLog', re.IGNORECASE),
    re.compile(r'Clear-Log', re.IGNORECASE),
    re.compile(r'Remove-EventLog', re.IGNORECASE),
]


class SecurityLogClearingDetector:
    """
    Detects attempts to clear Windows event logs.
    Tracks recent alerts to avoid flooding.
    """
    
    def __init__(self):
        """Initialize the detector."""
        self.dedup_window = timedelta(minutes=DEBOUNCE_MINUTES)
        # Track: (host, user, process_name, command_hash) -> last_alert_time
        self._recent_alerts: dict = defaultdict(lambda: datetime.min)
    
    def _cleanup_old_alerts(self):
        """Remove expired entries from the dedup cache."""
        cutoff = datetime.utcnow() - self.dedup_window
        expired = [k for k, v in self._recent_alerts.items() if v < cutoff]
        for k in expired:
            del self._recent_alerts[k]
    
    def _get_command_hash(self, cmd: str) -> str:
        """Get a hash of the command for deduplication."""
        if not cmd:
            return ""
        normalized = cmd.lower().strip()[:500]
        return hashlib.md5(normalized.encode()).hexdigest()[:16]
    
    def _extract_target_log(self, cmd: str) -> Optional[str]:
        """
        Extract the target log name from the command line.
        
        Returns the log name if found (e.g., "Security", "System"), or None.
        """
        if not cmd:
            return None
        
        cmd_lower = cmd.lower()
        
        # Check for wevtutil cl <logname>
        wevtutil_match = re.search(r'wevtutil\s+cl\s+(\S+)', cmd_lower)
        if wevtutil_match:
            log_name = wevtutil_match.group(1).strip('"\'')
            # Capitalize first letter for display
            return log_name.capitalize() if log_name in TARGET_LOGS else log_name
        
        # Check for PowerShell -LogName parameter
        logname_match = re.search(r'-LogName\s+["\']?(\w+)', cmd, re.IGNORECASE)
        if logname_match:
            log_name = logname_match.group(1)
            return log_name.capitalize() if log_name.lower() in TARGET_LOGS else log_name
        
        # Check if any target log is mentioned
        for log in TARGET_LOGS:
            if log in cmd_lower:
                return log.capitalize()
        
        return None
    
    def _is_wevtutil_clearing(self, process_name: str, cmd: str) -> bool:
        """Check if this is a wevtutil log clearing command."""
        if not process_name or not cmd:
            return False
        
        if process_name.lower() != "wevtutil.exe":
            return False
        
        # Must have "cl" (clear) command
        if not WEVTUTIL_CLEAR_PATTERN.search(cmd):
            return False
        
        # Must target a known log or use /logfile: syntax
        cmd_lower = cmd.lower()
        if "/logfile:" in cmd_lower:
            return True
        
        # Check if any target log is mentioned
        for log in TARGET_LOGS:
            if log in cmd_lower:
                return True
        
        return False
    
    def _is_powershell_clearing(self, process_name: str, cmd: str) -> bool:
        """Check if this is a PowerShell log clearing command."""
        if not process_name or not cmd:
            return False
        
        if process_name.lower() not in ("powershell.exe", "pwsh.exe"):
            return False
        
        # Must have a Clear-EventLog or similar cmdlet
        has_clear_cmdlet = any(p.search(cmd) for p in POWERSHELL_CLEAR_PATTERNS)
        if not has_clear_cmdlet:
            return False
        
        # Must target a known log
        cmd_lower = cmd.lower()
        for log in TARGET_LOGS:
            if log in cmd_lower:
                return True
        
        # Also trigger if -LogName is present (even without explicit log name)
        if "-logname" in cmd_lower:
            return True
        
        return False
    
    def detect(self, event: NormalizedEvent, db=None, config: dict = None) -> List[Alert]:
        """
        Check if the event represents a security log clearing attempt.
        
        Detects via:
        - Sysmon Event ID 1 (Process Create) with wevtutil/PowerShell
        - Security Event ID 4688 (Process Create) with command line
        
        Args:
            event: Normalized event to analyze
            db: Database connection (for future state queries)
            config: Detection configuration
            
        Returns:
            List of Alert objects (0 or 1 alert)
        """
        # Accept both Sysmon and Security events
        is_sysmon = event.provider and "Sysmon" in event.provider
        is_security_4688 = event.event_id == 4688 and event.category == EventCategory.AUTH
        
        if not (is_sysmon or is_security_4688):
            return []
        
        # Must have process_name and command_line
        if not event.process_name or not event.command_line:
            return []
        
        process_name = event.process_name
        cmd = event.command_line
        
        # Check for log clearing patterns
        is_clearing = False
        
        if self._is_wevtutil_clearing(process_name, cmd):
            is_clearing = True
            logger.debug(
                f"wevtutil log clearing detected: user={event.user}, "
                f"host={event.host}, cmd={cmd[:100]}..."
            )
        elif self._is_powershell_clearing(process_name, cmd):
            is_clearing = True
            logger.debug(
                f"PowerShell log clearing detected: user={event.user}, "
                f"host={event.host}, cmd={cmd[:100]}..."
            )
        
        if not is_clearing:
            return []
        
        # NOTE: In-memory deduplication removed.
        # Storage layer now handles aggregation via upsert_or_update_alert().
        # Each detection will either create a new alert or increment occurrence_count
        # on an existing open alert within the 30-minute merge window.
        
        # Extract target log name
        target_log = self._extract_target_log(cmd)
        
        # Build summary
        log_display = target_log if target_log else "event log"
        summary = (
            f"Event log clearing attempt: {process_name} cl {log_display} "
            f"by {event.user} on {event.host}"
        )
        
        # Truncate command line for display
        cmd_display = cmd[:500] + "..." if len(cmd) > 500 else cmd
        
        # Build details
        details_dict = {
            "command_line": cmd_display,
            "full_command_length": len(cmd),
            "process_name": process_name,
            "process_id": event.process_id,
            "parent_process_name": event.parent_process_name,
            "parent_process_id": event.parent_process_id,
            "image_path": event.image_path,
            "target_log": target_log,
            "user": event.user,
            "host": event.host,
            "provider": event.provider,
            "event_id": event.event_id,
        }
        
        details = json.dumps(details_dict, indent=2)
        
        alert = Alert(
            timestamp=event.timestamp,
            behavior=BehaviorType.SECURITY_LOG_CLEARING.value,
            risk_score=RISK_SCORE,
            host=event.host,
            user=event.user,
            source_ip=None,
            fail_count=None,
            file_event_count=None,
            archive_process_name=process_name,  # Store the tool used
            target_path=target_log,  # Store the target log name
            summary=summary,
            details=details
        )
        
        logger.info(
            "Alert[%s] host=%s user=%s risk=%d summary=%s",
            alert.behavior, alert.host, alert.user, alert.risk_score, alert.summary
        )
        
        return [alert]


# Global detector instance
_detector = SecurityLogClearingDetector()


def detect_security_log_clearing(
    event: NormalizedEvent,
    db=None,
    config: dict = None
) -> List[Alert]:
    """
    Detect security log clearing attempts.
    
    This is the main entry point for this behavior detector.
    
    Args:
        event: Normalized event to analyze
        db: Database connection
        config: Detection configuration
        
    Returns:
        List of Alert objects
    """
    return _detector.detect(event, db, config)

