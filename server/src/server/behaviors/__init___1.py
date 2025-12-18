"""
UEBA Behavior Detection Modules.

This package contains behavior detection rules for identifying
suspicious activity patterns in normalized events.

Active Behaviors:
1. failed_login_burst - Detects 5+ consecutive failed logins without success
2. suspicious_path_execution - Detects executables run from Downloads folder
3. security_log_clearing - Detects attempts to clear Windows event logs
4. restricted_hours_login - Detects logins during restricted hours (13:00-20:00)
5. firewall_disabled - Detects when Windows Firewall is turned off (Event ID 5025)
"""

from .suspicious_path_execution import detect_suspicious_path_execution
from .security_log_clearing import detect_security_log_clearing
from .failed_login_burst import detect_failed_login_burst
from .restricted_hours_login import detect_restricted_hours_login
from .firewall_disabled import detect_firewall_disabled
from .orchestrator import BehaviorOrchestrator, run_all_detectors

__all__ = [
    "detect_suspicious_path_execution",
    "detect_security_log_clearing",
    "detect_failed_login_burst",
    "detect_restricted_hours_login",
    "detect_firewall_disabled",
    "BehaviorOrchestrator",
    "run_all_detectors",
]

