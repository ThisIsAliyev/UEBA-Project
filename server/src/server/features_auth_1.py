"""
Authentication Feature Extraction for UEBA.

Extracts security-relevant features from authentication events.
These features are used by the risk engine for scoring.

Features:
- is_off_hours: Event occurred outside normal working hours (08:00-19:00)
- is_failed_logon: Event is a failed login attempt
- is_privileged_logon: Account appears to be privileged (admin-like)
- is_rare_source_ip: Source IP is rare/unusual (stub for now)
"""

from datetime import datetime
from typing import Dict, Any
from .models import NormalizedEvent, AuthResult


def is_off_hours(event: NormalizedEvent) -> bool:
    """
    Check if event occurred outside normal working hours.
    
    Normal hours: Monday-Friday, 08:00-19:00
    
    Args:
        event: NormalizedEvent with timestamp
        
    Returns:
        True if event is outside working hours
    """
    try:
        ts = event.timestamp
        # Weekend check (5=Saturday, 6=Sunday)
        if ts.weekday() >= 5:
            return True
        
        # Hour check (before 8 AM or after 7 PM)
        if ts.hour < 8 or ts.hour >= 19:
            return True
        
        return False
    except Exception:
        return False


def is_failed_logon(event: NormalizedEvent) -> bool:
    """
    Check if event is a failed login attempt.
    
    Args:
        event: NormalizedEvent with auth_result or event_id
        
    Returns:
        True if event is a failed logon
    """
    # Check auth_result field
    if event.auth_result == AuthResult.FAILED:
        return True
    if isinstance(event.auth_result, str) and event.auth_result.lower() == "failed":
        return True
    
    # Check event_id (Windows Security 4625)
    if event.event_id == 4625:
        return True
    
    # Check subcategory
    if event.subcategory == "logon_failed":
        return True
    
    return False


def is_privileged_logon(event: NormalizedEvent) -> bool:
    """
    Check if login is for a privileged account.
    
    Simple heuristic: account name contains admin-like keywords.
    
    Args:
        event: NormalizedEvent with user field
        
    Returns:
        True if account appears privileged
    """
    if not event.user:
        return False
    
    user_lower = event.user.lower()
    
    # Admin-like keywords
    privileged_keywords = [
        "admin",
        "administrator",
        "root",
        "domain admin",
        "enterprise admin",
        "schema admin",
        "backup operator",
        "system",
        "nt authority\\system",
    ]
    
    for keyword in privileged_keywords:
        if keyword in user_lower:
            return True
    
    # Check for built-in admin SID pattern
    if "s-1-5-21" in user_lower and user_lower.endswith("-500"):
        return True
    
    # Special privileges event (4672)
    if event.event_id == 4672:
        return True
    if event.subcategory == "special_privileges":
        return True
    
    return False


def is_rare_source_ip(event: NormalizedEvent) -> bool:
    """
    Check if source IP is rare/unusual.
    
    STUB: Currently returns False. In production, this would:
    - Compare against a baseline of known IPs
    - Use IP reputation data
    - Track IP frequency per user
    
    Args:
        event: NormalizedEvent with source_ip field
        
    Returns:
        True if source IP appears rare (currently always False)
    """
    # TODO: Implement actual IP rarity check
    # For now, always return False as a stub
    # This could be enhanced to:
    # - Check against a set of "known good" IPs
    # - Compare frequency of IP per user
    # - Use external threat intelligence
    
    if not event.source_ip:
        return False
    
    # Simple stub: mark external IPs as "rare"
    # (this is very basic, not production-ready)
    ip = event.source_ip
    
    # Known local/internal patterns
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return False
    if ip in ("127.0.0.1", "::1", "localhost"):
        return False
    
    # External IP - could be considered "rare" for stub purposes
    # But returning False to avoid false positives
    return False


def extract_features(event: NormalizedEvent) -> Dict[str, Any]:
    """
    Extract all authentication-related features from an event.
    
    Args:
        event: NormalizedEvent to analyze
        
    Returns:
        Dictionary of feature name -> value pairs
    """
    return {
        "is_off_hours": is_off_hours(event),
        "is_failed_logon": is_failed_logon(event),
        "is_privileged_logon": is_privileged_logon(event),
        "is_rare_source_ip": is_rare_source_ip(event),
    }
