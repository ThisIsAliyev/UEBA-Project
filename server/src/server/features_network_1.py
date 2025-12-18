"""
Network Feature Extraction for UEBA.

Extracts security-relevant features from network events.
These features are used by the risk engine for scoring.

Features:
- is_external_ip: Destination IP is not in private (RFC1918) range
- is_high_risk_port: Destination port is commonly targeted
- is_rare_destination: Destination is unusual (stub for now)
"""

import re
from typing import Dict, Any
from .models import NormalizedEvent


# High-risk ports commonly targeted by attackers
HIGH_RISK_PORTS = {
    21,     # FTP
    22,     # SSH
    23,     # Telnet
    25,     # SMTP
    53,     # DNS (can be abused for tunneling)
    135,    # RPC
    137,    # NetBIOS Name
    138,    # NetBIOS Datagram
    139,    # NetBIOS Session
    445,    # SMB
    1433,   # MSSQL
    1434,   # MSSQL Browser
    1521,   # Oracle
    3306,   # MySQL
    3389,   # RDP
    4444,   # Metasploit default
    5432,   # PostgreSQL
    5900,   # VNC
    5901,   # VNC
    5902,   # VNC
    5985,   # WinRM HTTP
    5986,   # WinRM HTTPS
    6379,   # Redis
    8080,   # HTTP Proxy
    8443,   # HTTPS Alt
    9200,   # Elasticsearch
    27017,  # MongoDB
}


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is in private (RFC1918) range.
    
    Private ranges:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - 127.0.0.0/8 (loopback)
    - 169.254.0.0/16 (link-local)
    
    Args:
        ip: IP address string
        
    Returns:
        True if IP is private/internal
    """
    if not ip:
        return True  # No IP = not external
    
    # Handle IPv6 loopback
    if ip in ("::1", "0:0:0:0:0:0:0:1"):
        return True
    
    # Simple pattern matching for IPv4
    if ip.startswith("10."):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("127."):
        return True
    if ip.startswith("169.254."):
        return True
    
    # 172.16.0.0 - 172.31.255.255
    if ip.startswith("172."):
        try:
            second_octet = int(ip.split(".")[1])
            if 16 <= second_octet <= 31:
                return True
        except (ValueError, IndexError):
            pass
    
    # Local hostnames
    if ip.lower() in ("localhost", "local"):
        return True
    
    return False


def is_external_ip(event: NormalizedEvent) -> bool:
    """
    Check if destination IP is external (not RFC1918 private).
    
    Args:
        event: NormalizedEvent with dest_ip field
        
    Returns:
        True if destination IP is external/public
    """
    if not event.dest_ip:
        return False
    
    return not is_private_ip(event.dest_ip)


def is_high_risk_port(event: NormalizedEvent) -> bool:
    """
    Check if destination port is a high-risk port.
    
    High-risk ports include RDP, SMB, SSH, and other
    commonly targeted services.
    
    Args:
        event: NormalizedEvent with dest_port field
        
    Returns:
        True if destination port is high-risk
    """
    if not event.dest_port:
        return False
    
    return event.dest_port in HIGH_RISK_PORTS


def is_rare_destination(event: NormalizedEvent) -> bool:
    """
    Check if destination is rare/unusual.
    
    STUB: Currently returns False. In production, this would:
    - Compare against baseline of normal destinations
    - Track destination frequency per host/user
    - Use threat intelligence feeds
    
    Args:
        event: NormalizedEvent with dest_ip field
        
    Returns:
        True if destination appears rare (currently always False)
    """
    # TODO: Implement actual rarity check
    # For now, always return False as a stub
    # This could be enhanced to:
    # - Check against known good destinations
    # - Compare frequency of destination per user/host
    # - Use external threat intelligence
    
    return False


def extract_features(event: NormalizedEvent) -> Dict[str, Any]:
    """
    Extract all network-related features from an event.
    
    Args:
        event: NormalizedEvent to analyze
        
    Returns:
        Dictionary of feature name -> value pairs
    """
    return {
        "is_external_ip": is_external_ip(event),
        "is_high_risk_port": is_high_risk_port(event),
        "is_rare_destination": is_rare_destination(event),
    }
