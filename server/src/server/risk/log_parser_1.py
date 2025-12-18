"""
Log Parser Utilities for Risk Engine.

Helper functions for extracting features from NormalizedEvent objects.
"""

import re
from typing import Dict, Optional

from ..models import NormalizedEvent


def extract_command_features(command_line: Optional[str]) -> Dict[str, any]:
    """
    Extract features from command line.
    
    Args:
        command_line: Command line string or None
        
    Returns:
        Dictionary of extracted features
    """
    if not command_line:
        return {
            "has_command_line": False,
            "command_length": 0,
            "has_encoding": False,
            "has_url": False,
            "has_suspicious_chars": False,
        }
    
    command_lower = command_line.lower()
    
    # Check for encoding indicators
    has_encoding = bool(
        re.search(r'-enc\b|-e\s+[a-z0-9+/=]{20,}', command_lower) or
        'base64' in command_lower or
        'encodedcommand' in command_lower
    )
    
    # Check for URLs
    has_url = bool(re.search(r'https?://|ftp://', command_lower))
    
    # Check for suspicious characters (high entropy, unusual patterns)
    has_suspicious_chars = bool(
        re.search(r'[%$`]', command_line) or
        len(set(command_line)) / max(len(command_line), 1) > 0.7  # High entropy
    )
    
    return {
        "has_command_line": True,
        "command_length": len(command_line),
        "has_encoding": has_encoding,
        "has_url": has_url,
        "has_suspicious_chars": has_suspicious_chars,
    }


def extract_process_features(
    process_name: Optional[str],
    parent_process_name: Optional[str],
    image_path: Optional[str]
) -> Dict[str, any]:
    """
    Extract features from process information.
    
    Args:
        process_name: Process name (e.g., "powershell.exe")
        parent_process_name: Parent process name
        image_path: Full path to executable
        
    Returns:
        Dictionary of extracted features
    """
    features = {
        "has_process": bool(process_name),
        "has_parent": bool(parent_process_name),
        "has_image_path": bool(image_path),
        "is_system_process": False,
        "is_script_interpreter": False,
        "parent_is_office": False,
        "parent_is_browser": False,
    }
    
    if process_name:
        process_lower = process_name.lower()
        
        # Check if script interpreter
        script_interpreters = [
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe", "python.exe",
            "perl.exe", "ruby.exe"
        ]
        features["is_script_interpreter"] = any(
            proc in process_lower for proc in script_interpreters
        )
        
        # Check if system process
        system_processes = [
            "svchost.exe", "explorer.exe", "winlogon.exe", "csrss.exe",
            "lsass.exe", "services.exe", "smss.exe"
        ]
        features["is_system_process"] = any(
            proc in process_lower for proc in system_processes
        )
    
    if parent_process_name:
        parent_lower = parent_process_name.lower()
        
        # Check if parent is Office application
        office_apps = [
            "outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe",
            "msaccess.exe", "onenote.exe"
        ]
        features["parent_is_office"] = any(
            app in parent_lower for app in office_apps
        )
        
        # Check if parent is browser
        browsers = [
            "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
            "opera.exe", "brave.exe"
        ]
        features["parent_is_browser"] = any(
            browser in parent_lower for browser in browsers
        )
    
    if image_path:
        # Check if path is in suspicious location
        path_lower = image_path.lower()
        suspicious_paths = [
            r"\\temp\\", r"\\appdata\\local\\temp", r"\\appdata\\roaming",
            r"\\windows\\temp"
        ]
        features["path_in_suspicious_location"] = any(
            re.search(pattern, path_lower) for pattern in suspicious_paths
        )
    else:
        features["path_in_suspicious_location"] = False
    
    return features


def extract_network_features(
    dest_ip: Optional[str],
    dest_port: Optional[int]
) -> Dict[str, any]:
    """
    Extract features from network information.
    
    Args:
        dest_ip: Destination IP address
        dest_port: Destination port
        
    Returns:
        Dictionary of extracted features
    """
    features = {
        "has_network": bool(dest_ip),
        "has_port": bool(dest_port),
        "is_internal_ip": False,
        "is_common_port": False,
        "is_suspicious_port": False,
    }
    
    if dest_ip:
        # Check if internal IP (simplified check)
        internal_patterns = [
            r"^10\.", r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", r"^192\.168\.", r"^127\."
        ]
        features["is_internal_ip"] = any(
            re.match(pattern, dest_ip) for pattern in internal_patterns
        )
    
    if dest_port:
        # Common ports (HTTP, HTTPS, DNS, etc.)
        common_ports = [80, 443, 53, 22, 21, 25, 110, 143, 993, 995]
        features["is_common_port"] = dest_port in common_ports
        
        # Suspicious ports (often used for C2, data exfiltration)
        suspicious_ports = [4444, 5555, 6666, 8080, 8443, 9999]
        features["is_suspicious_port"] = dest_port in suspicious_ports
    
    return features

