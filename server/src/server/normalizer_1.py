"""
Normalization Layer for UEBA Server.

This module transforms raw Sysmon/Windows events into the normalized
NormalizedEvent schema. This is the core of the "Normalization & Enrichment Layer".
"""

import json
import re
import logging
from datetime import datetime
from typing import Optional, Any
from .models import NormalizedEvent, EventLevel, EventCategory, AuthResult, EventSource

logger = logging.getLogger(__name__)


# Sysmon Event ID to description mapping
SYSMON_EVENT_TYPES = {
    1: "Process Creation",
    2: "File Creation Time Changed",
    3: "Network Connection",
    4: "Sysmon Service State Changed",
    5: "Process Terminated",
    6: "Driver Loaded",
    7: "Image Loaded",
    8: "CreateRemoteThread",
    9: "RawAccessRead",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "Registry Event (Create/Delete)",
    13: "Registry Event (Value Set)",
    14: "Registry Event (Rename)",
    15: "FileCreateStreamHash",
    16: "Sysmon Config Changed",
    17: "Pipe Created",
    18: "Pipe Connected",
    19: "WmiEventFilter",
    20: "WmiEventConsumer",
    21: "WmiEventConsumerToFilter",
    22: "DNS Query",
    23: "FileDelete",
    24: "Clipboard Changed",
    25: "Process Tampering",
    26: "FileDeleteDetected",
    255: "Error"
}

# Windows Security Event ID to description mapping
SECURITY_EVENT_TYPES = {
    # Authentication events
    4624: "Successful Logon",
    4625: "Failed Logon",
    4634: "Account Logoff",
    4647: "User Initiated Logoff",
    4648: "Explicit Credential Logon",
    4672: "Special Privileges Assigned",
    4776: "NTLM Authentication",
    
    # Lock/Unlock events (CRITICAL for UEBA)
    4800: "Workstation Locked",
    4801: "Workstation Unlocked",
    
    # Account management
    4720: "User Account Created",
    4722: "User Account Enabled",
    4724: "Password Reset Attempt",
    4725: "User Account Disabled",
    4726: "User Account Deleted",
    4738: "User Account Changed",
    4740: "Account Locked Out",
    
    # Process/Service events
    4688: "New Process Created",
    4689: "Process Exited",
    4697: "Service Installed",
    
    # Security policy/audit changes
    4719: "System Audit Policy Changed",
    4907: "Auditing Settings Changed",
    
    # Firewall events
    5025: "Firewall Service Stopped",
    5152: "Packet Filtered",
    5153: "Restrictive Filter Applied",
    5156: "Connection Allowed",
    5157: "Connection Blocked",
    
    # Scheduled tasks
    4698: "Scheduled Task Created",
    4699: "Scheduled Task Deleted",
    4702: "Scheduled Task Updated",
    
    # Object access
    4663: "Object Access Attempt",
    4656: "Handle Requested",
}

# Windows System Event ID to description mapping
SYSTEM_EVENT_TYPES = {
    # Service Control Manager events
    7000: "Service Failed to Start",
    7001: "Service Dependency Failed",
    7009: "Service Connection Timeout",
    7011: "Service Timeout",
    7023: "Service Terminated with Error",
    7024: "Service Terminated with Error",
    7026: "Boot-Start or System-Start Driver Failed",
    7031: "Service Terminated Unexpectedly",
    7034: "Service Terminated Unexpectedly",
    7035: "Service Control Request",
    7036: "Service State Changed",
    7040: "Service Start Type Changed",
    7045: "Service Installed",
    
    # DCOM events
    10016: "DCOM Permission Error",
    10010: "DCOM Server Not Responding",
    
    # Kernel/Driver events
    41: "Unexpected Shutdown",
    1001: "Bugcheck/BSOD",
    6005: "Event Log Service Started",
    6006: "Event Log Service Stopped",
    6008: "Unexpected Shutdown",
    6009: "OS Version Info",
    6013: "System Uptime",
    
    # Time service
    129: "NTP Time Sync Failed",
    134: "Time Sync Error",
    
    # Disk events
    7: "Disk Bad Block",
    11: "Disk Controller Error",
    15: "Disk Not Ready",
    51: "Disk Paging Error",
    52: "Disk Redundancy Degraded",
    55: "NTFS Error",
    153: "Disk I/O Retry",
    157: "Disk Surprise Removed",
}

# Windows Application Event ID to description mapping (common ones)
APPLICATION_EVENT_TYPES = {
    1000: "Application Error",
    1001: "Application Error (WER)",
    1002: "Application Hang",
    1026: ".NET Runtime Error",
    1033: "Windows Installer Completed",
    1034: "Windows Installer Reconfigured",
    11707: "Installation Completed Successfully",
    11708: "Installation Failed",
    11724: "Product Removal Completed",
}

# Provider to channel name mapping
PROVIDER_TO_CHANNEL = {
    "Microsoft-Windows-Security-Auditing": "Security",
    "Microsoft-Windows-Eventlog": "System",
    "Microsoft-Windows-Kernel-General": "System",
    "Microsoft-Windows-Kernel-Power": "System",
    "Microsoft-Windows-Kernel-Boot": "System",
    "Service Control Manager": "System",
    "Microsoft-Windows-DistributedCOM": "System",
    "Microsoft-Windows-Time-Service": "System",
    "Microsoft-Windows-DNS-Client": "System",
    "Microsoft-Windows-NTFS": "System",
    "disk": "System",
    "Application Error": "Application",
    "Windows Error Reporting": "Application",
    ".NET Runtime": "Application",
    "MsiInstaller": "Application",
}

# Windows Logon Type descriptions
LOGON_TYPES = {
    2: "Interactive (local)",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive (RDP)",
    11: "CachedInteractive",
}


def get_channel_from_provider(provider: str) -> str:
    """
    Determine the Windows Event Log channel name from the provider.
    
    Args:
        provider: The event provider name (e.g., "Microsoft-Windows-DistributedCOM")
        
    Returns:
        Channel name ("Security", "System", "Application", or "Windows Event")
    """
    if not provider:
        return "Windows Event"
    
    # Check direct mapping first
    if provider in PROVIDER_TO_CHANNEL:
        return PROVIDER_TO_CHANNEL[provider]
    
    # Check by provider prefix/pattern
    provider_lower = provider.lower()
    
    if "security" in provider_lower or "auditing" in provider_lower:
        return "Security"
    elif any(x in provider_lower for x in ["kernel", "ntfs", "disk", "driver", "scm", "dcom", "service"]):
        return "System"
    elif any(x in provider_lower for x in ["application", "error", "msi", ".net"]):
        return "Application"
    
    # Default fallback
    return "Windows Event"


def get_event_description(event_id: int, provider: str, channel: str) -> str:
    """
    Get a human-readable description for an event ID.
    
    Looks up the event ID in the appropriate mapping based on channel/provider.
    
    Args:
        event_id: The Windows Event ID
        provider: The event provider name
        channel: The channel name (Security, System, Application)
        
    Returns:
        Human-readable event description
    """
    # Try Security events first
    if channel == "Security" or "Security" in provider or "Auditing" in provider:
        if event_id in SECURITY_EVENT_TYPES:
            return SECURITY_EVENT_TYPES[event_id]
    
    # Try System events
    if channel == "System" or any(x in provider for x in ["Kernel", "DCOM", "Service", "NTFS", "disk"]):
        if event_id in SYSTEM_EVENT_TYPES:
            return SYSTEM_EVENT_TYPES[event_id]
    
    # Try Application events
    if channel == "Application" or any(x in provider for x in ["Application", "Error", "MsiInstaller", ".NET"]):
        if event_id in APPLICATION_EVENT_TYPES:
            return APPLICATION_EVENT_TYPES[event_id]
    
    # Fallback: check all mappings
    if event_id in SECURITY_EVENT_TYPES:
        return SECURITY_EVENT_TYPES[event_id]
    if event_id in SYSTEM_EVENT_TYPES:
        return SYSTEM_EVENT_TYPES[event_id]
    if event_id in APPLICATION_EVENT_TYPES:
        return APPLICATION_EVENT_TYPES[event_id]
    
    # Final fallback with correct channel name
    return f"{channel} Event {event_id}"


def parse_timestamp(time_str: Optional[str]) -> datetime:
    """
    Parse timestamp from various formats to datetime.
    
    Supports:
    - ISO 8601 formats
    - .NET JSON format: /Date(milliseconds)/ or /Date(milliseconds+offset)/
    - Unix timestamps (seconds or milliseconds)
    
    Args:
        time_str: Timestamp string in various formats
        
    Returns:
        datetime object in UTC
    """
    if not time_str:
        return datetime.utcnow()
    
    # Handle .NET JSON date format: /Date(1764380242011)/ or /Date(1764380242011+0000)/
    dotnet_match = re.match(r'/Date\((\d+)([+-]\d+)?\)/', str(time_str))
    if dotnet_match:
        try:
            milliseconds = int(dotnet_match.group(1))
            # Convert milliseconds to seconds
            return datetime.utcfromtimestamp(milliseconds / 1000.0)
        except (ValueError, OSError, OverflowError) as e:
            logger.warning(f"Invalid .NET timestamp value: {time_str} - {e}")
            return datetime.utcnow()
    
    # Handle pure numeric timestamps (Unix epoch)
    if isinstance(time_str, (int, float)):
        try:
            # If it's too large, it's probably milliseconds
            if time_str > 10000000000:
                return datetime.utcfromtimestamp(time_str / 1000.0)
            return datetime.utcfromtimestamp(time_str)
        except (ValueError, OSError, OverflowError):
            return datetime.utcnow()
    
    # Check if it's a numeric string
    if isinstance(time_str, str) and time_str.isdigit():
        try:
            ts = int(time_str)
            if ts > 10000000000:
                return datetime.utcfromtimestamp(ts / 1000.0)
            return datetime.utcfromtimestamp(ts)
        except (ValueError, OSError, OverflowError):
            pass
    
    # Try multiple string formats
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(str(time_str), fmt)
        except ValueError:
            continue
    
    # If all else fails, return current time
    logger.warning(f"Could not parse timestamp: {time_str}")
    return datetime.utcnow()


def parse_level(level_str: Optional[str]) -> EventLevel:
    """
    Parse event level string to EventLevel enum.
    """
    if not level_str:
        return EventLevel.INFORMATION
    
    level_lower = level_str.lower()
    
    if "error" in level_lower:
        return EventLevel.ERROR
    elif "warning" in level_lower or "warn" in level_lower:
        return EventLevel.WARNING
    elif "critical" in level_lower or "crit" in level_lower:
        return EventLevel.CRITICAL
    elif "verbose" in level_lower or "debug" in level_lower:
        return EventLevel.VERBOSE
    elif "info" in level_lower:
        return EventLevel.INFORMATION
    
    return EventLevel.UNKNOWN


def extract_from_message(message: str, pattern: str) -> Optional[str]:
    """
    Extract a value from the Message field using regex.
    
    Args:
        message: The raw message text
        pattern: Regex pattern with a capture group
        
    Returns:
        Captured value or None
    """
    if not message:
        return None
    
    match = re.search(pattern, message, re.IGNORECASE | re.MULTILINE)
    if match:
        return match.group(1).strip()
    return None


def extract_user_from_event(raw: dict) -> str:
    """
    Extract user information from various event fields.
    """
    # First, try to extract from Message field (most reliable for Sysmon)
    message = raw.get("Message", "")
    
    # Pattern: "User: DOMAIN\username" or "User: username"
    user_match = extract_from_message(message, r"\\nUser:\s*(.+?)(?:\r|\n|$)")
    if user_match and user_match != "N/A" and user_match != "-":
        return user_match
    
    # Also try without the \n prefix
    user_match = extract_from_message(message, r"User:\s*(.+?)(?:\r|\n|$)")
    if user_match and user_match != "N/A" and user_match != "-":
        return user_match
    
    # Try direct fields, but skip if it's a dict/SID object
    user = raw.get("User") or raw.get("AccountName")
    
    if user and not isinstance(user, dict) and user != "N/A":
        return str(user)
    
    # Try to extract from UserId if it's a simple string
    user_id = raw.get("UserId")
    if user_id and isinstance(user_id, str) and not user_id.startswith("S-"):
        return user_id
    
    # If UserId is a dict with a Value field (SID), try to resolve it
    if isinstance(user_id, dict):
        sid_value = user_id.get("Value", "")
        # Common SIDs
        sid_map = {
            "S-1-5-18": "NT AUTHORITY\\SYSTEM",
            "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
            "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE",
        }
        if sid_value in sid_map:
            return sid_map[sid_value]
    
    # Pattern: Account Name in Properties
    properties = raw.get("Properties", [])
    if isinstance(properties, list):
        for prop in properties:
            if isinstance(prop, dict):
                if "User" in str(prop.get("Name", "")):
                    return str(prop.get("Value", "unknown"))
    
    return "unknown"


def extract_process_info(raw: dict) -> dict:
    """
    Extract process-related information from event.
    
    Returns dict with: process_name, process_id, parent_process_name,
    parent_process_id, image_path, command_line
    """
    result = {
        "process_name": None,
        "process_id": None,
        "parent_process_name": None,
        "parent_process_id": None,
        "image_path": None,
        "command_line": None
    }
    
    message = raw.get("Message", "")
    
    # Extract Image (process path)
    image = extract_from_message(message, r"Image:\s*(.+?)(?:\r|\n|$)")
    if image:
        result["image_path"] = image
        # Extract process name from path
        result["process_name"] = image.split("\\")[-1] if "\\" in image else image.split("/")[-1]
    
    # Extract ProcessId
    pid_str = extract_from_message(message, r"ProcessId:\s*(\d+)")
    if pid_str:
        try:
            result["process_id"] = int(pid_str)
        except ValueError:
            pass
    
    # Extract ParentImage
    parent_image = extract_from_message(message, r"ParentImage:\s*(.+?)(?:\r|\n|$)")
    if parent_image:
        result["parent_process_name"] = parent_image.split("\\")[-1] if "\\" in parent_image else parent_image.split("/")[-1]
    
    # Extract ParentProcessId
    ppid_str = extract_from_message(message, r"ParentProcessId:\s*(\d+)")
    if ppid_str:
        try:
            result["parent_process_id"] = int(ppid_str)
        except ValueError:
            pass
    
    # Extract CommandLine
    cmd_line = extract_from_message(message, r"CommandLine:\s*(.+?)(?:\r|\n|$)")
    if cmd_line:
        result["command_line"] = cmd_line
    
    # Also check direct fields (some agents send structured data)
    if not result["image_path"]:
        result["image_path"] = raw.get("Image") or raw.get("ImagePath") or raw.get("NewProcessName")
    if not result["process_id"]:
        result["process_id"] = raw.get("ProcessId") or raw.get("ProcessID") or raw.get("NewProcessId")
    if not result["command_line"]:
        result["command_line"] = raw.get("CommandLine") or raw.get("Process Command Line")
    
    # Security event 4688 specific fields
    event_id = raw.get("EventID")
    if event_id == 4688:
        new_process_name = raw.get("NewProcessName", raw.get("Process Name", ""))
        if new_process_name and not result["process_name"]:
            result["image_path"] = new_process_name
            result["process_name"] = new_process_name.split("\\")[-1] if "\\" in new_process_name else new_process_name.split("/")[-1]
        
        # Try to extract command line from message for 4688
        if not result["command_line"]:
            cmd_from_msg = extract_from_message(raw.get("Message", ""), r"Process Command Line:\s*(.+?)(?:\r|\n|$)")
            if cmd_from_msg:
                result["command_line"] = cmd_from_msg
    
    return result


def extract_network_info(raw: dict) -> dict:
    """
    Extract network-related information from event.
    """
    result = {
        "source_ip": None,
        "source_port": None,
        "dest_ip": None,
        "dest_port": None
    }
    
    message = raw.get("Message", "")
    
    # Source IP and Port
    src_ip = extract_from_message(message, r"SourceIp:\s*(.+?)(?:\r|\n|$)")
    if src_ip:
        result["source_ip"] = src_ip
    
    src_port = extract_from_message(message, r"SourcePort:\s*(\d+)")
    if src_port:
        try:
            result["source_port"] = int(src_port)
        except ValueError:
            pass
    
    # Destination IP and Port
    dst_ip = extract_from_message(message, r"DestinationIp:\s*(.+?)(?:\r|\n|$)")
    if dst_ip:
        result["dest_ip"] = dst_ip
    
    dst_port = extract_from_message(message, r"DestinationPort:\s*(\d+)")
    if dst_port:
        try:
            result["dest_port"] = int(dst_port)
        except ValueError:
            pass
    
    return result


def extract_file_info(raw: dict) -> dict:
    """
    Extract file-related information from event.
    """
    result = {
        "target_filename": None,
        "file_hash": None
    }
    
    message = raw.get("Message", "")
    
    # Target filename
    target = extract_from_message(message, r"TargetFilename:\s*(.+?)(?:\r|\n|$)")
    if target:
        result["target_filename"] = target
    
    # File hash (try multiple hash types)
    for hash_type in ["SHA256", "SHA1", "MD5", "Hashes"]:
        hash_val = extract_from_message(message, rf"{hash_type}[=:]\s*([A-Fa-f0-9]+)")
        if hash_val:
            result["file_hash"] = hash_val
            break
    
    return result


def extract_sysmon_specific_fields(raw: dict, event_id: int) -> dict:
    """
    Extract Sysmon-specific fields based on event ID.
    
    Handles:
    - ID 8 (CreateRemoteThread): SourceImage, TargetImage, StartAddress, StartModule, StartFunction, NewThreadId
    - ID 10 (ProcessAccess): SourceImage, TargetImage, GrantedAccess, CallTrace
    - ID 12/13/14 (Registry): TargetObject, Details
    """
    result = {
        "source_image": None,
        "target_image": None,
        "granted_access": None,
        "call_trace": None,
        "start_address": None,
        "start_module": None,
        "start_function": None,
        "new_thread_id": None,
        "target_object": None,
        "registry_details": None,
    }
    
    message = raw.get("Message", "")
    
    # Extract SourceImage (used by ID 8, 10)
    source_image = extract_from_message(message, r"SourceImage:\s*(.+?)(?:\r|\n|$)")
    if source_image:
        result["source_image"] = source_image
    elif raw.get("SourceImage"):
        result["source_image"] = raw.get("SourceImage")
    
    # Extract TargetImage (used by ID 8, 10)
    target_image = extract_from_message(message, r"TargetImage:\s*(.+?)(?:\r|\n|$)")
    if target_image:
        result["target_image"] = target_image
    elif raw.get("TargetImage"):
        result["target_image"] = raw.get("TargetImage")
    
    # ID 10 (ProcessAccess) specific fields
    if event_id == 10:
        # GrantedAccess - hex value like 0x1410
        granted_access = extract_from_message(message, r"GrantedAccess:\s*(0x[0-9A-Fa-f]+|[0-9]+)")
        if granted_access:
            result["granted_access"] = granted_access
        elif raw.get("GrantedAccess"):
            result["granted_access"] = raw.get("GrantedAccess")
        
        # CallTrace
        call_trace = extract_from_message(message, r"CallTrace:\s*(.+?)(?:\r|\n|$)")
        if call_trace:
            result["call_trace"] = call_trace
        elif raw.get("CallTrace"):
            result["call_trace"] = raw.get("CallTrace")
    
    # ID 8 (CreateRemoteThread) specific fields - NOTE: does NOT have GrantedAccess
    if event_id == 8:
        # StartAddress
        start_address = extract_from_message(message, r"StartAddress:\s*(0x[0-9A-Fa-f]+|[0-9]+)")
        if start_address:
            result["start_address"] = start_address
        elif raw.get("StartAddress"):
            result["start_address"] = raw.get("StartAddress")
        
        # StartModule
        start_module = extract_from_message(message, r"StartModule:\s*(.+?)(?:\r|\n|$)")
        if start_module:
            result["start_module"] = start_module
        elif raw.get("StartModule"):
            result["start_module"] = raw.get("StartModule")
        
        # StartFunction
        start_function = extract_from_message(message, r"StartFunction:\s*(.+?)(?:\r|\n|$)")
        if start_function:
            result["start_function"] = start_function
        elif raw.get("StartFunction"):
            result["start_function"] = raw.get("StartFunction")
        
        # NewThreadId
        new_thread_id = extract_from_message(message, r"NewThreadId:\s*(\d+)")
        if new_thread_id:
            try:
                result["new_thread_id"] = int(new_thread_id)
            except ValueError:
                pass
        elif raw.get("NewThreadId"):
            try:
                result["new_thread_id"] = int(raw.get("NewThreadId"))
            except (ValueError, TypeError):
                pass
    
    # ID 12/13/14 (Registry) specific fields
    if event_id in (12, 13, 14):
        # TargetObject (registry key path)
        target_object = extract_from_message(message, r"TargetObject:\s*(.+?)(?:\r|\n|$)")
        if target_object:
            result["target_object"] = target_object
        elif raw.get("TargetObject"):
            result["target_object"] = raw.get("TargetObject")
        
        # Details (registry value for ID 13)
        if event_id == 13:
            details = extract_from_message(message, r"Details:\s*(.+?)(?:\r|\n|$)")
            if details:
                result["registry_details"] = details
            elif raw.get("Details"):
                result["registry_details"] = raw.get("Details")
    
    return result


def create_message_summary(event_id: int, raw: dict, process_info: dict) -> str:
    """
    Create a human-readable summary message for the event.
    """
    event_type = SYSMON_EVENT_TYPES.get(event_id, f"Event {event_id}")
    
    parts = [event_type]
    
    if process_info.get("process_name"):
        parts.append(f"- {process_info['process_name']}")
    
    # Add context based on event type
    message = raw.get("Message", "")
    
    if event_id == 1:  # Process Creation
        cmd = process_info.get("command_line", "")
        if cmd and len(cmd) > 100:
            cmd = cmd[:100] + "..."
        if cmd:
            parts.append(f"[{cmd}]")
    
    elif event_id == 3:  # Network Connection
        network = extract_network_info(raw)
        if network.get("dest_ip"):
            parts.append(f"-> {network['dest_ip']}:{network.get('dest_port', '?')}")
    
    elif event_id in [11, 23, 26]:  # File events
        file_info = extract_file_info(raw)
        if file_info.get("target_filename"):
            fn = file_info["target_filename"]
            if len(fn) > 60:
                fn = "..." + fn[-60:]
            parts.append(f"[{fn}]")
    
    elif event_id == 22:  # DNS Query
        query = extract_from_message(message, r"QueryName:\s*(.+?)(?:\r|\n|$)")
        if query:
            parts.append(f"[{query}]")
    
    return " ".join(parts)


def determine_category(provider: str, event_id: int) -> EventCategory:
    """
    Determine the event category based on provider and event ID.
    """
    # Windows Security events
    if provider == "Microsoft-Windows-Security-Auditing":
        # Authentication events
        if event_id in (4624, 4625, 4634, 4647, 4648, 4672, 4776):
            return EventCategory.AUTH
        # Account management
        elif event_id in (4720, 4722, 4724, 4725, 4726, 4738, 4740):
            return EventCategory.AUTH
        # Process events from Security log
        elif event_id in (4688, 4689, 4697):
            return EventCategory.PROCESS
        # Network/Firewall events
        elif event_id in (5025, 5152, 5153, 5156, 5157):
            return EventCategory.NETWORK
        # File/Object access
        elif event_id in (4663, 4656):
            return EventCategory.FILE
    
    # Sysmon events
    if "Sysmon" in provider:
        if event_id == 1:  # Process Create
            return EventCategory.PROCESS
        elif event_id == 3:  # Network Connection
            return EventCategory.NETWORK
        elif event_id in (11, 15, 23, 26):  # File events
            return EventCategory.FILE
        elif event_id in (12, 13, 14):  # Registry events
            return EventCategory.REGISTRY
        elif event_id in (5, 7, 8, 10):  # Process-related
            return EventCategory.PROCESS
    
    return EventCategory.OTHER


def derive_action_type(event_id: int, channel: str, provider: str) -> Optional[str]:
    """
    Derive action_type from event ID, channel, and provider.
    
    Returns action types like: lock, unlock, logon, logoff, ps_scriptblock, 
    defender_alert, firewall_change, task_created, wmi_exec, usb_insert, 
    rdp_connect, etc.
    """
    # Lock/Unlock events (CRITICAL for UEBA)
    if event_id == 4800:
        return "lock"
    elif event_id == 4801:
        return "unlock"
    
    # Authentication events
    if event_id == 4624:
        return "logon"
    elif event_id == 4625:
        return "logon_failed"
    elif event_id in (4634, 4647):
        return "logoff"
    elif event_id == 4672:
        return "special_logon"
    
    # PowerShell events (4100-4106 are common script block events)
    if "PowerShell" in channel or "PowerShell" in provider:
        if 4103 <= event_id <= 4106:
            return "ps_scriptblock"
        elif event_id == 4100:
            return "ps_runspace"
        elif event_id == 4101:
            return "ps_module"
        elif event_id >= 4100:
            return "ps_activity"
    
    # Defender events (1000-3000+ are alerts, 5000+ are config)
    if "Defender" in channel or "Defender" in provider:
        if 1000 <= event_id < 5000:
            return "defender_alert"
        elif event_id >= 5000:
            return "defender_config_change"
    
    # Firewall events (2000+ are firewall changes, 5000+ are filters)
    if "Firewall" in channel or "Firewall" in provider:
        if 2000 <= event_id < 3000:
            return "firewall_change"
        elif event_id in (5025, 5152, 5153, 5156, 5157):
            return "firewall_filter"
    
    # Task Scheduler events
    if "TaskScheduler" in channel or "TaskScheduler" in provider:
        if 100 <= event_id < 200:
            return "task_created"
        elif 200 <= event_id < 300:
            return "task_executed"
        elif 300 <= event_id < 400:
            return "task_deleted"
        elif 400 <= event_id < 500:
            return "task_updated"
    
    # WMI events (5857-5863 are common)
    if "WMI" in channel or "WMI" in provider:
        if 5857 <= event_id <= 5863:
            if event_id in (5859, 5860, 5861):
                return "wmi_consumer"
            elif event_id in (5861, 5862, 5863):
                return "wmi_filter"
            else:
                return "wmi_exec"
        elif event_id >= 5850:
            return "wmi_activity"
    
    # RDP/Terminal Services events
    if "TerminalServices" in channel or "TerminalServices" in provider:
        if 20 <= event_id < 200:
            return "rdp_connect"
        elif 200 <= event_id < 300:
            return "rdp_disconnect"
        elif event_id < 20:
            return "rdp_session"
    
    # BITS events (1-100 are common download events)
    if "Bits" in channel or "Bits" in provider:
        if 1 <= event_id <= 100:
            return "bits_download"
        elif event_id > 100:
            return "bits_activity"
    
    # AppLocker events (8000+)
    if "AppLocker" in channel or "AppLocker" in provider:
        if 8002 <= event_id <= 8007:
            return "applocker_block"
        elif event_id >= 8000:
            return "applocker_audit"
    
    # Code Integrity events (3000+)
    if "CodeIntegrity" in channel or "CodeIntegrity" in provider:
        if event_id >= 3000:
            return "code_integrity_block"
    
    # USB/Device events (from System log - event IDs vary by Windows version)
    # Common patterns: 20001-20100 for insert, 21001-21100 for remove
    if channel == "System":
        if 20000 <= event_id < 20100:
            return "usb_insert"
        elif 21000 <= event_id < 21100:
            return "usb_remove"
        elif event_id in (20001, 20002, 20003, 20004, 20005, 20006, 20007, 20008, 20009, 20010):
            return "device_insert"
        elif event_id in (21001, 21002, 21003, 21004, 21005, 21006, 21007, 21008, 21009, 21010):
            return "device_remove"
    
    return None


def normalize_security_event(raw: dict, raw_json: str, source: EventSource = EventSource.WINDOWS_EVENT) -> NormalizedEvent:
    """
    Normalize a Windows Security event (4624/4625/etc.) into a NormalizedEvent.
    
    Args:
        raw: Parsed JSON dictionary from the Windows agent
        raw_json: Original JSON string
        source: Event source type (defaults to WINDOWS_EVENT)
        
    Returns:
        NormalizedEvent object with auth fields populated
    """
    # Extract timestamp
    timestamp = parse_timestamp(
        raw.get("TimeCreated") or 
        raw.get("timestamp") or 
        raw.get("@timestamp")
    )
    
    # Host
    host = raw.get("MachineName") or raw.get("Computer") or raw.get("host") or "unknown"
    
    # Event ID
    event_id = raw.get("Id") or raw.get("EventID") or raw.get("event_id") or 0
    if isinstance(event_id, str):
        try:
            event_id = int(event_id)
        except ValueError:
            event_id = 0
    
    # Provider
    provider = raw.get("ProviderName") or raw.get("Provider") or "Microsoft-Windows-Security-Auditing"
    
    # Level
    level = parse_level(raw.get("LevelDisplayName") or raw.get("Level"))
    
    # User - try multiple fields
    user = (
        raw.get("TargetUserName") or 
        raw.get("User") or 
        raw.get("AccountName") or 
        "unknown"
    )
    
    # Add domain if available
    domain = raw.get("TargetDomainName") or raw.get("SubjectDomainName")
    if domain and domain != "-" and "\\" not in user:
        user = f"{domain}\\{user}"
    
    # Source IP
    source_ip = raw.get("IpAddress") or raw.get("SourceNetworkAddress")
    if source_ip in ("-", "::1", "127.0.0.1", None, ""):
        source_ip = None
    
    # Workstation
    workstation = raw.get("WorkstationName") or raw.get("Workstation")
    if workstation in ("-", None, ""):
        workstation = None
    
    # Logon Type
    logon_type = raw.get("LogonType")
    if logon_type is not None:
        try:
            logon_type = int(logon_type)
        except (ValueError, TypeError):
            logon_type = None
    
    # Auth Result and subcategory based on event type
    auth_result = AuthResult.UNKNOWN
    
    # Authentication events
    if event_id == 4624:
        auth_result = AuthResult.SUCCESS
        subcategory = "logon_success"
    elif event_id == 4625:
        auth_result = AuthResult.FAILED
        subcategory = "logon_failed"
    elif event_id in (4634, 4647):
        subcategory = "logoff"
    elif event_id == 4672:
        subcategory = "special_privileges"
    elif event_id == 4648:
        subcategory = "explicit_credential"
    elif event_id == 4776:
        subcategory = "ntlm_auth"
    # Account management events
    elif event_id == 4720:
        subcategory = "account_created"
    elif event_id == 4722:
        subcategory = "account_enabled"
    elif event_id == 4724:
        subcategory = "password_reset"
    elif event_id == 4725:
        subcategory = "account_disabled"
    elif event_id == 4726:
        subcategory = "account_deleted"
    elif event_id == 4738:
        subcategory = "account_changed"
    elif event_id == 4740:
        subcategory = "account_lockout"
    # Process/Service events
    elif event_id == 4688:
        subcategory = "process_created"
    elif event_id == 4689:
        subcategory = "process_exited"
    elif event_id == 4697:
        subcategory = "service_installed"
    # Security policy events
    elif event_id in (4719, 4907):
        subcategory = "audit_policy_changed"
    # Firewall events
    elif event_id == 5025:
        subcategory = "firewall_stopped"
    elif event_id in (5152, 5153, 5156, 5157):
        subcategory = "firewall_filter"
    # Scheduled task events
    elif event_id in (4698, 4699, 4702):
        subcategory = "scheduled_task"
    # Object access events
    elif event_id in (4663, 4656):
        subcategory = "object_access"
    else:
        subcategory = "other_security"
    
    # Failure reason (for 4625)
    failure_reason = raw.get("FailureReason") or raw.get("Status")
    
    # Extract metadata from envelope or event
    channel = raw.get("Channel") or raw.get("LogName") or get_channel_from_provider(provider)
    record_id = raw.get("RecordId") or raw.get("record_id")
    if isinstance(record_id, str):
        try:
            record_id = int(record_id)
        except ValueError:
            record_id = None
    
    # Extract user SID and logon ID from properties or direct fields
    user_sid = raw.get("TargetUserSid") or raw.get("SubjectUserSid") or raw.get("UserSid")
    logon_id = raw.get("TargetLogonId") or raw.get("SubjectLogonId") or raw.get("LogonId")
    if logon_id:
        logon_id = str(logon_id)
    
    # Extract task and keywords
    task = raw.get("Task")
    keywords = raw.get("Keywords") or raw.get("KeywordsDisplayNames")
    if isinstance(keywords, list):
        keywords = ", ".join(str(k) for k in keywords)
    elif keywords:
        keywords = str(keywords)
    
    # Derive action_type
    action_type = derive_action_type(event_id, channel, provider)
    
    # Create message summary - use correct channel name
    channel_name = channel
    event_desc = get_event_description(event_id, provider, channel_name)
    logon_desc = LOGON_TYPES.get(logon_type, f"Type {logon_type}") if logon_type else ""
    
    # Build informative message based on event type
    if event_id == 4800:
        msg_parts = [f"Workstation locked: {user}"]
    elif event_id == 4801:
        msg_parts = [f"Workstation unlocked: {user}"]
    elif event_id == 4624:
        msg_parts = [f"Successful logon: {user}"]
        if logon_desc:
            msg_parts.append(f"({logon_desc})")
        if source_ip:
            msg_parts.append(f"from {source_ip}")
    elif event_id == 4625:
        msg_parts = [f"Failed logon: {user}"]
        if logon_desc:
            msg_parts.append(f"({logon_desc})")
        if source_ip:
            msg_parts.append(f"from {source_ip}")
        if failure_reason:
            msg_parts.append(f"- {failure_reason}")
    elif event_id == 4688:
        # Process created - try to extract process info from raw data
        process_name = raw.get("NewProcessName", raw.get("Process Name", ""))
        if process_name:
            msg_parts = [f"Process created: {process_name.split(chr(92))[-1]}"]
        else:
            msg_parts = [event_desc, f"- {user}"]
    elif event_id == 4697:
        # Service installed
        service_name = raw.get("ServiceName", raw.get("Service Name", ""))
        msg_parts = [f"Service installed: {service_name}" if service_name else event_desc]
        msg_parts.append(f"by {user}")
    elif event_id in (5025, 5156, 5157):
        # Firewall events
        msg_parts = [event_desc]
    elif event_id in (4720, 4722, 4725, 4726, 4738, 4740):
        # Account management events
        target_user = raw.get("TargetUserName", user)
        msg_parts = [f"{event_desc}: {target_user}"]
    else:
        msg_parts = [event_desc, f"- {user}"]
    
    message = " ".join(msg_parts)
    
    # Determine category based on event type
    category = determine_category(provider, event_id)
    
    return NormalizedEvent(
        timestamp=timestamp,
        source=source,
        host=str(host),
        user=str(user),
        event_id=event_id,
        level=level,
        provider=str(provider),
        category=category,
        subcategory=subcategory,
        source_ip=source_ip,
        workstation=workstation,
        auth_result=auth_result,
        logon_type=logon_type,
        failure_reason=failure_reason if event_id == 4625 else None,
        message=message,
        raw_json=raw_json[:10000] if raw_json else None,
        # Maximum telemetry fields
        channel=channel,
        record_id=record_id,
        user_sid=user_sid,
        logon_id=logon_id,
        action_type=action_type,
        task=task,
        keywords=keywords
    )


def normalize_sysmon_event(raw: dict, raw_json: str, source: EventSource = EventSource.SYSMON) -> NormalizedEvent:
    """
    Normalize a Sysmon event into a NormalizedEvent.
    
    Args:
        raw: Parsed JSON dictionary from the Windows agent
        raw_json: Original JSON string
        source: Event source type (defaults to SYSMON)
        
    Returns:
        NormalizedEvent object
    """
    # Extract basic fields
    timestamp = parse_timestamp(
        raw.get("TimeCreated") or 
        raw.get("timestamp") or 
        raw.get("@timestamp")
    )
    
    host = raw.get("MachineName") or raw.get("Computer") or raw.get("host") or "unknown"
    user = extract_user_from_event(raw)
    
    # Event ID
    event_id = raw.get("Id") or raw.get("EventID") or raw.get("event_id") or 0
    if isinstance(event_id, str):
        try:
            event_id = int(event_id)
        except ValueError:
            event_id = 0
    
    # Level
    level = parse_level(
        raw.get("LevelDisplayName") or 
        raw.get("Level") or 
        raw.get("level")
    )
    
    # Provider
    provider = raw.get("ProviderName") or raw.get("Provider") or "Microsoft-Windows-Sysmon"
    
    # Determine category
    category = determine_category(provider, event_id)
    
    # Determine subcategory based on Sysmon Event ID
    subcategory_map = {
        1: "process_create",
        5: "process_terminate",
        10: "process_access",
        7: "image_load",
        8: "create_remote_thread",
        3: "connection",
        22: "dns_query",
        11: "file_create",
        15: "file_stream_create",
        23: "file_delete",
        26: "file_delete_detected",
        12: "registry_create_delete",
        13: "registry_value_set",
        14: "registry_rename",
    }
    subcategory = subcategory_map.get(event_id, "other")
    
    # Extract detailed information
    process_info = extract_process_info(raw)
    network_info = extract_network_info(raw)
    file_info = extract_file_info(raw)
    sysmon_info = extract_sysmon_specific_fields(raw, event_id)
    
    # Create summary message
    message = create_message_summary(event_id, raw, process_info)
    
    # Extract metadata from envelope or event
    channel = raw.get("Channel") or raw.get("LogName") or "Microsoft-Windows-Sysmon/Operational"
    record_id = raw.get("RecordId") or raw.get("record_id")
    if isinstance(record_id, str):
        try:
            record_id = int(record_id)
        except ValueError:
            record_id = None
    
    # Extract task and keywords
    task = raw.get("Task")
    keywords = raw.get("Keywords") or raw.get("KeywordsDisplayNames")
    if isinstance(keywords, list):
        keywords = ", ".join(str(k) for k in keywords)
    elif keywords:
        keywords = str(keywords)
    
    # Derive action_type for Sysmon events
    action_type = None  # Sysmon events use subcategory instead
    
    # Build normalized event
    return NormalizedEvent(
        timestamp=timestamp,
        source=source,
        host=str(host),
        user=str(user),
        event_id=event_id,
        level=level,
        provider=str(provider),
        category=category,
        subcategory=subcategory,
        process_name=process_info.get("process_name"),
        process_id=process_info.get("process_id"),
        parent_process_name=process_info.get("parent_process_name"),
        parent_process_id=process_info.get("parent_process_id"),
        image_path=process_info.get("image_path"),
        command_line=process_info.get("command_line"),
        source_ip=network_info.get("source_ip"),
        source_port=network_info.get("source_port"),
        dest_ip=network_info.get("dest_ip"),
        dest_port=network_info.get("dest_port"),
        target_filename=file_info.get("target_filename"),
        file_hash=file_info.get("file_hash"),
        message=message,
        raw_json=raw_json[:10000] if raw_json else None,
        # Maximum telemetry fields
        channel=channel,
        record_id=record_id,
        task=task,
        keywords=keywords,
        action_type=action_type,
        # Sysmon-specific fields
        source_image=sysmon_info.get("source_image"),
        target_image=sysmon_info.get("target_image"),
        granted_access=sysmon_info.get("granted_access"),
        call_trace=sysmon_info.get("call_trace"),
        start_address=sysmon_info.get("start_address"),
        start_module=sysmon_info.get("start_module"),
        start_function=sysmon_info.get("start_function"),
        new_thread_id=sysmon_info.get("new_thread_id"),
        target_object=sysmon_info.get("target_object"),
        registry_details=sysmon_info.get("registry_details"),
    )


def parse_envelope(raw_json: str) -> tuple[str, dict, str]:
    """
    Parse the event envelope to extract source and event data.
    
    Handles both new envelope format:
        {"source": "sysmon", "event": {...}}
    
    And legacy format (raw event without envelope):
        {"Id": 1, "TimeCreated": "...", ...}
    
    Args:
        raw_json: Raw JSON string from the Windows agent
        
    Returns:
        Tuple of (source_type, event_dict, original_json)
    """
    try:
        parsed = json.loads(raw_json)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON: {e}")
        raise
    
    # Check if this is the new envelope format (enhanced with metadata)
    if isinstance(parsed, dict) and "source" in parsed and "event" in parsed:
        # New envelope format - merge envelope metadata into event data
        source = parsed["source"]
        event_data = parsed["event"].copy() if isinstance(parsed["event"], dict) else parsed["event"]
        
        # Merge envelope-level metadata into event data for normalization
        if isinstance(event_data, dict):
            # Channel, provider, record_id, etc. from envelope
            if "channel" in parsed:
                event_data["Channel"] = parsed["channel"]
            if "provider" in parsed:
                event_data["ProviderName"] = parsed["provider"]
            if "event_id" in parsed:
                event_data["Id"] = parsed["event_id"]
            if "record_id" in parsed:
                event_data["RecordId"] = parsed["record_id"]
            if "computer" in parsed:
                event_data["MachineName"] = parsed["computer"]
            if "timestamp_utc" in parsed:
                event_data["TimeCreated"] = parsed["timestamp_utc"]
        
        return source, event_data, raw_json
    
    # Legacy format - try to determine source from event content
    # Check for old-style Source field added by agent
    old_source = parsed.get("Source", "").upper()
    
    # Linux event sources
    if old_source in ("JOURNALCTL", "LINUX_JOURNAL"):
        return "linux_journal", parsed, raw_json
    elif old_source in ("AUTH_LOG", "LINUX_AUTH"):
        return "linux_auth", parsed, raw_json
    elif old_source in ("SYSLOG", "LINUX_SYSLOG"):
        return "linux_syslog", parsed, raw_json
    elif old_source in ("AUDITD", "LINUX_AUDIT"):
        return "linux_audit", parsed, raw_json
    elif old_source == "LINUX_EVENT":
        # Generic Linux event - try to determine specific source
        if parsed.get("__CURSOR"):  # journalctl marker
            return "linux_journal", parsed, raw_json
        elif parsed.get("ProcessName") in ("sshd", "sudo", "su", "login"):
            return "linux_auth", parsed, raw_json
        return "linux_syslog", parsed, raw_json
    
    # Windows event sources
    if old_source in ("WINDOWS_SECURITY", "WINDOWS_EVENT", "WINDOWS_APPLICATION", "WINDOWS_SYSTEM"):
        return "windows_event", parsed, raw_json
    elif old_source == "SYSMON":
        return "sysmon", parsed, raw_json
    
    # Try to determine from provider
    provider = parsed.get("ProviderName") or parsed.get("Provider") or ""
    if "Sysmon" in provider:
        return "sysmon", parsed, raw_json
    elif provider == "Microsoft-Windows-Security-Auditing":
        return "windows_event", parsed, raw_json
    # Any other Windows event source should be treated as windows_event
    elif provider.startswith("Microsoft-Windows"):
        return "windows_event", parsed, raw_json
    
    # Check for Linux-specific fields
    if parsed.get("__CURSOR") or parsed.get("_HOSTNAME") or parsed.get("SYSLOG_IDENTIFIER"):
        return "linux_journal", parsed, raw_json
    
    # Default to windows_event for better catchall
    return "windows_event", parsed, raw_json


def normalize_event(raw_json: str) -> Optional[NormalizedEvent]:
    """
    Normalize a raw JSON event into a NormalizedEvent.
    
    This is the main entry point for the Normalization Layer.
    Routes to appropriate handler based on event source/provider.
    
    Supports:
    - Windows events: {"source": "sysmon"|"windows_event", "event": {...}}
    - Linux events: {"Source": "JOURNALCTL"|"AUTH_LOG"|"SYSLOG"|"AUDITD", ...}
    
    Args:
        raw_json: Raw JSON string from agent
        
    Returns:
        NormalizedEvent object, or None if parsing fails completely
    """
    try:
        source_type, event_data, original_json = parse_envelope(raw_json)
    except json.JSONDecodeError as e:
        # Create a minimal event for unparseable data
        return NormalizedEvent(
            timestamp=datetime.utcnow(),
            source=EventSource.UNKNOWN,
            host="unknown",
            user="unknown",
            event_id=0,
            level=EventLevel.ERROR,
            provider="unknown",
            category=EventCategory.OTHER,
            message=f"JSON Parse Error: {str(e)[:100]}",
            raw_json=raw_json[:5000] if raw_json else None
        )
    
    try:
        # Check for Linux event sources first
        linux_sources = ("JOURNALCTL", "AUTH_LOG", "SYSLOG", "AUDITD", 
                         "linux_journal", "linux_auth", "linux_syslog", "linux_audit")
        source_field = event_data.get("Source", "").upper()
        
        if source_type.startswith("linux") or source_field in linux_sources:
            return normalize_linux_event(event_data, original_json)
        
        # Map source string to EventSource enum for Windows
        if source_type == "windows_event":
            event_source = EventSource.WINDOWS_EVENT
        elif source_type == "sysmon":
            event_source = EventSource.SYSMON
        else:
            event_source = EventSource.SYSMON  # Default fallback
        
        # Get event details for routing
        provider = event_data.get("ProviderName") or event_data.get("Provider") or ""
        event_id = event_data.get("Id") or event_data.get("EventID") or event_data.get("event_id") or 0
        
        if isinstance(event_id, str):
            try:
                event_id = int(event_id)
            except ValueError:
                event_id = 0
        
        # Route to appropriate handler based on source type
        if source_type == "windows_event":
            # Check if it's a Security log event (auth, lock/unlock, etc.)
            channel = event_data.get("Channel") or event_data.get("LogName") or ""
            if channel == "Security" or event_id in (4624, 4625, 4634, 4648, 4672, 4776, 4800, 4801):
                return normalize_security_event(event_data, original_json, event_source)
            else:
                # Generic Windows Event - normalize as security event
                return normalize_security_event(event_data, original_json, event_source)
        
        # Also check provider for backward compatibility (any Security Auditing event)
        if provider == "Microsoft-Windows-Security-Auditing":
            return normalize_security_event(event_data, original_json, EventSource.WINDOWS_EVENT)
        
        # Default: Sysmon handler
        return normalize_sysmon_event(event_data, original_json, event_source)
        
    except Exception as e:
        logger.exception(f"Error normalizing event: {e}")
        # Return a minimal error event
        return NormalizedEvent(
            timestamp=datetime.utcnow(),
            source=EventSource.UNKNOWN,
            host="unknown",
            user="unknown",
            event_id=0,
            level=EventLevel.ERROR,
            provider="unknown",
            category=EventCategory.OTHER,
            message=f"Normalization Error: {str(e)[:100]}",
            raw_json=raw_json[:5000] if raw_json else None
        )


# ============================================
# Linux Event Types
# ============================================

LINUX_AUTH_EVENT_TYPES = {
    "sshd": "SSH Authentication",
    "sudo": "Sudo Command",
    "su": "Switch User",
    "login": "User Login",
    "passwd": "Password Change",
    "useradd": "User Added",
    "userdel": "User Deleted",
    "groupadd": "Group Added",
    "groupdel": "Group Deleted",
}

LINUX_AUDIT_EVENT_TYPES = {
    "SYSCALL": "System Call",
    "EXECVE": "Process Execution",
    "USER_AUTH": "User Authentication",
    "USER_ACCT": "User Account Access",
    "USER_CMD": "User Command",
    "USER_LOGIN": "User Login",
    "USER_LOGOUT": "User Logout",
    "CRED_ACQ": "Credential Acquired",
    "CRED_DISP": "Credential Disposed",
    "USER_START": "User Session Start",
    "USER_END": "User Session End",
    "SERVICE_START": "Service Started",
    "SERVICE_STOP": "Service Stopped",
    "ANOM_LOGIN_FAILURES": "Login Failures Anomaly",
    "ANOM_LOGIN_LOCATION": "Login Location Anomaly",
    "ANOM_LOGIN_TIME": "Login Time Anomaly",
}


def normalize_linux_event(raw: dict, raw_json: str) -> NormalizedEvent:
    """
    Normalize a Linux event into a NormalizedEvent.
    
    Handles events from:
    - journalctl (systemd journal)
    - auth.log / secure
    - syslog / messages
    - auditd
    
    Args:
        raw: Parsed JSON dictionary from the Linux agent
        raw_json: Original JSON string
        
    Returns:
        NormalizedEvent object
    """
    # Determine source type from event
    source_field = raw.get("Source", "").upper()
    
    if source_field == "AUDITD":
        event_source = EventSource.LINUX_AUDIT
    elif source_field == "AUTH_LOG":
        event_source = EventSource.LINUX_AUTH
    elif source_field == "SYSLOG":
        event_source = EventSource.LINUX_SYSLOG
    elif source_field == "JOURNALCTL":
        event_source = EventSource.LINUX_JOURNAL
    else:
        event_source = EventSource.LINUX_SYSLOG
    
    # Extract timestamp
    timestamp = parse_timestamp(
        raw.get("TimeCreated") or 
        raw.get("__REALTIME_TIMESTAMP") or
        raw.get("timestamp") or 
        raw.get("@timestamp")
    )
    
    # Host
    host = (
        raw.get("_HOSTNAME") or 
        raw.get("Hostname") or 
        raw.get("MachineName") or 
        raw.get("host") or 
        "unknown"
    )
    
    # User extraction
    user = (
        raw.get("_UID") or
        raw.get("USER") or
        raw.get("user") or
        raw.get("acct") or
        raw.get("auid") or
        "unknown"
    )
    
    # Try to extract user from message for auth events
    message = raw.get("Message") or raw.get("MESSAGE") or raw.get("RawMessage") or ""
    if user == "unknown" and message:
        # SSH: "Accepted password for username from IP"
        ssh_match = re.search(r"(?:Accepted|Failed)\s+\w+\s+for\s+(\S+)\s+from", message)
        if ssh_match:
            user = ssh_match.group(1)
        # sudo: "username : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/ls"
        sudo_match = re.search(r"^(\S+)\s*:\s*TTY=", message)
        if sudo_match:
            user = sudo_match.group(1)
    
    # Level
    priority = raw.get("PRIORITY") or raw.get("priority")
    if priority is not None:
        try:
            priority = int(priority)
            if priority <= 2:
                level = EventLevel.CRITICAL
            elif priority == 3:
                level = EventLevel.ERROR
            elif priority == 4:
                level = EventLevel.WARNING
            else:
                level = EventLevel.INFORMATION
        except (ValueError, TypeError):
            level = EventLevel.INFORMATION
    else:
        level = parse_level(raw.get("LevelDisplayName") or raw.get("Level"))
    
    # Provider/Unit
    provider = (
        raw.get("SYSLOG_IDENTIFIER") or
        raw.get("_COMM") or
        raw.get("ProcessName") or
        raw.get("Process") or
        raw.get("unit") or
        "linux"
    )
    
    # Event ID (use audit type or generate from provider)
    audit_type = raw.get("AuditType") or raw.get("type")
    if audit_type:
        # Map audit type to numeric ID for consistency
        audit_type_map = {
            "SYSCALL": 1300, "EXECVE": 1309, "USER_AUTH": 1100,
            "USER_ACCT": 1101, "USER_CMD": 1123, "USER_LOGIN": 1112,
            "USER_LOGOUT": 1113, "CRED_ACQ": 1103, "CRED_DISP": 1104,
            "USER_START": 1105, "USER_END": 1106,
            "SERVICE_START": 1130, "SERVICE_STOP": 1131,
        }
        event_id = audit_type_map.get(audit_type, 1000)
    else:
        # Generate event ID from provider hash for categorization
        event_id = abs(hash(provider)) % 10000
    
    # Determine category and subcategory
    category = EventCategory.OTHER
    subcategory = "linux_event"
    auth_result = None
    source_ip = None
    
    # Auth events detection
    if source_field == "AUTH_LOG" or provider in ("sshd", "sudo", "su", "login", "passwd"):
        category = EventCategory.AUTH
        
        if "Accepted" in message:
            auth_result = AuthResult.SUCCESS
            subcategory = "logon_success"
        elif "Failed" in message or "failure" in message.lower():
            auth_result = AuthResult.FAILED
            subcategory = "logon_failed"
        elif "session opened" in message.lower():
            auth_result = AuthResult.SUCCESS
            subcategory = "session_opened"
        elif "session closed" in message.lower():
            subcategory = "session_closed"
        elif provider == "sudo":
            subcategory = "sudo_command"
        
        # Extract source IP from SSH messages
        ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", message)
        if ip_match:
            source_ip = ip_match.group(1)
    
    # Audit events detection
    elif source_field == "AUDITD" or audit_type:
        if audit_type in ("USER_AUTH", "USER_LOGIN", "USER_ACCT", "CRED_ACQ"):
            category = EventCategory.AUTH
            if raw.get("res") == "success" or "success" in message.lower():
                auth_result = AuthResult.SUCCESS
                subcategory = "logon_success"
            elif raw.get("res") == "failed" or "failed" in message.lower():
                auth_result = AuthResult.FAILED
                subcategory = "logon_failed"
            else:
                subcategory = "auth_event"
        elif audit_type in ("EXECVE", "SYSCALL"):
            category = EventCategory.PROCESS
            subcategory = "process_exec"
        elif audit_type in ("SERVICE_START", "SERVICE_STOP"):
            category = EventCategory.PROCESS
            subcategory = "service_change"
    
    # Process info extraction
    process_name = raw.get("_COMM") or raw.get("ProcessName") or raw.get("exe")
    process_id = raw.get("_PID") or raw.get("ProcessId") or raw.get("pid")
    if process_id:
        try:
            process_id = int(process_id)
        except (ValueError, TypeError):
            process_id = None
    
    command_line = raw.get("_CMDLINE") or raw.get("cmd") or raw.get("a0")
    
    # Build summary message
    if audit_type and audit_type in LINUX_AUDIT_EVENT_TYPES:
        summary = f"{LINUX_AUDIT_EVENT_TYPES[audit_type]}: {message[:100]}" if message else LINUX_AUDIT_EVENT_TYPES[audit_type]
    elif provider in LINUX_AUTH_EVENT_TYPES:
        summary = f"{LINUX_AUTH_EVENT_TYPES[provider]}: {message[:100]}" if message else LINUX_AUTH_EVENT_TYPES[provider]
    else:
        summary = message[:200] if message else f"Linux {provider} event"
    
    # Action type derivation
    action_type = None
    if "ssh" in provider.lower():
        if auth_result == AuthResult.SUCCESS:
            action_type = "ssh_login_success"
        elif auth_result == AuthResult.FAILED:
            action_type = "ssh_login_failed"
    elif provider == "sudo":
        action_type = "sudo_command"
    elif provider == "su":
        action_type = "su_command"
    
    return NormalizedEvent(
        timestamp=timestamp,
        source=event_source,
        host=str(host),
        user=str(user),
        event_id=event_id,
        level=level,
        provider=str(provider),
        category=category,
        subcategory=subcategory,
        process_name=process_name,
        process_id=process_id,
        command_line=command_line,
        source_ip=source_ip,
        auth_result=auth_result,
        message=summary,
        raw_json=raw_json[:10000] if raw_json else None,
        action_type=action_type,
    )


def normalize_batch(raw_events: list[str]) -> list[NormalizedEvent]:
    """
    Normalize a batch of raw JSON events.
    
    Args:
        raw_events: List of raw JSON strings
        
    Returns:
        List of NormalizedEvent objects
    """
    results = []
    for raw in raw_events:
        event = normalize_event(raw)
        if event:
            results.append(event)
    return results

