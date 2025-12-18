"""
Process Feature Extraction for UEBA.

Extracts security-relevant features from process execution events.
These features are used by the risk engine for scoring.

Features:
- is_lolbin: Process is a "Living off the Land Binary" commonly abused
- is_suspicious_path: Process runs from suspicious location
- has_obfuscated_cmdline: Command line shows signs of obfuscation
"""

import re
from typing import Dict, Any
from .models import NormalizedEvent


# Living off the Land Binaries (LOLBins)
# These are legitimate Windows binaries often abused by attackers
LOLBINS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wmic.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "cscript.exe",
    "wscript.exe",
    "msiexec.exe",
    "schtasks.exe",
    "at.exe",
    "reg.exe",
    "net.exe",
    "net1.exe",
    "netsh.exe",
    "sc.exe",
    "taskkill.exe",
    "tasklist.exe",
    "whoami.exe",
    "systeminfo.exe",
    "hostname.exe",
    "ipconfig.exe",
    "nslookup.exe",
    "ping.exe",
    "tracert.exe",
    "arp.exe",
    "route.exe",
    "netstat.exe",
    "curl.exe",
    "wget.exe",  # Not native but commonly installed
    "certreq.exe",
    "cmstp.exe",
    "eudcedit.exe",
    "eventvwr.exe",
    "expand.exe",
    "explorer.exe", 
    "findstr.exe",
    "forfiles.exe",
    "ftp.exe",
    "gpscript.exe",
    "hh.exe",
    "ie4uinit.exe",
    "ieexec.exe",
    "infdefaultinstall.exe",
    "installutil.exe",
    "makecab.exe",
    "mavinject.exe",
    "microsoft.workflow.compiler.exe",
    "mmc.exe",
    "msconfig.exe",
    "msdeploy.exe",
    "msdt.exe",
    "msiexec.exe",
    "odbcconf.exe",
    "pcalua.exe",
    "pcwrun.exe",
    "pktmon.exe",
    "psr.exe",
    "rasautou.exe",
    "register-cimprovider.exe",
    "regasm.exe",
    "regedit.exe",
    "regsvcs.exe",
    "replace.exe",
    "rpcping.exe",
    "runscripthelper.exe",
    "scriptrunner.exe",
    "syncappvpublishingserver.exe",
    "ttdinject.exe",
    "tttracer.exe",
    "vbc.exe",
    "verclsid.exe",
    "wab.exe",
    "winrm.cmd",
    "wlrmdr.exe",
    "wuauclt.exe",
    "xwizard.exe",
}

# Suspicious paths where legitimate software rarely runs from
SUSPICIOUS_PATHS = [
    r"\temp\\",
    r"\tmp\\",
    r"\downloads\\",
    r"\appdata\local\temp\\",
    r"\users\public\\",
    r"\programdata\\",
    r"\\windows\\temp\\",
    r"\recycle",
    r"$recycle.bin",
    r"\perflogs\\",
]


def is_lolbin(event: NormalizedEvent) -> bool:
    """
    Check if process is a Living off the Land Binary (LOLBin).
    
    LOLBins are legitimate Windows binaries that can be abused
    for malicious purposes like downloading files, executing code,
    or evading detection.
    
    Args:
        event: NormalizedEvent with process_name field
        
    Returns:
        True if process name matches a known LOLBin
    """
    if not event.process_name:
        return False
    
    process_lower = event.process_name.lower()
    return process_lower in LOLBINS


def is_suspicious_path(event: NormalizedEvent) -> bool:
    """
    Check if process is running from a suspicious path.
    
    Suspicious paths include Temp, Downloads, and other
    user-writable locations that legitimate software rarely uses.
    
    Args:
        event: NormalizedEvent with image_path field
        
    Returns:
        True if process path appears suspicious
    """
    path = event.image_path
    if not path:
        return False
    
    path_lower = path.lower()
    
    for suspicious in SUSPICIOUS_PATHS:
        if suspicious in path_lower:
            return True
    
    return False


def has_obfuscated_cmdline(event: NormalizedEvent) -> bool:
    """
    Check if command line shows signs of obfuscation.
    
    Detects:
    - Very long command lines
    - Base64-like encoded segments
    - Excessive special characters
    - Character escaping patterns
    
    Args:
        event: NormalizedEvent with command_line field
        
    Returns:
        True if command line appears obfuscated
    """
    cmdline = event.command_line
    if not cmdline:
        return False
    
    # Very long command lines are suspicious
    if len(cmdline) > 500:
        return True
    
    # Base64-like patterns (long alphanumeric sequences)
    # Base64 uses A-Za-z0-9+/=
    base64_pattern = r'[A-Za-z0-9+/=]{50,}'
    if re.search(base64_pattern, cmdline):
        return True
    
    # PowerShell encoded command pattern
    if "-encodedcommand" in cmdline.lower() or "-enc " in cmdline.lower():
        return True
    if "-e " in cmdline.lower() and "powershell" in cmdline.lower():
        return True
    
    # Character obfuscation patterns
    # String concatenation: "pow" + "ers" + "hell"
    if cmdline.count('+') > 5:
        return True
    
    # Caret escaping: p^o^w^e^r^s^h^e^l^l
    if cmdline.count('^') > 5:
        return True
    
    # Tick escaping in PowerShell: `p`o`w`e`r`s`h`e`l`l
    if cmdline.count('`') > 5:
        return True
    
    # Excessive special characters
    special_chars = sum(1 for c in cmdline if c in '|&;${}[]()\\')
    if special_chars > 20:
        return True
    
    return False


def extract_features(event: NormalizedEvent) -> Dict[str, Any]:
    """
    Extract all process-related features from an event.
    
    Args:
        event: NormalizedEvent to analyze
        
    Returns:
        Dictionary of feature name -> value pairs
    """
    return {
        "is_lolbin": is_lolbin(event),
        "is_suspicious_path": is_suspicious_path(event),
        "has_obfuscated_cmdline": has_obfuscated_cmdline(event),
    }
