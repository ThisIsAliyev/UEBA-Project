"""
Whitelist/Blacklist Engine.

Provides fast checking of processes, commands, and paths against
configured whitelists and blacklists.

Whitelists: Known-good items that reduce risk score
Blacklists: Known-bad patterns that increase risk score

Lists can be global or OU/role-specific.
"""

import re
import logging
import sqlite3
from pathlib import Path
from typing import Optional, Dict, List, Set, Tuple, Any
from dataclasses import dataclass
from enum import Enum
from threading import Lock

import yaml

logger = logging.getLogger(__name__)


class ListMatchResult(str, Enum):
    """Result of whitelist/blacklist check."""
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    NONE = "none"


@dataclass
class ListCheckResult:
    """Result of whitelist/blacklist check with details."""
    match_type: ListMatchResult
    matched_rule: Optional[str] = None
    risk_modifier: int = 0  # -50 to +80
    description: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "match_type": self.match_type.value,
            "matched_rule": self.matched_rule,
            "risk_modifier": self.risk_modifier,
            "description": self.description,
        }


@dataclass
class ListRule:
    """A whitelist or blacklist rule."""
    list_type: str  # "whitelist" or "blacklist"
    match_type: str  # "process", "command_regex", "path", "hash"
    match_value: str
    risk_modifier: int
    description: str
    ou_role: Optional[str] = None  # None = global


class ListEngine:
    """
    Whitelist/blacklist checking engine.
    
    Supports:
    - Process whitelists (known-good executables)
    - Command blacklists (dangerous patterns via regex)
    - Path blacklists (suspicious execution locations)
    - Role-based lists (different rules per OU)
    
    Configuration can be loaded from:
    - YAML config file
    - SQLite database
    """
    
    # Default risk modifiers
    DEFAULT_WHITELIST_MODIFIER = -30
    DEFAULT_BLACKLIST_MODIFIER = 40
    
    def __init__(self, config_path: Optional[str] = None, db_path: Optional[str] = None):
        """
        Initialize list engine.
        
        Args:
            config_path: Path to YAML config file
            db_path: Path to SQLite database for dynamic lists
        """
        # In-memory lists for fast lookup
        self._process_whitelist: Set[str] = set()
        self._process_blacklist: Set[str] = set()
        self._command_blacklist: List[Tuple[re.Pattern, int, str]] = []
        self._path_blacklist: List[Tuple[re.Pattern, int, str]] = []
        self._hash_blacklist: Set[str] = set()
        
        # Role-specific lists
        self._role_lists: Dict[str, Dict[str, Set[str]]] = {}
        
        self._lock = Lock()
        
        # Load from config file
        if config_path:
            self.load_from_yaml(config_path)
        else:
            # Try default path
            default_path = Path(__file__).parent.parent.parent.parent / "config" / "lists.yaml"
            if default_path.exists():
                self.load_from_yaml(str(default_path))
            else:
                self._load_defaults()
        
        # Initialize database if provided
        if db_path:
            self.db_path = db_path
            self._init_db()
        else:
            self.db_path = None
        
        logger.info(
            f"List engine initialized: "
            f"{len(self._process_whitelist)} whitelisted processes, "
            f"{len(self._command_blacklist)} blacklist patterns"
        )
    
    def _load_defaults(self):
        """Load default whitelist/blacklist rules."""
        # Common Windows system processes (whitelist)
        self._process_whitelist = {
            "explorer.exe", "svchost.exe", "services.exe", "lsass.exe",
            "csrss.exe", "wininit.exe", "winlogon.exe", "dwm.exe",
            "taskhostw.exe", "sihost.exe", "fontdrvhost.exe",
            "searchindexer.exe", "searchprotocolhost.exe",
            "runtimebroker.exe", "applicationframehost.exe",
            "systemsettings.exe", "settingsynchost.exe",
            "smartscreen.exe", "securityhealthservice.exe",
            "msmpeng.exe", "nissrv.exe",  # Windows Defender
            "spoolsv.exe", "printfilterpipelinesvc.exe",  # Print
            "dllhost.exe", "conhost.exe", "cmd.exe",
        }
        
        # Dangerous command patterns (blacklist)
        dangerous_patterns = [
            (r"-enc\s+[A-Za-z0-9+/=]{20,}", 50, "Encoded PowerShell command"),
            (r"-encodedcommand\s+", 50, "Encoded PowerShell command"),
            (r"-e\s+[A-Za-z0-9+/=]{20,}", 45, "Possible encoded command"),
            (r"downloadstring|downloadfile|invoke-webrequest", 40, "Download command"),
            (r"invoke-expression|iex\s*\(", 45, "Dynamic code execution"),
            (r"bypass|unrestricted|hidden", 35, "Execution policy bypass"),
            (r"-nop\s+-w\s+hidden", 50, "Hidden PowerShell"),
            (r"net\s+user\s+.*\s+/add", 60, "User creation"),
            (r"net\s+localgroup\s+administrators", 55, "Admin group modification"),
            (r"reg\s+add.*\\run", 50, "Registry Run key modification"),
            (r"schtasks\s+/create", 40, "Scheduled task creation"),
            (r"wmic\s+.*process\s+call\s+create", 55, "WMI process creation"),
            (r"certutil.*-decode", 50, "Certutil decode (LOLBin)"),
            (r"bitsadmin.*transfer", 45, "BITS transfer (LOLBin)"),
            (r"mshta\s+", 50, "MSHTA execution"),
            (r"regsvr32\s+/s\s+/n\s+/u", 55, "Regsvr32 bypass"),
            (r"rundll32.*javascript:", 60, "Rundll32 script execution"),
        ]
        
        for pattern, modifier, desc in dangerous_patterns:
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                self._command_blacklist.append((compiled, modifier, desc))
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{pattern}': {e}")
        
        # Suspicious paths (blacklist)
        path_patterns = [
            (r"\\temp\\", 25, "Execution from Temp folder"),
            (r"\\tmp\\", 25, "Execution from Tmp folder"),
            (r"\\downloads\\", 20, "Execution from Downloads"),
            (r"\\appdata\\local\\temp", 25, "Execution from AppData Temp"),
            (r"\\programdata\\", 15, "Execution from ProgramData"),
            (r"\\\$recycle\.bin\\", 40, "Execution from Recycle Bin"),
            (r"\\users\\public\\", 20, "Execution from Public folder"),
        ]
        
        for pattern, modifier, desc in path_patterns:
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                self._path_blacklist.append((compiled, modifier, desc))
            except re.error as e:
                logger.warning(f"Invalid path pattern '{pattern}': {e}")
    
    def load_from_yaml(self, config_path: str):
        """Load lists from YAML configuration file."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            if not config:
                self._load_defaults()
                return
            
            # Load process whitelist
            whitelist = config.get("whitelist", {})
            self._process_whitelist = set(
                p.lower() for p in whitelist.get("processes", [])
            )
            
            # Load process blacklist
            blacklist = config.get("blacklist", {})
            self._process_blacklist = set(
                p.lower() for p in blacklist.get("processes", [])
            )
            
            # Load command patterns
            for item in blacklist.get("command_patterns", []):
                try:
                    pattern = re.compile(item["pattern"], re.IGNORECASE)
                    modifier = item.get("risk_modifier", self.DEFAULT_BLACKLIST_MODIFIER)
                    desc = item.get("description", "Blacklisted command pattern")
                    self._command_blacklist.append((pattern, modifier, desc))
                except (re.error, KeyError) as e:
                    logger.warning(f"Invalid command pattern: {e}")
            
            # Load path patterns
            for item in blacklist.get("path_patterns", []):
                try:
                    pattern = re.compile(item["pattern"], re.IGNORECASE)
                    modifier = item.get("risk_modifier", 25)
                    desc = item.get("description", "Blacklisted path")
                    self._path_blacklist.append((pattern, modifier, desc))
                except (re.error, KeyError) as e:
                    logger.warning(f"Invalid path pattern: {e}")
            
            # Load hash blacklist
            self._hash_blacklist = set(
                h.lower() for h in blacklist.get("hashes", [])
            )
            
            # Load role-specific lists
            for role_name, role_config in config.get("roles", {}).items():
                self._role_lists[role_name] = {
                    "allowed_processes": set(
                        p.lower() for p in role_config.get("allowed_processes", [])
                    ),
                    "denied_processes": set(
                        p.lower() for p in role_config.get("denied_processes", [])
                    ),
                }
            
            logger.info(f"Loaded lists from {config_path}")
            
        except Exception as e:
            logger.warning(f"Failed to load lists from {config_path}: {e}")
            self._load_defaults()
    
    def _init_db(self):
        """Initialize database for dynamic lists."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS lists (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    list_type TEXT NOT NULL,
                    match_type TEXT NOT NULL,
                    match_value TEXT NOT NULL,
                    risk_modifier INTEGER DEFAULT 0,
                    description TEXT,
                    ou_role TEXT,
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL,
                    UNIQUE(list_type, match_type, match_value, ou_role)
                )
            """)
    
    def check(
        self,
        process_name: Optional[str] = None,
        command_line: Optional[str] = None,
        image_path: Optional[str] = None,
        file_hash: Optional[str] = None,
        role: Optional[str] = None
    ) -> ListCheckResult:
        """
        Check event against whitelists and blacklists.
        
        Order of checks:
        1. Hash blacklist (highest priority)
        2. Process blacklist
        3. Command pattern blacklist
        4. Path blacklist
        5. Process whitelist (can override if no blacklist match)
        6. Role-specific lists
        
        Args:
            process_name: Process name to check
            command_line: Command line to check
            image_path: Executable path to check
            file_hash: File hash to check
            role: User's OU/role for role-specific lists
            
        Returns:
            ListCheckResult with match type and risk modifier
        """
        with self._lock:
            # Check 1: Hash blacklist (highest priority)
            if file_hash and file_hash.lower() in self._hash_blacklist:
                return ListCheckResult(
                    match_type=ListMatchResult.BLACKLIST,
                    matched_rule=f"hash:{file_hash[:16]}...",
                    risk_modifier=80,
                    description="Known malicious file hash"
                )
            
            # Check 2: Process blacklist
            if process_name:
                proc_lower = process_name.lower()
                if proc_lower in self._process_blacklist:
                    return ListCheckResult(
                        match_type=ListMatchResult.BLACKLIST,
                        matched_rule=f"process:{process_name}",
                        risk_modifier=60,
                        description="Blacklisted process"
                    )
            
            # Check 3: Command pattern blacklist
            if command_line:
                for pattern, modifier, desc in self._command_blacklist:
                    if pattern.search(command_line):
                        return ListCheckResult(
                            match_type=ListMatchResult.BLACKLIST,
                            matched_rule=f"command:{pattern.pattern[:30]}...",
                            risk_modifier=modifier,
                            description=desc
                        )
            
            # Check 4: Path blacklist
            if image_path:
                for pattern, modifier, desc in self._path_blacklist:
                    if pattern.search(image_path):
                        return ListCheckResult(
                            match_type=ListMatchResult.BLACKLIST,
                            matched_rule=f"path:{pattern.pattern[:30]}...",
                            risk_modifier=modifier,
                            description=desc
                        )
            
            # Check 5: Role-specific denied processes
            if role and role in self._role_lists:
                role_config = self._role_lists[role]
                if process_name and process_name.lower() in role_config.get("denied_processes", set()):
                    return ListCheckResult(
                        match_type=ListMatchResult.BLACKLIST,
                        matched_rule=f"role:{role}:denied:{process_name}",
                        risk_modifier=50,
                        description=f"Process denied for role {role}"
                    )
            
            # Check 6: Process whitelist (only if no blacklist match)
            if process_name:
                proc_lower = process_name.lower()
                if proc_lower in self._process_whitelist:
                    return ListCheckResult(
                        match_type=ListMatchResult.WHITELIST,
                        matched_rule=f"process:{process_name}",
                        risk_modifier=self.DEFAULT_WHITELIST_MODIFIER,
                        description="Whitelisted system process"
                    )
                
                # Check role-specific allowed processes
                if role and role in self._role_lists:
                    role_config = self._role_lists[role]
                    if proc_lower in role_config.get("allowed_processes", set()):
                        return ListCheckResult(
                            match_type=ListMatchResult.WHITELIST,
                            matched_rule=f"role:{role}:allowed:{process_name}",
                            risk_modifier=-20,
                            description=f"Process allowed for role {role}"
                        )
            
            # No match
            return ListCheckResult(
                match_type=ListMatchResult.NONE,
                risk_modifier=0
            )
    
    def add_to_whitelist(
        self,
        match_type: str,
        match_value: str,
        description: str = "",
        role: Optional[str] = None
    ):
        """Add item to whitelist."""
        with self._lock:
            if match_type == "process":
                self._process_whitelist.add(match_value.lower())
            
            if self.db_path:
                self._save_to_db("whitelist", match_type, match_value, 
                               self.DEFAULT_WHITELIST_MODIFIER, description, role)
    
    def add_to_blacklist(
        self,
        match_type: str,
        match_value: str,
        risk_modifier: int = 40,
        description: str = "",
        role: Optional[str] = None
    ):
        """Add item to blacklist."""
        with self._lock:
            if match_type == "process":
                self._process_blacklist.add(match_value.lower())
            elif match_type == "hash":
                self._hash_blacklist.add(match_value.lower())
            elif match_type == "command_regex":
                try:
                    pattern = re.compile(match_value, re.IGNORECASE)
                    self._command_blacklist.append((pattern, risk_modifier, description))
                except re.error:
                    logger.warning(f"Invalid regex: {match_value}")
                    return
            
            if self.db_path:
                self._save_to_db("blacklist", match_type, match_value,
                               risk_modifier, description, role)
    
    def _save_to_db(
        self,
        list_type: str,
        match_type: str,
        match_value: str,
        risk_modifier: int,
        description: str,
        role: Optional[str]
    ):
        """Save list entry to database."""
        if not self.db_path:
            return
        
        try:
            from datetime import datetime
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO lists
                       (list_type, match_type, match_value, risk_modifier, 
                        description, ou_role, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (list_type, match_type, match_value, risk_modifier,
                     description, role, datetime.utcnow().isoformat())
                )
        except Exception as e:
            logger.warning(f"Failed to save list entry: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get list engine statistics."""
        return {
            "whitelist_processes": len(self._process_whitelist),
            "blacklist_processes": len(self._process_blacklist),
            "blacklist_commands": len(self._command_blacklist),
            "blacklist_paths": len(self._path_blacklist),
            "blacklist_hashes": len(self._hash_blacklist),
            "roles": list(self._role_lists.keys()),
        }


# Global instance
_list_engine: Optional[ListEngine] = None


def get_list_engine() -> ListEngine:
    """Get or create global list engine instance."""
    global _list_engine
    
    if _list_engine is None:
        _list_engine = ListEngine()
    
    return _list_engine
