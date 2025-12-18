"""
Rule-Based Risk Scorer.

Fast rule-based risk assessment using pattern matching and whitelist/blacklist.
"""

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

from ..models import NormalizedEvent
from .log_parser import extract_command_features, extract_process_features

logger = logging.getLogger(__name__)


class RuleBasedScorer:
    """
    Rule-based risk scorer using configurable patterns.
    
    Supports:
    - Whitelist (fast exit, risk = 0)
    - Blacklist patterns (high risk)
    - Suspicious parent-child relationships
    - Path validation
    """
    
    def __init__(self, rules_config_path: Optional[str] = None):
        """
        Initialize rule scorer.
        
        Args:
            rules_config_path: Path to rules.yaml file
        """
        if rules_config_path is None:
            # Default path relative to this module
            rules_file = Path(__file__).parent / "config" / "rules.yaml"
        else:
            rules_file = Path(rules_config_path)
        
        if not rules_file.exists():
            logger.warning(f"Rules config not found at {rules_file}, using defaults")
            self.rules = self._default_rules()
        else:
            with open(rules_file, 'r') as f:
                self.rules = yaml.safe_load(f)
        
        # Compile regex patterns for performance
        self._compile_patterns()
    
    def _default_rules(self) -> Dict:
        """Return default rules if config file not found."""
        return {
            "whitelist": {
                "processes": ["svchost.exe", "explorer.exe"],
                "parent_child": []
            },
            "blacklist": {
                "command_patterns": [
                    {"pattern": "powershell.*-enc", "risk_score": 95}
                ]
            },
            "suspicious_parent_child": [],
            "path_validation": {
                "system_dirs": ["C:\\Windows\\System32"],
                "suspicious_dirs": []
            }
        }
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for performance."""
        # Compile blacklist command patterns
        self._compiled_command_patterns: List[Tuple[re.Pattern, float, str]] = []
        for pattern_config in self.rules.get("blacklist", {}).get("command_patterns", []):
            try:
                pattern = re.compile(
                    pattern_config["pattern"],
                    re.IGNORECASE
                )
                risk_score = pattern_config.get("risk_score", 90)
                description = pattern_config.get("description", "")
                self._compiled_command_patterns.append((pattern, risk_score, description))
            except re.error as e:
                logger.warning(f"Invalid regex pattern: {pattern_config.get('pattern')}: {e}")
        
        # Compile suspicious parent-child patterns
        self._compiled_parent_child: List[Tuple[re.Pattern, re.Pattern, float, str]] = []
        for pc_config in self.rules.get("suspicious_parent_child", []):
            try:
                parent_pattern = re.compile(
                    pc_config.get("parent_pattern", ".*"),
                    re.IGNORECASE
                )
                child_pattern = re.compile(
                    pc_config.get("child_pattern", ".*"),
                    re.IGNORECASE
                )
                risk_score = pc_config.get("risk_score", 70)
                description = pc_config.get("description", "")
                self._compiled_parent_child.append(
                    (parent_pattern, child_pattern, risk_score, description)
                )
            except re.error as e:
                logger.warning(f"Invalid parent-child pattern: {e}")
    
    def score(self, event: NormalizedEvent, context_features: Optional[Dict] = None) -> float:
        """
        Calculate rule-based risk score (0-100).
        
        Args:
            event: NormalizedEvent to score
            context_features: Optional context features (not used in MVP, for future)
            
        Returns:
            Risk score from 0.0 to 100.0
        """
        # Fast exit: Check whitelist first
        if self._is_whitelisted(event):
            return 0.0
        
        # Check blacklist patterns (highest priority)
        blacklist_score = self._check_blacklist(event)
        if blacklist_score >= 90:
            return blacklist_score  # Fast exit for critical patterns
        
        # Check suspicious parent-child relationships
        parent_child_score = self._check_parent_child(event)
        
        # Check path validation
        path_score = self._check_path_validation(event)
        
        # Return maximum of all scores
        return max(blacklist_score, parent_child_score, path_score)
    
    def _is_whitelisted(self, event: NormalizedEvent) -> bool:
        """Check if event matches whitelist (safe, risk = 0)."""
        whitelist = self.rules.get("whitelist", {})
        
        # Check process whitelist
        if event.process_name:
            process_lower = event.process_name.lower()
            whitelisted_processes = [
                p.lower() for p in whitelist.get("processes", [])
            ]
            if process_lower in whitelisted_processes:
                return True
        
        # Check parent-child whitelist
        if event.parent_process_name and event.process_name:
            parent_lower = event.parent_process_name.lower()
            child_lower = event.process_name.lower()
            
            for pc in whitelist.get("parent_child", []):
                if (parent_lower == pc.get("parent", "").lower() and
                    child_lower == pc.get("child", "").lower()):
                    return True
        
        return False
    
    def _check_blacklist(self, event: NormalizedEvent) -> float:
        """Check command line against blacklist patterns."""
        if not event.command_line:
            return 0.0
        
        command_lower = event.command_line.lower()
        
        # Check all compiled patterns
        for pattern, risk_score, description in self._compiled_command_patterns:
            if pattern.search(command_lower):
                logger.debug(
                    f"Blacklist match: {description} (score={risk_score}) "
                    f"for process={event.process_name}"
                )
                return risk_score
        
        return 0.0
    
    def _check_parent_child(self, event: NormalizedEvent) -> float:
        """Check for suspicious parent-child relationships."""
        if not event.parent_process_name or not event.process_name:
            return 0.0
        
        parent_lower = event.parent_process_name.lower()
        child_lower = event.process_name.lower()
        
        # Check compiled patterns
        for parent_pattern, child_pattern, risk_score, description in self._compiled_parent_child:
            if parent_pattern.match(parent_lower) and child_pattern.match(child_lower):
                logger.debug(
                    f"Suspicious parent-child: {description} (score={risk_score}) "
                    f"{event.parent_process_name} -> {event.process_name}"
                )
                return risk_score
        
        return 0.0
    
    def _check_path_validation(self, event: NormalizedEvent) -> float:
        """Validate process path against system/suspicious directories."""
        if not event.image_path:
            return 0.0
        
        path_validation = self.rules.get("path_validation", {})
        image_path_lower = event.image_path.lower()
        
        # Check if system process is running from suspicious location
        process_features = extract_process_features(
            event.process_name,
            event.parent_process_name,
            event.image_path
        )
        
        if process_features.get("is_system_process") and process_features.get("path_in_suspicious_location"):
            risk_score = path_validation.get("system_process_suspicious_path_risk", 85)
            logger.debug(
                f"System process in suspicious path: {event.image_path} (score={risk_score})"
            )
            return risk_score
        
        return 0.0

