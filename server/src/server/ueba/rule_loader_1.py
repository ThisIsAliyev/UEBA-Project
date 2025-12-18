"""
UEBA Detection Rule Loader.

Loads and validates YAML detection rules with support for:
- Sysmon and Windows Security event matching
- Field-based conditions with multiple operators
- MITRE ATT&CK mapping
- Tuning parameters (dedup, allowlists)
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

logger = logging.getLogger(__name__)


@dataclass
class MitreMapping:
    """MITRE ATT&CK technique mapping."""
    tactic: str
    technique_id: str
    technique: str


@dataclass
class MatchCondition:
    """Single field match condition."""
    field: str
    op: str
    value: Any
    case_sensitive: bool = False
    
    # Supported operators
    SUPPORTED_OPS = {
        'equals', 'not_equals', 'contains', 'not_contains',
        'startswith', 'endswith', 'regex',
        'contains_any', 'endswith_any', 'startswith_any', 'equals_any',
        'gt', 'gte', 'lt', 'lte', 'in_list', 'not_in_list'
    }
    
    def __post_init__(self):
        if self.op not in self.SUPPORTED_OPS:
            raise ValueError(f"Unsupported operator: {self.op}. Supported: {self.SUPPORTED_OPS}")


@dataclass
class DetectionRule:
    """Detection rule definition."""
    id: str
    name: str
    description: str
    enabled: bool
    
    # Log source
    service: str  # sysmon, security, system
    event_ids: List[int]
    
    # Risk scoring
    base_score: int  # 0-100
    confidence: str  # low, medium, high
    risk_object: str  # user, host
    
    # MITRE mapping
    mitre: List[MitreMapping]
    
    # Match conditions
    match_all: List[MatchCondition] = field(default_factory=list)
    match_any: List[MatchCondition] = field(default_factory=list)
    match_none: List[MatchCondition] = field(default_factory=list)
    
    # Tuning
    dedup_minutes: int = 5
    allowlist: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    
    # Test cases
    tests: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        # Validate base_score
        if not 0 <= self.base_score <= 100:
            raise ValueError(f"Rule {self.id}: base_score must be 0-100, got {self.base_score}")
        
        # Validate confidence
        if self.confidence not in ('low', 'medium', 'high'):
            raise ValueError(f"Rule {self.id}: confidence must be low/medium/high, got {self.confidence}")
        
        # Validate risk_object
        if self.risk_object not in ('user', 'host'):
            raise ValueError(f"Rule {self.id}: risk_object must be user/host, got {self.risk_object}")
        
        # Validate event_ids are integers
        for eid in self.event_ids:
            if not isinstance(eid, int):
                raise ValueError(f"Rule {self.id}: event_ids must be integers, got {type(eid)}")


class RuleLoader:
    """
    Loads and manages YAML detection rules.
    
    Supports loading from single file or directory of rule files.
    """
    
    def __init__(self, rules_path: Optional[str] = None):
        """
        Initialize rule loader.
        
        Args:
            rules_path: Path to rules YAML file or directory containing rule files.
                       If None, uses default path.
        """
        if rules_path is None:
            # Default: server/config/rules/
            self.rules_path = Path(__file__).parent.parent.parent.parent / "config" / "rules"
        else:
            self.rules_path = Path(rules_path)
        
        self.rules: Dict[str, DetectionRule] = {}
        self._rules_by_event_id: Dict[int, List[DetectionRule]] = {}
        self._compiled_patterns: Dict[str, re.Pattern] = {}
    
    def load_rules(self) -> int:
        """
        Load all rules from configured path.
        
        Returns:
            Number of rules loaded successfully.
        """
        self.rules.clear()
        self._rules_by_event_id.clear()
        
        if not self.rules_path.exists():
            logger.warning(f"Rules path does not exist: {self.rules_path}")
            return 0
        
        if self.rules_path.is_file():
            self._load_rules_file(self.rules_path)
        else:
            # Load all YAML files in directory
            for yaml_file in self.rules_path.glob("*.yaml"):
                self._load_rules_file(yaml_file)
            for yaml_file in self.rules_path.glob("*.yml"):
                self._load_rules_file(yaml_file)
        
        # Build event_id index for fast lookup
        self._build_event_id_index()
        
        logger.info(f"Loaded {len(self.rules)} detection rules")
        return len(self.rules)
    
    def _load_rules_file(self, file_path: Path):
        """Load rules from a single YAML file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = yaml.safe_load(f)
            
            if content is None:
                logger.warning(f"Empty rules file: {file_path}")
                return
            
            # Handle both single rule and list of rules
            rules_list = content if isinstance(content, list) else [content]
            
            # Also handle 'rules' key wrapper
            if isinstance(content, dict) and 'rules' in content:
                rules_list = content['rules']
            
            for rule_data in rules_list:
                try:
                    rule = self._parse_rule(rule_data)
                    if rule.enabled:
                        self.rules[rule.id] = rule
                        logger.debug(f"Loaded rule: {rule.id} - {rule.name}")
                    else:
                        logger.debug(f"Skipped disabled rule: {rule.id}")
                except Exception as e:
                    logger.error(f"Failed to parse rule in {file_path}: {e}")
        
        except Exception as e:
            logger.error(f"Failed to load rules file {file_path}: {e}")
    
    def _parse_rule(self, data: Dict[str, Any]) -> DetectionRule:
        """Parse a single rule from YAML data."""
        # Required fields
        rule_id = data.get('id')
        if not rule_id:
            raise ValueError("Rule missing required field: id")
        
        name = data.get('name', f"Rule {rule_id}")
        description = data.get('description', '')
        enabled = data.get('enabled', True)
        
        # Log source
        logsource = data.get('logsource', {})
        service = logsource.get('service', 'sysmon')
        event_ids = logsource.get('event_ids', [])
        if isinstance(event_ids, int):
            event_ids = [event_ids]
        
        # Risk scoring
        risk = data.get('risk', {})
        base_score = risk.get('base_score', 50)
        confidence = risk.get('confidence', 'medium')
        risk_object = risk.get('risk_object', 'user')
        
        # MITRE mapping
        mitre_list = []
        for m in data.get('mitre', []):
            mitre_list.append(MitreMapping(
                tactic=m.get('tactic', ''),
                technique_id=m.get('technique_id', ''),
                technique=m.get('technique', '')
            ))
        
        # Match conditions
        match = data.get('match', {})
        match_all = self._parse_conditions(match.get('all', []))
        match_any = self._parse_conditions(match.get('any', []))
        match_none = self._parse_conditions(match.get('none', []))
        
        # Tuning
        tuning = data.get('tuning', {})
        dedup_minutes = tuning.get('dedup_minutes', 5)
        allowlist = tuning.get('allowlist', [])
        notes = tuning.get('notes', [])
        
        # Tests
        tests = data.get('tests', [])
        
        return DetectionRule(
            id=rule_id,
            name=name,
            description=description,
            enabled=enabled,
            service=service,
            event_ids=event_ids,
            base_score=base_score,
            confidence=confidence,
            risk_object=risk_object,
            mitre=mitre_list,
            match_all=match_all,
            match_any=match_any,
            match_none=match_none,
            dedup_minutes=dedup_minutes,
            allowlist=allowlist,
            notes=notes,
            tests=tests
        )
    
    def _parse_conditions(self, conditions: List[Dict]) -> List[MatchCondition]:
        """Parse match conditions from YAML."""
        result = []
        for cond in conditions:
            result.append(MatchCondition(
                field=cond.get('field', ''),
                op=cond.get('op', 'equals'),
                value=cond.get('value'),
                case_sensitive=cond.get('case_sensitive', False)
            ))
        return result
    
    def _build_event_id_index(self):
        """Build index of rules by event_id for fast lookup."""
        self._rules_by_event_id.clear()
        for rule in self.rules.values():
            for event_id in rule.event_ids:
                if event_id not in self._rules_by_event_id:
                    self._rules_by_event_id[event_id] = []
                self._rules_by_event_id[event_id].append(rule)
    
    def get_rules_for_event_id(self, event_id: int) -> List[DetectionRule]:
        """Get all rules that apply to a specific event ID."""
        return self._rules_by_event_id.get(event_id, [])
    
    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """Get a specific rule by ID."""
        return self.rules.get(rule_id)
    
    def get_all_rules(self) -> List[DetectionRule]:
        """Get all loaded rules."""
        return list(self.rules.values())


# Global rule loader instance
_rule_loader: Optional[RuleLoader] = None


def get_rule_loader(rules_path: Optional[str] = None) -> RuleLoader:
    """Get or create global rule loader instance."""
    global _rule_loader
    if _rule_loader is None:
        _rule_loader = RuleLoader(rules_path)
        _rule_loader.load_rules()
    return _rule_loader
