"""
UEBA Scoring Engine.

Implements:
- Event scoring (0-100) based on matched detection rules
- Context modifiers (off_hours, rare_host, privileged_user, etc.)
- Entity aggregation with dedup and decay
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import NormalizedEvent
from .rule_loader import DetectionRule, MatchCondition, RuleLoader, get_rule_loader

logger = logging.getLogger(__name__)


@dataclass
class RuleMatch:
    """Result of a single rule match."""
    rule: DetectionRule
    matched_fields: Dict[str, Any]  # field -> matched value
    evidence: Dict[str, Any]  # Evidence for explainability


@dataclass
class EventScore:
    """Scoring result for a single event."""
    event_score: int  # 0-100, capped
    matched_rules: List[RuleMatch]
    base_score: int  # Highest base_score among matches
    bonus_score: int  # Additional points for multiple matches
    modifiers_applied: Dict[str, float]  # modifier_name -> adjustment
    final_score: int  # After modifiers, capped at 100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'event_score': self.event_score,
            'base_score': self.base_score,
            'bonus_score': self.bonus_score,
            'final_score': self.final_score,
            'modifiers_applied': self.modifiers_applied,
            'matched_rules': [
                {
                    'rule_id': m.rule.id,
                    'rule_name': m.rule.name,
                    'base_score': m.rule.base_score,
                    'confidence': m.rule.confidence,
                    'mitre': [{'tactic': t.tactic, 'technique_id': t.technique_id} for t in m.rule.mitre],
                    'evidence': m.evidence
                }
                for m in self.matched_rules
            ]
        }


@dataclass
class EntityScore:
    """Aggregated risk score for an entity (user or host)."""
    entity_type: str  # 'user' or 'host'
    entity_id: str
    score_1h: float
    score_24h: float
    last_updated: datetime
    contributing_rules: List[str]  # rule_ids that contributed
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'entity_type': self.entity_type,
            'entity_id': self.entity_id,
            'score_1h': round(self.score_1h, 2),
            'score_24h': round(self.score_24h, 2),
            'last_updated': self.last_updated.isoformat(),
            'contributing_rules': self.contributing_rules
        }


class ContextModifiers:
    """
    Context-based score modifiers.
    
    Applies UEBA behavioral context without ML:
    - off_hours: Event outside user's normal hours
    - rare_host_for_user: First-seen host for user
    - rare_process_for_user: First-seen process for user
    - privileged_user: User in admin group
    - high_value_asset: Host tagged as critical
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        
        # In-memory baselines (would be loaded from DB in production)
        self._user_hours: Dict[str, Set[int]] = {}  # user -> set of active hours
        self._user_hosts: Dict[str, Set[str]] = {}  # user -> set of known hosts
        self._user_processes: Dict[str, Set[str]] = {}  # user -> set of known processes
        self._privileged_users: Set[str] = set()
        self._high_value_hosts: Set[str] = set()
    
    def _default_config(self) -> Dict[str, Any]:
        return {
            'off_hours_bonus': 10,
            'rare_host_bonus': 15,
            'rare_process_bonus': 10,
            'privileged_user_multiplier': 1.2,
            'high_value_asset_multiplier': 1.2,
            'default_work_hours': list(range(8, 18)),  # 8 AM - 6 PM
        }
    
    def load_baselines(self, storage) -> None:
        """Load baselines from storage."""
        # TODO: Load from baseline_stats table
        pass
    
    def set_privileged_users(self, users: List[str]) -> None:
        """Set list of privileged users."""
        self._privileged_users = set(u.lower() for u in users)
    
    def set_high_value_hosts(self, hosts: List[str]) -> None:
        """Set list of high-value hosts."""
        self._high_value_hosts = set(h.lower() for h in hosts)
    
    def update_user_baseline(self, user: str, host: str, process: str, hour: int) -> None:
        """Update user baseline with observed activity."""
        user_lower = user.lower()
        
        if user_lower not in self._user_hours:
            self._user_hours[user_lower] = set()
        self._user_hours[user_lower].add(hour)
        
        if user_lower not in self._user_hosts:
            self._user_hosts[user_lower] = set()
        self._user_hosts[user_lower].add(host.lower())
        
        if user_lower not in self._user_processes:
            self._user_processes[user_lower] = set()
        if process:
            self._user_processes[user_lower].add(process.lower())
    
    def compute_modifiers(self, event: NormalizedEvent) -> Dict[str, float]:
        """
        Compute all applicable modifiers for an event.
        
        Returns dict of modifier_name -> score_adjustment
        """
        modifiers = {}
        user_lower = event.user.lower() if event.user else ''
        host_lower = event.host.lower() if event.host else ''
        process_lower = (event.process_name or '').lower()
        event_hour = event.timestamp.hour if event.timestamp else datetime.utcnow().hour
        
        # Off-hours check
        user_hours = self._user_hours.get(user_lower, set())
        if user_hours:
            # User has baseline - check if current hour is unusual
            if event_hour not in user_hours:
                modifiers['off_hours'] = self.config['off_hours_bonus']
        else:
            # No baseline - use default work hours
            if event_hour not in self.config['default_work_hours']:
                modifiers['off_hours'] = self.config['off_hours_bonus']
        
        # Rare host check
        user_hosts = self._user_hosts.get(user_lower, set())
        if user_hosts and host_lower and host_lower not in user_hosts:
            modifiers['rare_host_for_user'] = self.config['rare_host_bonus']
        
        # Rare process check
        user_processes = self._user_processes.get(user_lower, set())
        if user_processes and process_lower and process_lower not in user_processes:
            modifiers['rare_process_for_user'] = self.config['rare_process_bonus']
        
        # Privileged user check (multiplicative)
        if user_lower in self._privileged_users:
            modifiers['privileged_user'] = self.config['privileged_user_multiplier']
        
        # High-value asset check (multiplicative)
        if host_lower in self._high_value_hosts:
            modifiers['high_value_asset'] = self.config['high_value_asset_multiplier']
        
        return modifiers
    
    def apply_modifiers(self, base_score: int, modifiers: Dict[str, float]) -> int:
        """
        Apply modifiers to base score.
        
        Additive modifiers are applied first, then multiplicative.
        Result is capped at 100.
        """
        score = float(base_score)
        
        # Apply additive modifiers
        for name, value in modifiers.items():
            if name in ('off_hours', 'rare_host_for_user', 'rare_process_for_user'):
                score += value
        
        # Apply multiplicative modifiers
        for name, value in modifiers.items():
            if name in ('privileged_user', 'high_value_asset'):
                score *= value
        
        return min(100, int(round(score)))


class EntityAggregator:
    """
    Aggregates event scores to entity (user/host) level.
    
    Maintains rolling scores with:
    - Deduplication within time window
    - Score decay over time
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        
        # In-memory entity scores
        # Key: (entity_type, entity_id) -> list of (timestamp, score, rule_id, dedup_key)
        self._entity_events: Dict[Tuple[str, str], List[Tuple[datetime, int, str, str]]] = {}
        
        # Dedup tracking: (entity_type, entity_id, rule_id, dedup_key) -> last_seen
        self._dedup_cache: Dict[Tuple[str, str, str, str], datetime] = {}
    
    def _default_config(self) -> Dict[str, Any]:
        return {
            'decay_factor': 0.5,  # Score multiplier per hour
            'decay_interval_minutes': 60,
            'dedup_minutes': 5,
            'window_1h_minutes': 60,
            'window_24h_minutes': 1440,
        }
    
    def _generate_dedup_key(self, event: NormalizedEvent, rule: DetectionRule) -> str:
        """Generate deduplication key from event and rule."""
        # Key fields: rule_id + entity + key identifying fields
        key_parts = [
            rule.id,
            event.user or '',
            event.host or '',
            event.process_name or '',
            str(event.event_id),
        ]
        return '|'.join(key_parts)
    
    def _is_duplicate(self, entity_type: str, entity_id: str, 
                      rule_id: str, dedup_key: str, dedup_minutes: int) -> bool:
        """Check if this is a duplicate within the dedup window."""
        cache_key = (entity_type, entity_id, rule_id, dedup_key)
        last_seen = self._dedup_cache.get(cache_key)
        
        if last_seen is None:
            return False
        
        elapsed = (datetime.utcnow() - last_seen).total_seconds() / 60
        return elapsed < dedup_minutes
    
    def _mark_seen(self, entity_type: str, entity_id: str, 
                   rule_id: str, dedup_key: str) -> None:
        """Mark this event as seen for dedup purposes."""
        cache_key = (entity_type, entity_id, rule_id, dedup_key)
        self._dedup_cache[cache_key] = datetime.utcnow()
    
    def _cleanup_old_entries(self) -> None:
        """Remove old entries from caches."""
        now = datetime.utcnow()
        cutoff_24h = now - timedelta(minutes=self.config['window_24h_minutes'])
        
        # Clean entity events
        for key in list(self._entity_events.keys()):
            events = self._entity_events[key]
            self._entity_events[key] = [
                e for e in events if e[0] > cutoff_24h
            ]
            if not self._entity_events[key]:
                del self._entity_events[key]
        
        # Clean dedup cache (keep for 24h max)
        for key in list(self._dedup_cache.keys()):
            if self._dedup_cache[key] < cutoff_24h:
                del self._dedup_cache[key]
    
    def add_event_score(self, event: NormalizedEvent, 
                        event_score: EventScore) -> Tuple[bool, List[str]]:
        """
        Add event score to entity aggregation.
        
        Returns:
            Tuple of (was_added, list of skipped rule_ids due to dedup)
        """
        if not event_score.matched_rules:
            return False, []
        
        skipped_rules = []
        added = False
        
        for match in event_score.matched_rules:
            rule = match.rule
            entity_type = rule.risk_object
            entity_id = event.user if entity_type == 'user' else event.host
            
            if not entity_id or entity_id == 'unknown':
                continue
            
            dedup_key = self._generate_dedup_key(event, rule)
            dedup_minutes = rule.dedup_minutes or self.config['dedup_minutes']
            
            # Check dedup
            if self._is_duplicate(entity_type, entity_id, rule.id, dedup_key, dedup_minutes):
                skipped_rules.append(rule.id)
                continue
            
            # Add to entity events
            entity_key = (entity_type, entity_id)
            if entity_key not in self._entity_events:
                self._entity_events[entity_key] = []
            
            self._entity_events[entity_key].append((
                datetime.utcnow(),
                event_score.final_score,
                rule.id,
                dedup_key
            ))
            
            self._mark_seen(entity_type, entity_id, rule.id, dedup_key)
            added = True
        
        # Periodic cleanup
        if len(self._dedup_cache) > 10000:
            self._cleanup_old_entries()
        
        return added, skipped_rules
    
    def get_entity_score(self, entity_type: str, entity_id: str) -> EntityScore:
        """Get current aggregated score for an entity."""
        now = datetime.utcnow()
        entity_key = (entity_type, entity_id)
        events = self._entity_events.get(entity_key, [])
        
        score_1h = 0.0
        score_24h = 0.0
        contributing_rules = set()
        
        cutoff_1h = now - timedelta(minutes=self.config['window_1h_minutes'])
        cutoff_24h = now - timedelta(minutes=self.config['window_24h_minutes'])
        
        for ts, score, rule_id, _ in events:
            if ts < cutoff_24h:
                continue
            
            # Apply decay based on age
            age_hours = (now - ts).total_seconds() / 3600
            decay = self.config['decay_factor'] ** age_hours
            decayed_score = score * decay
            
            score_24h += decayed_score
            contributing_rules.add(rule_id)
            
            if ts >= cutoff_1h:
                score_1h += decayed_score
        
        return EntityScore(
            entity_type=entity_type,
            entity_id=entity_id,
            score_1h=score_1h,
            score_24h=score_24h,
            last_updated=now,
            contributing_rules=list(contributing_rules)
        )


class UEBAScorer:
    """
    Main UEBA scoring engine.
    
    Evaluates events against detection rules and produces:
    - Event scores (0-100)
    - Entity aggregated scores
    - Alert decisions
    """
    
    def __init__(self, rules_path: Optional[str] = None, 
                 config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        self.rule_loader = get_rule_loader(rules_path)
        self.modifiers = ContextModifiers(self.config.get('modifiers'))
        self.aggregator = EntityAggregator(self.config.get('aggregation'))
        
        # Compiled regex cache
        self._regex_cache: Dict[str, re.Pattern] = {}
    
    def _default_config(self) -> Dict[str, Any]:
        return {
            'bonus_per_high_confidence_match': 5,
            'max_event_score': 100,
            'modifiers': None,
            'aggregation': None,
        }
    
    def reload_rules(self) -> int:
        """Reload detection rules from disk."""
        return self.rule_loader.load_rules()
    
    def score_event(self, event: NormalizedEvent) -> EventScore:
        """
        Score a single event against all applicable rules.
        
        Returns EventScore with matched rules and final score.
        """
        matched_rules: List[RuleMatch] = []
        
        # Get rules for this event ID
        applicable_rules = self.rule_loader.get_rules_for_event_id(event.event_id)
        
        for rule in applicable_rules:
            match_result = self._evaluate_rule(event, rule)
            if match_result:
                matched_rules.append(match_result)
        
        if not matched_rules:
            return EventScore(
                event_score=0,
                matched_rules=[],
                base_score=0,
                bonus_score=0,
                modifiers_applied={},
                final_score=0
            )
        
        # Calculate base score (highest among matches)
        base_score = max(m.rule.base_score for m in matched_rules)
        
        # Calculate bonus for additional high-confidence matches
        high_conf_count = sum(1 for m in matched_rules if m.rule.confidence == 'high')
        bonus_score = min(
            (high_conf_count - 1) * self.config['bonus_per_high_confidence_match'],
            self.config['max_event_score'] - base_score
        ) if high_conf_count > 1 else 0
        
        event_score = min(self.config['max_event_score'], base_score + bonus_score)
        
        # Apply context modifiers
        modifiers = self.modifiers.compute_modifiers(event)
        final_score = self.modifiers.apply_modifiers(event_score, modifiers)
        
        # Update user baseline
        if event.user and event.user != 'unknown':
            self.modifiers.update_user_baseline(
                event.user,
                event.host or '',
                event.process_name or '',
                event.timestamp.hour if event.timestamp else datetime.utcnow().hour
            )
        
        return EventScore(
            event_score=event_score,
            matched_rules=matched_rules,
            base_score=base_score,
            bonus_score=bonus_score,
            modifiers_applied=modifiers,
            final_score=final_score
        )
    
    def _evaluate_rule(self, event: NormalizedEvent, 
                       rule: DetectionRule) -> Optional[RuleMatch]:
        """
        Evaluate a single rule against an event.
        
        Returns RuleMatch if rule matches, None otherwise.
        """
        # Check service match
        event_service = self._get_event_service(event)
        if rule.service != event_service:
            return None
        
        # Check allowlist first
        if self._matches_allowlist(event, rule):
            return None
        
        matched_fields = {}
        evidence = {}
        
        # Evaluate 'all' conditions (must all match)
        for cond in rule.match_all:
            result = self._evaluate_condition(event, cond)
            if not result[0]:
                return None
            matched_fields[cond.field] = result[1]
            evidence[cond.field] = result[1]
        
        # Evaluate 'any' conditions (at least one must match)
        if rule.match_any:
            any_matched = False
            for cond in rule.match_any:
                result = self._evaluate_condition(event, cond)
                if result[0]:
                    any_matched = True
                    matched_fields[cond.field] = result[1]
                    evidence[cond.field] = result[1]
            if not any_matched:
                return None
        
        # Evaluate 'none' conditions (none must match)
        for cond in rule.match_none:
            result = self._evaluate_condition(event, cond)
            if result[0]:
                return None  # Exclusion matched, rule doesn't apply
        
        return RuleMatch(
            rule=rule,
            matched_fields=matched_fields,
            evidence=evidence
        )
    
    def _get_event_service(self, event: NormalizedEvent) -> str:
        """Determine the service type for an event."""
        provider = event.provider or ''
        channel = event.channel or ''
        
        if 'Sysmon' in provider:
            return 'sysmon'
        elif 'Security' in channel or 'Security-Auditing' in provider:
            return 'security'
        elif 'System' in channel:
            return 'system'
        else:
            return 'sysmon'  # Default
    
    def _matches_allowlist(self, event: NormalizedEvent, 
                           rule: DetectionRule) -> bool:
        """Check if event matches any allowlist entry."""
        for entry in rule.allowlist:
            all_match = True
            for field_name, allowed_values in entry.items():
                field_value = self._get_field_value(event, field_name)
                if field_value is None:
                    all_match = False
                    break
                
                if isinstance(allowed_values, list):
                    if not any(self._value_matches(field_value, v, 'endswith') 
                              for v in allowed_values):
                        all_match = False
                        break
                else:
                    if not self._value_matches(field_value, allowed_values, 'endswith'):
                        all_match = False
                        break
            
            if all_match:
                return True
        
        return False
    
    def _evaluate_condition(self, event: NormalizedEvent, 
                            cond: MatchCondition) -> Tuple[bool, Any]:
        """
        Evaluate a single match condition.
        
        Returns (matched: bool, field_value: Any)
        """
        field_value = self._get_field_value(event, cond.field)
        
        if field_value is None:
            return (False, None)
        
        matched = self._value_matches(field_value, cond.value, cond.op, cond.case_sensitive)
        return (matched, field_value)
    
    def _get_field_value(self, event: NormalizedEvent, field_path: str) -> Any:
        """
        Get field value from event using dot notation.
        
        Supports paths like:
        - process.name -> process_name
        - process.target_image -> target_image
        - process.source_image -> source_image
        - process.granted_access -> granted_access
        """
        # Map dotted paths to actual field names
        field_mapping = {
            'process.name': 'process_name',
            'process.image': 'image_path',
            'process.command_line': 'command_line',
            'process.parent_name': 'parent_process_name',
            'process.parent_image': 'parent_process_name',
            'process.target_image': 'target_image',
            'process.source_image': 'source_image',
            'process.granted_access': 'granted_access',
            'process.call_trace': 'call_trace',
            'process.start_address': 'start_address',
            'process.start_module': 'start_module',
            'file.target': 'target_filename',
            'file.name': 'target_filename',
            'file.hash': 'file_hash',
            'registry.target': 'target_object',
            'registry.details': 'registry_details',
            'network.dest_ip': 'dest_ip',
            'network.dest_port': 'dest_port',
            'network.source_ip': 'source_ip',
            'auth.logon_type': 'logon_type',
            'auth.result': 'auth_result',
            'service.name': 'service_name',
            'service.file_name': 'service_file_name',
            'task.name': 'task_name',
            'share.name': 'share_name',
            'share.path': 'share_path',
            'kerberos.encryption_type': 'ticket_encryption_type',
        }
        
        # Try mapped path first
        actual_field = field_mapping.get(field_path, field_path)
        
        # Handle direct field access
        if hasattr(event, actual_field):
            return getattr(event, actual_field)
        
        # Try without dots (direct field name)
        field_name = field_path.replace('.', '_')
        if hasattr(event, field_name):
            return getattr(event, field_name)
        
        return None
    
    def _value_matches(self, field_value: Any, pattern: Any, 
                       op: str, case_sensitive: bool = False) -> bool:
        """Check if field value matches pattern using specified operator."""
        if field_value is None:
            return False
        
        # Convert to string for string operations
        str_value = str(field_value)
        if not case_sensitive:
            str_value = str_value.lower()
        
        def normalize(v):
            return str(v) if case_sensitive else str(v).lower()
        
        if op == 'equals':
            return str_value == normalize(pattern)
        
        elif op == 'not_equals':
            return str_value != normalize(pattern)
        
        elif op == 'contains':
            return normalize(pattern) in str_value
        
        elif op == 'not_contains':
            return normalize(pattern) not in str_value
        
        elif op == 'startswith':
            return str_value.startswith(normalize(pattern))
        
        elif op == 'endswith':
            return str_value.endswith(normalize(pattern))
        
        elif op == 'regex':
            pattern_str = str(pattern)
            if pattern_str not in self._regex_cache:
                flags = 0 if case_sensitive else re.IGNORECASE
                self._regex_cache[pattern_str] = re.compile(pattern_str, flags)
            return bool(self._regex_cache[pattern_str].search(str(field_value)))
        
        elif op == 'contains_any':
            if not isinstance(pattern, list):
                pattern = [pattern]
            return any(normalize(p) in str_value for p in pattern)
        
        elif op == 'endswith_any':
            if not isinstance(pattern, list):
                pattern = [pattern]
            return any(str_value.endswith(normalize(p)) for p in pattern)
        
        elif op == 'startswith_any':
            if not isinstance(pattern, list):
                pattern = [pattern]
            return any(str_value.startswith(normalize(p)) for p in pattern)
        
        elif op == 'equals_any':
            if not isinstance(pattern, list):
                pattern = [pattern]
            return any(str_value == normalize(p) for p in pattern)
        
        elif op == 'in_list':
            if not isinstance(pattern, list):
                pattern = [pattern]
            return str_value in [normalize(p) for p in pattern]
        
        elif op == 'not_in_list':
            if not isinstance(pattern, list):
                pattern = [pattern]
            return str_value not in [normalize(p) for p in pattern]
        
        elif op in ('gt', 'gte', 'lt', 'lte'):
            try:
                num_value = float(field_value)
                num_pattern = float(pattern)
                if op == 'gt':
                    return num_value > num_pattern
                elif op == 'gte':
                    return num_value >= num_pattern
                elif op == 'lt':
                    return num_value < num_pattern
                elif op == 'lte':
                    return num_value <= num_pattern
            except (ValueError, TypeError):
                return False
        
        return False
    
    def process_event(self, event: NormalizedEvent) -> Tuple[EventScore, Optional[EntityScore], Optional[EntityScore]]:
        """
        Process an event through the full scoring pipeline.
        
        Returns:
            Tuple of (event_score, user_entity_score, host_entity_score)
        """
        # Score the event
        event_score = self.score_event(event)
        
        if not event_score.matched_rules:
            return event_score, None, None
        
        # Add to entity aggregation
        self.aggregator.add_event_score(event, event_score)
        
        # Get updated entity scores
        user_score = None
        host_score = None
        
        if event.user and event.user != 'unknown':
            user_score = self.aggregator.get_entity_score('user', event.user)
        
        if event.host and event.host != 'unknown':
            host_score = self.aggregator.get_entity_score('host', event.host)
        
        return event_score, user_score, host_score


# Global scorer instance
_ueba_scorer: Optional[UEBAScorer] = None


def get_ueba_scorer(rules_path: Optional[str] = None) -> UEBAScorer:
    """Get or create global UEBA scorer instance."""
    global _ueba_scorer
    if _ueba_scorer is None:
        _ueba_scorer = UEBAScorer(rules_path)
    return _ueba_scorer
