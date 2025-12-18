"""
UEBA Alert Manager.

Handles:
- Alert generation when entity scores cross thresholds
- Flood prevention (rate limiting, dedup)
- Alert storage with explainability
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from .scoring_engine import EventScore, EntityScore

logger = logging.getLogger(__name__)


@dataclass
class AlertThresholds:
    """Configurable alert thresholds."""
    investigate_1h: float = 60.0  # Entity 1h score for investigate queue
    alert_1h: float = 80.0  # Entity 1h score for alert
    critical_1h: float = 120.0  # Entity 1h score for critical
    critical_event_score: int = 90  # Single event score for critical (with high confidence)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AlertThresholds':
        return cls(
            investigate_1h=data.get('investigate_1h', 60.0),
            alert_1h=data.get('alert_1h', 80.0),
            critical_1h=data.get('critical_1h', 120.0),
            critical_event_score=data.get('critical_event_score', 90),
        )


@dataclass
class UEBAAlert:
    """UEBA alert with full explainability."""
    id: Optional[int] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    # Entity info
    entity_type: str = ''  # 'user' or 'host'
    entity_id: str = ''
    
    # Scoring
    score: float = 0.0
    severity: str = 'medium'  # medium, high, critical
    
    # Alert details
    title: str = ''
    summary: str = ''
    
    # Explainability
    linked_rule_hits: List[Dict[str, Any]] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    
    # Lifecycle
    status: str = 'open'  # open, acknowledged, closed
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'created_at': self.created_at.isoformat(),
            'entity_type': self.entity_type,
            'entity_id': self.entity_id,
            'score': round(self.score, 2),
            'severity': self.severity,
            'title': self.title,
            'summary': self.summary,
            'linked_rule_hits': self.linked_rule_hits,
            'evidence': self.evidence,
            'mitre_tactics': self.mitre_tactics,
            'mitre_techniques': self.mitre_techniques,
            'status': self.status,
        }


@dataclass 
class RuleHit:
    """Record of a single rule hit for storage."""
    id: Optional[int] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_id: Optional[int] = None
    event_uuid: Optional[str] = None
    user: str = ''
    host: str = ''
    rule_id: str = ''
    base_score: int = 0
    final_event_score: int = 0
    modifiers_applied: Dict[str, float] = field(default_factory=dict)
    evidence_json: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'event_id': self.event_id,
            'event_uuid': self.event_uuid,
            'user': self.user,
            'host': self.host,
            'rule_id': self.rule_id,
            'base_score': self.base_score,
            'final_event_score': self.final_event_score,
            'modifiers_applied': self.modifiers_applied,
            'evidence_json': self.evidence_json,
        }


class FloodController:
    """
    Flood prevention for alerts.
    
    Implements:
    - Max alerts per entity per hour
    - Graceful degradation under load
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        
        # Track alerts per entity: (entity_type, entity_id) -> list of timestamps
        self._alert_times: Dict[Tuple[str, str], List[datetime]] = {}
        
        # Flood state
        self._in_flood_mode = False
        self._flood_queue: List[UEBAAlert] = []
    
    def _default_config(self) -> Dict[str, Any]:
        return {
            'max_alerts_per_entity_per_hour': 5,
            'flood_threshold_per_minute': 100,
            'flood_queue_max_size': 1000,
        }
    
    def can_alert(self, entity_type: str, entity_id: str) -> Tuple[bool, str]:
        """
        Check if we can generate an alert for this entity.
        
        Returns (can_alert, reason)
        """
        now = datetime.utcnow()
        entity_key = (entity_type, entity_id)
        
        # Get recent alerts for this entity
        if entity_key not in self._alert_times:
            self._alert_times[entity_key] = []
        
        # Clean old entries
        cutoff = now - timedelta(hours=1)
        self._alert_times[entity_key] = [
            t for t in self._alert_times[entity_key] if t > cutoff
        ]
        
        # Check rate limit
        max_alerts = self.config['max_alerts_per_entity_per_hour']
        if len(self._alert_times[entity_key]) >= max_alerts:
            return False, f"Rate limit: {max_alerts} alerts/hour for {entity_type}:{entity_id}"
        
        return True, ""
    
    def record_alert(self, entity_type: str, entity_id: str) -> None:
        """Record that an alert was generated."""
        entity_key = (entity_type, entity_id)
        if entity_key not in self._alert_times:
            self._alert_times[entity_key] = []
        self._alert_times[entity_key].append(datetime.utcnow())
    
    def queue_for_batch(self, alert: UEBAAlert) -> bool:
        """
        Queue an alert for batch processing during flood.
        
        Returns True if queued, False if queue is full.
        """
        if len(self._flood_queue) >= self.config['flood_queue_max_size']:
            return False
        self._flood_queue.append(alert)
        return True
    
    def get_queued_alerts(self) -> List[UEBAAlert]:
        """Get and clear queued alerts."""
        alerts = self._flood_queue
        self._flood_queue = []
        return alerts


class AlertManager:
    """
    Main alert management class.
    
    Coordinates:
    - Alert generation from scores
    - Flood prevention
    - Storage of rule hits and alerts
    """
    
    def __init__(self, storage=None, config: Optional[Dict[str, Any]] = None):
        self.storage = storage
        self.config = config or {}
        
        self.thresholds = AlertThresholds.from_dict(
            self.config.get('thresholds', {})
        )
        self.flood_controller = FloodController(
            self.config.get('flood_control', {})
        )
        
        # Track recent alerts for dedup
        self._recent_alerts: Dict[Tuple[str, str], datetime] = {}
        self._alert_dedup_minutes = self.config.get('alert_dedup_minutes', 15)
    
    def _is_duplicate_alert(self, entity_type: str, entity_id: str, 
                            severity: str) -> bool:
        """Check if we recently generated a similar alert."""
        key = (entity_type, entity_id)
        last_alert = self._recent_alerts.get(key)
        
        if last_alert is None:
            return False
        
        elapsed = (datetime.utcnow() - last_alert).total_seconds() / 60
        return elapsed < self._alert_dedup_minutes
    
    def _mark_alert_generated(self, entity_type: str, entity_id: str) -> None:
        """Mark that we generated an alert for this entity."""
        self._recent_alerts[(entity_type, entity_id)] = datetime.utcnow()
    
    def evaluate_for_alert(self, event_score: EventScore,
                           user_entity: Optional[EntityScore],
                           host_entity: Optional[EntityScore]) -> List[UEBAAlert]:
        """
        Evaluate scores and generate alerts if thresholds are crossed.
        
        Returns list of generated alerts.
        """
        alerts = []
        
        # Check for critical single-event alert
        if event_score.final_score >= self.thresholds.critical_event_score:
            # Check if any matched rule has high confidence
            has_high_conf = any(
                m.rule.confidence == 'high' for m in event_score.matched_rules
            )
            if has_high_conf:
                alert = self._create_event_alert(event_score, 'critical')
                if alert:
                    alerts.append(alert)
        
        # Check user entity score
        if user_entity:
            alert = self._evaluate_entity_alert(user_entity, event_score)
            if alert:
                alerts.append(alert)
        
        # Check host entity score
        if host_entity:
            alert = self._evaluate_entity_alert(host_entity, event_score)
            if alert:
                alerts.append(alert)
        
        return alerts
    
    def _evaluate_entity_alert(self, entity: EntityScore,
                               event_score: EventScore) -> Optional[UEBAAlert]:
        """Evaluate entity score and generate alert if needed."""
        severity = None
        
        if entity.score_1h >= self.thresholds.critical_1h:
            severity = 'critical'
        elif entity.score_1h >= self.thresholds.alert_1h:
            severity = 'high'
        elif entity.score_1h >= self.thresholds.investigate_1h:
            severity = 'medium'
        
        if severity is None:
            return None
        
        # Check dedup
        if self._is_duplicate_alert(entity.entity_type, entity.entity_id, severity):
            return None
        
        # Check flood control
        can_alert, reason = self.flood_controller.can_alert(
            entity.entity_type, entity.entity_id
        )
        if not can_alert:
            logger.warning(f"Alert suppressed: {reason}")
            return None
        
        # Create alert
        alert = self._create_entity_alert(entity, event_score, severity)
        
        # Record for flood control and dedup
        self.flood_controller.record_alert(entity.entity_type, entity.entity_id)
        self._mark_alert_generated(entity.entity_type, entity.entity_id)
        
        return alert
    
    def _create_event_alert(self, event_score: EventScore, 
                            severity: str) -> Optional[UEBAAlert]:
        """Create alert for a single high-risk event."""
        if not event_score.matched_rules:
            return None
        
        # Get entity info from first matched rule
        first_match = event_score.matched_rules[0]
        entity_type = first_match.rule.risk_object
        
        # Collect MITRE info
        tactics = set()
        techniques = set()
        for match in event_score.matched_rules:
            for m in match.rule.mitre:
                tactics.add(m.tactic)
                techniques.add(m.technique_id)
        
        # Build linked rule hits
        linked_rules = []
        for match in event_score.matched_rules:
            linked_rules.append({
                'rule_id': match.rule.id,
                'rule_name': match.rule.name,
                'base_score': match.rule.base_score,
                'evidence': match.evidence,
            })
        
        title = f"Critical: {first_match.rule.name}"
        summary = f"High-risk event detected. Score: {event_score.final_score}. " \
                  f"Matched {len(event_score.matched_rules)} rule(s)."
        
        return UEBAAlert(
            entity_type=entity_type,
            entity_id='',  # Will be filled by caller
            score=event_score.final_score,
            severity=severity,
            title=title,
            summary=summary,
            linked_rule_hits=linked_rules,
            evidence=event_score.to_dict(),
            mitre_tactics=list(tactics),
            mitre_techniques=list(techniques),
        )
    
    def _create_entity_alert(self, entity: EntityScore,
                             event_score: EventScore,
                             severity: str) -> UEBAAlert:
        """Create alert for entity threshold crossing."""
        # Collect MITRE info from recent rules
        tactics = set()
        techniques = set()
        linked_rules = []
        
        for match in event_score.matched_rules:
            for m in match.rule.mitre:
                tactics.add(m.tactic)
                techniques.add(m.technique_id)
            linked_rules.append({
                'rule_id': match.rule.id,
                'rule_name': match.rule.name,
                'base_score': match.rule.base_score,
            })
        
        severity_labels = {
            'medium': 'Investigate',
            'high': 'Alert',
            'critical': 'Critical',
        }
        
        title = f"{severity_labels.get(severity, 'Alert')}: " \
                f"{entity.entity_type.title()} {entity.entity_id} risk threshold"
        
        summary = f"{entity.entity_type.title()} '{entity.entity_id}' has accumulated " \
                  f"risk score of {entity.score_1h:.1f} in the last hour. " \
                  f"Contributing rules: {', '.join(entity.contributing_rules[:5])}"
        
        return UEBAAlert(
            entity_type=entity.entity_type,
            entity_id=entity.entity_id,
            score=entity.score_1h,
            severity=severity,
            title=title,
            summary=summary,
            linked_rule_hits=linked_rules,
            evidence={
                'score_1h': entity.score_1h,
                'score_24h': entity.score_24h,
                'contributing_rules': entity.contributing_rules,
            },
            mitre_tactics=list(tactics),
            mitre_techniques=list(techniques),
        )
    
    def create_rule_hit(self, event, event_score: EventScore) -> List[RuleHit]:
        """Create RuleHit records for storage."""
        hits = []
        
        for match in event_score.matched_rules:
            hit = RuleHit(
                timestamp=datetime.utcnow(),
                event_id=getattr(event, 'id', None),
                user=getattr(event, 'user', ''),
                host=getattr(event, 'host', ''),
                rule_id=match.rule.id,
                base_score=match.rule.base_score,
                final_event_score=event_score.final_score,
                modifiers_applied=event_score.modifiers_applied,
                evidence_json=match.evidence,
            )
            hits.append(hit)
        
        return hits
    
    def store_rule_hits(self, hits: List[RuleHit]) -> None:
        """Store rule hits to database."""
        if not self.storage or not hits:
            return
        
        try:
            self.storage.store_rule_hits(hits)
        except Exception as e:
            logger.error(f"Failed to store rule hits: {e}")
    
    def store_alert(self, alert: UEBAAlert) -> Optional[int]:
        """Store alert to database."""
        if not self.storage:
            return None
        
        try:
            return self.storage.store_ueba_alert(alert)
        except Exception as e:
            logger.error(f"Failed to store alert: {e}")
            return None


# Global alert manager instance
_alert_manager: Optional[AlertManager] = None


def get_alert_manager(storage=None) -> AlertManager:
    """Get or create global alert manager instance."""
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager(storage)
    return _alert_manager
