"""
UEBA (User and Entity Behavior Analytics) Detection Engine.

This module provides rule-based detection with:
- YAML detection rule schema and loader
- Event scoring (0-100)
- Context modifiers (off_hours, rare_host, etc.)
- Entity aggregation with dedup/decay
- Alert generation with explainability
"""

from .rule_loader import DetectionRule, RuleLoader
from .scoring_engine import UEBAScorer, EventScore, EntityScore, get_ueba_scorer
from .alert_manager import AlertManager

__all__ = [
    'DetectionRule',
    'RuleLoader', 
    'UEBAScorer',
    'EventScore',
    'EntityScore',
    'AlertManager',
    'get_ueba_scorer',
]
