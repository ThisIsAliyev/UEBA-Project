"""
AI Risk Engine - Main Orchestrator.

Combines rule-based scoring, feature-based scoring, and context analysis
to produce comprehensive risk assessments.
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Any

import yaml

from ..models import NormalizedEvent, EventCategory
from ..storage import EventStorage
from .context_state import ContextManager, get_context_manager
from .rule_scorer import RuleBasedScorer
from .feature_config import get_feature_weight, get_scoring_config, get_category_features
from .anomaly_detector import IsolationForestAnomalyDetector
from .. import features_auth, features_process, features_network

logger = logging.getLogger(__name__)


@dataclass
class RiskResult:
    """Result of risk assessment."""
    risk_score: float  # 0-100
    risk_level: str  # "info" | "low" | "medium" | "high" | "critical"
    rule_score: float
    feature_score: float  # Feature-based scoring
    anomaly_score: float  # Placeholder until ML Phase
    context_score: float  # Placeholder until ML Phase
    components: Dict[str, Any]  # Detailed breakdown


class RiskEngine:
    """
    Main risk assessment engine.
    
    Orchestrates all risk assessment layers:
    - Layer 0: Context state management
    - Layer 1: Rule-based scoring
    - Layer 2: Anomaly detection (Phase 2)
    - Layer 3: Embedding analysis (Phase 3)
    """
    
    def __init__(self, config_path: Optional[str] = None, storage: Optional[EventStorage] = None):
        """
        Initialize risk engine.
        
        Args:
            config_path: Path to risk_engine.yaml config file
            storage: EventStorage instance (required for anomaly detection)
        """
        # Load configuration
        if config_path is None:
            # Default path: server/config/risk_engine.yaml
            config_file = Path(__file__).parent.parent.parent.parent / "config" / "risk_engine.yaml"
        else:
            config_file = Path(config_path)
        
        if not config_file.exists():
            logger.warning(f"Risk engine config not found at {config_file}, using defaults")
            self.config = self._default_config()
        else:
            with open(config_file, 'r') as f:
                self.config = yaml.safe_load(f)
        
        # Load thresholds
        thresholds_path = Path(__file__).parent / "config" / "thresholds.yaml"
        if thresholds_path.exists():
            with open(thresholds_path, 'r') as f:
                self.thresholds = yaml.safe_load(f)
        else:
            logger.warning(f"Thresholds config not found, using defaults")
            self.thresholds = self._default_thresholds()
        
        # Initialize components
        self.enabled = self.config.get("enabled", True)
        
        if not self.enabled:
            logger.info("Risk engine is disabled in configuration")
            return
        
        # Context manager
        context_config = self.thresholds.get("context", {})
        self.context_manager = get_context_manager()
        self.context_manager.maxlen = context_config.get("window_size", 50)
        self.context_manager.recent_window_minutes = context_config.get(
            "recent_events_window_minutes", 5
        )
        self.context_manager.max_age_minutes = context_config.get(
            "max_context_age_minutes", 60
        )
        
        # Rule-based scorer
        rules_path = self.config.get("config_paths", {}).get("rules")
        if rules_path:
            # Resolve relative to risk module
            rules_file = Path(__file__).parent / rules_path
        else:
            rules_file = Path(__file__).parent / "config" / "rules.yaml"
        
        self.rule_scorer = RuleBasedScorer(str(rules_file))
        
        # Phase 2: Initialize anomaly detector
        self.anomaly_detector: Optional[IsolationForestAnomalyDetector] = None
        anomaly_config = self.config.get("anomaly_detection", {})
        if anomaly_config.get("enabled", False) and storage is not None:
            model_path = anomaly_config.get("model_path", "data/risk_models/isolation_forest.pkl")
            # Resolve relative to project root
            if not Path(model_path).is_absolute():
                model_path = str(Path(__file__).parent.parent.parent.parent / model_path)
            
            detector_config = {
                "default_score": 0.0,
                "raw_min": -0.5,
                "raw_max": 0.5,
            }
            self.anomaly_detector = IsolationForestAnomalyDetector(
                model_path=model_path,
                storage=storage,
                config=detector_config
            )
            logger.info("Anomaly detector initialized")
        else:
            if anomaly_config.get("enabled", False) and storage is None:
                logger.warning("Anomaly detection enabled but no storage provided, skipping initialization")
        
        # TODO: Phase 3 - Initialize embedding analyzer
        # self.embedding_analyzer = EmbeddingRiskAnalyzer(...)
        
        logger.info("Risk engine initialized")
    
    def _default_config(self) -> Dict:
        """Return default configuration."""
        return {
            "enabled": True,
            "config_paths": {
                "rules": "config/rules.yaml",
                "thresholds": "config/thresholds.yaml"
            }
        }
    
    def _default_thresholds(self) -> Dict:
        """Return default thresholds."""
        return {
            "risk_levels": {
                "low_max": 40,
                "medium_max": 70,
                "high_min": 71
            },
            "weights": {
                "rule": 0.3,
                "anomaly": 0.4,
                "context": 0.3
            }
        }
    
    def assess_risk(self, event: NormalizedEvent) -> RiskResult:
        """
        Assess risk for a normalized event.
        
        Combines:
        - Rule-based scoring (existing)
        - Feature-based scoring (new)
        
        Args:
            event: NormalizedEvent to assess
            
        Returns:
            RiskResult with risk score, level, and component scores
        """
        if not self.enabled:
            # Return neutral risk if disabled
            return RiskResult(
                risk_score=0.0,
                risk_level="info",
                rule_score=0.0,
                feature_score=0.0,
                anomaly_score=0.0,
                context_score=0.0,
                components={}
            )
        
        try:
            # Get or create context for this user/host
            context = self.context_manager.get_context(event.user, event.host)
            
            # Add event to context (for future events)
            context.add_event(event)
            
            # Extract context features
            context_features = context.get_features(event)
            
            # Layer 1: Rule-based scoring
            rule_score = self.rule_scorer.score(event, context_features.__dict__)
            
            # Layer 2: Feature-based scoring (NEW)
            feature_score, extracted_features = self._compute_feature_score(event)
            
            # Layer 3: Anomaly detection (Phase 2)
            if self.anomaly_detector is not None:
                anomaly_score = self.anomaly_detector.detect(event, context)
            else:
                anomaly_score = 0.0
            
            # TODO: ML Phase - Embedding/context analysis
            context_score = 0.0
            
            # Calculate final risk score using thresholds.yaml weights
            weights = self.thresholds.get("weights", {})
            
            # Combine rule_score and feature_score with sub-weights
            scoring_config = get_scoring_config()
            rule_sub_weight = scoring_config.get("rule_weight", 0.6)
            feature_sub_weight = scoring_config.get("feature_weight", 0.4)
            combined_rule_feature = rule_sub_weight * rule_score + feature_sub_weight * feature_score
            
            # Final risk calculation using weights from thresholds.yaml
            final_risk = (
                weights.get("rule", 0.3) * combined_rule_feature +
                weights.get("anomaly", 0.4) * anomaly_score +
                weights.get("context", 0.3) * context_score
            )
            
            # Determine risk level using new thresholds
            risk_level = self._determine_risk_level(final_risk, scoring_config)
            
            # Build components dict
            components = {
                "rule_score": rule_score,
                "feature_score": feature_score,
                "anomaly_score": anomaly_score,
                "context_score": context_score,
                "extracted_features": extracted_features,
                "context_features": {
                    "events_last_5min": context_features.events_last_5min,
                    "unique_processes": context_features.unique_processes_in_window,
                    "is_new_process": context_features.is_new_process,
                }
            }
            
            # Log high-risk events if configured
            settings = self.config.get("settings", {})
            if settings.get("log_high_risk_only", True) and risk_level in ("high", "critical"):
                logger.warning(
                    f"High-risk event: user={event.user}, host={event.host}, "
                    f"process={event.process_name}, risk={final_risk:.1f}, "
                    f"rule_score={rule_score:.1f}, feature_score={feature_score:.1f}"
                )
            elif settings.get("log_assessments", False):
                logger.debug(
                    f"Risk assessment: user={event.user}, host={event.host}, "
                    f"risk={final_risk:.1f}, level={risk_level}"
                )
            
            return RiskResult(
                risk_score=final_risk,
                risk_level=risk_level,
                rule_score=rule_score,
                feature_score=feature_score,
                anomaly_score=anomaly_score,
                context_score=context_score,
                components=components
            )
        
        except Exception as e:
            logger.exception(f"Error in risk assessment: {e}")
            # Return neutral risk on error (don't block pipeline)
            return RiskResult(
                risk_score=0.0,
                risk_level="info",
                rule_score=0.0,
                feature_score=0.0,
                anomaly_score=0.0,
                context_score=0.0,
                components={"error": str(e)}
            )
    
    def _compute_feature_score(self, event: NormalizedEvent) -> tuple[float, Dict[str, Any]]:
        """
        Compute feature-based risk score for an event.
        
        Args:
            event: NormalizedEvent to analyze
            
        Returns:
            Tuple of (normalized_score 0-100, extracted_features dict)
        """
        extracted_features = {}
        feature_score_raw = 0.0
        
        # Get event category
        category = event.category
        if isinstance(category, EventCategory):
            category = category.value
        
        # Map category to feature extractor and config category
        category_mapping = {
            "auth": ("authentication", features_auth),
            "process": ("process_execution", features_process),
            "network": ("network", features_network),
        }
        
        if category not in category_mapping:
            # No feature extractor for this category
            return 0.0, {}
        
        config_category, feature_module = category_mapping[category]
        
        # Extract features using the appropriate module
        try:
            extracted_features = feature_module.extract_features(event)
        except Exception as e:
            logger.warning(f"Feature extraction failed for category {category}: {e}")
            return 0.0, {}
        
        # Calculate weighted sum of True features
        for feature_name, feature_value in extracted_features.items():
            if feature_value:  # Only count True/truthy features
                weight = get_feature_weight(config_category, feature_name)
                feature_score_raw += weight
        
        # Normalize to 0-100 scale
        scoring_config = get_scoring_config()
        max_sum = scoring_config.get("max_feature_sum", 10.0)
        
        # Clamp and normalize
        clamped = min(feature_score_raw, max_sum)
        feature_score = (clamped / max_sum) * 100
        
        return feature_score, extracted_features
    
    def _determine_risk_level(self, score: float, scoring_config: Dict[str, Any]) -> str:
        """
        Determine risk level from score using configured thresholds.
        
        Args:
            score: Risk score (0-100)
            scoring_config: Configuration with risk_levels thresholds
            
        Returns:
            Risk level string: "critical", "high", "medium", "low", or "info"
        """
        risk_levels = scoring_config.get("risk_levels", {})
        
        critical_threshold = risk_levels.get("critical", 80)
        high_threshold = risk_levels.get("high", 60)
        medium_threshold = risk_levels.get("medium", 40)
        low_threshold = risk_levels.get("low", 20)
        
        if score >= critical_threshold:
            return "critical"
        elif score >= high_threshold:
            return "high"
        elif score >= medium_threshold:
            return "medium"
        elif score >= low_threshold:
            return "low"
        else:
            return "info"


# Global risk engine instance
_risk_engine: Optional[RiskEngine] = None


def get_risk_engine(storage: Optional[EventStorage] = None) -> RiskEngine:
    """
    Get or create global risk engine instance.
    
    Args:
        storage: EventStorage instance (required for anomaly detection on first call)
    
    Returns:
        RiskEngine instance
    """
    global _risk_engine
    if _risk_engine is None:
        _risk_engine = RiskEngine(storage=storage)
    return _risk_engine

