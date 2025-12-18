"""
Feature Configuration Helper for UEBA Risk Engine.

Loads feature weights from features_config.yaml and provides
accessor functions for the risk engine.
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional
import yaml

logger = logging.getLogger(__name__)

# Global config cache
_config: Optional[Dict[str, Any]] = None


def load_config() -> Dict[str, Any]:
    """
    Load the features configuration from YAML file.
    
    Returns:
        Configuration dictionary
    """
    global _config
    
    if _config is not None:
        return _config
    
    # Default path: server/config/features_config.yaml
    config_file = Path(__file__).parent.parent.parent.parent / "config" / "features_config.yaml"
    
    if not config_file.exists():
        logger.warning(f"Features config not found at {config_file}, using defaults")
        _config = _default_config()
        return _config
    
    try:
        with open(config_file, 'r') as f:
            _config = yaml.safe_load(f)
        logger.info(f"Loaded feature config from {config_file}")
    except Exception as e:
        logger.error(f"Failed to load features config: {e}")
        _config = _default_config()
    
    return _config


def _default_config() -> Dict[str, Any]:
    """Return default configuration if YAML file is missing."""
    return {
        "features": {
            "authentication": {
                "is_off_hours": {"weight": 0.6},
                "is_failed_logon": {"weight": 0.8},
                "is_privileged_logon": {"weight": 0.7},
                "is_rare_source_ip": {"weight": 0.9},
            },
            "process_execution": {
                "is_lolbin": {"weight": 0.7},
                "is_suspicious_path": {"weight": 0.7},
                "has_obfuscated_cmdline": {"weight": 0.9},
            },
            "network": {
                "is_external_ip": {"weight": 0.5},
                "is_high_risk_port": {"weight": 0.8},
                "is_rare_destination": {"weight": 0.9},
            },
        },
        "scoring": {
            "rule_weight": 0.6,
            "feature_weight": 0.4,
            "max_feature_sum": 10.0,
            "risk_levels": {
                "critical": 80,
                "high": 60,
                "medium": 40,
                "low": 20,
            },
        },
    }


def get_feature_weight(category: str, feature_name: str) -> float:
    """
    Get the weight for a specific feature.
    
    Args:
        category: Feature category (authentication, process_execution, network)
        feature_name: Name of the feature (e.g., is_off_hours)
        
    Returns:
        Weight value (0.0-1.0), or 0.5 as default if not found
    """
    config = load_config()
    features = config.get("features", {})
    
    category_config = features.get(category, {})
    feature_config = category_config.get(feature_name, {})
    
    return feature_config.get("weight", 0.5)


def get_scoring_config() -> Dict[str, Any]:
    """
    Get the scoring configuration.
    
    Returns:
        Dictionary with rule_weight, feature_weight, max_feature_sum, risk_levels
    """
    config = load_config()
    return config.get("scoring", {
        "rule_weight": 0.6,
        "feature_weight": 0.4,
        "max_feature_sum": 10.0,
        "risk_levels": {"critical": 80, "high": 60, "medium": 40, "low": 20},
    })


def get_category_features(category: str) -> Dict[str, Dict[str, Any]]:
    """
    Get all feature configurations for a category.
    
    Args:
        category: Feature category (authentication, process_execution, network)
        
    Returns:
        Dictionary of feature_name -> {weight, description, ...}
    """
    config = load_config()
    features = config.get("features", {})
    return features.get(category, {})


def reload_config() -> None:
    """Force reload of configuration from file."""
    global _config
    _config = None
    load_config()
