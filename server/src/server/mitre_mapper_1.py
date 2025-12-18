"""
MITRE ATT&CK Mapping Module.

Loads MITRE mappings from config and enriches alerts with tactic/technique IDs.
"""

import logging
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

# Global config cache
_mapping_config: Optional[Dict[str, Any]] = None


def load_mapping_config() -> Dict[str, Any]:
    """Load MITRE mapping configuration from YAML file."""
    global _mapping_config
    
    if _mapping_config is not None:
        return _mapping_config
    
    # Default path: server/config/mitre_mapping.yaml
    config_file = Path(__file__).parent.parent.parent.parent / "config" / "mitre_mapping.yaml"
    
    if not config_file.exists():
        logger.warning(f"MITRE mapping config not found at {config_file}, using defaults")
        _mapping_config = _default_mapping()
        return _mapping_config
    
    try:
        with open(config_file, 'r') as f:
            _mapping_config = yaml.safe_load(f)
        logger.info(f"Loaded MITRE mapping config from {config_file}")
    except Exception as e:
        logger.error(f"Failed to load MITRE mapping config: {e}")
        _mapping_config = _default_mapping()
    
    return _mapping_config


def _default_mapping() -> Dict[str, Any]:
    """Return default mapping if YAML file is missing."""
    return {
        "mappings": {
            "realtime_risk_event": {
                "tactics": ["TA0001"],
                "techniques": ["T1078"],
                "description": "Generic security event"
            }
        },
        "default": {
            "tactics": ["TA0001"],
            "techniques": ["T1078"],
            "description": "Generic security event"
        }
    }


def get_mapping(key: str) -> Dict[str, Any]:
    """
    Get MITRE mapping for a behavior/rule key.
    
    Args:
        key: Behavior name or rule name (e.g., "after_hours_data_exfil", "failed_login_burst")
        
    Returns:
        Dict with keys: tactics (list), techniques (list), description (str)
    """
    config = load_mapping_config()
    mappings = config.get("mappings", {})
    
    # Try exact match
    if key in mappings:
        return mappings[key]
    
    # Try case-insensitive match
    key_lower = key.lower()
    for mapping_key, mapping_value in mappings.items():
        if mapping_key.lower() == key_lower:
            return mapping_value
    
    # Fallback to default
    default = config.get("default", {
        "tactics": ["TA0001"],
        "techniques": ["T1078"],
        "description": "Generic security event"
    })
    logger.debug(f"No MITRE mapping found for '{key}', using default")
    return default


def enrich_alert(alert: Any) -> Any:
    """
    Enrich an alert object/dict with MITRE ATT&CK mapping.
    
    Args:
        alert: Alert object (Pydantic model) or dict with 'behavior' key
        
    Returns:
        Same alert object/dict with mitre_tactics and mitre_techniques added/updated
    """
    # Extract behavior key
    if hasattr(alert, 'behavior'):
        behavior = alert.behavior
    elif isinstance(alert, dict):
        behavior = alert.get('behavior', 'realtime_risk_event')
    else:
        behavior = 'realtime_risk_event'
    
    # Get mapping
    mapping = get_mapping(behavior)
    
    # Add/update fields
    if hasattr(alert, 'mitre_tactics'):
        alert.mitre_tactics = mapping.get("tactics", [])
        alert.mitre_techniques = mapping.get("techniques", [])
    elif isinstance(alert, dict):
        alert['mitre_tactics'] = mapping.get("tactics", [])
        alert['mitre_techniques'] = mapping.get("techniques", [])
    else:
        # Try to set attributes
        try:
            alert.mitre_tactics = mapping.get("tactics", [])
            alert.mitre_techniques = mapping.get("techniques", [])
        except AttributeError:
            logger.warning(f"Could not set MITRE fields on alert object: {type(alert)}")
    
    return alert


def reload_config() -> None:
    """Force reload of mapping configuration from file."""
    global _mapping_config
    _mapping_config = None
    load_mapping_config()

