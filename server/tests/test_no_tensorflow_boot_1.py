"""
Test that core UEBA modules import without TensorFlow.

This test ensures that TensorFlow is an optional dependency and
the core server functionality can work without it installed.
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_models_import_without_tensorflow():
    """Test that models.py (schemas) imports without TensorFlow."""
    from server.models import NormalizedEvent, Alert, EventCategory, AuthResult
    assert NormalizedEvent is not None
    assert Alert is not None


def test_storage_import_without_tensorflow():
    """Test that storage module imports without TensorFlow."""
    from server.storage import EventStorage, get_storage
    assert EventStorage is not None


def test_ml_models_lazy_load():
    """Test that ml_models package uses lazy loading for TensorFlow."""
    from server.ml_models import TF_AVAILABLE, build_sequence_model
    
    # TF_AVAILABLE should be False if TensorFlow is not installed
    # (or True if it is installed - either way, no crash)
    assert isinstance(TF_AVAILABLE, bool)
    
    # If TF is not available, calling the function should raise HTTPException(503)
    if not TF_AVAILABLE:
        import pytest
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            build_sequence_model()
        assert exc_info.value.status_code == 503


def test_normalizer_import_without_tensorflow():
    """Test that normalizer imports without TensorFlow."""
    from server.normalizer import normalize_event
    assert normalize_event is not None


def test_risk_engine_components_import():
    """Test that risk engine components import without TensorFlow."""
    from server.risk.rule_scorer import RuleBasedScorer
    from server.risk.anomaly_detector import IsolationForestAnomalyDetector
    assert RuleBasedScorer is not None
    assert IsolationForestAnomalyDetector is not None


def test_behaviors_import_without_tensorflow():
    """Test that behavior detectors import without TensorFlow."""
    from server.behaviors import run_all_detectors
    assert run_all_detectors is not None


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
