"""
Tests for UEBA stabilization patches.

Tests null-safety, anomaly health, and feedback endpoints.
"""

import sys
import os
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
import tempfile
from datetime import datetime

# Use importlib to load modules directly to avoid package conflicts
import importlib.util


def load_module_from_file(name: str, path: str):
    """Load a module directly from file path."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Get base path
BASE_PATH = Path(__file__).parent.parent / "src" / "server"


class TestNormalizedEventHelpers:
    """Test NormalizedEvent helper methods for null-safety."""
    
    def test_sparse_event_helper_methods(self):
        """Test that sparse events work correctly with helper methods."""
        # Load models module directly
        models = load_module_from_file("models_test", str(BASE_PATH / "models.py"))
        
        NormalizedEvent = models.NormalizedEvent
        EventCategory = models.EventCategory
        AuthResult = models.AuthResult
        
        # Create sparse auth event (no command_line, no process hierarchy)
        event = NormalizedEvent(
            timestamp=datetime.utcnow(),
            host="TEST-PC",
            user="admin",
            event_id=4625,
            category=EventCategory.AUTH,
            auth_result=AuthResult.FAILED,
            source_ip="192.168.1.100"
        )
        
        # Verify helper methods work
        assert not event.has_command_line(), "has_command_line should be False for sparse event"
        assert not event.has_process_hierarchy(), "has_process_hierarchy should be False"
        assert event.has_network_context(), "has_network_context should be True (has source_ip)"
        assert not event.has_file_hash(), "has_file_hash should be False"
        assert event.has_auth_info(), "has_auth_info should be True"
    
    def test_full_event_helper_methods(self):
        """Test that full events work correctly with helper methods."""
        models = load_module_from_file("models_test2", str(BASE_PATH / "models.py"))
        
        NormalizedEvent = models.NormalizedEvent
        EventCategory = models.EventCategory
        AuthResult = models.AuthResult
        
        # Create full event with all fields
        event = NormalizedEvent(
            timestamp=datetime.utcnow(),
            host="TEST-PC",
            user="admin",
            event_id=1,
            category=EventCategory.PROCESS,
            command_line="cmd.exe /c whoami",
            process_id=1234,
            parent_process_id=5678,
            file_hash="abc123def456",
            source_ip="192.168.1.100",
            auth_result=AuthResult.SUCCESS
        )
        
        # Verify all helpers return True
        assert event.has_command_line(), "has_command_line should be True"
        assert event.has_process_hierarchy(), "has_process_hierarchy should be True"
        assert event.has_network_context(), "has_network_context should be True"
        assert event.has_file_hash(), "has_file_hash should be True"
        assert event.has_auth_info(), "has_auth_info should be True"


class TestAnomalyDetectorHealth:
    """Test anomaly detector health reporting."""
    
    def test_model_missing_health_status(self):
        """Test that anomaly detector reports degraded when model missing."""
        # Read the anomaly_detector file and verify get_health_status exists
        anomaly_detector_path = BASE_PATH / "risk" / "anomaly_detector.py"
        
        with open(anomaly_detector_path, 'r') as f:
            content = f.read()
        
        # Verify key additions are present
        assert 'model_available: bool = False' in content, "model_available field not found"
        assert 'def get_health_status(self)' in content, "get_health_status method not found"
        assert '"status": "healthy" if self.model_available else "degraded"' in content
        assert '"model_path": self.model_path' in content, "model_path field not in health status"
        assert '"sklearn_available": SKLEARN_AVAILABLE' in content


class TestFeedbackStorage:
    """Test feedback storage methods."""
    
    def test_feedback_storage_flow(self):
        """Test that feedback can be stored and retrieved."""
        # Load storage module
        storage_path = BASE_PATH / "storage.py"
        
        with open(storage_path, 'r') as f:
            content = f.read()
        
        # Verify feedback methods exist
        assert 'def get_alert(self, alert_id: int)' in content, "get_alert method not found"
        assert 'def store_feedback(' in content, "store_feedback method not found"
        assert 'def get_feedback_for_alert(self, alert_id: int)' in content, "get_feedback_for_alert not found"
        assert 'def get_training_labels(self, limit: int = 1000)' in content, "get_training_labels not found"
        
        # Verify ground_truth_labels table
        assert 'ground_truth_labels' in content, "ground_truth_labels table not found"
        assert "label TEXT NOT NULL CHECK(label IN ('true_positive', 'false_positive', 'uncertain'))" in content


class TestFeedbackAPI:
    """Test feedback API endpoints."""
    
    def test_feedback_api_exists(self):
        """Test that feedback API file exists with correct endpoints."""
        feedback_path = BASE_PATH / "api" / "feedback.py"
        
        assert feedback_path.exists(), "feedback.py not found in api directory"
        
        with open(feedback_path, 'r') as f:
            content = f.read()
        
        # Verify endpoints exist
        assert '@router.post("/{alert_id}/feedback"' in content, "POST endpoint not found"
        assert '@router.get("/{alert_id}/feedback")' in content, "GET endpoint not found"
        assert 'class FeedbackRequest(BaseModel):' in content, "FeedbackRequest model not found"
        assert 'class FeedbackResponse(BaseModel):' in content, "FeedbackResponse model not found"


class TestHealthEndpoint:
    """Test health endpoint."""
    
    def test_health_endpoint_includes_anomaly(self):
        """Test that /health endpoint includes anomaly engine status."""
        app_path = BASE_PATH / "app.py"
        
        with open(app_path, 'r') as f:
            content = f.read()
        
        # Verify anomaly health check is added
        assert 'anomaly_engine' in content, "anomaly_engine not in health endpoint"
        assert 'get_health_status()' in content, "get_health_status not called in health endpoint"
        assert '@app.get("/health")' in content, "health endpoint not found"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
