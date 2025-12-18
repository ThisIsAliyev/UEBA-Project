"""
Unit tests for Alert Deduplication / Aggregation.

Tests the upsert_or_update_alert() method in storage layer.
"""

import os
import sqlite3
import tempfile
import pytest
from datetime import datetime, timedelta

from src.server.models import Alert, BehaviorType
from src.server.storage import EventStorage


@pytest.fixture
def storage():
    """Create a temporary storage instance for testing."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    
    storage = EventStorage(db_path=db_path)
    yield storage
    
    # Cleanup
    try:
        os.unlink(db_path)
    except:
        pass


def test_first_detection_creates_new_alert(storage):
    """Test: First detection creates new alert with occurrence_count=1."""
    alert = Alert(
        timestamp=datetime.utcnow(),
        behavior=BehaviorType.FAILED_LOGIN_BURST.value,
        risk_score=70,
        host="workstation1",
        user="john.doe",
        summary="5 consecutive failed logins"
    )
    
    alert_id = storage.upsert_or_update_alert(alert)
    
    # Verify alert was created
    alerts, count = storage.get_alerts()
    assert count == 1
    assert alerts[0].id == alert_id
    assert alerts[0].occurrence_count == 1
    assert alerts[0].status == "open"


def test_repeated_detection_increments_count(storage):
    """Test: Same detection within merge window increments occurrence_count."""
    base_time = datetime.utcnow()
    
    # First alert
    alert1 = Alert(
        timestamp=base_time,
        behavior=BehaviorType.SUSPICIOUS_PATH_EXECUTION.value,
        risk_score=65,
        host="workstation1",
        user="john.doe",
        summary="Executable from Downloads"
    )
    alert_id = storage.upsert_or_update_alert(alert1)
    
    # Second alert - same user/host/behavior within 30 minutes
    alert2 = Alert(
        timestamp=base_time + timedelta(minutes=10),
        behavior=BehaviorType.SUSPICIOUS_PATH_EXECUTION.value,
        risk_score=65,
        host="workstation1",
        user="john.doe",
        summary="Executable from Downloads"
    )
    alert_id_2 = storage.upsert_or_update_alert(alert2)
    
    # Should be same alert ID
    assert alert_id_2 == alert_id
    
    # Verify only one alert with count=2
    alerts, count = storage.get_alerts()
    assert count == 1
    assert alerts[0].occurrence_count == 2
    assert alerts[0].risk_score == 70  # 65 + 5


def test_detection_after_window_creates_new_alert(storage):
    """Test: Detection after merge window creates new alert."""
    # First alert (pretend it's from 45 minutes ago)
    old_time = datetime.utcnow() - timedelta(minutes=45)
    
    alert1 = Alert(
        timestamp=old_time,
        behavior=BehaviorType.FIREWALL_DISABLED.value,
        risk_score=85,
        host="workstation1",
        user="admin",
        summary="Firewall disabled"
    )
    alert_id_1 = storage.upsert_or_update_alert(alert1)
    
    # Second alert - 45 minutes later (beyond 30-minute window)
    alert2 = Alert(
        timestamp=datetime.utcnow(),
        behavior=BehaviorType.FIREWALL_DISABLED.value,
        risk_score=85,
        host="workstation1",
        user="admin",
        summary="Firewall disabled"
    )
    alert_id_2 = storage.upsert_or_update_alert(alert2)
    
    # Should be different alert IDs
    assert alert_id_2 != alert_id_1
    
    # Verify we have two alerts
    alerts, count = storage.get_alerts()
    assert count == 2


def test_different_user_creates_separate_alert(storage):
    """Test: Different user creates separate alert even within window."""
    base_time = datetime.utcnow()
    
    # Alert for user1
    alert1 = Alert(
        timestamp=base_time,
        behavior=BehaviorType.RESTRICTED_HOURS_LOGIN.value,
        risk_score=60,
        host="workstation1",
        user="user1",
        summary="Login during restricted hours"
    )
    storage.upsert_or_update_alert(alert1)
    
    # Alert for user2 - different user, same host
    alert2 = Alert(
        timestamp=base_time + timedelta(minutes=5),
        behavior=BehaviorType.RESTRICTED_HOURS_LOGIN.value,
        risk_score=60,
        host="workstation1",
        user="user2",
        summary="Login during restricted hours"
    )
    storage.upsert_or_update_alert(alert2)
    
    # Verify we have two separate alerts
    alerts, count = storage.get_alerts()
    assert count == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
