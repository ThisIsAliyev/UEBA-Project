"""
Offline Training Script for IsolationForest Anomaly Detection.

Loads historical events from the database, extracts features using the same
logic as IsolationForestAnomalyDetector, trains an IsolationForest model,
and saves it to disk.

Usage:
    python -m server.scripts.train_isolation_forest --days 30 --contamination 0.1
"""

import argparse
import logging
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import List

import numpy as np
import yaml

try:
    from sklearn.ensemble import IsolationForest
    import joblib
except ImportError:
    print("ERROR: scikit-learn is required for training. Install with: pip install scikit-learn")
    sys.exit(1)

from server.storage import EventStorage
from server.models import NormalizedEvent

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_config() -> dict:
    """Load risk_engine.yaml configuration."""
    config_path = Path(__file__).parent.parent / "config" / "risk_engine.yaml"
    
    if not config_path.exists():
        logger.warning(f"Config not found at {config_path}, using defaults")
        return {
            "anomaly_detection": {
                "model_path": "data/risk_models/isolation_forest.pkl",
                "contamination": 0.1,
                "training_days": 30
            }
        }
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    logger.info(f"Loaded config from {config_path}")
    return config


def load_training_events(storage: EventStorage, days: int) -> List[NormalizedEvent]:
    """
    Load events from the last `days` days from the events table.
    
    Args:
        storage: EventStorage instance
        days: Number of days to look back
        
    Returns:
        List of NormalizedEvent objects
    """
    cutoff = datetime.utcnow() - timedelta(days=days)
    
    logger.info(f"Loading events from the last {days} days (since {cutoff.isoformat()})")
    
    # Query events in batches to avoid memory issues
    events = []
    offset = 0
    batch_size = 1000
    
    while True:
        batch, total = storage.get_events(
            limit=batch_size,
            offset=offset,
            since_timestamp=cutoff
        )
        
        if not batch:
            break
        
        events.extend(batch)
        offset += batch_size
        
        logger.info(f"Loaded {len(events)} / {total} events...")
        
        if offset >= total:
            break
    
    logger.info(f"Loaded {len(events)} total events for training")
    return events


def extract_features_from_event(event: NormalizedEvent, storage: EventStorage) -> List[float]:
    """
    Extract feature vector from an event.
    
    IMPORTANT: This MUST match the feature extraction logic in
    IsolationForestAnomalyDetector._extract_features() exactly.
    
    Features (9 total):
    1. hour_of_day (0-23)
    2. day_of_week (0-6, Monday=0)
    3. is_weekend (0 or 1)
    4. is_working_hours (0 or 1)
    5. user_events_24h (count)
    6. user_unique_source_ips_7d (count)
    7. is_new_source_ip_30d (0 or 1)
    8. is_new_host_30d (0 or 1)
    9. source_ip_events_24h (count)
    """
    # Time-based features
    ts = event.timestamp
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts)
        except Exception:
            ts = datetime.utcnow()

    hour_of_day = ts.hour
    day_of_week = ts.weekday()  # 0=Monday
    is_weekend = 1.0 if day_of_week >= 5 else 0.0
    is_working_hours = 1.0 if 9 <= hour_of_day < 18 else 0.0

    # Historical stats from storage
    user_events_24h = float(_count_user_events_last_hours(storage, event.user, hours=24, before=ts))
    user_unique_source_ips_7d = float(_count_user_unique_source_ips_days(storage, event.user, days=7, before=ts))
    is_new_source_ip_30d = 1.0 if _is_new_source_ip_for_user_days(storage, event.user, event.source_ip, days=30, before=ts) else 0.0
    is_new_host_30d = 1.0 if _is_new_host_for_user_days(storage, event.user, event.host, days=30, before=ts) else 0.0
    source_ip_events_24h = float(_count_source_ip_events_last_hours(storage, event.source_ip, hours=24, before=ts))

    return [
        float(hour_of_day),
        float(day_of_week),
        is_weekend,
        is_working_hours,
        user_events_24h,
        user_unique_source_ips_7d,
        is_new_source_ip_30d,
        is_new_host_30d,
        source_ip_events_24h,
    ]


def _count_user_events_last_hours(storage: EventStorage, user: str, hours: int, before: datetime) -> int:
    """Count events for a user in the last N hours before a given timestamp."""
    if not user or user == "unknown":
        return 0
    
    try:
        cutoff = before - timedelta(hours=hours)
        with storage._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM events WHERE user = ? AND timestamp > ? AND timestamp < ?",
                (user, cutoff.isoformat(), before.isoformat())
            )
            result = cursor.fetchone()
            return result[0] if result else 0
    except Exception:
        return 0


def _count_user_unique_source_ips_days(storage: EventStorage, user: str, days: int, before: datetime) -> int:
    """Count unique source IPs for a user in the last N days before a given timestamp."""
    if not user or user == "unknown":
        return 0
    
    try:
        cutoff = before - timedelta(days=days)
        with storage._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """SELECT COUNT(DISTINCT source_ip) FROM events 
                   WHERE user = ? AND timestamp > ? AND timestamp < ? AND source_ip IS NOT NULL""",
                (user, cutoff.isoformat(), before.isoformat())
            )
            result = cursor.fetchone()
            return result[0] if result else 0
    except Exception:
        return 0


def _is_new_source_ip_for_user_days(storage: EventStorage, user: str, source_ip: str, days: int, before: datetime) -> bool:
    """Check if this source IP is new for the user in the last N days before a given timestamp."""
    if not user or user == "unknown" or not source_ip:
        return False
    
    try:
        cutoff = before - timedelta(days=days)
        with storage._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """SELECT COUNT(*) FROM events 
                   WHERE user = ? AND source_ip = ? AND timestamp > ? AND timestamp < ?""",
                (user, source_ip, cutoff.isoformat(), before.isoformat())
            )
            result = cursor.fetchone()
            count = result[0] if result else 0
            return count == 0
    except Exception:
        return False


def _is_new_host_for_user_days(storage: EventStorage, user: str, host: str, days: int, before: datetime) -> bool:
    """Check if this host is new for the user in the last N days before a given timestamp."""
    if not user or user == "unknown" or not host or host == "unknown":
        return False
    
    try:
        cutoff = before - timedelta(days=days)
        with storage._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """SELECT COUNT(*) FROM events 
                   WHERE user = ? AND host = ? AND timestamp > ? AND timestamp < ?""",
                (user, host, cutoff.isoformat(), before.isoformat())
            )
            result = cursor.fetchone()
            count = result[0] if result else 0
            return count == 0
    except Exception:
        return False


def _count_source_ip_events_last_hours(storage: EventStorage, source_ip: str, hours: int, before: datetime) -> int:
    """Count events from a source IP in the last N hours before a given timestamp."""
    if not source_ip:
        return 0
    
    try:
        cutoff = before - timedelta(hours=hours)
        with storage._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM events WHERE source_ip = ? AND timestamp > ? AND timestamp < ?",
                (source_ip, cutoff.isoformat(), before.isoformat())
            )
            result = cursor.fetchone()
            return result[0] if result else 0
    except Exception:
        return 0


def build_feature_matrix(events: List[NormalizedEvent], storage: EventStorage) -> np.ndarray:
    """
    Build feature matrix from events.
    
    Args:
        events: List of NormalizedEvent objects
        storage: EventStorage instance for historical queries
        
    Returns:
        NumPy array of shape (n_samples, n_features)
    """
    logger.info(f"Extracting features from {len(events)} events...")
    
    features = []
    for i, event in enumerate(events):
        if i % 100 == 0:
            logger.info(f"Processed {i}/{len(events)} events...")
        
        try:
            feature_vector = extract_features_from_event(event, storage)
            features.append(feature_vector)
        except Exception as e:
            logger.warning(f"Failed to extract features from event {event.id}: {e}")
            continue
    
    X = np.array(features)
    logger.info(f"Feature matrix shape: {X.shape}")
    
    return X


def train_isolation_forest(X: np.ndarray, contamination: float) -> IsolationForest:
    """
    Train an IsolationForest model.
    
    Args:
        X: Feature matrix (n_samples, n_features)
        contamination: Expected proportion of outliers (e.g., 0.1 = 10%)
        
    Returns:
        Trained IsolationForest model
    """
    logger.info(f"Training IsolationForest with contamination={contamination}")
    logger.info(f"Training data: {X.shape[0]} samples, {X.shape[1]} features")
    
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
        verbose=1
    )
    
    model.fit(X)
    
    logger.info("Training complete!")
    return model


def save_model(model: IsolationForest, model_path: str) -> None:
    """
    Save the trained model to disk.
    
    Args:
        model: Trained IsolationForest model
        model_path: Path to save the model
    """
    # Resolve path relative to project root
    if not Path(model_path).is_absolute():
        model_path = str(Path(__file__).parent.parent.parent / model_path)
    
    # Ensure directory exists
    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    
    joblib.dump(model, model_path)
    logger.info(f"Model saved to: {Path(model_path).absolute()}")


def main():
    """Main training pipeline."""
    parser = argparse.ArgumentParser(description="Train IsolationForest anomaly detection model")
    parser.add_argument(
        "--days",
        type=int,
        default=None,
        help="Number of days of historical data to use (overrides config)"
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=None,
        help="Expected proportion of anomalies (overrides config)"
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Path to events database (default: data/events.db)"
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config()
    anomaly_config = config.get("anomaly_detection", {})
    
    # Get parameters (CLI overrides config)
    days = args.days if args.days is not None else anomaly_config.get("training_days", 30)
    contamination = args.contamination if args.contamination is not None else anomaly_config.get("contamination", 0.1)
    model_path = anomaly_config.get("model_path", "data/risk_models/isolation_forest.pkl")
    
    # Database path
    if args.db_path:
        db_path = args.db_path
    else:
        db_path = str(Path(__file__).parent.parent.parent / "data" / "events.db")
    
    logger.info("=" * 60)
    logger.info("IsolationForest Training Configuration")
    logger.info("=" * 60)
    logger.info(f"Training days: {days}")
    logger.info(f"Contamination: {contamination}")
    logger.info(f"Model path: {model_path}")
    logger.info(f"Database: {db_path}")
    logger.info("=" * 60)
    
    # Initialize storage
    logger.info("Initializing storage...")
    storage = EventStorage(db_path=db_path)
    
    # Load training events
    events = load_training_events(storage, days)
    
    if len(events) < 100:
        logger.error(f"Insufficient training data: {len(events)} events. Need at least 100.")
        sys.exit(1)
    
    # Build feature matrix
    X = build_feature_matrix(events, storage)
    
    if X.shape[0] < 100:
        logger.error(f"Insufficient valid samples: {X.shape[0]}. Need at least 100.")
        sys.exit(1)
    
    # Train model
    model = train_isolation_forest(X, contamination)
    
    # Save model
    save_model(model, model_path)
    
    logger.info("=" * 60)
    logger.info("Training complete!")
    logger.info(f"Model saved to: {model_path}")
    logger.info(f"Trained on {X.shape[0]} events with {X.shape[1]} features")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
