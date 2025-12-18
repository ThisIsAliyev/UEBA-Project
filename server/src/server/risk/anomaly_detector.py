"""
IsolationForest Anomaly Detection Layer for UEBA Risk Engine.

Provides online anomaly scoring using a pre-trained IsolationForest model.
Extracts behavioral features from events and historical data to detect anomalies.
"""

from __future__ import annotations
from typing import Optional, List, Dict, Any
import logging
import time
from datetime import datetime, timedelta

try:
    from sklearn.ensemble import IsolationForest
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logging.warning("scikit-learn not available, anomaly detection will be disabled")

from ..models import NormalizedEvent
from ..storage import EventStorage

logger = logging.getLogger(__name__)

# Rate limiting for mismatch warnings
_last_mismatch_warning_time: float = 0.0
MISMATCH_WARNING_INTERVAL_SEC: float = 60.0  # Log mismatch warning at most once per minute
_mismatch_diag_logged: bool = False  # One-time diagnostic logging flag


class IsolationForestAnomalyDetector:
    """
    Wraps a trained IsolationForest model and provides a 0-100 anomaly score
    for a given NormalizedEvent.
    
    Features extracted:
    - Temporal: hour_of_day, day_of_week, is_weekend, is_working_hours
    - User behavior: events_24h, unique_source_ips_7d, new_source_ip, new_host
    - Source IP behavior: source_ip_events_24h
    """

    def __init__(
        self, 
        model_path: str, 
        storage: EventStorage, 
        config: Optional[dict] = None
    ) -> None:
        """
        Initialize the anomaly detector.
        
        Args:
            model_path: Path to the trained IsolationForest model (.pkl file)
            storage: EventStorage instance for querying historical data
            config: Optional configuration dict with keys:
                - default_score: Score to return when model is unavailable (default: 0.0)
                - raw_min: Min expected raw score from IsolationForest (default: -0.5)
                - raw_max: Max expected raw score from IsolationForest (default: 0.5)
        """
        self.model_path = model_path
        self.storage = storage
        self.config = config or {}
        self._logger = logging.getLogger(__name__)
        self._model: Optional[IsolationForest] = None
        self._enabled: bool = False
        self._default_score: float = float(self.config.get("default_score", 0.0))
        self.model_available: bool = False  # Track model availability for health checks
        self._model_n_features: Optional[int] = None  # Expected feature count from model
        self._mismatch_count: int = 0  # Track feature mismatch occurrences

        self._load_model()

    def _load_model(self) -> None:
        """Load the IsolationForest model from disk."""
        if not SKLEARN_AVAILABLE:
            self._logger.warning("scikit-learn not available, anomaly detection disabled")
            self._model = None
            self._enabled = False
            self.model_available = False
            return
        
        try:
            self._model = joblib.load(self.model_path)
            self._enabled = True
            self.model_available = True
            # Log model metadata for debugging
            if hasattr(self._model, 'n_features_in_'):
                self._model_n_features = self._model.n_features_in_
                self._logger.info(
                    "IsolationForest model loaded from %s (expects %d features)",
                    self.model_path, self._model_n_features
                )
            else:
                self._logger.info("IsolationForest model loaded from %s", self.model_path)
        except FileNotFoundError:
            # Try to find model in database
            try:
                model_info = self.storage.get_active_model("isolation_forest")
                if model_info and "model_path" in model_info:
                    alt_path = model_info["model_path"]
                    self._logger.info(f"Trying alternative model path from database: {alt_path}")
                    try:
                        self._model = joblib.load(alt_path)
                        self._enabled = True
                        self.model_available = True
                        self._logger.info(f"IsolationForest model loaded from alternative path: {alt_path}")
                        return
                    except Exception as alt_exc:
                        self._logger.warning(f"Failed to load model from alternative path: {alt_exc}")
            except Exception as db_exc:
                self._logger.warning(f"Failed to query database for model: {db_exc}")
                
            self._logger.warning(
                "IsolationForest model not found at %s. Anomaly detection disabled.",
                self.model_path,
            )
            self._model = None
            self._enabled = False
            self.model_available = False
        except Exception as exc:
            self._logger.warning(
                "IsolationForest model could not be loaded from %s: %s. Falling back to disabled mode.",
                self.model_path,
                exc,
            )
            self._model = None
            self._enabled = False
            self.model_available = False

    def detect(self, event: NormalizedEvent, context: Optional[any] = None) -> float:
        """
        Compute an anomaly score in [0, 100] for this event.
        
        Args:
            event: NormalizedEvent to score
            context: Optional ContextState (not used currently)
            
        Returns:
            Anomaly score where:
            - 0   = very normal
            - 100 = highly anomalous
        """
        global _last_mismatch_warning_time, _mismatch_diag_logged
        
        if not self._enabled or self._model is None:
            return self._default_score

        features = self._extract_features(event)
        if not features:
            return self._default_score

        # IsolationForest expects shape (n_samples, n_features)
        X = [features]
        
        # MVP HOTFIX: Handle feature count mismatch gracefully
        if self._model_n_features is not None:
            actual_features = len(features)
            if actual_features != self._model_n_features:
                self._mismatch_count += 1
                
                # One-time detailed diagnostic logging
                if not _mismatch_diag_logged:
                    _mismatch_diag_logged = True
                    runtime_feature_names = [
                        "hour_of_day", "day_of_week", "is_weekend", "is_working_hours",
                        "user_events_24h", "user_unique_source_ips_7d", "is_new_source_ip_30d",
                        "is_new_host_30d", "source_ip_events_24h"
                    ]
                    self._logger.warning(
                        "=== FEATURE MISMATCH DIAGNOSTIC (one-time) ===\n"
                        "  Model path: %s\n"
                        "  Model expects: %d features\n"
                        "  Runtime got: %d features\n"
                        "  Runtime feature names: %s\n"
                        "  Action: Returning anomaly_score=0.0 (no crash)",
                        self.model_path, self._model_n_features, actual_features,
                        runtime_feature_names
                    )
                
                # Rate-limited warning (once per minute)
                current_time = time.time()
                if current_time - _last_mismatch_warning_time >= MISMATCH_WARNING_INTERVAL_SEC:
                    _last_mismatch_warning_time = current_time
                    self._logger.warning(
                        "Feature mismatch: model expects %d, got %d. score=0.0 (total: %d)",
                        self._model_n_features, actual_features, self._mismatch_count
                    )
                # Return default score instead of crashing
                return self._default_score
        
        try:
            raw_scores = self._model.score_samples(X)  # higher => more normal
            raw_score = float(raw_scores[0])
        except Exception as exc:
            # Rate-limited error logging
            current_time = time.time()
            if current_time - _last_mismatch_warning_time >= MISMATCH_WARNING_INTERVAL_SEC:
                _last_mismatch_warning_time = current_time
                self._logger.error("Error scoring event with IsolationForest: %s", exc)
            return self._default_score

        return self._raw_score_to_0_100(raw_score)

    def _extract_features(self, event: NormalizedEvent) -> List[float]:
        """
        Build a numeric feature vector for the given event.

        IMPORTANT:
        - The order of features here MUST match the order used during training.
        - Keep this list relatively small and robust.
        
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
        user_events_24h = float(self._count_user_events_last_hours(event.user, hours=24))
        user_unique_source_ips_7d = float(self._count_user_unique_source_ips_days(event.user, days=7))
        is_new_source_ip_30d = 1.0 if self._is_new_source_ip_for_user_days(event.user, event.source_ip, days=30) else 0.0
        is_new_host_30d = 1.0 if self._is_new_host_for_user_days(event.user, event.host, days=30) else 0.0
        source_ip_events_24h = float(self._count_source_ip_events_last_hours(event.source_ip, hours=24))

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

    # ========== Helper methods using EventStorage ==========

    def _count_user_events_last_hours(self, user: str, hours: int) -> int:
        """Count events for a user in the last N hours."""
        if not user or user == "unknown":
            return 0
        
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            with self.storage._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT COUNT(*) FROM events WHERE user = ? AND timestamp > ?",
                    (user, cutoff.isoformat())
                )
                result = cursor.fetchone()
                return result[0] if result else 0
        except Exception as e:
            self._logger.debug(f"Error counting user events: {e}")
            return 0

    def _count_user_unique_source_ips_days(self, user: str, days: int) -> int:
        """Count unique source IPs for a user in the last N days."""
        if not user or user == "unknown":
            return 0
        
        try:
            cutoff = datetime.utcnow() - timedelta(days=days)
            with self.storage._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT COUNT(DISTINCT source_ip) FROM events 
                       WHERE user = ? AND timestamp > ? AND source_ip IS NOT NULL""",
                    (user, cutoff.isoformat())
                )
                result = cursor.fetchone()
                return result[0] if result else 0
        except Exception as e:
            self._logger.debug(f"Error counting unique source IPs: {e}")
            return 0

    def _is_new_source_ip_for_user_days(self, user: str, source_ip: Optional[str], days: int) -> bool:
        """Check if this source IP is new for the user in the last N days."""
        if not user or user == "unknown" or not source_ip:
            return False
        
        try:
            cutoff = datetime.utcnow() - timedelta(days=days)
            with self.storage._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT COUNT(*) FROM events 
                       WHERE user = ? AND source_ip = ? AND timestamp > ?""",
                    (user, source_ip, cutoff.isoformat())
                )
                result = cursor.fetchone()
                count = result[0] if result else 0
                return count == 0
        except Exception as e:
            self._logger.debug(f"Error checking new source IP: {e}")
            return False

    def _is_new_host_for_user_days(self, user: str, host: str, days: int) -> bool:
        """Check if this host is new for the user in the last N days."""
        if not user or user == "unknown" or not host or host == "unknown":
            return False
        
        try:
            cutoff = datetime.utcnow() - timedelta(days=days)
            with self.storage._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT COUNT(*) FROM events 
                       WHERE user = ? AND host = ? AND timestamp > ?""",
                    (user, host, cutoff.isoformat())
                )
                result = cursor.fetchone()
                count = result[0] if result else 0
                return count == 0
        except Exception as e:
            self._logger.debug(f"Error checking new host: {e}")
            return False

    def _count_source_ip_events_last_hours(self, source_ip: Optional[str], hours: int) -> int:
        """Count events from a source IP in the last N hours."""
        if not source_ip:
            return 0
        
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            with self.storage._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT COUNT(*) FROM events WHERE source_ip = ? AND timestamp > ?",
                    (source_ip, cutoff.isoformat())
                )
                result = cursor.fetchone()
                return result[0] if result else 0
        except Exception as e:
            self._logger.debug(f"Error counting source IP events: {e}")
            return 0

    # ========== Score normalization ==========

    def _raw_score_to_0_100(self, raw_score: float) -> float:
        """
        Transform IsolationForest raw score (higher = more normal)
        into a 0-100 anomaly score (higher = more anomalous).

        Approach:
        - Clamp raw_score to a reasonable range [low, high]
        - Map linearly so that low → 100, high → 0
        """
        low = self.config.get("raw_min", -0.5)
        high = self.config.get("raw_max", 0.5)

        clamped = max(min(raw_score, high), low)
        # normal_score in [0, 1], higher = more normal
        normal_score_01 = (clamped - low) / (high - low)
        # anomaly_score in [0, 100], higher = more anomalous
        anomaly_score_01 = 1.0 - normal_score_01
        return float(max(0.0, min(100.0, anomaly_score_01 * 100.0)))

    def get_health_status(self) -> Dict[str, Any]:
        """
        Get health status of anomaly detector for monitoring.
        
        Returns:
            Dict with status, model_available, model_path, sklearn_available, and reason
        """
        reason = None
        if not SKLEARN_AVAILABLE:
            reason = "scikit-learn not installed"
        elif not self.model_available:
            reason = f"Model file not found or failed to load: {self.model_path}"
        
        return {
            "status": "healthy" if self.model_available else "degraded",
            "model_available": self.model_available,
            "model_path": self.model_path,
            "sklearn_available": SKLEARN_AVAILABLE,
            "model_n_features": self._model_n_features,
            "feature_mismatch_count": self._mismatch_count,
            "reason": reason
        }
    
    def detect_with_session_features(
        self, 
        features: Dict[str, float]
    ) -> float:
        """
        Compute anomaly score using session-aggregated features.
        
        This method uses the session feature vector format from
        SessionAggregator for scoring.
        
        Args:
            features: Dict of session features (from session_features table)
            
        Returns:
            Anomaly score 0-100 (higher = more anomalous)
        """
        global _last_mismatch_warning_time
        
        if not self._enabled or self._model is None:
            return self._default_score
        
        # Convert features dict to vector in correct order
        from ..baseline.session_aggregator import SessionAggregator
        feature_names = SessionAggregator.get_feature_names()
        
        try:
            feature_vector = [float(features.get(name, 0)) for name in feature_names]
            
            # MVP HOTFIX: Handle feature count mismatch gracefully
            if self._model_n_features is not None:
                actual_features = len(feature_vector)
                if actual_features != self._model_n_features:
                    self._mismatch_count += 1
                    # Rate-limited warning
                    current_time = time.time()
                    if current_time - _last_mismatch_warning_time >= MISMATCH_WARNING_INTERVAL_SEC:
                        _last_mismatch_warning_time = current_time
                        self._logger.warning(
                            "Session feature mismatch: model expects %d, got %d. (total: %d)",
                            self._model_n_features, actual_features, self._mismatch_count
                        )
                    return self._default_score
            
            X = [feature_vector]
            raw_scores = self._model.score_samples(X)
            raw_score = float(raw_scores[0])
            
            return self._raw_score_to_0_100(raw_score)
            
        except Exception as exc:
            # Rate-limited error logging
            current_time = time.time()
            if current_time - _last_mismatch_warning_time >= MISMATCH_WARNING_INTERVAL_SEC:
                _last_mismatch_warning_time = current_time
                self._logger.error("Error scoring session features: %s", exc)
            return self._default_score
    
    def reload_model(self) -> bool:
        """
        Reload the model from disk (after retraining).
        
        Returns:
            True if model was reloaded successfully
        """
        self._load_model()
        return self._enabled


# ============================================
# Global Model Training Functions
# ============================================

async def train_global_isolation_forest(
    storage,
    sessions: List[Dict[str, Any]],
    contamination: float = 0.05,
    n_estimators: int = 100
) -> Optional[Dict[str, Any]]:
    """
    Train a global IsolationForest model on session features.
    
    Args:
        storage: EventStorage instance
        sessions: List of session feature dicts from get_session_features()
        contamination: Expected proportion of outliers (default 5%)
        n_estimators: Number of trees in the forest
        
    Returns:
        Dict with model_path, trained_at, training_samples, or None on failure
    """
    if not SKLEARN_AVAILABLE:
        logger.warning("scikit-learn not available, cannot train model")
        return None
    
    if len(sessions) < 50:
        logger.warning(f"Insufficient sessions for training: {len(sessions)} (need >= 50)")
        return None
    
    try:
        import numpy as np
        from pathlib import Path
        
        # Get feature names for vector conversion
        from ..baseline.session_aggregator import SessionAggregator
        feature_names = SessionAggregator.get_feature_names()
        
        # Build feature matrix
        X = []
        for session in sessions:
            features = session.get("features", {})
            vector = [float(features.get(name, 0)) for name in feature_names]
            X.append(vector)
        
        X = np.array(X)
        logger.info(f"Training IsolationForest on {X.shape[0]} sessions, {X.shape[1]} features")
        
        # Train model
        model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        model.fit(X)
        
        # Ensure model directory exists
        from ..config import get_config
        config = get_config()
        model_dir = config.root_dir / "data" / "risk_models"
        model_dir.mkdir(parents=True, exist_ok=True)
        
        # Save model
        model_filename = "isolation_forest_global.pkl"
        model_path = model_dir / model_filename
        
        try:
            joblib.dump(model, model_path)
            logger.info(f"Model saved to {model_path}")
        except Exception as e:
            logger.error(f"Failed to save model to {model_path}: {e}")
            # Try alternative location in case of permission issues
            alt_model_dir = Path("/tmp/risk_models")
            alt_model_dir.mkdir(parents=True, exist_ok=True)
            alt_model_path = alt_model_dir / model_filename
            try:
                joblib.dump(model, alt_model_path)
                model_path = alt_model_path
                logger.info(f"Model saved to alternative location: {model_path}")
            except Exception as e2:
                logger.error(f"Failed to save model to alternative location: {e2}")
                return None
        
        trained_at = datetime.utcnow()
        
        # Store metadata in database
        storage.store_model_metadata(
            model_type="isolation_forest",
            model_path=str(model_path),
            trained_at=trained_at,
            training_samples=len(sessions),
            entity_id=None,  # Global model
            entity_type=None,
            feature_version="v1",
            metrics={
                "n_estimators": n_estimators,
                "contamination": contamination,
                "features": feature_names
            }
        )
        
        logger.info(f"IsolationForest model saved to {model_path}")
        
        return {
            "model_path": str(model_path),
            "trained_at": trained_at.isoformat(),
            "training_samples": len(sessions)
        }
        
    except Exception as e:
        logger.exception(f"Error training IsolationForest: {e}")
        return None


def get_or_create_anomaly_detector(storage) -> IsolationForestAnomalyDetector:
    """
    Get or create anomaly detector with fallback to global model.
    
    Checks for trained model in database, falls back to default path.
    """
    from ..config import get_config
    
    config = get_config()
    
    # Check for active model in database
    active_model = storage.get_active_model("isolation_forest")
    
    if active_model and active_model.get("model_path"):
        model_path = active_model["model_path"]
    else:
        # Fallback to default path
        model_path = str(config.root_dir / "data" / "risk_models" / "isolation_forest.pkl")
    
    detector_config = {
        "default_score": 0.0,
        "raw_min": -0.5,
        "raw_max": 0.5,
    }
    
    return IsolationForestAnomalyDetector(
        model_path=model_path,
        storage=storage,
        config=detector_config
    )
