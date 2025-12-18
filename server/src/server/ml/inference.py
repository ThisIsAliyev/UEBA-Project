"""
Real-Time Anomaly Inference Module

Loads trained LSTM/ConvLSTM models and performs real-time anomaly detection
on incoming user events.

NOTE: TensorFlow is an OPTIONAL dependency. This module should only be
imported when ML features are actually used, not at server startup.
"""

import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging
from datetime import datetime, timedelta
import asyncio
from collections import defaultdict

from .feature_extractor import FeatureExtractor
from ..core.optional_deps import require_tf, get_tensorflow

logger = logging.getLogger(__name__)


def _get_tf():
    """Get TensorFlow module lazily."""
    require_tf()
    return get_tensorflow()


def _get_calculate_wdd():
    """Lazily import calculate_wdd to avoid TF import at module level."""
    require_tf()
    from ..ml_models.conv_lstm import calculate_wdd
    return calculate_wdd


class AnomalyInference:
    """
    Real-time anomaly detection using trained LSTM/ConvLSTM models.
    """
    
    def __init__(
        self,
        model_dir: str = "data/models/lstm_convlstm",
        cache_size: int = 100
    ):
        """
        Initialize anomaly inference engine.
        
        Args:
            model_dir: Directory containing trained models
            cache_size: Maximum number of models to keep in memory
        """
        self.model_dir = Path(model_dir)
        self.extractor = FeatureExtractor()
        
        # Model cache: {user_id: {'lstm': model, 'convlstm': model}}
        self.model_cache = {}
        self.cache_size = cache_size
        
        # Event buffer: {user_id: DataFrame}
        self.event_buffer = defaultdict(list)
        
        # Load MLP classifier
        self.mlp_model = None
        self._load_mlp_model()
    
    def _load_mlp_model(self):
        """Load the combined MLP classifier."""
        mlp_path = self.model_dir / "combined_mlp.h5"
        
        if mlp_path.exists():
            try:
                tf = _get_tf()
                self.mlp_model = tf.keras.models.load_model(str(mlp_path))
                logger.info(f"Loaded MLP classifier from {mlp_path}")
            except Exception as e:
                logger.error(f"Error loading MLP model: {e}")
        else:
            logger.warning(f"MLP model not found at {mlp_path}")
    
    async def load_models_for_user(self, user_id: str) -> bool:
        """
        Load LSTM and ConvLSTM models for a specific user.
        
        Args:
            user_id: User identifier
        
        Returns:
            True if models loaded successfully, False otherwise
        """
        # Check cache
        if user_id in self.model_cache:
            return True
        
        # Check cache size
        if len(self.model_cache) >= self.cache_size:
            # Remove oldest entry
            oldest_user = next(iter(self.model_cache))
            del self.model_cache[oldest_user]
            logger.debug(f"Evicted user {oldest_user} from model cache")
        
        # Load models
        lstm_path = self.model_dir / f"user_{user_id}_lstm.h5"
        convlstm_path = self.model_dir / f"user_{user_id}_convlstm.h5"
        
        if not lstm_path.exists() or not convlstm_path.exists():
            logger.warning(f"Models not found for user {user_id}")
            return False
        
        try:
            # Load in thread to avoid blocking
            tf = _get_tf()
            loop = asyncio.get_event_loop()
            lstm_model = await loop.run_in_executor(
                None,
                tf.keras.models.load_model,
                str(lstm_path)
            )
            convlstm_model = await loop.run_in_executor(
                None,
                tf.keras.models.load_model,
                str(convlstm_path)
            )
            
            self.model_cache[user_id] = {
                'lstm': lstm_model,
                'convlstm': convlstm_model
            }
            
            logger.info(f"Loaded models for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading models for user {user_id}: {e}")
            return False
    
    async def add_event(self, event: Dict) -> None:
        """
        Add an event to the buffer for a user.
        
        Args:
            event: Event dictionary with user, timestamp, event_type, etc.
        """
        user_id = event.get('user')
        if not user_id:
            return
        
        self.event_buffer[user_id].append(event)
    
    async def analyze_day(
        self,
        user_id: str,
        date: str,
        user_events: Optional[pd.DataFrame] = None
    ) -> Dict[str, any]:
        """
        Analyze a specific day for a user and detect anomalies.
        
        Args:
            user_id: User identifier
            date: Date string (YYYY-MM-DD)
            user_events: Optional DataFrame of user events (if None, uses buffer)
        
        Returns:
            Dictionary with analysis results
        """
        # Load models if not cached
        models_loaded = await self.load_models_for_user(user_id)
        if not models_loaded:
            return {
                'user': user_id,
                'date': date,
                'status': 'error',
                'message': 'Models not available'
            }
        
        # Get user events
        if user_events is None:
            # Convert buffer to DataFrame
            if user_id not in self.event_buffer or not self.event_buffer[user_id]:
                return {
                    'user': user_id,
                    'date': date,
                    'status': 'error',
                    'message': 'No events available'
                }
            
            user_events = pd.DataFrame(self.event_buffer[user_id])
        
        # Get dates
        dates = sorted(user_events['date'].unique())
        
        if date not in dates:
            return {
                'user': user_id,
                'date': date,
                'status': 'error',
                'message': 'Date not found in events'
            }
        
        date_idx = dates.index(date)
        
        # Need at least 4 previous days
        if date_idx < 4:
            return {
                'user': user_id,
                'date': date,
                'status': 'insufficient_history',
                'message': 'Need at least 4 days of history'
            }
        
        # Prepare input (4 previous days)
        sequences = []
        feature_maps = []
        
        for i in range(4):
            prev_date = dates[date_idx - 4 + i]
            
            # Extract sequence
            seq = self.extractor.extract_daily_sequence(user_events, prev_date, 32)
            sequences.append(seq)
            
            # Extract features
            features = self.extractor.extract_daily_features(user_events, prev_date)
            feat_map = self.extractor.prepare_feature_map(features, (6, 8))
            feature_maps.append(feat_map)
        
        # Prepare model inputs
        seq_input = np.concatenate(sequences).reshape(1, -1)
        feat_input = np.stack(feature_maps).reshape(1, -1)
        
        # Get models
        lstm_model = self.model_cache[user_id]['lstm']
        convlstm_model = self.model_cache[user_id]['convlstm']
        
        # Predict in thread pool
        loop = asyncio.get_event_loop()
        seq_pred = await loop.run_in_executor(
            None,
            lambda: lstm_model.predict(seq_input, verbose=0)[0]
        )
        feat_pred = await loop.run_in_executor(
            None,
            lambda: convlstm_model.predict(feat_input, verbose=0)[0]
        )
        
        # Get actual values for target date
        actual_seq = self.extractor.extract_daily_sequence(user_events, date, 32)
        actual_features = self.extractor.extract_daily_features(user_events, date)
        actual_feat_map = self.extractor.prepare_feature_map(actual_features, (6, 8))
        
        # Calculate deviations
        seq_dev = float(np.mean((actual_seq - seq_pred) ** 2))
        feat_dev = float(np.mean((actual_feat_map.flatten() - feat_pred) ** 2))
        
        # Role deviation (simplified - would need role baseline)
        role_dev = 0.0
        
        # MLP prediction
        anomaly_score = 0.5
        anomaly_flag = False
        
        if self.mlp_model is not None:
            deviation_input = np.array([[seq_dev, feat_dev, role_dev]], dtype=np.float32)
            anomaly_score = float(
                await loop.run_in_executor(
                    None,
                    lambda: self.mlp_model.predict(deviation_input, verbose=0)[0][0]
                )
            )
            anomaly_flag = anomaly_score > 0.5
        
        return {
            'user': user_id,
            'date': date,
            'status': 'success',
            'sequence_deviation': seq_dev,
            'feature_deviation': feat_dev,
            'role_deviation': role_dev,
            'anomaly_score': anomaly_score,
            'anomaly_flag': anomaly_flag,
            'severity': self._calculate_severity(anomaly_score),
            'timestamp': datetime.now().isoformat()
        }
    
    def _calculate_severity(self, anomaly_score: float) -> str:
        """
        Calculate severity level based on anomaly score.
        
        Args:
            anomaly_score: Anomaly probability (0-1)
        
        Returns:
            Severity level string
        """
        if anomaly_score > 0.8:
            return "high"
        elif anomaly_score > 0.5:
            return "medium"
        else:
            return "low"
    
    async def batch_analyze(
        self,
        user_id: str,
        start_date: str,
        end_date: str,
        user_events: pd.DataFrame
    ) -> List[Dict[str, any]]:
        """
        Analyze multiple days for a user.
        
        Args:
            user_id: User identifier
            start_date: Start date (YYYY-MM-DD)
            end_date: End date (YYYY-MM-DD)
            user_events: DataFrame of user events
        
        Returns:
            List of analysis results for each day
        """
        results = []
        
        dates = sorted(user_events['date'].unique())
        date_range = [d for d in dates if start_date <= d <= end_date]
        
        for date in date_range:
            result = await self.analyze_day(user_id, date, user_events)
            results.append(result)
        
        return results
    
    def clear_buffer(self, user_id: Optional[str] = None):
        """
        Clear event buffer.
        
        Args:
            user_id: If specified, clear only this user's buffer
        """
        if user_id:
            if user_id in self.event_buffer:
                del self.event_buffer[user_id]
        else:
            self.event_buffer.clear()
    
    def get_buffer_stats(self) -> Dict[str, int]:
        """
        Get statistics about event buffer.
        
        Returns:
            Dictionary with buffer statistics
        """
        return {
            'num_users': len(self.event_buffer),
            'total_events': sum(len(events) for events in self.event_buffer.values()),
            'cached_models': len(self.model_cache)
        }
