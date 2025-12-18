"""
LSTM/ConvLSTM Anomaly Detector Integration

Integrates deep learning-based anomaly detection into the risk engine.
Follows OpenUBA's open-model philosophy for transparent, explainable detection.
"""

import logging
from typing import Dict, Optional, Any
from datetime import datetime, timedelta
import asyncio

from ..models import NormalizedEvent
from ..ml.inference import AnomalyInference

logger = logging.getLogger(__name__)


class LSTMConvLSTMAnomalyDetector:
    """
    Deep learning anomaly detector using LSTM/ConvLSTM models.
    
    Provides transparent, explainable anomaly scores based on:
    - Sequence deviation (LSTM)
    - Feature deviation (ConvLSTM)
    - Role deviation (statistical baseline)
    """
    
    def __init__(
        self,
        model_dir: str = "data/models/lstm_convlstm",
        enabled: bool = True,
        threshold: float = 0.5
    ):
        """
        Initialize LSTM/ConvLSTM anomaly detector.
        
        Args:
            model_dir: Directory containing trained models
            enabled: Whether detector is enabled
            threshold: Anomaly score threshold for flagging
        """
        self.enabled = enabled
        self.threshold = threshold
        
        if not self.enabled:
            logger.info("LSTM/ConvLSTM anomaly detector is disabled")
            return
        
        # Initialize inference engine
        self.inference = AnomalyInference(model_dir=model_dir)
        
        # Daily analysis cache: {(user, date): result}
        self.analysis_cache = {}
        
        # Pending analysis tasks
        self.pending_tasks = {}
        
        logger.info(f"LSTM/ConvLSTM anomaly detector initialized (threshold={threshold})")
    
    def detect(
        self,
        event: NormalizedEvent,
        context: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Detect anomaly for an event (synchronous wrapper).
        
        Note: LSTM/ConvLSTM models require daily aggregation.
        This method returns cached score or schedules analysis.
        
        Args:
            event: Normalized event
            context: Optional context features
        
        Returns:
            Anomaly score (0-1)
        """
        if not self.enabled:
            return 0.0
        
        user = event.user
        date = event.timestamp.split('T')[0] if 'T' in event.timestamp else event.timestamp.split()[0]
        
        # Check cache
        cache_key = (user, date)
        if cache_key in self.analysis_cache:
            result = self.analysis_cache[cache_key]
            return result.get('anomaly_score', 0.0)
        
        # Schedule daily analysis (async task)
        if cache_key not in self.pending_tasks:
            self._schedule_daily_analysis(user, date)
        
        # Return default score until analysis completes
        return 0.0
    
    def _schedule_daily_analysis(self, user: str, date: str):
        """
        Schedule asynchronous daily analysis for a user.
        
        Args:
            user: User identifier
            date: Date string
        """
        cache_key = (user, date)
        
        # Create task
        async def analyze():
            try:
                result = await self.inference.analyze_day(user, date)
                self.analysis_cache[cache_key] = result
                logger.info(f"Completed analysis for {user} on {date}: score={result.get('anomaly_score', 0.0):.3f}")
            except Exception as e:
                logger.error(f"Error analyzing {user} on {date}: {e}")
            finally:
                if cache_key in self.pending_tasks:
                    del self.pending_tasks[cache_key]
        
        # Store task reference
        self.pending_tasks[cache_key] = analyze
        
        # Note: Task will be executed by background scheduler
        logger.debug(f"Scheduled analysis for {user} on {date}")
    
    async def analyze_day_async(
        self,
        user: str,
        date: str
    ) -> Dict[str, Any]:
        """
        Asynchronously analyze a specific day for anomalies.
        
        Args:
            user: User identifier
            date: Date string (YYYY-MM-DD)
        
        Returns:
            Analysis result dictionary
        """
        if not self.enabled:
            return {'status': 'disabled'}
        
        result = await self.inference.analyze_day(user, date)
        
        # Cache result
        cache_key = (user, date)
        self.analysis_cache[cache_key] = result
        
        return result
    
    def get_explanation(
        self,
        user: str,
        date: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get explainable analysis for a specific user-date.
        
        Provides transparency following OpenUBA principles.
        
        Args:
            user: User identifier
            date: Date string
        
        Returns:
            Dictionary with deviation details and explanation
        """
        cache_key = (user, date)
        
        if cache_key not in self.analysis_cache:
            return None
        
        result = self.analysis_cache[cache_key]
        
        if result.get('status') != 'success':
            return result
        
        # Build explanation
        explanation = {
            'user': user,
            'date': date,
            'anomaly_detected': result.get('anomaly_flag', False),
            'anomaly_score': result.get('anomaly_score', 0.0),
            'severity': result.get('severity', 'low'),
            'deviations': {
                'sequence': {
                    'value': result.get('sequence_deviation', 0.0),
                    'description': 'Deviation in daily action sequence from normal pattern'
                },
                'features': {
                    'value': result.get('feature_deviation', 0.0),
                    'description': 'Deviation in activity features (logons, emails, file access, etc.)'
                },
                'role': {
                    'value': result.get('role_deviation', 0.0),
                    'description': 'Deviation from typical behavior for user role'
                }
            },
            'interpretation': self._interpret_deviations(result),
            'timestamp': result.get('timestamp')
        }
        
        return explanation
    
    def _interpret_deviations(self, result: Dict[str, Any]) -> str:
        """
        Generate human-readable interpretation of deviations.
        
        Args:
            result: Analysis result
        
        Returns:
            Interpretation string
        """
        seq_dev = result.get('sequence_deviation', 0.0)
        feat_dev = result.get('feature_deviation', 0.0)
        role_dev = result.get('role_deviation', 0.0)
        score = result.get('anomaly_score', 0.0)
        
        if score < 0.3:
            return "Behavior is consistent with normal patterns."
        elif score < 0.5:
            return "Minor deviations detected, but within acceptable range."
        elif score < 0.7:
            if seq_dev > feat_dev:
                return "Unusual sequence of actions detected. User performed activities in an atypical order."
            else:
                return "Unusual activity levels detected. User's behavior differs from typical patterns."
        else:
            reasons = []
            if seq_dev > 1.0:
                reasons.append("highly unusual action sequence")
            if feat_dev > 1.0:
                reasons.append("abnormal activity levels")
            if role_dev > 1.0:
                reasons.append("behavior inconsistent with role")
            
            if reasons:
                return f"Significant anomaly detected: {', '.join(reasons)}."
            else:
                return "Significant anomaly detected across multiple dimensions."
    
    def clear_cache(self, older_than_days: int = 7):
        """
        Clear old entries from analysis cache.
        
        Args:
            older_than_days: Remove entries older than this many days
        """
        cutoff_date = (datetime.now() - timedelta(days=older_than_days)).strftime('%Y-%m-%d')
        
        keys_to_remove = [
            key for key in self.analysis_cache.keys()
            if key[1] < cutoff_date
        ]
        
        for key in keys_to_remove:
            del self.analysis_cache[key]
        
        logger.info(f"Cleared {len(keys_to_remove)} old cache entries")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get detector statistics.
        
        Returns:
            Dictionary with statistics
        """
        total_analyzed = len(self.analysis_cache)
        anomalies = sum(
            1 for result in self.analysis_cache.values()
            if result.get('anomaly_flag', False)
        )
        
        return {
            'enabled': self.enabled,
            'total_analyzed': total_analyzed,
            'anomalies_detected': anomalies,
            'pending_tasks': len(self.pending_tasks),
            'cache_size': total_analyzed,
            'inference_stats': self.inference.get_buffer_stats() if self.enabled else {}
        }
