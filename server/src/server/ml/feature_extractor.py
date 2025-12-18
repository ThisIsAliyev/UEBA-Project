"""
Feature Extraction for UEBA Anomaly Detection

Extracts action features, action sequences, and role features from user logs
following the methodology in Tian et al. (2020).
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Optional
from datetime import datetime, time
import logging

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    Extracts comprehensive features from user activity logs.
    
    Features include:
    - Action features: Statistical metrics of daily activities
    - Action sequences: Chronological event sequences
    - Role features: Comparison with role-based baselines
    """
    
    # Working hours definition (9 AM to 6 PM)
    WORK_START = time(9, 0)
    WORK_END = time(18, 0)
    
    def __init__(self):
        """Initialize feature extractor."""
        self.role_profiles = {}
    
    def extract_daily_features(
        self,
        user_events: pd.DataFrame,
        date: str
    ) -> Dict[str, float]:
        """
        Extract action features for a single day.
        
        Args:
            user_events: DataFrame of user events
            date: Date string (YYYY-MM-DD format)
        
        Returns:
            Dictionary of feature values
        """
        # Filter events for this date
        day_events = user_events[user_events['date'] == date]
        
        if day_events.empty:
            return self._get_empty_features()
        
        features = {}
        
        # Parse timestamps
        day_events['hour'] = pd.to_datetime(day_events['timestamp']).dt.hour
        day_events['minute'] = pd.to_datetime(day_events['timestamp']).dt.minute
        day_events['weekday'] = pd.to_datetime(day_events['date']).dt.weekday
        
        # Logon/Logoff features
        logon_events = day_events[day_events['event_type'] == 'logon']
        logoff_events = day_events[day_events['event_type'] == 'logoff']
        
        features['weekday_logon'] = self._count_working_hours(logon_events)
        features['weekday_logoff'] = self._count_working_hours(logoff_events)
        features['after_hours_logon'] = len(logon_events) - features['weekday_logon']
        features['weekend_logon'] = 1 if day_events['weekday'].iloc[0] >= 5 else 0
        
        # Online time estimation (hours)
        if len(logon_events) > 0 and len(logoff_events) > 0:
            first_logon = day_events[day_events['event_type'] == 'logon']['timestamp'].min()
            last_logoff = day_events[day_events['event_type'] == 'logoff']['timestamp'].max()
            online_time = (pd.to_datetime(last_logoff) - pd.to_datetime(first_logon)).total_seconds() / 3600
            features['online_time'] = max(0, min(24, online_time))
        else:
            features['online_time'] = 0
        
        # Device features
        device_events = day_events[day_events['event_type'].str.contains('device', na=False)]
        features['num_devices'] = len(device_events[device_events['event_type'] == 'device_connect'])
        
        # Email features
        email_events = day_events[day_events['event_type'] == 'email']
        features['num_emails'] = len(email_events)
        features['after_hours_email'] = len(email_events) - self._count_working_hours(email_events)
        
        # HTTP features
        http_events = day_events[day_events['event_type'] == 'http']
        features['num_websites'] = len(http_events)
        
        # File features
        file_events = day_events[day_events['event_type'].str.contains('file', na=False)]
        features['num_files'] = len(file_events)
        
        return features
    
    def extract_daily_sequence(
        self,
        user_events: pd.DataFrame,
        date: str,
        max_length: int = 32
    ) -> np.ndarray:
        """
        Extract action sequence for a single day.
        
        Args:
            user_events: DataFrame of user events
            date: Date string
            max_length: Maximum sequence length (pad or truncate)
        
        Returns:
            Numpy array of event type indices
        """
        from ..ml.cert_loader import CERTDataLoader
        
        # Filter events for this date
        day_events = user_events[user_events['date'] == date].copy()
        day_events = day_events.sort_values('timestamp')
        
        # Convert event types to indices
        loader = CERTDataLoader()
        sequence = []
        
        for event_type in day_events['event_type']:
            if event_type in loader.event_type_map:
                sequence.append(loader.event_type_map[event_type])
            else:
                sequence.append(0)  # Unknown event type
        
        # Pad or truncate to max_length
        if len(sequence) < max_length:
            sequence.extend([0] * (max_length - len(sequence)))
        else:
            sequence = sequence[:max_length]
        
        return np.array(sequence, dtype=np.int32)
    
    def prepare_feature_map(
        self,
        features: Dict[str, float],
        map_shape: Tuple[int, int] = (6, 8)
    ) -> np.ndarray:
        """
        Convert feature dictionary to 2D feature map for ConvLSTM.
        
        Args:
            features: Dictionary of feature values
            map_shape: Shape of output feature map (rows, cols)
        
        Returns:
            2D numpy array feature map
        """
        # Define feature order
        feature_keys = [
            'weekday_logon', 'weekday_logoff', 'after_hours_logon', 'weekend_logon',
            'online_time', 'num_devices', 'num_emails', 'after_hours_email',
            'num_websites', 'num_files'
        ]
        
        # Extract values in order
        values = [features.get(key, 0.0) for key in feature_keys]
        
        # Pad to fill map_shape
        total_size = map_shape[0] * map_shape[1]
        if len(values) < total_size:
            values.extend([0.0] * (total_size - len(values)))
        else:
            values = values[:total_size]
        
        # Reshape to 2D map
        feature_map = np.array(values, dtype=np.float32).reshape(map_shape)
        
        return feature_map
    
    def calculate_role_features(
        self,
        all_users_features: Dict[str, List[Dict[str, float]]],
        role: str
    ) -> Dict[str, float]:
        """
        Calculate average features for a role (baseline profile).
        
        Args:
            all_users_features: Dictionary mapping user_id to list of daily features
            role: Role identifier
        
        Returns:
            Dictionary of average feature values for the role
        """
        role_feature_lists = {key: [] for key in self._get_empty_features().keys()}
        
        # Aggregate features from all users in this role
        for user_id, daily_features_list in all_users_features.items():
            for daily_features in daily_features_list:
                for key, value in daily_features.items():
                    role_feature_lists[key].append(value)
        
        # Calculate averages
        role_features = {}
        for key, values in role_feature_lists.items():
            if values:
                role_features[key] = np.mean(values)
            else:
                role_features[key] = 0.0
        
        return role_features
    
    def calculate_role_deviation(
        self,
        user_features: Dict[str, float],
        role_features: Dict[str, float]
    ) -> float:
        """
        Calculate deviation between user features and role baseline.
        
        Args:
            user_features: User's daily features
            role_features: Role baseline features
        
        Returns:
            Euclidean distance (deviation score)
        """
        # Select key features for role comparison
        comparison_keys = [
            'weekday_logon', 'online_time', 'num_emails',
            'num_websites', 'num_devices'
        ]
        
        deviations = []
        for key in comparison_keys:
            user_val = user_features.get(key, 0.0)
            role_val = role_features.get(key, 0.0)
            deviations.append((user_val - role_val) ** 2)
        
        # Euclidean distance
        role_deviation = np.sqrt(np.sum(deviations))
        
        return float(role_deviation)
    
    def _count_working_hours(self, events: pd.DataFrame) -> int:
        """Count events occurring during working hours."""
        if events.empty:
            return 0
        
        count = 0
        for _, row in events.iterrows():
            hour = row.get('hour', 0)
            if self.WORK_START.hour <= hour < self.WORK_END.hour:
                count += 1
        
        return count
    
    def _get_empty_features(self) -> Dict[str, float]:
        """Return empty feature dictionary with all keys."""
        return {
            'weekday_logon': 0.0,
            'weekday_logoff': 0.0,
            'after_hours_logon': 0.0,
            'weekend_logon': 0.0,
            'online_time': 0.0,
            'num_devices': 0.0,
            'num_emails': 0.0,
            'after_hours_email': 0.0,
            'num_websites': 0.0,
            'num_files': 0.0
        }
    
    def prepare_training_data(
        self,
        user_events: pd.DataFrame,
        num_days: int = 4,
        seq_len: int = 32,
        feature_map_shape: Tuple[int, int] = (6, 8)
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Prepare training data with sliding window approach.
        
        Args:
            user_events: DataFrame of user events
            num_days: Number of days to use for prediction
            seq_len: Sequence length per day
            feature_map_shape: Shape of feature maps
        
        Returns:
            Tuple of (seq_X, seq_y, feat_X, feat_y) arrays
        """
        # Get unique dates
        dates = sorted(user_events['date'].unique())
        
        if len(dates) < num_days + 1:
            logger.warning(f"Not enough days for training: {len(dates)}")
            return np.array([]), np.array([]), np.array([]), np.array([])
        
        seq_X_list = []
        seq_y_list = []
        feat_X_list = []
        feat_y_list = []
        
        # Sliding window
        for i in range(len(dates) - num_days):
            # Extract sequences for num_days
            sequences = []
            feature_maps = []
            
            for j in range(num_days):
                date = dates[i + j]
                seq = self.extract_daily_sequence(user_events, date, seq_len)
                sequences.append(seq)
                
                features = self.extract_daily_features(user_events, date)
                feat_map = self.prepare_feature_map(features, feature_map_shape)
                feature_maps.append(feat_map)
            
            # Target: next day
            target_date = dates[i + num_days]
            target_seq = self.extract_daily_sequence(user_events, target_date, seq_len)
            target_features = self.extract_daily_features(user_events, target_date)
            target_feat_map = self.prepare_feature_map(target_features, feature_map_shape)
            
            # Flatten sequences for LSTM input
            seq_X_list.append(np.concatenate(sequences))
            seq_y_list.append(target_seq)
            
            # Stack feature maps for ConvLSTM input
            feat_X_list.append(np.stack(feature_maps))
            feat_y_list.append(target_feat_map.flatten())
        
        return (
            np.array(seq_X_list),
            np.array(seq_y_list),
            np.array(feat_X_list),
            np.array(feat_y_list)
        )
