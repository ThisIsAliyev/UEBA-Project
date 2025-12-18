"""
Model Training Pipeline for LSTM/ConvLSTM Anomaly Detection

Trains individual models per user following the methodology in Tian et al. (2020).
"""

import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging
import json
from datetime import datetime

from ..ml_models.conv_lstm import (
    build_sequence_model,
    build_feature_model,
    build_combined_mlp,
    calculate_wdd
)
from .cert_loader import CERTDataLoader
from .feature_extractor import FeatureExtractor

logger = logging.getLogger(__name__)


class ModelTrainer:
    """
    Trains LSTM, ConvLSTM, and MLP models for UEBA anomaly detection.
    """
    
    def __init__(
        self,
        data_dir: str = "data/cert",
        model_dir: str = "data/models/lstm_convlstm",
        reports_dir: str = "reports"
    ):
        """
        Initialize model trainer.
        
        Args:
            data_dir: Directory containing CERT dataset
            model_dir: Directory to save trained models
            reports_dir: Directory to save training reports
        """
        self.data_dir = Path(data_dir)
        self.model_dir = Path(model_dir)
        self.reports_dir = Path(reports_dir)
        
        # Create directories
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        self.loader = CERTDataLoader(str(self.data_dir))
        self.extractor = FeatureExtractor()
    
    def train_user_models(
        self,
        user_id: str,
        user_events: pd.DataFrame,
        epochs: int = 40,
        batch_size: int = 32,
        validation_split: float = 0.2
    ) -> Dict[str, any]:
        """
        Train LSTM and ConvLSTM models for a specific user.
        
        Args:
            user_id: User identifier
            user_events: DataFrame of user events
            epochs: Number of training epochs
            batch_size: Batch size for training
            validation_split: Validation data split ratio
        
        Returns:
            Dictionary with training results
        """
        logger.info(f"Training models for user: {user_id}")
        
        # Prepare training data
        seq_X, seq_y, feat_X, feat_y = self.extractor.prepare_training_data(
            user_events,
            num_days=4,
            seq_len=32,
            feature_map_shape=(6, 8)
        )
        
        if len(seq_X) == 0:
            logger.warning(f"Insufficient data for user {user_id}")
            return {'status': 'insufficient_data'}
        
        logger.info(f"Prepared {len(seq_X)} training samples")
        
        results = {}
        
        # Train LSTM sequence model
        logger.info("Training LSTM sequence model...")
        lstm_model = build_sequence_model(seq_len=32, num_days=4)
        
        lstm_history = lstm_model.fit(
            seq_X,
            seq_y,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            verbose=0
        )
        
        # Save LSTM model
        lstm_path = self.model_dir / f"user_{user_id}_lstm.h5"
        lstm_model.save(str(lstm_path))
        logger.info(f"Saved LSTM model to {lstm_path}")
        
        results['lstm'] = {
            'final_loss': float(lstm_history.history['loss'][-1]),
            'final_val_loss': float(lstm_history.history['val_loss'][-1]) if 'val_loss' in lstm_history.history else None,
            'model_path': str(lstm_path)
        }
        
        # Train ConvLSTM feature model
        logger.info("Training ConvLSTM feature model...")
        
        # Reshape feature data for ConvLSTM
        feat_X_reshaped = feat_X.reshape(feat_X.shape[0], -1)
        
        convlstm_model = build_feature_model(
            feature_map_shape=(4, 6, 8, 1)
        )
        
        convlstm_history = convlstm_model.fit(
            feat_X_reshaped,
            feat_y,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            verbose=0
        )
        
        # Save ConvLSTM model
        convlstm_path = self.model_dir / f"user_{user_id}_convlstm.h5"
        convlstm_model.save(str(convlstm_path))
        logger.info(f"Saved ConvLSTM model to {convlstm_path}")
        
        results['convlstm'] = {
            'final_loss': float(convlstm_history.history['loss'][-1]),
            'final_val_loss': float(convlstm_history.history['val_loss'][-1]) if 'val_loss' in convlstm_history.history else None,
            'model_path': str(convlstm_path)
        }
        
        results['status'] = 'success'
        results['user_id'] = user_id
        results['num_samples'] = len(seq_X)
        
        return results
    
    def prepare_mlp_training_data(
        self,
        logs: Dict[str, pd.DataFrame],
        user_list: List[str],
        insider_scenarios: Optional[pd.DataFrame] = None,
        max_users: int = 50
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prepare training data for MLP classifier.
        
        Calculates deviations for all users and creates labeled dataset.
        
        Args:
            logs: Dictionary of log DataFrames
            user_list: List of user IDs
            insider_scenarios: DataFrame with ground truth labels
            max_users: Maximum number of users to process
        
        Returns:
            Tuple of (X, y) where X contains deviations and y contains labels
        """
        import tensorflow as tf
        
        X_list = []
        y_list = []
        
        # Process subset of users
        for user_id in user_list[:max_users]:
            logger.info(f"Processing user {user_id} for MLP training...")
            
            # Get user events
            user_events = self.loader.merge_logs_by_user(logs, user_id)
            
            if user_events.empty:
                continue
            
            # Load trained models
            lstm_path = self.model_dir / f"user_{user_id}_lstm.h5"
            convlstm_path = self.model_dir / f"user_{user_id}_convlstm.h5"
            
            if not lstm_path.exists() or not convlstm_path.exists():
                logger.warning(f"Models not found for user {user_id}, skipping")
                continue
            
            try:
                lstm_model = tf.keras.models.load_model(str(lstm_path))
                convlstm_model = tf.keras.models.load_model(str(convlstm_path))
            except Exception as e:
                logger.error(f"Error loading models for {user_id}: {e}")
                continue
            
            # Get dates
            dates = sorted(user_events['date'].unique())
            
            # Calculate deviations for each day
            for i in range(4, len(dates)):
                date = dates[i]
                
                # Prepare input (4 previous days)
                sequences = []
                feature_maps = []
                
                for j in range(4):
                    prev_date = dates[i - 4 + j]
                    seq = self.extractor.extract_daily_sequence(user_events, prev_date, 32)
                    sequences.append(seq)
                    
                    features = self.extractor.extract_daily_features(user_events, prev_date)
                    feat_map = self.extractor.prepare_feature_map(features, (6, 8))
                    feature_maps.append(feat_map)
                
                # Predict
                seq_input = np.concatenate(sequences).reshape(1, -1)
                feat_input = np.stack(feature_maps).reshape(1, -1)
                
                seq_pred = lstm_model.predict(seq_input, verbose=0)[0]
                feat_pred = convlstm_model.predict(feat_input, verbose=0)[0]
                
                # Get actual values
                actual_seq = self.extractor.extract_daily_sequence(user_events, date, 32)
                actual_features = self.extractor.extract_daily_features(user_events, date)
                actual_feat_map = self.extractor.prepare_feature_map(actual_features, (6, 8))
                
                # Calculate deviations
                seq_dev = np.mean((actual_seq - seq_pred) ** 2)
                feat_dev = np.mean((actual_feat_map.flatten() - feat_pred) ** 2)
                
                # Role deviation (simplified - using zero baseline for now)
                role_dev = 0.0
                
                # Determine label
                label = 0  # Normal by default
                if insider_scenarios is not None:
                    # Check if this user-date is an insider threat
                    insider_match = insider_scenarios[
                        (insider_scenarios['user'] == user_id) &
                        (insider_scenarios['date'] == date)
                    ]
                    if not insider_match.empty:
                        label = 1
                
                X_list.append([seq_dev, feat_dev, role_dev])
                y_list.append(label)
        
        X = np.array(X_list, dtype=np.float32)
        y = np.array(y_list, dtype=np.float32)
        
        logger.info(f"Prepared MLP training data: {len(X)} samples, {np.sum(y)} anomalies")
        
        return X, y
    
    def train_mlp_classifier(
        self,
        X: np.ndarray,
        y: np.ndarray,
        epochs: int = 50,
        batch_size: int = 32,
        validation_split: float = 0.2
    ) -> Dict[str, any]:
        """
        Train MLP classifier for final anomaly decision.
        
        Args:
            X: Input deviations (seq_dev, feat_dev, role_dev)
            y: Labels (0=normal, 1=anomaly)
            epochs: Number of training epochs
            batch_size: Batch size
            validation_split: Validation split ratio
        
        Returns:
            Dictionary with training results
        """
        logger.info("Training MLP classifier...")
        
        # Build model
        mlp_model = build_combined_mlp(input_dim=3, hidden_units=8)
        
        # Train
        history = mlp_model.fit(
            X, y,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            verbose=1
        )
        
        # Save model
        mlp_path = self.model_dir / "combined_mlp.h5"
        mlp_model.save(str(mlp_path))
        logger.info(f"Saved MLP model to {mlp_path}")
        
        # Evaluate
        results = {
            'final_loss': float(history.history['loss'][-1]),
            'final_accuracy': float(history.history['accuracy'][-1]),
            'final_auc': float(history.history['auc'][-1]),
            'model_path': str(mlp_path)
        }
        
        if 'val_loss' in history.history:
            results['final_val_loss'] = float(history.history['val_loss'][-1])
            results['final_val_accuracy'] = float(history.history['val_accuracy'][-1])
            results['final_val_auc'] = float(history.history['val_auc'][-1])
        
        return results
    
    def train_full_pipeline(
        self,
        max_users: int = 10,
        epochs: int = 40
    ) -> Dict[str, any]:
        """
        Train complete pipeline: LSTM/ConvLSTM for users, then MLP.
        
        Args:
            max_users: Maximum number of users to train
            epochs: Number of epochs per model
        
        Returns:
            Dictionary with complete training results
        """
        logger.info("Starting full training pipeline...")
        
        # Load data
        logs = self.loader.load_all_logs()
        if not logs:
            logger.error("No logs loaded, cannot train")
            return {'status': 'error', 'message': 'No data loaded'}
        
        user_list = self.loader.get_user_list(logs)
        logger.info(f"Found {len(user_list)} users")
        
        insider_scenarios = self.loader.load_insider_scenarios()
        
        # Train individual user models
        user_results = []
        successful_users = []
        
        for user_id in user_list[:max_users]:
            user_events = self.loader.merge_logs_by_user(logs, user_id)
            
            if len(user_events) < 100:  # Minimum events threshold
                logger.info(f"Skipping user {user_id}: insufficient events")
                continue
            
            result = self.train_user_models(user_id, user_events, epochs=epochs)
            user_results.append(result)
            
            if result.get('status') == 'success':
                successful_users.append(user_id)
        
        logger.info(f"Successfully trained models for {len(successful_users)} users")
        
        # Train MLP classifier
        if len(successful_users) >= 5:
            logger.info("Preparing MLP training data...")
            X, y = self.prepare_mlp_training_data(
                logs,
                successful_users,
                insider_scenarios,
                max_users=len(successful_users)
            )
            
            if len(X) > 0:
                mlp_results = self.train_mlp_classifier(X, y, epochs=50)
            else:
                mlp_results = {'status': 'insufficient_data'}
        else:
            mlp_results = {'status': 'insufficient_users'}
        
        # Save report
        report = {
            'timestamp': datetime.now().isoformat(),
            'num_users_attempted': max_users,
            'num_users_successful': len(successful_users),
            'user_results': user_results,
            'mlp_results': mlp_results
        }
        
        report_path = self.reports_dir / "model_training_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Training complete. Report saved to {report_path}")
        
        return report
