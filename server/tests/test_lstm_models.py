"""
Test Suite for LSTM/ConvLSTM Anomaly Detection Models

Tests model architecture, training, and inference pipelines.
"""

import sys
from pathlib import Path

# Add server to path
server_root = Path(__file__).parent.parent
sys.path.insert(0, str(server_root / "src"))

import unittest
import numpy as np
import tempfile
import shutil
from server.models.conv_lstm import (
    build_sequence_model,
    build_feature_model,
    build_combined_mlp,
    calculate_wdd
)
from server.ml.feature_extractor import FeatureExtractor
import pandas as pd


class TestModelArchitecture(unittest.TestCase):
    """Test LSTM/ConvLSTM model architectures."""
    
    def test_lstm_sequence_model(self):
        """Test LSTM sequence model builds correctly."""
        model = build_sequence_model(seq_len=32, num_days=4)
        
        # Check input/output shapes
        self.assertEqual(model.input_shape, (None, 128))  # 4 days * 32 seq_len
        self.assertEqual(model.output_shape, (None, 32))
        
        # Test prediction
        test_input = np.random.randint(0, 37, size=(1, 128))
        output = model.predict(test_input, verbose=0)
        self.assertEqual(output.shape, (1, 32))
    
    def test_convlstm_feature_model(self):
        """Test ConvLSTM feature model builds correctly."""
        model = build_feature_model(feature_map_shape=(4, 6, 8, 1))
        
        # Check model builds
        self.assertIsNotNone(model)
        
        # Test prediction
        test_input = np.random.randn(1, 192).astype(np.float32)  # 4*6*8*1
        output = model.predict(test_input, verbose=0)
        self.assertEqual(len(output.shape), 2)
    
    def test_mlp_classifier(self):
        """Test MLP classifier builds correctly."""
        model = build_combined_mlp(input_dim=3, hidden_units=8)
        
        # Check input/output shapes
        self.assertEqual(model.input_shape, (None, 3))
        self.assertEqual(model.output_shape, (None, 1))
        
        # Test prediction
        test_input = np.array([[0.5, 0.3, 0.2]], dtype=np.float32)
        output = model.predict(test_input, verbose=0)
        self.assertEqual(output.shape, (1, 1))
        self.assertTrue(0 <= output[0][0] <= 1)  # Sigmoid output
    
    def test_wdd_calculation(self):
        """Test Weighted Deviation Degree calculation."""
        y_true = np.array([1.0, 2.0, 3.0])
        y_pred = np.array([1.1, 2.2, 2.9])
        
        wdd = calculate_wdd(y_true, y_pred)
        self.assertIsInstance(wdd, float)
        self.assertGreater(wdd, 0)


class TestFeatureExtraction(unittest.TestCase):
    """Test feature extraction pipeline."""
    
    def setUp(self):
        """Set up test data."""
        self.extractor = FeatureExtractor()
        
        # Create sample user events
        self.sample_events = pd.DataFrame({
            'timestamp': [
                '2021-09-01 09:00:00',
                '2021-09-01 10:30:00',
                '2021-09-01 14:00:00',
                '2021-09-01 17:00:00'
            ],
            'date': ['2021-09-01'] * 4,
            'event_type': ['logon', 'email', 'http', 'logoff']
        })
    
    def test_extract_daily_features(self):
        """Test daily feature extraction."""
        features = self.extractor.extract_daily_features(
            self.sample_events,
            '2021-09-01'
        )
        
        # Check required features exist
        self.assertIn('weekday_logon', features)
        self.assertIn('num_emails', features)
        self.assertIn('online_time', features)
        
        # Check values are reasonable
        self.assertEqual(features['num_emails'], 1)
        self.assertGreaterEqual(features['online_time'], 0)
    
    def test_extract_daily_sequence(self):
        """Test daily sequence extraction."""
        sequence = self.extractor.extract_daily_sequence(
            self.sample_events,
            '2021-09-01',
            max_length=32
        )
        
        # Check shape
        self.assertEqual(sequence.shape, (32,))
        
        # Check values are valid indices
        self.assertTrue(np.all(sequence >= 0))
    
    def test_prepare_feature_map(self):
        """Test feature map preparation."""
        features = {
            'weekday_logon': 1.0,
            'num_emails': 5.0,
            'online_time': 8.0
        }
        
        feature_map = self.extractor.prepare_feature_map(features, (6, 8))
        
        # Check shape
        self.assertEqual(feature_map.shape, (6, 8))
        
        # Check dtype
        self.assertEqual(feature_map.dtype, np.float32)
    
    def test_role_deviation_calculation(self):
        """Test role deviation calculation."""
        user_features = {
            'weekday_logon': 2.0,
            'online_time': 10.0,
            'num_emails': 20.0
        }
        
        role_features = {
            'weekday_logon': 1.5,
            'online_time': 8.0,
            'num_emails': 15.0
        }
        
        deviation = self.extractor.calculate_role_deviation(
            user_features,
            role_features
        )
        
        self.assertIsInstance(deviation, float)
        self.assertGreater(deviation, 0)


class TestTrainingPipeline(unittest.TestCase):
    """Test model training pipeline."""
    
    def setUp(self):
        """Set up test environment."""
        # Create temporary directories
        self.temp_dir = tempfile.mkdtemp()
        self.model_dir = Path(self.temp_dir) / "models"
        self.model_dir.mkdir()
    
    def tearDown(self):
        """Clean up temporary files."""
        shutil.rmtree(self.temp_dir)
    
    def test_model_training_smoke(self):
        """Smoke test for model training (minimal data)."""
        # Create minimal training data
        seq_X = np.random.randint(0, 37, size=(10, 128))
        seq_y = np.random.randint(0, 37, size=(10, 32))
        
        # Build and train LSTM
        model = build_sequence_model(seq_len=32, num_days=4)
        history = model.fit(seq_X, seq_y, epochs=2, verbose=0)
        
        # Check training completed
        self.assertIn('loss', history.history)
        self.assertEqual(len(history.history['loss']), 2)
        
        # Save model
        model_path = self.model_dir / "test_lstm.h5"
        model.save(str(model_path))
        
        # Check file exists
        self.assertTrue(model_path.exists())


class TestInference(unittest.TestCase):
    """Test inference pipeline."""
    
    def test_anomaly_score_range(self):
        """Test that anomaly scores are in valid range."""
        # Create MLP model
        model = build_combined_mlp()
        
        # Test various deviation inputs
        test_cases = [
            [0.1, 0.1, 0.1],  # Low deviations
            [0.5, 0.5, 0.5],  # Medium deviations
            [2.0, 2.0, 2.0],  # High deviations
        ]
        
        for deviations in test_cases:
            input_data = np.array([deviations], dtype=np.float32)
            score = model.predict(input_data, verbose=0)[0][0]
            
            # Score should be between 0 and 1 (sigmoid output)
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 1.0)


def run_tests():
    """Run all tests."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestModelArchitecture))
    suite.addTests(loader.loadTestsFromTestCase(TestFeatureExtraction))
    suite.addTests(loader.loadTestsFromTestCase(TestTrainingPipeline))
    suite.addTests(loader.loadTestsFromTestCase(TestInference))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
