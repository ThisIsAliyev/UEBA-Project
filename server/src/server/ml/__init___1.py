"""
Machine Learning Pipeline for UEBA System
Includes data preparation, training, and inference modules

NOTE: TensorFlow is an OPTIONAL dependency. ModelTrainer and AnomalyInference
require TensorFlow and are lazy-loaded to avoid import errors.
"""

# These don't require TensorFlow
from .cert_loader import CERTDataLoader
from .feature_extractor import FeatureExtractor

# Lazy imports for TF-dependent modules
def get_model_trainer():
    """Lazy-load ModelTrainer (requires TensorFlow)."""
    from .train import ModelTrainer
    return ModelTrainer

def get_anomaly_inference():
    """Lazy-load AnomalyInference (requires TensorFlow)."""
    from .inference import AnomalyInference
    return AnomalyInference

__all__ = [
    'CERTDataLoader',
    'FeatureExtractor',
    'get_model_trainer',
    'get_anomaly_inference'
]
