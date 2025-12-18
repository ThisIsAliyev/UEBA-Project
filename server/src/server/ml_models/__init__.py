"""
ML Models Package for UEBA System
Includes LSTM, ConvLSTM, and MLP architectures for insider threat detection

NOTE: TensorFlow is an OPTIONAL dependency. Core UEBA functionality works without it.
ML model functions are lazy-loaded to avoid import errors when TF is not installed.
"""

from ..core.optional_deps import require_tf, TF_AVAILABLE


def build_sequence_model(*args, **kwargs):
    """Lazy-load and call build_sequence_model from conv_lstm module."""
    require_tf()
    from .conv_lstm import build_sequence_model as _build_sequence_model
    return _build_sequence_model(*args, **kwargs)


def build_feature_model(*args, **kwargs):
    """Lazy-load and call build_feature_model from conv_lstm module."""
    require_tf()
    from .conv_lstm import build_feature_model as _build_feature_model
    return _build_feature_model(*args, **kwargs)


def build_combined_mlp(*args, **kwargs):
    """Lazy-load and call build_combined_mlp from conv_lstm module."""
    require_tf()
    from .conv_lstm import build_combined_mlp as _build_combined_mlp
    return _build_combined_mlp(*args, **kwargs)


__all__ = [
    'TF_AVAILABLE',
    'require_tf',
    'build_sequence_model',
    'build_feature_model',
    'build_combined_mlp'
]
