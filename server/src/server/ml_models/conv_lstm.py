"""
Deep Learning Model Architectures for UEBA Anomaly Detection

Based on Tian et al. (2020) - User and Entity Behavior Analysis under Urban Big Data
Implements LSTM for sequence analysis, ConvLSTM for feature analysis, and MLP for decision fusion.
"""

import tensorflow as tf
from tensorflow.keras import layers, models
from typing import Tuple, Optional
import logging

logger = logging.getLogger(__name__)


def build_sequence_model(
    seq_len: int = 32,
    num_days: int = 4,
    num_event_types: int = 37,
    lstm_units_1: int = 100,
    lstm_units_2: int = 160
) -> models.Model:
    """
    Build LSTM model for action sequence anomaly detection.
    
    Uses N days of action sequences to predict the next day's sequence.
    Deviation between prediction and reality indicates anomalous behavior.
    
    Args:
        seq_len: Maximum sequence length per day (default: 32 events)
        num_days: Number of historical days to use (default: 4)
        num_event_types: Number of distinct event types (default: 37)
        lstm_units_1: Units in first LSTM layer (default: 100)
        lstm_units_2: Units in second LSTM layer (default: 160)
    
    Returns:
        Compiled Keras model for sequence prediction
    """
    model = models.Sequential(name="LSTM_Sequence_Model")
    
    # Input: flattened 4-day sequences
    model.add(layers.Input(shape=(num_days * seq_len,)))
    
    # Reshape to (num_days, seq_len) for LSTM processing
    model.add(layers.Reshape((num_days, seq_len)))
    
    # Two-layer LSTM architecture
    model.add(layers.LSTM(
        lstm_units_1,
        activation='tanh',
        return_sequences=True,
        name='lstm_layer_1'
    ))
    
    model.add(layers.LSTM(
        lstm_units_2,
        activation='tanh',
        return_sequences=False,
        name='lstm_layer_2'
    ))
    
    # Output layer: predict next day's sequence
    model.add(layers.Dense(seq_len, activation='linear', name='output'))
    
    # Compile with MSE loss for regression
    model.compile(
        optimizer='adam',
        loss='mse',
        metrics=['mae']
    )
    
    logger.info(f"Built LSTM sequence model: {model.count_params()} parameters")
    return model


def build_feature_model(
    feature_map_shape: Tuple[int, int, int, int] = (4, 6, 8, 1),
    convlstm_filters: Tuple[int, int, int] = (24, 128, 48),
    dense_units: int = 48
) -> models.Model:
    """
    Build ConvLSTM model for action feature anomaly detection.
    
    Uses convolutional LSTM to capture both temporal patterns and spatial
    relationships between different activity features.
    
    Args:
        feature_map_shape: Shape of feature map (days, rows, cols, channels)
        convlstm_filters: Number of filters for each ConvLSTM layer
        dense_units: Units in final dense layer
    
    Returns:
        Compiled Keras model for feature prediction
    """
    num_days, rows, cols, channels = feature_map_shape
    input_size = num_days * rows * cols * channels
    
    model = models.Sequential(name="ConvLSTM_Feature_Model")
    
    # Input: flattened feature maps
    model.add(layers.Input(shape=(input_size,)))
    
    # Reshape to 5D tensor for ConvLSTM: (batch, time, rows, cols, channels)
    model.add(layers.Reshape(feature_map_shape))
    
    # Three ConvLSTM layers with different activation functions
    model.add(layers.ConvLSTM2D(
        filters=convlstm_filters[0],
        kernel_size=(2, 3),
        activation='elu',
        return_sequences=True,
        padding='same',
        name='convlstm_layer_1'
    ))
    
    model.add(layers.ConvLSTM2D(
        filters=convlstm_filters[1],
        kernel_size=(2, 3),
        activation='tanh',
        return_sequences=True,
        padding='same',
        name='convlstm_layer_2'
    ))
    
    model.add(layers.ConvLSTM2D(
        filters=convlstm_filters[2],
        kernel_size=(2, 3),
        activation='tanh',
        return_sequences=False,
        padding='same',
        name='convlstm_layer_3'
    ))
    
    # MaxPooling and flattening
    model.add(layers.MaxPooling2D(pool_size=(3, 3), name='maxpool'))
    model.add(layers.Flatten())
    
    # Dropout for regularization
    model.add(layers.Dropout(0.5, name='dropout'))
    
    # Dense layer for feature reconstruction
    model.add(layers.Dense(dense_units, activation='relu', name='output'))
    
    # Compile with MSE loss
    model.compile(
        optimizer='adam',
        loss='mse',
        metrics=['mae']
    )
    
    logger.info(f"Built ConvLSTM feature model: {model.count_params()} parameters")
    return model


def build_combined_mlp(
    input_dim: int = 3,
    hidden_units: int = 8,
    dropout_rate: float = 0.3
) -> models.Model:
    """
    Build MLP for comprehensive anomaly decision.
    
    Combines deviations from sequence, features, and role analysis
    to make final anomaly classification.
    
    Args:
        input_dim: Number of deviation inputs (seq_dev, feat_dev, role_dev)
        hidden_units: Units in hidden layer
        dropout_rate: Dropout rate for regularization
    
    Returns:
        Compiled Keras model for binary classification
    """
    model = models.Sequential(name="Deviation_Classifier_MLP")
    
    # Input layer
    model.add(layers.Input(shape=(input_dim,)))
    
    # Hidden layer with ReLU activation
    model.add(layers.Dense(
        hidden_units,
        activation='relu',
        name='hidden_layer'
    ))
    
    # Dropout for regularization
    model.add(layers.Dropout(dropout_rate, name='dropout'))
    
    # Output layer with sigmoid for binary classification
    model.add(layers.Dense(
        1,
        activation='sigmoid',
        name='output'
    ))
    
    # Compile with binary crossentropy
    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy', tf.keras.metrics.AUC(name='auc')]
    )
    
    logger.info(f"Built MLP classifier: {model.count_params()} parameters")
    return model


def calculate_wdd(y_true, y_pred, weights: Optional[list] = None) -> float:
    """
    Calculate Weighted Deviation Degree (WDD).
    
    WDD weighs squared errors according to feature importance,
    as some features are more indicative of anomalies than others.
    
    Args:
        y_true: Ground truth values
        y_pred: Predicted values
        weights: Optional weights for each feature
    
    Returns:
        Weighted deviation degree score
    """
    import numpy as np
    
    if weights is None:
        weights = np.ones_like(y_true)
    
    squared_errors = (y_true - y_pred) ** 2
    weighted_errors = weights * squared_errors
    wdd = np.mean(weighted_errors)
    
    return float(wdd)
