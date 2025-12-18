"""
FastAPI Endpoints for ML Model Management

Provides API endpoints for training, inference, and monitoring of
LSTM/ConvLSTM anomaly detection models.

NOTE: These endpoints require TensorFlow. If TF is not installed,
endpoints will return 503 Service Unavailable.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

# Lazy imports - don't import TF-dependent modules at module level
# from ..ml.train import ModelTrainer  # Lazy loaded
# from ..ml.inference import AnomalyInference  # Lazy loaded
# from ..risk.lstm_anomaly_detector import LSTMConvLSTMAnomalyDetector  # Lazy loaded

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ml", tags=["Machine Learning"])


# Global instances (lazy initialized)
_trainer = None
_detector = None


from ..core.optional_deps import require_tf


def get_trainer():
    """Get or create ModelTrainer instance (lazy load, requires TensorFlow)."""
    require_tf()
    global _trainer
    if _trainer is None:
        from ..ml.train import ModelTrainer
        _trainer = ModelTrainer()
    return _trainer


def get_detector():
    """Get or create detector instance (lazy load, requires TensorFlow)."""
    require_tf()
    global _detector
    if _detector is None:
        from ..risk.lstm_anomaly_detector import LSTMConvLSTMAnomalyDetector
        _detector = LSTMConvLSTMAnomalyDetector()
    return _detector


# Request/Response Models
class TrainRequest(BaseModel):
    """Request to train models."""
    max_users: int = Field(default=10, ge=1, le=100, description="Maximum number of users to train")
    epochs: int = Field(default=40, ge=1, le=200, description="Training epochs")
    force_retrain: bool = Field(default=False, description="Force retraining even if models exist")


class TrainStatus(BaseModel):
    """Training status response."""
    status: str
    message: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    progress: Optional[Dict[str, Any]] = None


class AnalyzeRequest(BaseModel):
    """Request to analyze a specific user-date."""
    user_id: str = Field(..., description="User identifier")
    date: str = Field(..., description="Date in YYYY-MM-DD format")


class AnalyzeResponse(BaseModel):
    """Analysis response."""
    user: str
    date: str
    status: str
    anomaly_score: Optional[float] = None
    anomaly_flag: Optional[bool] = None
    severity: Optional[str] = None
    sequence_deviation: Optional[float] = None
    feature_deviation: Optional[float] = None
    role_deviation: Optional[float] = None
    timestamp: Optional[str] = None


class ExplanationResponse(BaseModel):
    """Explainable analysis response."""
    user: str
    date: str
    anomaly_detected: bool
    anomaly_score: float
    severity: str
    deviations: Dict[str, Any]
    interpretation: str
    timestamp: Optional[str] = None


# Training status tracking
_training_status = {
    "status": "idle",
    "message": "No training in progress",
    "started_at": None,
    "completed_at": None,
    "progress": {}
}


@router.post("/train", response_model=TrainStatus)
async def train_models(
    request: TrainRequest,
    background_tasks: BackgroundTasks
):
    """
    Train LSTM/ConvLSTM models for anomaly detection.
    
    This is a long-running operation that runs in the background.
    Use /api/ml/train/status to check progress.
    """
    global _training_status
    
    if _training_status["status"] == "running":
        raise HTTPException(
            status_code=409,
            detail="Training already in progress"
        )
    
    # Update status
    _training_status = {
        "status": "running",
        "message": f"Training models for up to {request.max_users} users",
        "started_at": datetime.now().isoformat(),
        "completed_at": None,
        "progress": {
            "max_users": request.max_users,
            "epochs": request.epochs
        }
    }
    
    # Schedule background training
    def train_task():
        global _training_status
        try:
            trainer = get_trainer()
            result = trainer.train_full_pipeline(
                max_users=request.max_users,
                epochs=request.epochs
            )
            
            _training_status = {
                "status": "completed",
                "message": f"Training completed successfully",
                "started_at": _training_status["started_at"],
                "completed_at": datetime.now().isoformat(),
                "progress": result
            }
            
        except Exception as e:
            logger.error(f"Training failed: {e}", exc_info=True)
            _training_status = {
                "status": "failed",
                "message": f"Training failed: {str(e)}",
                "started_at": _training_status["started_at"],
                "completed_at": datetime.now().isoformat(),
                "progress": {}
            }
    
    background_tasks.add_task(train_task)
    
    return TrainStatus(**_training_status)


@router.get("/train/status", response_model=TrainStatus)
async def get_training_status():
    """
    Get current training status.
    """
    return TrainStatus(**_training_status)


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_user_day(request: AnalyzeRequest):
    """
    Analyze a specific user-date for anomalies.
    
    Requires trained models for the user.
    """
    detector = get_detector()
    
    try:
        result = await detector.analyze_day_async(
            user=request.user_id,
            date=request.date
        )
        
        return AnalyzeResponse(**result)
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )


@router.get("/explain/{user_id}/{date}", response_model=ExplanationResponse)
async def get_explanation(
    user_id: str,
    date: str
):
    """
    Get explainable analysis for a specific user-date.
    
    Provides transparent breakdown of anomaly detection reasoning.
    """
    detector = get_detector()
    
    explanation = detector.get_explanation(user_id, date)
    
    if explanation is None:
        raise HTTPException(
            status_code=404,
            detail=f"No analysis found for user {user_id} on {date}"
        )
    
    if explanation.get('status') != 'success' and 'anomaly_detected' not in explanation:
        raise HTTPException(
            status_code=400,
            detail=explanation.get('message', 'Analysis not available')
        )
    
    return ExplanationResponse(**explanation)


@router.get("/anomalies")
async def get_anomalies(
    min_score: float = Query(0.5, ge=0.0, le=1.0, description="Minimum anomaly score"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results")
):
    """
    Get list of detected anomalies.
    
    Returns anomalies above the specified score threshold.
    """
    detector = get_detector()
    
    anomalies = []
    
    for (user, date), result in detector.analysis_cache.items():
        if result.get('status') == 'success':
            score = result.get('anomaly_score', 0.0)
            if score >= min_score:
                anomalies.append({
                    'user': user,
                    'date': date,
                    'anomaly_score': score,
                    'severity': result.get('severity', 'low'),
                    'anomaly_flag': result.get('anomaly_flag', False)
                })
    
    # Sort by score descending
    anomalies.sort(key=lambda x: x['anomaly_score'], reverse=True)
    
    return {
        'count': len(anomalies),
        'anomalies': anomalies[:limit]
    }


@router.get("/stats")
async def get_ml_stats():
    """
    Get ML system statistics.
    """
    detector = get_detector()
    stats = detector.get_stats()
    
    return {
        'detector': stats,
        'training': {
            'status': _training_status['status'],
            'last_started': _training_status.get('started_at'),
            'last_completed': _training_status.get('completed_at')
        }
    }


@router.post("/cache/clear")
async def clear_cache(
    older_than_days: int = Query(7, ge=1, le=365, description="Clear entries older than N days")
):
    """
    Clear old entries from analysis cache.
    """
    detector = get_detector()
    detector.clear_cache(older_than_days=older_than_days)
    
    return {
        'status': 'success',
        'message': f'Cleared cache entries older than {older_than_days} days'
    }
