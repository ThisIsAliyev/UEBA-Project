"""
Feedback API for analyst labeling.

Allows analysts to provide ground truth labels for alerts,
which can be used for supervised learning and model improvement.
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..storage import get_storage

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/alerts", tags=["feedback"])


class FeedbackRequest(BaseModel):
    """Request body for submitting feedback."""
    label: str = Field(..., description="One of: true_positive, false_positive, uncertain")
    notes: Optional[str] = Field(None, description="Optional analyst notes")
    analyst_username: Optional[str] = Field("system", description="Analyst username")


class FeedbackResponse(BaseModel):
    """Response after submitting feedback."""
    success: bool
    feedback_id: int
    message: str


@router.post("/{alert_id}/feedback", response_model=FeedbackResponse)
async def submit_feedback(
    alert_id: int,
    feedback: FeedbackRequest
):
    """
    Submit analyst feedback for an alert.
    
    Args:
        alert_id: Alert ID to label
        feedback: Feedback data (label, notes, analyst)
        
    Returns:
        FeedbackResponse with feedback_id
    """
    # Validate label
    valid_labels = ['true_positive', 'false_positive', 'uncertain']
    if feedback.label not in valid_labels:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid label. Must be one of: {', '.join(valid_labels)}"
        )
    
    # Get storage
    storage = get_storage()
    
    # Check if alert exists
    alert = storage.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    
    # Store feedback
    try:
        feedback_id = storage.store_feedback(
            alert_id=alert_id,
            label=feedback.label,
            analyst_username=feedback.analyst_username or "system",
            notes=feedback.notes,
            snapshot_risk_score=alert.risk_score,
            snapshot_confidence=0.8  # Default confidence
        )
        
        logger.info(
            f"Feedback submitted: alert_id={alert_id}, label={feedback.label}, "
            f"analyst={feedback.analyst_username}, feedback_id={feedback_id}"
        )
        
        return FeedbackResponse(
            success=True,
            feedback_id=feedback_id,
            message=f"Feedback recorded for alert {alert_id}"
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to store feedback: {e}")
        raise HTTPException(status_code=500, detail="Failed to store feedback")


@router.get("/{alert_id}/feedback")
async def get_feedback(alert_id: int):
    """
    Get all feedback for an alert.
    
    Args:
        alert_id: Alert ID
        
    Returns:
        List of feedback records
    """
    storage = get_storage()
    
    # Check if alert exists
    alert = storage.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    
    # Get feedback
    feedback_list = storage.get_feedback_for_alert(alert_id)
    
    return {
        "alert_id": alert_id,
        "feedback_count": len(feedback_list),
        "feedback": feedback_list
    }
