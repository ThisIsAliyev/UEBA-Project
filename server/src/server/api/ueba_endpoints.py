"""
UEBA API Endpoints.

Provides REST API for:
- Baseline status and management
- Session feature status
- Model status and training triggers
- Scheduler status
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ueba", tags=["ueba"])


class BaselineStatusResponse(BaseModel):
    """Response for baseline status."""
    entity_count: int
    last_update: Optional[str]
    global_baseline_exists: bool
    sample_entities: list


class SessionStatusResponse(BaseModel):
    """Response for session status."""
    total_sessions: int
    sessions_last_24h: int
    unique_entities: int
    last_session: Optional[str]


class ModelStatusResponse(BaseModel):
    """Response for model status."""
    model_available: bool
    model_path: Optional[str]
    trained_at: Optional[str]
    training_samples: Optional[int]
    feature_version: Optional[str]


class SchedulerStatusResponse(BaseModel):
    """Response for scheduler status."""
    running: bool
    jobs: list
    next_baseline_run: Optional[str]
    next_session_run: Optional[str]
    next_training_run: Optional[str]


@router.get("/status")
async def get_ueba_status():
    """
    Get overall UEBA system status.
    
    Returns status of baselines, sessions, models, and scheduler.
    """
    from ..storage import get_storage
    from ..config import get_config
    
    storage = get_storage()
    config = get_config()
    
    # Check baseline status
    global_baseline = storage.get_baseline("__global__", "global")
    baseline_exists = len(global_baseline) > 0
    
    # Check session status
    sessions = storage.get_session_features(limit=1)
    sessions_exist = len(sessions) > 0
    
    # Check model status
    model_info = storage.get_active_model("isolation_forest")
    model_available = model_info is not None
    
    # Check scheduler status
    scheduler_running = False
    try:
        from ..scheduler import is_scheduler_running
        scheduler_running = is_scheduler_running()
    except ImportError:
        pass
    
    return {
        "status": "healthy" if (baseline_exists and model_available) else "degraded",
        "learning_mode": config.learning_mode,
        "components": {
            "baseline": {
                "status": "ready" if baseline_exists else "empty",
                "global_baseline_exists": baseline_exists
            },
            "sessions": {
                "status": "ready" if sessions_exist else "empty",
                "has_data": sessions_exist
            },
            "model": {
                "status": "ready" if model_available else "not_trained",
                "available": model_available,
                "trained_at": model_info.get("trained_at") if model_info else None
            },
            "scheduler": {
                "status": "running" if scheduler_running else "stopped",
                "running": scheduler_running
            }
        },
        "config": {
            "anomaly_alerts_enabled": config.ueba.anomaly_alerts_enabled,
            "anomaly_alert_threshold": config.ueba.anomaly_alert_threshold,
            "enrichment_enabled": config.ueba.enrichment_enabled
        }
    }


@router.get("/baselines")
async def get_baseline_status(
    entity_type: Optional[str] = Query(None, description="Filter by entity type (user/host)"),
    limit: int = Query(20, ge=1, le=100)
):
    """
    Get baseline statistics and sample entities.
    """
    from ..storage import get_storage
    
    storage = get_storage()
    
    # Get global baseline
    global_baseline = storage.get_baseline("__global__", "global")
    
    # Get sample entities with baselines
    with storage._get_connection() as conn:
        cursor = conn.cursor()
        
        if entity_type:
            cursor.execute("""
                SELECT DISTINCT entity_id, entity_type, MAX(window_end) as last_update
                FROM baseline_stats
                WHERE entity_type = ? AND entity_id != '__global__'
                GROUP BY entity_id, entity_type
                ORDER BY last_update DESC
                LIMIT ?
            """, (entity_type, limit))
        else:
            cursor.execute("""
                SELECT DISTINCT entity_id, entity_type, MAX(window_end) as last_update
                FROM baseline_stats
                WHERE entity_id != '__global__'
                GROUP BY entity_id, entity_type
                ORDER BY last_update DESC
                LIMIT ?
            """, (limit,))
        
        entities = [
            {
                "entity_id": row[0],
                "entity_type": row[1],
                "last_update": row[2]
            }
            for row in cursor.fetchall()
        ]
        
        # Get total count
        cursor.execute("""
            SELECT COUNT(DISTINCT entity_id || entity_type)
            FROM baseline_stats
            WHERE entity_id != '__global__'
        """)
        total_count = cursor.fetchone()[0]
    
    return {
        "total_entities": total_count,
        "global_baseline_exists": len(global_baseline) > 0,
        "sample_entities": entities,
        "last_global_update": global_baseline[0].get("window_end") if global_baseline else None
    }


@router.get("/baselines/{entity_type}/{entity_id}")
async def get_entity_baseline(entity_type: str, entity_id: str):
    """
    Get baseline details for a specific entity.
    """
    from ..storage import get_storage
    from ..baseline.baseline_builder import get_baseline_builder
    
    storage = get_storage()
    builder = get_baseline_builder()
    
    baselines = builder.get_baseline(entity_id, entity_type)
    maturity = builder.get_entity_maturity(entity_id, entity_type)
    
    if not baselines:
        raise HTTPException(status_code=404, detail="No baseline found for entity")
    
    return {
        "entity_id": entity_id,
        "entity_type": entity_type,
        "maturity": maturity,
        "baselines": baselines
    }


@router.get("/sessions")
async def get_session_status(
    entity_id: Optional[str] = Query(None),
    entity_type: Optional[str] = Query(None),
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(50, ge=1, le=200)
):
    """
    Get session feature statistics.
    """
    from ..storage import get_storage
    
    storage = get_storage()
    
    since = datetime.utcnow() - timedelta(hours=hours)
    
    sessions = storage.get_session_features(
        entity_id=entity_id,
        entity_type=entity_type,
        since=since,
        limit=limit
    )
    
    # Get counts
    with storage._get_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM session_features")
        total_count = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(*) FROM session_features
            WHERE window_end > ?
        """, (since.isoformat(),))
        recent_count = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(DISTINCT entity_id || entity_type)
            FROM session_features
        """)
        unique_entities = cursor.fetchone()[0]
    
    return {
        "total_sessions": total_count,
        "sessions_in_range": recent_count,
        "unique_entities": unique_entities,
        "time_range_hours": hours,
        "sessions": sessions[:limit]
    }


@router.get("/model")
async def get_model_status():
    """
    Get anomaly detection model status.
    """
    from ..storage import get_storage
    from ..risk.anomaly_detector import SKLEARN_AVAILABLE
    from pathlib import Path
    
    storage = get_storage()
    
    # Get active model from database
    model_info = storage.get_active_model("isolation_forest")
    
    # Check if model file exists
    model_file_exists = False
    if model_info and model_info.get("model_path"):
        model_file_exists = Path(model_info["model_path"]).exists()
    
    return {
        "sklearn_available": SKLEARN_AVAILABLE,
        "model_in_database": model_info is not None,
        "model_file_exists": model_file_exists,
        "model_info": model_info,
        "training_required": not model_file_exists
    }


@router.post("/model/train")
async def trigger_model_training(background_tasks: BackgroundTasks):
    """
    Trigger model training manually.
    
    Training runs in background.
    """
    from ..storage import get_storage
    from ..risk.anomaly_detector import train_global_isolation_forest
    
    storage = get_storage()
    
    # Get session features for training
    since = datetime.utcnow() - timedelta(days=7)
    sessions = storage.get_session_features(since=since, limit=10000)
    
    if len(sessions) < 50:
        raise HTTPException(
            status_code=400,
            detail=f"Insufficient data for training: {len(sessions)} sessions (need >= 50)"
        )
    
    async def train_in_background():
        try:
            result = await train_global_isolation_forest(storage, sessions)
            if result:
                logger.info(f"Model training completed: {result}")
            else:
                logger.warning("Model training returned no result")
        except Exception as e:
            logger.error(f"Model training failed: {e}")
    
    background_tasks.add_task(train_in_background)
    
    return {
        "status": "training_started",
        "training_samples": len(sessions),
        "message": "Model training started in background"
    }


@router.get("/scheduler")
async def get_scheduler_status():
    """
    Get background scheduler status.
    """
    try:
        from ..scheduler import get_scheduler, is_scheduler_running
        
        scheduler = get_scheduler()
        running = is_scheduler_running()
        
        jobs = []
        if scheduler and running:
            for job in scheduler.get_jobs():
                jobs.append({
                    "id": job.id,
                    "name": job.name,
                    "next_run": job.next_run_time.isoformat() if job.next_run_time else None
                })
        
        return {
            "running": running,
            "scheduler_available": scheduler is not None,
            "jobs": jobs
        }
        
    except ImportError:
        return {
            "running": False,
            "scheduler_available": False,
            "jobs": [],
            "error": "APScheduler not installed"
        }


@router.post("/scheduler/run-baseline")
async def trigger_baseline_update(background_tasks: BackgroundTasks):
    """
    Trigger baseline update manually.
    """
    try:
        from ..scheduler.background_tasks import run_baseline_update
        
        background_tasks.add_task(run_baseline_update)
        
        return {
            "status": "started",
            "message": "Baseline update started in background"
        }
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="APScheduler not installed"
        )


@router.post("/scheduler/run-sessions")
async def trigger_session_aggregation(
    background_tasks: BackgroundTasks,
    bootstrap_hours: int = 0
):
    """
    Trigger session aggregation manually.
    
    Args:
        bootstrap_hours: If > 0, aggregate for the past N hours (bootstrap mode).
                         Use this to backfill session features from existing events.
                         Example: bootstrap_hours=24 to aggregate last 24 hours.
    """
    try:
        from ..scheduler.background_tasks import run_session_aggregation
        
        if bootstrap_hours > 0:
            background_tasks.add_task(run_session_aggregation, bootstrap_hours=bootstrap_hours)
            return {
                "status": "started",
                "message": f"Session aggregation started in bootstrap mode (past {bootstrap_hours} hours)"
            }
        else:
            background_tasks.add_task(run_session_aggregation, bootstrap_hours=0)
            return {
                "status": "started",
                "message": "Session aggregation started in background"
            }
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="APScheduler not installed"
        )
