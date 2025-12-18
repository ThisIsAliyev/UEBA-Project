"""
UEBA Background Scheduler.

APScheduler-based background tasks for baseline computation,
session aggregation, and model training.

Integrates with FastAPI lifecycle (startup/shutdown).
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# Optional APScheduler import with graceful fallback
try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.interval import IntervalTrigger
    from apscheduler.triggers.cron import CronTrigger
    APSCHEDULER_AVAILABLE = True
except ImportError:
    APSCHEDULER_AVAILABLE = False
    logger.warning("APScheduler not installed. Background tasks disabled. Install with: pip install apscheduler")

# Global scheduler instance
_scheduler: Optional["AsyncIOScheduler"] = None


def is_scheduler_running() -> bool:
    """Check if scheduler is running."""
    global _scheduler
    if _scheduler is None:
        return False
    return _scheduler.running


def get_scheduler() -> Optional["AsyncIOScheduler"]:
    """Get the global scheduler instance."""
    global _scheduler
    return _scheduler


async def run_baseline_update():
    """
    Background job: Update entity baselines.
    
    Runs every 6 hours (configurable).
    Computes baselines for all active entities.
    """
    logger.info("[SCHEDULER] Starting baseline update job...")
    start_time = datetime.utcnow()
    
    try:
        from ..storage import get_storage
        from ..config import get_config
        from ..baseline.baseline_builder import BaselineBuilder
        
        config = get_config()
        storage = get_storage()
        builder = BaselineBuilder(storage)
        
        lookback_days = config.scheduler.baseline_lookback_days
        window_end = datetime.utcnow()
        window_start = window_end - timedelta(days=lookback_days)
        
        # Update baselines for users
        users = storage.get_unique_entities("user", window_start)
        logger.info(f"[SCHEDULER] Updating baselines for {len(users)} users...")
        
        user_count = 0
        for user in users:
            try:
                builder.update_baseline(user, "user", window_start, window_end)
                user_count += 1
            except Exception as e:
                logger.warning(f"[SCHEDULER] Failed to update baseline for user {user}: {e}")
        
        # Update baselines for hosts
        hosts = storage.get_unique_entities("host", window_start)
        logger.info(f"[SCHEDULER] Updating baselines for {len(hosts)} hosts...")
        
        host_count = 0
        for host in hosts:
            try:
                builder.update_baseline(host, "host", window_start, window_end)
                host_count += 1
            except Exception as e:
                logger.warning(f"[SCHEDULER] Failed to update baseline for host {host}: {e}")
        
        # Update global baseline
        try:
            builder.update_global_baseline(window_start, window_end)
        except Exception as e:
            logger.warning(f"[SCHEDULER] Failed to update global baseline: {e}")
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        logger.info(
            f"[SCHEDULER] Baseline update complete: "
            f"{user_count} users, {host_count} hosts in {duration:.1f}s"
        )
        
    except Exception as e:
        logger.exception(f"[SCHEDULER] Baseline update job failed: {e}")


async def run_session_aggregation(bootstrap_hours: int = 0):
    """
    Background job: Aggregate session features.
    
    Runs every hour (configurable).
    Computes session features for the previous hour window.
    
    Args:
        bootstrap_hours: If > 0, aggregate for the past N hours (bootstrap mode)
    """
    logger.info("[SCHEDULER] Starting session aggregation job...")
    start_time = datetime.utcnow()
    
    try:
        from ..storage import get_storage
        from ..baseline.session_aggregator import SessionAggregator
        
        storage = get_storage()
        aggregator = SessionAggregator(storage)
        
        # Determine window based on regular run or bootstrap mode
        window_end = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        if bootstrap_hours > 0:
            # Bootstrap mode: aggregate for past N hours
            window_start = window_end - timedelta(hours=bootstrap_hours)
            logger.info(f"[SCHEDULER] Running in bootstrap mode for past {bootstrap_hours} hours")
        else:
            # Regular mode: aggregate for previous hour
            window_start = window_end - timedelta(hours=1)
        
        # DEBUG: Log window parameters and event counts
        with storage._get_connection() as conn:
            cursor = conn.cursor()
            
            # Count events by timestamp (original)
            cursor.execute(
                "SELECT COUNT(*) FROM events WHERE timestamp BETWEEN ? AND ?", 
                (window_start.isoformat(), window_end.isoformat())
            )
            timestamp_count = cursor.fetchone()[0]
            
            # Count events by ingested_at (new approach)
            cursor.execute(
                "SELECT COUNT(*) FROM events WHERE ingested_at BETWEEN ? AND ?", 
                (window_start.isoformat(), window_end.isoformat())
            )
            ingested_count = cursor.fetchone()[0]
            
            logger.debug(
                f"[SCHEDULER] Window parameters: {window_start.isoformat()} to {window_end.isoformat()} UTC\n"
                f"Events by timestamp: {timestamp_count}, Events by ingested_at: {ingested_count}"
            )
        
        # Get active entities in this window
        users = storage.get_unique_entities("user", window_start)
        hosts = storage.get_unique_entities("host", window_start)
        
        logger.info(
            f"[SCHEDULER] Aggregating session features for "
            f"{len(users)} users, {len(hosts)} hosts (window: {window_start} to {window_end})"
        )
        
        session_count = 0
        
        # Aggregate user sessions
        for user in users:
            try:
                result = aggregator.aggregate_session(user, "user", window_start, window_end)
                if result:
                    session_count += 1
            except Exception as e:
                logger.warning(f"[SCHEDULER] Failed to aggregate session for user {user}: {e}")
        
        # Aggregate host sessions
        for host in hosts:
            try:
                result = aggregator.aggregate_session(host, "host", window_start, window_end)
                if result:
                    session_count += 1
            except Exception as e:
                logger.warning(f"[SCHEDULER] Failed to aggregate session for host {host}: {e}")
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        logger.info(
            f"[SCHEDULER] Session aggregation complete: "
            f"{session_count} sessions created in {duration:.1f}s"
        )
        
        return session_count
        
    except Exception as e:
        logger.exception(f"[SCHEDULER] Session aggregation job failed: {e}")
        return 0


async def run_model_training():
    """
    Background job: Train/retrain IsolationForest model.
    
    Runs daily (configurable).
    Trains global model on all session features.
    """
    logger.info("[SCHEDULER] Starting model training job...")
    start_time = datetime.utcnow()
    
    try:
        from ..storage import get_storage
        from ..risk.anomaly_detector import train_global_isolation_forest
        
        storage = get_storage()
        
        # Get session features from last 7 days for training
        since = datetime.utcnow() - timedelta(days=7)
        sessions = storage.get_session_features(since=since, limit=10000)
        
        if len(sessions) < 50:
            logger.warning(
                f"[SCHEDULER] Insufficient data for model training: "
                f"{len(sessions)} sessions (need at least 50). Skipping."
            )
            return
        
        logger.info(f"[SCHEDULER] Training IsolationForest on {len(sessions)} sessions...")
        
        result = await train_global_isolation_forest(storage, sessions)
        
        if result:
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.info(
                f"[SCHEDULER] Model training complete in {duration:.1f}s. "
                f"Model saved to: {result.get('model_path', 'unknown')}"
            )
        else:
            logger.warning("[SCHEDULER] Model training returned no result")
        
    except Exception as e:
        logger.exception(f"[SCHEDULER] Model training job failed: {e}")


def start_scheduler():
    """
    Start the background scheduler.
    
    Should be called during FastAPI startup.
    """
    global _scheduler
    
    if not APSCHEDULER_AVAILABLE:
        logger.warning("[SCHEDULER] APScheduler not available. Background tasks disabled.")
        return None
    
    try:
        from ..config import get_config
        config = get_config()
        
        if not config.scheduler.enabled:
            logger.info("[SCHEDULER] Scheduler disabled in configuration.")
            return None
        
        _scheduler = AsyncIOScheduler(timezone="UTC")
        
        # Add baseline update job
        baseline_interval = config.scheduler.baseline_interval_minutes
        _scheduler.add_job(
            run_baseline_update,
            IntervalTrigger(minutes=baseline_interval),
            id="baseline_update",
            name="Baseline Update",
            replace_existing=True,
            max_instances=1
        )
        logger.info(f"[SCHEDULER] Baseline update job scheduled (every {baseline_interval} minutes)")
        
        # Add session aggregation job
        session_interval = config.scheduler.session_interval_minutes
        _scheduler.add_job(
            run_session_aggregation,
            IntervalTrigger(minutes=session_interval),
            id="session_aggregation",
            name="Session Aggregation",
            replace_existing=True,
            max_instances=1
        )
        logger.info(f"[SCHEDULER] Session aggregation job scheduled (every {session_interval} minutes)")
        
        # Add model training job (runs at 2 AM UTC daily by default)
        train_hours = config.scheduler.model_train_interval_hours
        if train_hours >= 24:
            # Daily at 2 AM
            _scheduler.add_job(
                run_model_training,
                CronTrigger(hour=2, minute=0),
                id="model_training",
                name="Model Training (Daily)",
                replace_existing=True,
                max_instances=1
            )
            logger.info("[SCHEDULER] Model training job scheduled (daily at 02:00 UTC)")
        else:
            # Every N hours
            _scheduler.add_job(
                run_model_training,
                IntervalTrigger(hours=train_hours),
                id="model_training",
                name="Model Training",
                replace_existing=True,
                max_instances=1
            )
            logger.info(f"[SCHEDULER] Model training job scheduled (every {train_hours} hours)")
        
        _scheduler.start()
        logger.info("[SCHEDULER] Background scheduler started successfully")
        
        return _scheduler
        
    except Exception as e:
        logger.exception(f"[SCHEDULER] Failed to start scheduler: {e}")
        return None


def stop_scheduler():
    """
    Stop the background scheduler.
    
    Should be called during FastAPI shutdown.
    """
    global _scheduler
    
    if _scheduler is not None:
        try:
            _scheduler.shutdown(wait=False)
            logger.info("[SCHEDULER] Background scheduler stopped")
        except Exception as e:
            logger.warning(f"[SCHEDULER] Error stopping scheduler: {e}")
        finally:
            _scheduler = None


async def run_initial_jobs_if_needed():
    """
    Run initial baseline and session jobs if no data exists.
    
    Called on startup to bootstrap the system.
    """
    try:
        from ..storage import get_storage
        
        storage = get_storage()
        
        # Check if we have any baseline stats
        baselines = storage.get_baseline("__global__", "global")
        
        if not baselines:
            logger.info("[SCHEDULER] No baseline data found. Running initial baseline computation...")
            await run_baseline_update()
        
        # Check if we have any session features
        sessions = storage.get_session_features(limit=1)
        
        # Check if we have events but no sessions
        with storage._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM events")
            event_count = cursor.fetchone()[0]
            
            if sessions:
                logger.info(f"[SCHEDULER] Found {event_count} events and existing session features. No bootstrap needed.")
            elif event_count > 0:
                # We have events but no sessions - bootstrap from last 24 hours
                logger.info(
                    f"[SCHEDULER] Found {event_count} events but no session features. "
                    f"Running bootstrap aggregation for past 24 hours..."
                )
                bootstrap_hours = 24  # Aggregate last 24 hours of data
                session_count = await run_session_aggregation(bootstrap_hours=bootstrap_hours)
                logger.info(f"[SCHEDULER] Bootstrap completed: {session_count} sessions created")
            else:
                logger.info("[SCHEDULER] No events found. Skipping session bootstrap.")
            
    except Exception as e:
        logger.warning(f"[SCHEDULER] Initial jobs check failed: {e}")
