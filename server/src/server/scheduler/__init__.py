"""
UEBA Background Scheduler Module.

Provides APScheduler-based background tasks for:
- Baseline computation (every 6 hours)
- Session feature aggregation (every 1 hour)
- Model training (daily)
"""

from .background_tasks import (
    start_scheduler,
    stop_scheduler,
    get_scheduler,
    is_scheduler_running,
    run_initial_jobs_if_needed
)

__all__ = [
    "start_scheduler",
    "stop_scheduler",
    "get_scheduler",
    "is_scheduler_running",
    "run_initial_jobs_if_needed"
]
