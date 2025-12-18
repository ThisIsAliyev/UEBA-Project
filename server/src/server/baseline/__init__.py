"""
Baseline and Whitelist/Blacklist Module.

Provides:
- BaselineManager: Tracks user/host behavior patterns
- ListEngine: Whitelist/blacklist checking
- BaselineDeviation: Deviation calculation from normal behavior
- BaselineBuilder: Computes and stores entity baselines (NEW)
- SessionAggregator: Computes hourly session features (NEW)
"""

from .manager import BaselineManager, get_baseline_manager, BaselineDeviation
from .lists import ListEngine, ListMatchResult, ListCheckResult, get_list_engine
from .baseline_builder import BaselineBuilder, get_baseline_builder
from .session_aggregator import SessionAggregator, get_session_aggregator

__all__ = [
    "BaselineManager",
    "get_baseline_manager",
    "BaselineDeviation",
    "ListEngine",
    "ListMatchResult",
    "ListCheckResult",
    "get_list_engine",
    "BaselineBuilder",
    "get_baseline_builder",
    "SessionAggregator",
    "get_session_aggregator",
]
