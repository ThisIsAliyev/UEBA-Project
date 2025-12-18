"""
Baseline Statistics Manager.

Tracks and manages user/host behavior baselines for anomaly detection.
Implements Tier 1 statistics:
- Active hours per user
- Common processes per user/host
- Common process chains (parent-child relationships)

The baseline is updated incrementally as events are processed and
queried during risk assessment to detect deviations.
"""

import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Set, List, Tuple, Any
from dataclasses import dataclass, field
from threading import Lock

logger = logging.getLogger(__name__)


@dataclass
class BaselineDeviation:
    """
    Deviation from baseline for an event.
    
    Used by the risk engine to factor baseline anomalies into scoring.
    """
    is_unusual_hour: bool = False
    is_new_process: bool = False
    is_rare_parent_child: bool = False
    is_high_event_rate: bool = False
    events_last_5min: int = 0
    deviation_score: float = 0.0  # 0-100 combined deviation score
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "is_unusual_hour": self.is_unusual_hour,
            "is_new_process": self.is_new_process,
            "is_rare_parent_child": self.is_rare_parent_child,
            "is_high_event_rate": self.is_high_event_rate,
            "events_last_5min": self.events_last_5min,
            "deviation_score": self.deviation_score,
        }


@dataclass
class UserBaseline:
    """Cached baseline data for a user/host combination."""
    user: str
    host: str
    typical_start_hour: int = 8  # Default 8 AM
    typical_end_hour: int = 18  # Default 6 PM
    common_processes: Set[str] = field(default_factory=set)
    common_process_chains: Set[Tuple[str, str]] = field(default_factory=set)
    avg_events_per_5min: float = 10.0
    last_updated: float = 0.0


class BaselineManager:
    """
    Manages user/host behavior baselines.
    
    Features:
    - In-memory cache for fast lookups
    - SQLite persistence for baseline data
    - Incremental updates as events are processed
    - Deviation calculation for risk scoring
    
    Database Schema:
    - baselines: User/host baseline statistics
    - process_stats: Process occurrence counts
    - process_chain_stats: Parent-child relationship counts
    """
    
    # Deviation score weights
    WEIGHT_UNUSUAL_HOUR = 15
    WEIGHT_NEW_PROCESS = 25
    WEIGHT_RARE_CHAIN = 30
    WEIGHT_HIGH_EVENT_RATE = 20
    
    # Thresholds
    MIN_OBSERVATIONS = 10  # Minimum events before baseline is reliable
    PROCESS_RARITY_THRESHOLD = 3  # Process seen < N times is "new"
    CHAIN_RARITY_THRESHOLD = 2  # Chain seen < N times is "rare"
    HIGH_EVENT_RATE_MULTIPLIER = 3.0  # Events > N * avg is "high rate"
    
    def __init__(self, db_path: Optional[str] = None, cache_ttl: float = 300.0):
        """
        Initialize baseline manager.
        
        Args:
            db_path: Path to SQLite database (default: data/baselines.db)
            cache_ttl: Cache time-to-live in seconds
        """
        if db_path is None:
            # Default path relative to server root
            db_path = str(Path(__file__).parent.parent.parent.parent / "data" / "baselines.db")
        
        self.db_path = db_path
        self.cache_ttl = cache_ttl
        
        # In-memory cache: key = "user:host"
        self._cache: Dict[str, UserBaseline] = {}
        self._cache_lock = Lock()
        
        # Recent event counts for rate detection
        self._recent_events: Dict[str, List[float]] = {}  # key -> list of timestamps
        
        # Initialize database
        self._init_db()
        
        logger.info(f"Baseline manager initialized with DB: {db_path}")
    
    def _init_db(self):
        """Initialize database schema."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                -- User/host baselines
                CREATE TABLE IF NOT EXISTS baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user TEXT NOT NULL,
                    host TEXT NOT NULL,
                    ou_role TEXT DEFAULT 'default',
                    typical_start_hour INTEGER DEFAULT 8,
                    typical_end_hour INTEGER DEFAULT 18,
                    total_events INTEGER DEFAULT 0,
                    avg_events_per_5min REAL DEFAULT 10.0,
                    updated_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(user, host)
                );
                
                -- Process occurrence statistics
                CREATE TABLE IF NOT EXISTS process_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user TEXT NOT NULL,
                    host TEXT NOT NULL,
                    process_name TEXT NOT NULL,
                    occurrence_count INTEGER DEFAULT 1,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    UNIQUE(user, host, process_name)
                );
                
                -- Process chain (parent-child) statistics
                CREATE TABLE IF NOT EXISTS process_chain_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user TEXT NOT NULL,
                    host TEXT NOT NULL,
                    parent_process TEXT NOT NULL,
                    child_process TEXT NOT NULL,
                    occurrence_count INTEGER DEFAULT 1,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    UNIQUE(user, host, parent_process, child_process)
                );
                
                -- Indexes for fast lookups
                CREATE INDEX IF NOT EXISTS idx_baselines_user_host ON baselines(user, host);
                CREATE INDEX IF NOT EXISTS idx_process_stats_user_host ON process_stats(user, host);
                CREATE INDEX IF NOT EXISTS idx_chain_stats_user_host ON process_chain_stats(user, host);
            """)
    
    def _get_cache_key(self, user: str, host: str) -> str:
        """Generate cache key."""
        return f"{user.lower()}:{host.lower()}"
    
    def _load_baseline(self, user: str, host: str) -> UserBaseline:
        """Load baseline from database."""
        baseline = UserBaseline(user=user, host=host)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Load main baseline
                row = conn.execute(
                    "SELECT * FROM baselines WHERE user = ? AND host = ?",
                    (user.lower(), host.lower())
                ).fetchone()
                
                if row:
                    baseline.typical_start_hour = row["typical_start_hour"]
                    baseline.typical_end_hour = row["typical_end_hour"]
                    baseline.avg_events_per_5min = row["avg_events_per_5min"]
                
                # Load common processes (top 50 by occurrence)
                rows = conn.execute(
                    """SELECT process_name FROM process_stats 
                       WHERE user = ? AND host = ? 
                       ORDER BY occurrence_count DESC LIMIT 50""",
                    (user.lower(), host.lower())
                ).fetchall()
                baseline.common_processes = {row["process_name"].lower() for row in rows}
                
                # Load common process chains (top 100)
                rows = conn.execute(
                    """SELECT parent_process, child_process FROM process_chain_stats
                       WHERE user = ? AND host = ?
                       ORDER BY occurrence_count DESC LIMIT 100""",
                    (user.lower(), host.lower())
                ).fetchall()
                baseline.common_process_chains = {
                    (row["parent_process"].lower(), row["child_process"].lower())
                    for row in rows
                }
                
        except Exception as e:
            logger.warning(f"Failed to load baseline for {user}@{host}: {e}")
        
        baseline.last_updated = time.time()
        return baseline
    
    def _get_baseline(self, user: str, host: str) -> UserBaseline:
        """Get baseline from cache or load from database."""
        cache_key = self._get_cache_key(user, host)
        
        with self._cache_lock:
            if cache_key in self._cache:
                baseline = self._cache[cache_key]
                # Check if cache is still valid
                if time.time() - baseline.last_updated < self.cache_ttl:
                    return baseline
            
            # Load from database
            baseline = self._load_baseline(user, host)
            self._cache[cache_key] = baseline
            return baseline
    
    def get_deviation(
        self,
        user: str,
        host: str,
        process_name: Optional[str],
        parent_process: Optional[str],
        event_hour: int
    ) -> BaselineDeviation:
        """
        Calculate deviation from baseline for an event.
        
        This is called during risk assessment for every event.
        Must be fast (<5ms).
        
        Args:
            user: Username
            host: Hostname
            process_name: Process name (optional)
            parent_process: Parent process name (optional)
            event_hour: Hour of event (0-23)
            
        Returns:
            BaselineDeviation with flags and combined score
        """
        deviation = BaselineDeviation()
        score_components = []
        
        # Get baseline
        baseline = self._get_baseline(user, host)
        
        # Check 1: Unusual hour
        if baseline.typical_start_hour and baseline.typical_end_hour:
            if not (baseline.typical_start_hour <= event_hour <= baseline.typical_end_hour):
                deviation.is_unusual_hour = True
                score_components.append(self.WEIGHT_UNUSUAL_HOUR)
        
        # Check 2: New process
        if process_name:
            proc_lower = process_name.lower()
            if proc_lower not in baseline.common_processes:
                # Check if it's truly new (not just rare)
                count = self._get_process_count(user, host, proc_lower)
                if count < self.PROCESS_RARITY_THRESHOLD:
                    deviation.is_new_process = True
                    score_components.append(self.WEIGHT_NEW_PROCESS)
        
        # Check 3: Rare parent-child chain
        if process_name and parent_process:
            chain = (parent_process.lower(), process_name.lower())
            if chain not in baseline.common_process_chains:
                count = self._get_chain_count(user, host, chain[0], chain[1])
                if count < self.CHAIN_RARITY_THRESHOLD:
                    deviation.is_rare_parent_child = True
                    score_components.append(self.WEIGHT_RARE_CHAIN)
        
        # Check 4: High event rate
        cache_key = self._get_cache_key(user, host)
        events_5min = self._count_recent_events(cache_key)
        deviation.events_last_5min = events_5min
        
        if events_5min > baseline.avg_events_per_5min * self.HIGH_EVENT_RATE_MULTIPLIER:
            deviation.is_high_event_rate = True
            score_components.append(self.WEIGHT_HIGH_EVENT_RATE)
        
        # Calculate combined deviation score (0-100)
        deviation.deviation_score = min(100.0, sum(score_components))
        
        return deviation
    
    def _get_process_count(self, user: str, host: str, process_name: str) -> int:
        """Get occurrence count for a process."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    """SELECT occurrence_count FROM process_stats
                       WHERE user = ? AND host = ? AND process_name = ?""",
                    (user.lower(), host.lower(), process_name.lower())
                ).fetchone()
                return row[0] if row else 0
        except Exception:
            return 0
    
    def _get_chain_count(
        self, user: str, host: str, parent: str, child: str
    ) -> int:
        """Get occurrence count for a process chain."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    """SELECT occurrence_count FROM process_chain_stats
                       WHERE user = ? AND host = ? 
                       AND parent_process = ? AND child_process = ?""",
                    (user.lower(), host.lower(), parent.lower(), child.lower())
                ).fetchone()
                return row[0] if row else 0
        except Exception:
            return 0
    
    def _count_recent_events(self, cache_key: str) -> int:
        """Count events in last 5 minutes for rate detection."""
        now = time.time()
        cutoff = now - 300  # 5 minutes
        
        if cache_key not in self._recent_events:
            return 0
        
        # Clean old timestamps and count
        self._recent_events[cache_key] = [
            t for t in self._recent_events[cache_key] if t > cutoff
        ]
        return len(self._recent_events[cache_key])
    
    def update_baseline(
        self,
        user: str,
        host: str,
        process_name: Optional[str],
        parent_process: Optional[str],
        event_hour: int
    ):
        """
        Update baseline with new observation.
        
        Called for each processed event. Updates are batched/async
        to avoid blocking the main pipeline.
        
        Args:
            user: Username
            host: Hostname
            process_name: Process name
            parent_process: Parent process name
            event_hour: Hour of event
        """
        now = datetime.utcnow().isoformat()
        cache_key = self._get_cache_key(user, host)
        
        # Track recent event for rate detection
        if cache_key not in self._recent_events:
            self._recent_events[cache_key] = []
        self._recent_events[cache_key].append(time.time())
        
        # Limit recent events list size
        if len(self._recent_events[cache_key]) > 1000:
            self._recent_events[cache_key] = self._recent_events[cache_key][-500:]
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Update or create baseline
                conn.execute(
                    """INSERT INTO baselines (user, host, total_events, updated_at, created_at)
                       VALUES (?, ?, 1, ?, ?)
                       ON CONFLICT(user, host) DO UPDATE SET
                       total_events = total_events + 1,
                       updated_at = ?""",
                    (user.lower(), host.lower(), now, now, now)
                )
                
                # Update process stats
                if process_name:
                    conn.execute(
                        """INSERT INTO process_stats 
                           (user, host, process_name, occurrence_count, first_seen, last_seen)
                           VALUES (?, ?, ?, 1, ?, ?)
                           ON CONFLICT(user, host, process_name) DO UPDATE SET
                           occurrence_count = occurrence_count + 1,
                           last_seen = ?""",
                        (user.lower(), host.lower(), process_name.lower(), now, now, now)
                    )
                
                # Update process chain stats
                if process_name and parent_process:
                    conn.execute(
                        """INSERT INTO process_chain_stats
                           (user, host, parent_process, child_process, 
                            occurrence_count, first_seen, last_seen)
                           VALUES (?, ?, ?, ?, 1, ?, ?)
                           ON CONFLICT(user, host, parent_process, child_process) DO UPDATE SET
                           occurrence_count = occurrence_count + 1,
                           last_seen = ?""",
                        (user.lower(), host.lower(), parent_process.lower(),
                         process_name.lower(), now, now, now)
                    )
                
                conn.commit()
                
        except Exception as e:
            logger.warning(f"Failed to update baseline for {user}@{host}: {e}")
        
        # Invalidate cache
        with self._cache_lock:
            if cache_key in self._cache:
                del self._cache[cache_key]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get baseline manager statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                baseline_count = conn.execute(
                    "SELECT COUNT(*) FROM baselines"
                ).fetchone()[0]
                process_count = conn.execute(
                    "SELECT COUNT(*) FROM process_stats"
                ).fetchone()[0]
                chain_count = conn.execute(
                    "SELECT COUNT(*) FROM process_chain_stats"
                ).fetchone()[0]
                
                return {
                    "baselines": baseline_count,
                    "processes_tracked": process_count,
                    "chains_tracked": chain_count,
                    "cache_size": len(self._cache),
                }
        except Exception as e:
            return {"error": str(e)}


# Global instance
_baseline_manager: Optional[BaselineManager] = None


def get_baseline_manager() -> BaselineManager:
    """Get or create global baseline manager instance."""
    global _baseline_manager
    
    if _baseline_manager is None:
        _baseline_manager = BaselineManager()
    
    return _baseline_manager
