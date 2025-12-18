"""
Storage Layer for UEBA Server.

Handles persistence of normalized events to SQLite database.
Provides efficient querying for the web UI.
"""

import sqlite3
import json
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager

from .models import NormalizedEvent, EventLevel, EventStats, Alert, AlertStats, AlertResponse, BehaviorType, EventSource
from .config import get_config

logger = logging.getLogger(__name__)


class EventStorage:
    """
    SQLite-based storage for normalized events.
    Thread-safe implementation for concurrent access.
    """
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize the storage layer.
        
        Args:
            db_path: Path to SQLite database file. If None, uses config.
        """
        if db_path is None:
            config = get_config()
            db_path = str(config.root_dir / config.database.path)
        
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema."""
        # Ensure directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Create events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ingested_at TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT 'sysmon',
                    host TEXT NOT NULL,
                    user TEXT NOT NULL,
                    event_id INTEGER NOT NULL,
                    level TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    process_name TEXT,
                    process_id INTEGER,
                    parent_process_name TEXT,
                    parent_process_id INTEGER,
                    image_path TEXT,
                    command_line TEXT,
                    source_ip TEXT,
                    source_port INTEGER,
                    dest_ip TEXT,
                    dest_port INTEGER,
                    target_filename TEXT,
                    file_hash TEXT,
                    message TEXT NOT NULL,
                    raw_json TEXT
                )
            """)
            
            # Add source column if it doesn't exist (migration for existing DBs)
            try:
                cursor.execute("ALTER TABLE events ADD COLUMN source TEXT NOT NULL DEFAULT 'sysmon'")
                logger.info("Added 'source' column to events table")
            except sqlite3.OperationalError:
                pass  # Column already exists
            
            # Add risk assessment columns (migration for existing DBs)
            risk_columns = [
                ("risk_score", "REAL"),
                ("risk_level", "TEXT"),
                ("rule_score", "REAL"),
                ("anomaly_score", "REAL"),
                ("context_score", "REAL"),
            ]
            for col_name, col_type in risk_columns:
                try:
                    cursor.execute(f"ALTER TABLE events ADD COLUMN {col_name} {col_type}")
                    logger.info(f"Added '{col_name}' column to events table")
                except sqlite3.OperationalError:
                    pass  # Column already exists
            
            # Add category/subcategory columns (migration for existing DBs)
            category_columns = [
                ("category", "TEXT"),
                ("subcategory", "TEXT"),
            ]
            for col_name, col_type in category_columns:
                try:
                    cursor.execute(f"ALTER TABLE events ADD COLUMN {col_name} {col_type}")
                    logger.info(f"Added '{col_name}' column to events table")
                except sqlite3.OperationalError:
                    pass  # Column already exists
            
            # Add maximum telemetry columns (migration for existing DBs)
            telemetry_columns = [
                ("channel", "TEXT"),  # Windows Event Log channel name
                ("record_id", "INTEGER"),  # Windows Event RecordId
                ("user_sid", "TEXT"),  # User SID if available
                ("logon_id", "TEXT"),  # Logon ID for session tracking
                ("action_type", "TEXT"),  # Derived action type (lock, unlock, logon, etc.)
                ("task", "INTEGER"),  # Windows Event Task
                ("keywords", "TEXT"),  # Windows Event Keywords
                ("ts_ms", "INTEGER"),  # UTC epoch milliseconds for timezone-safe queries
            ]
            for col_name, col_type in telemetry_columns:
                try:
                    cursor.execute(f"ALTER TABLE events ADD COLUMN {col_name} {col_type}")
                    logger.info(f"Added '{col_name}' column to events table")
                except sqlite3.OperationalError:
                    pass  # Column already exists
            
            # Create indexes for efficient querying
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_timestamp 
                ON events(timestamp DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_ingested 
                ON events(ingested_at DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_host 
                ON events(host)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_level 
                ON events(level)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_event_id 
                ON events(event_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_source 
                ON events(source)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_channel 
                ON events(channel)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_action_type 
                ON events(action_type)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_record_id 
                ON events(record_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_ts_ms 
                ON events(ts_ms DESC)
            """)
            
            # Migration: Backfill ts_ms for existing events that don't have it
            cursor.execute("""
                UPDATE events 
                SET ts_ms = CAST(strftime('%s', ingested_at) AS INTEGER) * 1000
                WHERE ts_ms IS NULL AND ingested_at IS NOT NULL
            """)
            if cursor.rowcount > 0:
                logger.info(f"Migrated {cursor.rowcount} events to ts_ms format")
            
            # ============================================
            # Alerts Table for UEBA Detection Results
            # ============================================
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    behavior TEXT NOT NULL,
                    risk_score INTEGER NOT NULL DEFAULT 50,
                    host TEXT NOT NULL DEFAULT 'unknown',
                    user TEXT NOT NULL DEFAULT 'unknown',
                    source_ip TEXT,
                    fail_count INTEGER,
                    file_event_count INTEGER,
                    archive_process_name TEXT,
                    target_path TEXT,
                    summary TEXT NOT NULL DEFAULT '',
                    details TEXT,
                    status TEXT NOT NULL DEFAULT 'open',
                    first_seen TEXT,
                    last_seen TEXT,
                    occurrence_count INTEGER NOT NULL DEFAULT 1
                )
            """)
            
            # Migration: Add new columns for alert aggregation (if they don't exist)
            alert_columns = [
                ("status", "TEXT NOT NULL DEFAULT 'open'"),
                ("first_seen", "TEXT"),
                ("last_seen", "TEXT"),
                ("occurrence_count", "INTEGER NOT NULL DEFAULT 1"),
                # MVP P0: Alert explainability and MITRE mapping
                ("reasons", "TEXT"),  # JSON array of reason objects
                ("mitre_tactics", "TEXT"),  # JSON array of MITRE tactic IDs
                ("mitre_techniques", "TEXT"),  # JSON array of MITRE technique IDs
                ("evidence_event_ids", "TEXT"),  # JSON array of event IDs
            ]
            for col_name, col_type in alert_columns:
                try:
                    cursor.execute(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type}")
                    logger.info(f"Added '{col_name}' column to alerts table")
                except sqlite3.OperationalError:
                    pass  # Column already exists
            
            # Alerts indexes
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp 
                ON alerts(timestamp DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_behavior 
                ON alerts(behavior)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_risk_score 
                ON alerts(risk_score DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_host 
                ON alerts(host)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_user 
                ON alerts(user)
            """)
            # Index for fast open alert lookup (deduplication)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_open_lookup 
                ON alerts(host, user, behavior, status)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_status 
                ON alerts(status)
            """)
            
            # ============================================
            # App Settings Table (MVP: Baseline Window Control)
            # ============================================
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    description TEXT,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)
            
            # Initialize default settings if table is empty
            cursor.execute("SELECT COUNT(*) FROM app_settings")
            if cursor.fetchone()[0] == 0:
                default_settings = [
                    ("baseline_window_hours", "6", "Baseline training window in hours (for demo: shorter windows)"),
                    ("baseline_min_events", "50", "Minimum events required for baseline training"),
                    ("scan_window_hours", "1", "Anomaly scan window in hours"),
                    ("scan_interval_minutes", "60", "Anomaly scan interval in minutes"),
                    ("anomaly_threshold", "0.7", "Anomaly score threshold (0-1) for alert generation"),
                    ("dedup_window_minutes", "60", "Alert deduplication window in minutes"),
                    ("realtime_alert_threshold", "80", "Real-time alert threshold (0-100) for ingest pipeline"),
                ]
                for key, value, desc in default_settings:
                    cursor.execute("""
                        INSERT INTO app_settings (key, value, description)
                        VALUES (?, ?, ?)
                    """, (key, value, desc))
                logger.info("Initialized default app settings")
            
            # ============================================
            # Ground Truth Labels Table for Analyst Feedback
            # ============================================
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ground_truth_labels (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id INTEGER NOT NULL,
                    event_id INTEGER,
                    label TEXT NOT NULL CHECK(label IN ('true_positive', 'false_positive', 'uncertain')),
                    analyst_username TEXT,
                    labeled_at TEXT NOT NULL DEFAULT (datetime('now')),
                    notes TEXT,
                    training_eligible INTEGER DEFAULT 1,
                    snapshot_risk_score REAL,
                    snapshot_confidence REAL,
                    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
                )
            """)
            
            # Indexes for ground truth labels
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_ground_truth_alert_id 
                ON ground_truth_labels(alert_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_ground_truth_training_eligible 
                ON ground_truth_labels(training_eligible)
                WHERE training_eligible = 1
            """)
            
            # ============================================
            # Baseline Stats Table (UEBA Entity Baselines)
            # ============================================
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS baseline_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    feature_name TEXT NOT NULL,
                    feature_type TEXT NOT NULL,
                    feature_value TEXT NOT NULL,
                    window_start TEXT NOT NULL,
                    window_end TEXT NOT NULL,
                    sample_count INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    UNIQUE(entity_id, entity_type, feature_name, window_end)
                )
            """)
            
            # Indexes for baseline_stats
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_baseline_entity 
                ON baseline_stats(entity_id, entity_type)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_baseline_window 
                ON baseline_stats(window_end DESC)
            """)
            
            # ============================================
            # Session Features Table (Hourly Aggregations)
            # ============================================
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS session_features (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    entity_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    window_start TEXT NOT NULL,
                    window_end TEXT NOT NULL,
                    features TEXT NOT NULL,
                    feature_version TEXT NOT NULL DEFAULT 'v1',
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)
            
            # Indexes for session_features
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_session_entity_time 
                ON session_features(entity_id, entity_type, window_start DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_session_window 
                ON session_features(window_end DESC)
            """)
            
            # ============================================
            # Models Table (ML Model Metadata)
            # ============================================
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS models (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    model_type TEXT NOT NULL,
                    entity_id TEXT,
                    entity_type TEXT,
                    model_path TEXT NOT NULL,
                    feature_version TEXT NOT NULL DEFAULT 'v1',
                    trained_at TEXT NOT NULL,
                    training_samples INTEGER DEFAULT 0,
                    metrics TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)
            
            # Indexes for models
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_models_type_entity 
                ON models(model_type, entity_id, entity_type)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_models_status 
                ON models(status)
            """)
            
            # Additional performance indexes for events table
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_user_timestamp 
                ON events(user, timestamp DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_host_timestamp 
                ON events(host, timestamp DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_category 
                ON events(category)
            """)
            
            # ============================================
            # UEBA Rule Hits Table
            # ============================================
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rule_hits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_id INTEGER,
                    event_uuid TEXT,
                    user TEXT NOT NULL,
                    host TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    base_score INTEGER NOT NULL,
                    final_event_score INTEGER NOT NULL,
                    modifiers_applied TEXT,
                    evidence_json TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_rule_hits_timestamp 
                ON rule_hits(timestamp DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_rule_hits_user 
                ON rule_hits(user, timestamp DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_rule_hits_host 
                ON rule_hits(host, timestamp DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_rule_hits_rule_id 
                ON rule_hits(rule_id)
            """)
            
            # ============================================
            # UEBA Entity Risk Table
            # ============================================
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS entity_risk (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    window TEXT NOT NULL,
                    score REAL NOT NULL,
                    contributing_rules TEXT,
                    last_updated TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    UNIQUE(entity_type, entity_id, window)
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_entity_risk_lookup 
                ON entity_risk(entity_type, entity_id, window)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_entity_risk_score 
                ON entity_risk(score DESC)
            """)
            
            # ============================================
            # UEBA Alerts Table (enhanced)
            # ============================================
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ueba_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    score REAL NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    summary TEXT,
                    linked_rule_hits TEXT,
                    evidence TEXT,
                    mitre_tactics TEXT,
                    mitre_techniques TEXT,
                    status TEXT NOT NULL DEFAULT 'open'
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_ueba_alerts_created 
                ON ueba_alerts(created_at DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_ueba_alerts_entity 
                ON ueba_alerts(entity_type, entity_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_ueba_alerts_severity 
                ON ueba_alerts(severity)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_ueba_alerts_status 
                ON ueba_alerts(status)
            """)
            
            conn.commit()
            logger.info(f"Database initialized at {self.db_path}")
    
    @contextmanager
    def _get_connection(self):
        """Get a thread-safe database connection."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def store_event(self, event: NormalizedEvent) -> int:
        """
        Store a single normalized event.
        
        Args:
            event: NormalizedEvent to store
            
        Returns:
            ID of the inserted event
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Get source value
                source_val = event.source if isinstance(event.source, str) else event.source.value
                
                # Calculate ts_ms (UTC epoch milliseconds) for timezone-safe queries
                ts_ms = int(event.ingested_at.timestamp() * 1000)
                
                cursor.execute("""
                    INSERT INTO events (
                        timestamp, ingested_at, source, host, user, event_id, level,
                        provider, process_name, process_id, parent_process_name,
                        parent_process_id, image_path, command_line, source_ip,
                        source_port, dest_ip, dest_port, target_filename,
                        file_hash, message, raw_json,
                        risk_score, risk_level, rule_score, anomaly_score, context_score,
                        category, subcategory,
                        channel, record_id, user_sid, logon_id, action_type, task, keywords, ts_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.timestamp.isoformat(),
                    event.ingested_at.isoformat(),
                    source_val,
                    event.host,
                    event.user,
                    event.event_id,
                    event.level if isinstance(event.level, str) else event.level.value,
                    event.provider,
                    event.process_name,
                    event.process_id,
                    event.parent_process_name,
                    event.parent_process_id,
                    event.image_path,
                    event.command_line,
                    event.source_ip,
                    event.source_port,
                    event.dest_ip,
                    event.dest_port,
                    event.target_filename,
                    event.file_hash,
                    event.message,
                    event.raw_json,
                    event.risk_score,
                    event.risk_level,
                    event.rule_score,
                    event.anomaly_score,
                    event.context_score,
                    event.category if isinstance(event.category, str) else event.category.value if event.category else None,
                    event.subcategory,
                    getattr(event, 'channel', None),
                    getattr(event, 'record_id', None),
                    getattr(event, 'user_sid', None),
                    getattr(event, 'logon_id', None),
                    getattr(event, 'action_type', None),
                    getattr(event, 'task', None),
                    getattr(event, 'keywords', None),
                    ts_ms
                ))
                
                conn.commit()
                return cursor.lastrowid
    
    def store_events(self, events: list[NormalizedEvent]) -> list[int]:
        """
        Store multiple events in a single transaction.
        
        Args:
            events: List of NormalizedEvent objects
            
        Returns:
            List of inserted event IDs
        """
        if not events:
            return []
        
        ids = []
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                for event in events:
                    # Get source value
                    source_val = event.source if isinstance(event.source, str) else event.source.value
                    # Calculate ts_ms (UTC epoch milliseconds)
                    ts_ms = int(event.ingested_at.timestamp() * 1000)
                    
                    cursor.execute("""
                        INSERT INTO events (
                            timestamp, ingested_at, source, host, user, event_id, level,
                            provider, process_name, process_id, parent_process_name,
                            parent_process_id, image_path, command_line, source_ip,
                            source_port, dest_ip, dest_port, target_filename,
                            file_hash, message, raw_json, ts_ms
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        event.timestamp.isoformat(),
                        event.ingested_at.isoformat(),
                        source_val,
                        event.host,
                        event.user,
                        event.event_id,
                        event.level if isinstance(event.level, str) else event.level.value,
                        event.provider,
                        event.process_name,
                        event.process_id,
                        event.parent_process_name,
                        event.parent_process_id,
                        event.image_path,
                        event.command_line,
                        event.source_ip,
                        event.source_port,
                        event.dest_ip,
                        event.dest_port,
                        event.target_filename,
                        event.file_hash,
                        event.message,
                        event.raw_json,
                        ts_ms
                    ))
                    ids.append(cursor.lastrowid)
                
                conn.commit()
        
        return ids
    
    def store_events_bulk(self, events: list[NormalizedEvent]) -> list[int]:
        """
        Store multiple events using executemany for better performance.
        
        This is optimized for high-throughput scenarios with many events.
        
        Args:
            events: List of NormalizedEvent objects
            
        Returns:
            List of inserted event IDs (approximate, as executemany doesn't return individual IDs)
        """
        if not events:
            return []
        
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Prepare data for executemany
                data = []
                for event in events:
                    source_val = event.source if isinstance(event.source, str) else event.source.value
                    level_val = event.level if isinstance(event.level, str) else event.level.value
                    category_val = event.category if isinstance(event.category, str) else event.category.value if event.category else None
                    # Calculate ts_ms (UTC epoch milliseconds)
                    ts_ms = int(event.ingested_at.timestamp() * 1000)
                    
                    data.append((
                        event.timestamp.isoformat(),
                        event.ingested_at.isoformat(),
                        source_val,
                        event.host,
                        event.user,
                        event.event_id,
                        level_val,
                        event.provider,
                        event.process_name,
                        event.process_id,
                        event.parent_process_name,
                        event.parent_process_id,
                        event.image_path,
                        event.command_line,
                        event.source_ip,
                        event.source_port,
                        event.dest_ip,
                        event.dest_port,
                        event.target_filename,
                        event.file_hash,
                        event.message,
                        event.raw_json,
                        event.risk_score,
                        event.risk_level,
                        event.rule_score,
                        event.anomaly_score,
                        event.context_score,
                        category_val,
                        event.subcategory,
                        ts_ms
                    ))
                
                # Use executemany for bulk insert
                cursor.executemany("""
                    INSERT INTO events (
                        timestamp, ingested_at, source, host, user, event_id, level,
                        provider, process_name, process_id, parent_process_name,
                        parent_process_id, image_path, command_line, source_ip,
                        source_port, dest_ip, dest_port, target_filename,
                        file_hash, message, raw_json,
                        risk_score, risk_level, rule_score, anomaly_score, context_score,
                        category, subcategory, ts_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, data)
                
                conn.commit()
                
                # Get the IDs of inserted rows (approximate - lastrowid gives first ID)
                # For exact IDs, we'd need to query, but for performance we return approximate range
                first_id = cursor.lastrowid
                count = len(events)
                return list(range(first_id, first_id + count))
    
    def _row_to_event(self, row: sqlite3.Row) -> NormalizedEvent:
        """Convert a database row to NormalizedEvent."""
        from .models import EventCategory
        
        # Parse source field with fallback for old records
        source_str = row['source'] if 'source' in row.keys() else 'sysmon'
        try:
            source = EventSource(source_str)
        except ValueError:
            source = EventSource.SYSMON
        
        # Parse category field with fallback
        category_str = row['category'] if 'category' in row.keys() else None
        if category_str:
            try:
                category = EventCategory(category_str)
            except ValueError:
                category = EventCategory.OTHER
        else:
            category = EventCategory.OTHER
        
        return NormalizedEvent(
            id=row['id'],
            timestamp=datetime.fromisoformat(row['timestamp']),
            ingested_at=datetime.fromisoformat(row['ingested_at']),
            source=source,
            host=row['host'],
            user=row['user'],
            event_id=row['event_id'],
            level=EventLevel(row['level']) if row['level'] in [e.value for e in EventLevel] else EventLevel.UNKNOWN,
            provider=row['provider'],
            category=category,
            subcategory=row['subcategory'] if 'subcategory' in row.keys() else None,
            process_name=row['process_name'],
            process_id=row['process_id'],
            parent_process_name=row['parent_process_name'],
            parent_process_id=row['parent_process_id'],
            image_path=row['image_path'],
            command_line=row['command_line'],
            source_ip=row['source_ip'],
            source_port=row['source_port'],
            dest_ip=row['dest_ip'],
            dest_port=row['dest_port'],
            target_filename=row['target_filename'],
            file_hash=row['file_hash'],
            message=row['message'],
            raw_json=row['raw_json'],
            risk_score=row['risk_score'] if 'risk_score' in row.keys() else None,
            risk_level=row['risk_level'] if 'risk_level' in row.keys() else None,
            rule_score=row['rule_score'] if 'rule_score' in row.keys() else None,
            anomaly_score=row['anomaly_score'] if 'anomaly_score' in row.keys() else None,
            context_score=row['context_score'] if 'context_score' in row.keys() else None,
        )
    
    def get_event_count(self) -> int:
        """Get total count of events in database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM events")
            return cursor.fetchone()[0]
    
    def get_events(
        self,
        limit: int = 100,
        offset: int = 0,
        since_id: Optional[int] = None,
        since_timestamp: Optional[datetime] = None,
        host: Optional[str] = None,
        level: Optional[str] = None,
        event_id: Optional[int] = None,
        source: Optional[str] = None
    ) -> tuple[list[NormalizedEvent], int]:
        """
        Query events with filtering and pagination.
        
        Args:
            limit: Maximum number of events to return
            offset: Number of events to skip
            since_id: Return events with ID greater than this
            since_timestamp: Return events after this timestamp
            host: Filter by host name
            level: Filter by level
            event_id: Filter by event ID
            source: Filter by event source (sysmon, windows_event)
            
        Returns:
            Tuple of (list of events, total count matching filters)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Build WHERE clause
            conditions = []
            params = []
            
            if since_id is not None:
                conditions.append("id > ?")
                params.append(since_id)
            
            if since_timestamp is not None:
                conditions.append("ingested_at > ?")
                params.append(since_timestamp.isoformat())
            
            if host:
                conditions.append("host = ?")
                params.append(host)
            
            if level:
                conditions.append("level = ?")
                params.append(level)
            
            if event_id is not None:
                conditions.append("event_id = ?")
                params.append(event_id)
            
            if source:
                conditions.append("source = ?")
                params.append(source)
            
            where_clause = ""
            if conditions:
                where_clause = "WHERE " + " AND ".join(conditions)
            
            # Get total count
            cursor.execute(f"SELECT COUNT(*) FROM events {where_clause}", params)
            total_count = cursor.fetchone()[0]
            
            # Get events
            query = f"""
                SELECT * FROM events 
                {where_clause}
                ORDER BY id DESC
                LIMIT ? OFFSET ?
            """
            cursor.execute(query, params + [limit, offset])
            
            events = [self._row_to_event(row) for row in cursor.fetchall()]
            
            return events, total_count
    
    def get_latest_event_id(self) -> int:
        """Get the ID of the most recent event."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(id) FROM events")
            result = cursor.fetchone()[0]
            return result if result else 0
    
    def get_stats(self) -> EventStats:
        """Get statistics about stored events."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Total events
            cursor.execute("SELECT COUNT(*) FROM events")
            total = cursor.fetchone()[0]
            
            # Events in last hour
            hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()
            cursor.execute("SELECT COUNT(*) FROM events WHERE ingested_at > ?", (hour_ago,))
            last_hour = cursor.fetchone()[0]
            
            # Events in last day
            day_ago = (datetime.utcnow() - timedelta(days=1)).isoformat()
            cursor.execute("SELECT COUNT(*) FROM events WHERE ingested_at > ?", (day_ago,))
            last_day = cursor.fetchone()[0]
            
            # Unique hosts
            cursor.execute("SELECT COUNT(DISTINCT host) FROM events")
            unique_hosts = cursor.fetchone()[0]
            
            # Unique users
            cursor.execute("SELECT COUNT(DISTINCT user) FROM events")
            unique_users = cursor.fetchone()[0]
            
            # Error count (last 24h)
            cursor.execute(
                "SELECT COUNT(*) FROM events WHERE level = 'Error' AND ingested_at > ?",
                (day_ago,)
            )
            errors = cursor.fetchone()[0]
            
            # Warning count (last 24h)
            cursor.execute(
                "SELECT COUNT(*) FROM events WHERE level = 'Warning' AND ingested_at > ?",
                (day_ago,)
            )
            warnings = cursor.fetchone()[0]
            
            # Counts by source
            by_source = {}
            cursor.execute("SELECT source, COUNT(*) FROM events GROUP BY source")
            for row in cursor.fetchall():
                by_source[row[0]] = row[1]
            
            return EventStats(
                total_events=total,
                events_last_hour=last_hour,
                events_last_day=last_day,
                unique_hosts=unique_hosts,
                unique_users=unique_users,
                error_count=errors,
                warning_count=warnings,
                by_source=by_source
            )
    
    # ============================================
    # Alert Storage Methods
    # ============================================
    
    # List of valid behaviors for filtering (5 core UEBA behaviors + ML-based)
    VALID_BEHAVIORS = [
        "failed_login_burst",
        "suspicious_path_execution",
        "security_log_clearing",
        "restricted_hours_login",
        "firewall_disabled",
        "ueba_anomaly"  # ML/baseline-based anomaly detection
    ]
    
    # Merge window for alert aggregation (in minutes)
    MERGE_WINDOW_MINUTES = 30
    
    def store_alert(self, alert: Alert) -> int:
        """
        Store a single alert (simple insert, no deduplication).
        
        Args:
            alert: Alert to store
            
        Returns:
            ID of the inserted alert
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Use alert timestamp as first_seen/last_seen if not provided
                first_seen = alert.first_seen or alert.timestamp
                last_seen = alert.last_seen or alert.timestamp
                
                # Serialize JSON fields
                import json
                reasons_json = json.dumps(alert.reasons) if alert.reasons else None
                mitre_tactics_json = json.dumps(alert.mitre_tactics) if alert.mitre_tactics else None
                mitre_techniques_json = json.dumps(alert.mitre_techniques) if alert.mitre_techniques else None
                evidence_event_ids_json = json.dumps(alert.evidence_event_ids) if alert.evidence_event_ids else None
                
                cursor.execute("""
                    INSERT INTO alerts (
                        timestamp, behavior, risk_score, host, user,
                        source_ip, fail_count, file_event_count,
                        archive_process_name, target_path, summary, details,
                        status, first_seen, last_seen, occurrence_count,
                        reasons, mitre_tactics, mitre_techniques, evidence_event_ids
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert.timestamp.isoformat(),
                    alert.behavior,
                    alert.risk_score,
                    alert.host,
                    alert.user,
                    alert.source_ip,
                    alert.fail_count,
                    alert.file_event_count,
                    alert.archive_process_name,
                    alert.target_path,
                    alert.summary,
                    alert.details,
                    alert.status,
                    first_seen.isoformat(),
                    last_seen.isoformat(),
                    alert.occurrence_count,
                    reasons_json,
                    mitre_tactics_json,
                    mitre_techniques_json,
                    evidence_event_ids_json
                ))
                
                conn.commit()
                logger.info(f"Stored alert: behavior={alert.behavior}, risk={alert.risk_score}")
                return cursor.lastrowid
    
    def upsert_or_update_alert(self, alert: Alert, merge_window_minutes: Optional[int] = None) -> int:
        """
        Insert new alert OR update existing open alert with same (host, user, behavior).
        
        This is the primary method for storing alerts with deduplication.
        
        Logic:
        1. Find open alert with same (host, user, behavior) within merge_window
        2. If found: increment occurrence_count, update last_seen, update summary
        3. If not found: insert new alert
        
        Args:
            alert: Alert to store/update
            merge_window_minutes: Time window for aggregation (default: 30 minutes)
            
        Returns:
            ID of the inserted or updated alert
        """
        if merge_window_minutes is None:
            merge_window_minutes = self.MERGE_WINDOW_MINUTES
        
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Calculate the cutoff time for merge window
                cutoff = (datetime.utcnow() - timedelta(minutes=merge_window_minutes)).isoformat()
                
                # Look for existing open alert with same host, user, behavior within window
                cursor.execute("""
                    SELECT id, occurrence_count, first_seen, risk_score
                    FROM alerts 
                    WHERE host = ? AND user = ? AND behavior = ? 
                      AND status = 'open'
                      AND last_seen > ?
                    ORDER BY last_seen DESC
                    LIMIT 1
                """, (
                    alert.host.lower(),
                    alert.user.lower(),
                    alert.behavior,
                    cutoff
                ))
                
                existing = cursor.fetchone()
                
                if existing:
                    # Update existing alert: increment occurrence_count, update last_seen
                    alert_id = existing[0]
                    new_count = existing[1] + 1
                    existing_risk = existing[3]
                    
                    # Optionally bump risk score (+5 per occurrence, max 100)
                    new_risk = min(100, existing_risk + 5)
                    
                    # Update summary to reflect count
                    new_summary = alert.summary
                    if new_count > 1:
                        # Append occurrence info to summary
                        base_summary = alert.summary.split(' [')[0]  # Remove previous occurrence suffix
                        new_summary = f"{base_summary} [{new_count} occurrences]"
                    
                    # Serialize JSON fields for update
                    import json
                    reasons_json = json.dumps(alert.reasons) if alert.reasons else None
                    mitre_tactics_json = json.dumps(alert.mitre_tactics) if alert.mitre_tactics else None
                    mitre_techniques_json = json.dumps(alert.mitre_techniques) if alert.mitre_techniques else None
                    evidence_event_ids_json = json.dumps(alert.evidence_event_ids) if alert.evidence_event_ids else None
                    
                    cursor.execute("""
                        UPDATE alerts SET
                            occurrence_count = ?,
                            last_seen = ?,
                            risk_score = ?,
                            summary = ?,
                            details = ?,
                            reasons = ?,
                            mitre_tactics = ?,
                            mitre_techniques = ?,
                            evidence_event_ids = ?,
                            timestamp = ?
                        WHERE id = ?
                    """, (
                        new_count,
                        alert.timestamp.isoformat(),
                        new_risk,
                        new_summary,
                        alert.details,
                        reasons_json,
                        mitre_tactics_json,
                        mitre_techniques_json,
                        evidence_event_ids_json,
                        alert.timestamp.isoformat(),
                        alert_id
                    ))
                    
                    conn.commit()
                    logger.info(
                        f"Updated alert: id={alert_id}, behavior={alert.behavior}, "
                        f"occurrence_count={new_count}, risk={new_risk}"
                    )
                    return alert_id
                else:
                    # Insert new alert
                    first_seen = alert.first_seen or alert.timestamp
                    last_seen = alert.last_seen or alert.timestamp
                    
                    # Serialize JSON fields
                    import json
                    reasons_json = json.dumps(alert.reasons) if alert.reasons else None
                    mitre_tactics_json = json.dumps(alert.mitre_tactics) if alert.mitre_tactics else None
                    mitre_techniques_json = json.dumps(alert.mitre_techniques) if alert.mitre_techniques else None
                    evidence_event_ids_json = json.dumps(alert.evidence_event_ids) if alert.evidence_event_ids else None
                    
                    cursor.execute("""
                        INSERT INTO alerts (
                            timestamp, behavior, risk_score, host, user,
                            source_ip, fail_count, file_event_count,
                            archive_process_name, target_path, summary, details,
                            status, first_seen, last_seen, occurrence_count,
                            reasons, mitre_tactics, mitre_techniques, evidence_event_ids
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        alert.timestamp.isoformat(),
                        alert.behavior,
                        alert.risk_score,
                        alert.host.lower(),
                        alert.user.lower(),
                        alert.source_ip,
                        alert.fail_count,
                        alert.file_event_count,
                        alert.archive_process_name,
                        alert.target_path,
                        alert.summary,
                        alert.details,
                        alert.status,
                        first_seen.isoformat(),
                        last_seen.isoformat(),
                        alert.occurrence_count,
                        reasons_json,
                        mitre_tactics_json,
                        mitre_techniques_json,
                        evidence_event_ids_json
                    ))
                    
                    conn.commit()
                    alert_id = cursor.lastrowid
                    logger.info(f"Created new alert: id={alert_id}, behavior={alert.behavior}, risk={alert.risk_score}")
                    return alert_id
    
    def _row_to_alert(self, row: sqlite3.Row) -> Alert:
        """Convert a database row to Alert."""
        # Handle new fields with fallback for older rows
        keys = row.keys()
        import json
        
        # Parse first_seen/last_seen with fallback to timestamp
        timestamp = datetime.fromisoformat(row['timestamp'])
        first_seen = datetime.fromisoformat(row['first_seen']) if 'first_seen' in keys and row['first_seen'] else timestamp
        last_seen = datetime.fromisoformat(row['last_seen']) if 'last_seen' in keys and row['last_seen'] else timestamp
        status = row['status'] if 'status' in keys and row['status'] else 'open'
        occurrence_count = row['occurrence_count'] if 'occurrence_count' in keys and row['occurrence_count'] else 1
        
        # Parse JSON fields
        reasons = None
        if 'reasons' in keys and row['reasons']:
            try:
                reasons = json.loads(row['reasons'])
            except (json.JSONDecodeError, TypeError):
                reasons = None
        
        mitre_tactics = None
        if 'mitre_tactics' in keys and row['mitre_tactics']:
            try:
                mitre_tactics = json.loads(row['mitre_tactics'])
            except (json.JSONDecodeError, TypeError):
                mitre_tactics = None
        
        mitre_techniques = None
        if 'mitre_techniques' in keys and row['mitre_techniques']:
            try:
                mitre_techniques = json.loads(row['mitre_techniques'])
            except (json.JSONDecodeError, TypeError):
                mitre_techniques = None
        
        evidence_event_ids = None
        if 'evidence_event_ids' in keys and row['evidence_event_ids']:
            try:
                evidence_event_ids = json.loads(row['evidence_event_ids'])
            except (json.JSONDecodeError, TypeError):
                evidence_event_ids = None
        
        return Alert(
            id=row['id'],
            timestamp=timestamp,
            behavior=row['behavior'],
            risk_score=row['risk_score'],
            host=row['host'],
            user=row['user'],
            source_ip=row['source_ip'],
            fail_count=row['fail_count'],
            file_event_count=row['file_event_count'],
            archive_process_name=row['archive_process_name'],
            target_path=row['target_path'],
            summary=row['summary'],
            details=row['details'],
            status=status,
            first_seen=first_seen,
            last_seen=last_seen,
            occurrence_count=occurrence_count,
            reasons=reasons,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            evidence_event_ids=evidence_event_ids
        )
    
    def get_alerts(
        self,
        limit: int = 200,
        offset: int = 0,
        behavior: Optional[str] = None,
        min_risk: Optional[int] = None,
        since: Optional[datetime] = None,
        since_id: Optional[int] = None,
        host: Optional[str] = None,
        user: Optional[str] = None
    ) -> tuple[list[Alert], int]:
        """
        Query alerts with filtering and pagination.
        
        Only returns alerts from the 3 valid behavior types.
        
        Args:
            limit: Maximum number of alerts to return
            offset: Number of alerts to skip
            behavior: Filter by specific behavior type
            min_risk: Minimum risk score filter
            since: Return alerts after this timestamp
            since_id: Return alerts with ID greater than this
            host: Filter by hostname
            user: Filter by user
            
        Returns:
            Tuple of (list of alerts, total count matching filters)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Build WHERE clause - always filter to valid behaviors
            conditions = [f"behavior IN ({','.join(['?' for _ in self.VALID_BEHAVIORS])})"]
            params = list(self.VALID_BEHAVIORS)
            
            if behavior and behavior in self.VALID_BEHAVIORS:
                conditions.append("behavior = ?")
                params.append(behavior)
            
            if min_risk is not None:
                conditions.append("risk_score >= ?")
                params.append(min_risk)
            
            if since is not None:
                conditions.append("timestamp > ?")
                params.append(since.isoformat())
            
            if since_id is not None:
                conditions.append("id > ?")
                params.append(since_id)
            
            if host:
                conditions.append("host = ?")
                params.append(host)
            
            if user:
                conditions.append("user = ?")
                params.append(user)
            
            where_clause = "WHERE " + " AND ".join(conditions)
            
            # Get total count
            cursor.execute(f"SELECT COUNT(*) FROM alerts {where_clause}", params)
            total_count = cursor.fetchone()[0]
            
            # Get alerts
            query = f"""
                SELECT * FROM alerts 
                {where_clause}
                ORDER BY timestamp DESC, id DESC
                LIMIT ? OFFSET ?
            """
            cursor.execute(query, params + [limit, offset])
            
            alerts = [self._row_to_alert(row) for row in cursor.fetchall()]
            
            return alerts, total_count
    
    def get_latest_alert_id(self) -> int:
        """Get the ID of the most recent alert."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(id) FROM alerts")
            result = cursor.fetchone()[0]
            return result if result else 0
    
    def get_alert_stats(self) -> AlertStats:
        """Get statistics about alerts for the dashboard."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Filter clause for valid behaviors
            behavior_filter = f"behavior IN ({','.join(['?' for _ in self.VALID_BEHAVIORS])})"
            behavior_params = list(self.VALID_BEHAVIORS)
            
            # Total alerts (for valid behaviors)
            cursor.execute(
                f"SELECT COUNT(*) FROM alerts WHERE {behavior_filter}",
                behavior_params
            )
            total = cursor.fetchone()[0]
            
            # Alerts in last hour
            hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()
            cursor.execute(
                f"SELECT COUNT(*) FROM alerts WHERE {behavior_filter} AND timestamp > ?",
                behavior_params + [hour_ago]
            )
            last_hour = cursor.fetchone()[0]
            
            # Alerts in last 24h
            day_ago = (datetime.utcnow() - timedelta(days=1)).isoformat()
            cursor.execute(
                f"SELECT COUNT(*) FROM alerts WHERE {behavior_filter} AND timestamp > ?",
                behavior_params + [day_ago]
            )
            last_24h = cursor.fetchone()[0]
            
            # Unique hosts with alerts
            cursor.execute(
                f"SELECT COUNT(DISTINCT host) FROM alerts WHERE {behavior_filter} AND host != 'unknown' AND host != ''",
                behavior_params
            )
            unique_hosts = cursor.fetchone()[0]
            
            # Unique users with alerts
            cursor.execute(
                f"SELECT COUNT(DISTINCT user) FROM alerts WHERE {behavior_filter} AND user != 'unknown' AND user != ''",
                behavior_params
            )
            unique_users = cursor.fetchone()[0]
            
            # High risk alerts (risk_score >= 80) in last 24h
            cursor.execute(
                f"SELECT COUNT(*) FROM alerts WHERE {behavior_filter} AND risk_score >= 80 AND timestamp > ?",
                behavior_params + [day_ago]
            )
            high_risk = cursor.fetchone()[0]
            
            # Counts by behavior type
            by_behavior = {}
            for behavior in self.VALID_BEHAVIORS:
                cursor.execute(
                    "SELECT COUNT(*) FROM alerts WHERE behavior = ?",
                    (behavior,)
                )
                by_behavior[behavior] = cursor.fetchone()[0]
            
            return AlertStats(
                total_alerts=total,
                alerts_last_hour=last_hour,
                alerts_last_24h=last_24h,
                unique_hosts=unique_hosts,
                unique_users=unique_users,
                high_risk_24h=high_risk,
                by_behavior=by_behavior
            )
    
    def get_alerts_summary(self, hours: int = 24) -> dict:
        """
        Get time-series summary of alerts for charts.
        
        Uses adaptive bucket sizing matching events summary:
        - Last Hour (1h): 1-minute buckets
        - Last 24 Hours (24h): 15-minute buckets
        - Last 7 Days (168h+): 1-hour buckets
        - Last 30 Days (720h+): 4-hour buckets
        
        Returns:
            dict with 'timeline' (bucketed counts), 'by_category' (behavior counts), 'bucket_size'
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Get alerts in the last N hours
            cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
            behavior_filter = f"behavior IN ({','.join(['?' for _ in self.VALID_BEHAVIORS])})"
            behavior_params = list(self.VALID_BEHAVIORS)
            
            # Adaptive bucket sizing based on time range
            if hours <= 1:
                bucket_format = '%Y-%m-%d %H:%M:00'
                bucket_size = 1
            elif hours <= 24:
                bucket_format = '%Y-%m-%d %H:%M:00'
                bucket_size = 15
            elif hours <= 168:
                bucket_format = '%Y-%m-%d %H:00:00'
                bucket_size = 60
            else:
                bucket_format = '%Y-%m-%d %H:00:00'
                bucket_size = 240
            
            # Query with appropriate bucket format
            cursor.execute(f"""
                SELECT 
                    strftime('{bucket_format}', timestamp) as bucket,
                    COUNT(*) as count
                FROM alerts
                WHERE {behavior_filter} AND timestamp > ?
                GROUP BY bucket
                ORDER BY bucket
            """, behavior_params + [cutoff])
            
            raw_timeline = {}
            for row in cursor.fetchall():
                raw_timeline[row[0]] = row[1]
            
            # Aggregate to appropriate bucket size
            timeline = {}
            if bucket_size >= 15 and hours <= 24 and hours > 1:
                for timestamp_str, count in raw_timeline.items():
                    try:
                        dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:00')
                        minute = (dt.minute // 15) * 15
                        bucket_dt = dt.replace(minute=minute, second=0)
                        bucket_key = bucket_dt.strftime('%Y-%m-%d %H:%M:00')
                        timeline[bucket_key] = timeline.get(bucket_key, 0) + count
                    except ValueError:
                        timeline[timestamp_str] = count
            elif bucket_size >= 240:
                for timestamp_str, count in raw_timeline.items():
                    try:
                        dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:00:00')
                        hour = (dt.hour // 4) * 4
                        bucket_dt = dt.replace(hour=hour, minute=0, second=0)
                        bucket_key = bucket_dt.strftime('%Y-%m-%d %H:00:00')
                        timeline[bucket_key] = timeline.get(bucket_key, 0) + count
                    except ValueError:
                        timeline[timestamp_str] = count
            else:
                timeline = raw_timeline
            
            # Counts by behavior category
            cursor.execute(f"""
                SELECT behavior, COUNT(*) as count
                FROM alerts
                WHERE {behavior_filter} AND timestamp > ?
                GROUP BY behavior
            """, behavior_params + [cutoff])
            
            by_category = {}
            for row in cursor.fetchall():
                by_category[row[0]] = row[1]
            
            logger.debug(f"Alerts summary: hours={hours}, bucket_size={bucket_size}min, data_points={len(timeline)}")
            
            return {
                'timeline': timeline,
                'by_category': by_category,
                'bucket_size': bucket_size
            }
    
    def get_events_summary(self, hours: int = 24) -> dict:
        """
        Get time-series summary of events for charts.
        
        Uses ingested_at TEXT column with strftime for reliable bucketing.
        Adaptive bucket sizing for performance and readability:
        - Last Hour (1h): 1-minute buckets (60 data points)
        - Last 24 Hours (24h): 15-minute buckets (96 data points)
        - Last 7 Days (168h+): 1-hour buckets
        - Last 30 Days (720h+): 4-hour buckets
        
        Returns:
            dict with 'timeline' (bucketed counts), 'by_source' (source counts), 'bucket_size' (in minutes)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Calculate cutoff as ISO string
            cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
            
            # Adaptive bucket sizing based on time range
            if hours <= 1:
                bucket_format = '%Y-%m-%d %H:%M:00'
                bucket_size = 1
            elif hours <= 24:
                bucket_format = '%Y-%m-%d %H:%M:00'
                bucket_size = 15
            elif hours <= 168:  # 7 days
                bucket_format = '%Y-%m-%d %H:00:00'
                bucket_size = 60
            else:
                bucket_format = '%Y-%m-%d %H:00:00'
                bucket_size = 240
            
            # Query using ingested_at TEXT column with strftime
            cursor.execute(f"""
                SELECT 
                    strftime('{bucket_format}', ingested_at) as bucket,
                    COUNT(*) as count
                FROM events
                WHERE ingested_at > ?
                GROUP BY bucket
                ORDER BY bucket
            """, (cutoff,))
            
            raw_timeline = {}
            for row in cursor.fetchall():
                if row[0]:
                    raw_timeline[row[0]] = row[1]
            
            # For 15-minute or larger buckets, aggregate the minute data
            timeline = {}
            if bucket_size == 15 and hours <= 24 and hours > 1:
                # Aggregate to 15-minute buckets
                for timestamp_str, count in raw_timeline.items():
                    try:
                        dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:00')
                        # Round down to nearest 15-minute interval
                        minute = (dt.minute // 15) * 15
                        bucket_dt = dt.replace(minute=minute, second=0)
                        bucket_key = bucket_dt.strftime('%Y-%m-%d %H:%M:00')
                        timeline[bucket_key] = timeline.get(bucket_key, 0) + count
                    except ValueError:
                        timeline[timestamp_str] = count
            elif bucket_size >= 240:
                # Aggregate to 4-hour buckets
                for timestamp_str, count in raw_timeline.items():
                    try:
                        dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:00:00')
                        # Round down to nearest 4-hour interval
                        hour = (dt.hour // 4) * 4
                        bucket_dt = dt.replace(hour=hour, minute=0, second=0)
                        bucket_key = bucket_dt.strftime('%Y-%m-%d %H:00:00')
                        timeline[bucket_key] = timeline.get(bucket_key, 0) + count
                    except ValueError:
                        timeline[timestamp_str] = count
            else:
                timeline = raw_timeline
            
            # Counts by source
            cursor.execute("""
                SELECT source, COUNT(*) as count
                FROM events
                WHERE ingested_at > ?
                GROUP BY source
            """, (cutoff,))
            
            by_source = {}
            for row in cursor.fetchall():
                by_source[row[0]] = row[1]
            
            logger.debug(f"Events summary: hours={hours}, bucket_size={bucket_size}min, data_points={len(timeline)}")
            
            return {
                'timeline': timeline,
                'by_source': by_source,
                'bucket_size': bucket_size
            }
    
    def cleanup_old_events(self, max_events: int):
        """
        Remove old events if we exceed max_events limit.
        
        Args:
            max_events: Maximum number of events to keep
        """
        if max_events <= 0:
            return
        
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("SELECT COUNT(*) FROM events")
                count = cursor.fetchone()[0]
                
                if count > max_events:
                    # Delete oldest events
                    delete_count = count - max_events
                    cursor.execute("""
                        DELETE FROM events 
                        WHERE id IN (
                            SELECT id FROM events 
                            ORDER BY id ASC 
                            LIMIT ?
                        )
                    """, (delete_count,))
                    conn.commit()
                    logger.info(f"Cleaned up {delete_count} old events")

    # ============================================
    # Feedback Methods for Ground Truth Labels
    # ============================================
    
    def get_alert(self, alert_id: int) -> Optional[Alert]:
        """
        Get a single alert by ID.
        
        Args:
            alert_id: Alert ID
            
        Returns:
            Alert object or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
            row = cursor.fetchone()
            
            if row:
                return self._row_to_alert(row)
            return None
    
    def store_feedback(
        self,
        alert_id: int,
        label: str,
        analyst_username: str = "system",
        notes: Optional[str] = None,
        snapshot_risk_score: Optional[float] = None,
        snapshot_confidence: Optional[float] = None
    ) -> int:
        """
        Store analyst feedback for an alert.
        
        Args:
            alert_id: Alert ID
            label: One of 'true_positive', 'false_positive', 'uncertain'
            analyst_username: Username of analyst providing feedback
            notes: Optional notes
            snapshot_risk_score: Risk score at time of labeling
            snapshot_confidence: Confidence at time of labeling
            
        Returns:
            Feedback ID
        """
        # Validate label
        valid_labels = ['true_positive', 'false_positive', 'uncertain']
        if label not in valid_labels:
            raise ValueError(f"Invalid label: {label}. Must be one of {valid_labels}")
        
        # Get alert to capture current scores if not provided
        alert = self.get_alert(alert_id)
        if not alert:
            raise ValueError(f"Alert {alert_id} not found")
        
        event_id = None  # Could link to specific event if needed
        if snapshot_risk_score is None:
            snapshot_risk_score = alert.risk_score
        if snapshot_confidence is None:
            snapshot_confidence = 0.8  # Default confidence
        
        # Training eligible: exclude 'uncertain' labels
        training_eligible = 1 if label != 'uncertain' else 0
        
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO ground_truth_labels 
                    (alert_id, event_id, label, analyst_username, notes, 
                     training_eligible, snapshot_risk_score, snapshot_confidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert_id, event_id, label, analyst_username, notes,
                    training_eligible, snapshot_risk_score, snapshot_confidence
                ))
                conn.commit()
                return cursor.lastrowid
    
    def get_feedback_for_alert(self, alert_id: int) -> List[dict]:
        """Get all feedback for an alert."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, alert_id, event_id, label, analyst_username, 
                       labeled_at, notes, training_eligible,
                       snapshot_risk_score, snapshot_confidence
                FROM ground_truth_labels
                WHERE alert_id = ?
                ORDER BY labeled_at DESC
            """, (alert_id,))
            
            rows = cursor.fetchall()
            return [
                {
                    "id": row[0],
                    "alert_id": row[1],
                    "event_id": row[2],
                    "label": row[3],
                    "analyst_username": row[4],
                    "labeled_at": row[5],
                    "notes": row[6],
                    "training_eligible": row[7],
                    "snapshot_risk_score": row[8],
                    "snapshot_confidence": row[9]
                }
                for row in rows
            ]
    
    def get_training_labels(self, limit: int = 1000) -> List[dict]:
        """
        Get training-eligible labels for ML training.
        
        Excludes 'uncertain' labels (training_eligible=0).
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT gtl.id, gtl.alert_id, gtl.event_id, gtl.label,
                       gtl.snapshot_risk_score, gtl.snapshot_confidence,
                       a.behavior, a.user, a.host, a.timestamp
                FROM ground_truth_labels gtl
                JOIN alerts a ON gtl.alert_id = a.id
                WHERE gtl.training_eligible = 1
                ORDER BY gtl.labeled_at DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            return [
                {
                    "id": row[0],
                    "alert_id": row[1],
                    "event_id": row[2],
                    "label": row[3],
                    "snapshot_risk_score": row[4],
                    "snapshot_confidence": row[5],
                    "behavior": row[6],
                    "user": row[7],
                    "host": row[8],
                    "timestamp": row[9]
                }
                for row in rows
            ]


    # ============================================
    # Baseline Stats Methods
    # ============================================
    
    def store_baseline(
        self,
        entity_id: str,
        entity_type: str,
        feature_name: str,
        feature_type: str,
        feature_value: str,
        window_start: datetime,
        window_end: datetime,
        sample_count: int = 0
    ) -> int:
        """
        Store or update a baseline stat for an entity.
        
        Uses UPSERT to replace existing baseline for same entity/feature/window.
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                now = datetime.utcnow().isoformat()
                
                cursor.execute("""
                    INSERT INTO baseline_stats 
                    (entity_id, entity_type, feature_name, feature_type, feature_value,
                     window_start, window_end, sample_count, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(entity_id, entity_type, feature_name, window_end) 
                    DO UPDATE SET
                        feature_value = excluded.feature_value,
                        sample_count = excluded.sample_count,
                        updated_at = excluded.updated_at
                """, (
                    entity_id.lower(), entity_type.lower(), feature_name, feature_type,
                    feature_value, window_start.isoformat(), window_end.isoformat(),
                    sample_count, now, now
                ))
                
                conn.commit()
                return cursor.lastrowid
    
    def get_baseline(
        self,
        entity_id: str,
        entity_type: str,
        feature_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get baseline stats for an entity.
        
        Returns most recent baseline for each feature.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if feature_name:
                cursor.execute("""
                    SELECT * FROM baseline_stats
                    WHERE entity_id = ? AND entity_type = ? AND feature_name = ?
                    ORDER BY window_end DESC
                    LIMIT 1
                """, (entity_id.lower(), entity_type.lower(), feature_name))
            else:
                # Get most recent baseline for each feature
                cursor.execute("""
                    SELECT bs.* FROM baseline_stats bs
                    INNER JOIN (
                        SELECT entity_id, entity_type, feature_name, MAX(window_end) as max_window
                        FROM baseline_stats
                        WHERE entity_id = ? AND entity_type = ?
                        GROUP BY entity_id, entity_type, feature_name
                    ) latest ON bs.entity_id = latest.entity_id 
                        AND bs.entity_type = latest.entity_type
                        AND bs.feature_name = latest.feature_name
                        AND bs.window_end = latest.max_window
                """, (entity_id.lower(), entity_type.lower()))
            
            rows = cursor.fetchall()
            return [
                {
                    "id": row["id"],
                    "entity_id": row["entity_id"],
                    "entity_type": row["entity_type"],
                    "feature_name": row["feature_name"],
                    "feature_type": row["feature_type"],
                    "feature_value": row["feature_value"],
                    "window_start": row["window_start"],
                    "window_end": row["window_end"],
                    "sample_count": row["sample_count"]
                }
                for row in rows
            ]
    
    def get_global_baseline(self, feature_name: str) -> Optional[Dict[str, Any]]:
        """Get global baseline (entity_id='__global__')."""
        baselines = self.get_baseline("__global__", "global", feature_name)
        return baselines[0] if baselines else None
    
    # ============================================
    # Session Features Methods
    # ============================================
    
    def store_session_features(
        self,
        session_id: str,
        entity_id: str,
        entity_type: str,
        window_start: datetime,
        window_end: datetime,
        features: Dict[str, Any],
        feature_version: str = "v1"
    ) -> int:
        """Store aggregated session features for an entity."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO session_features
                    (session_id, entity_id, entity_type, window_start, window_end, 
                     features, feature_version, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
                """, (
                    session_id, entity_id.lower(), entity_type.lower(),
                    window_start.isoformat(), window_end.isoformat(),
                    json.dumps(features), feature_version
                ))
                
                conn.commit()
                return cursor.lastrowid
    
    def get_session_features(
        self,
        entity_id: Optional[str] = None,
        entity_type: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Query session features with filtering."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            conditions = []
            params = []
            
            if entity_id:
                conditions.append("entity_id = ?")
                params.append(entity_id.lower())
            
            if entity_type:
                conditions.append("entity_type = ?")
                params.append(entity_type.lower())
            
            if since:
                conditions.append("window_end > ?")
                params.append(since.isoformat())
            
            where_clause = ""
            if conditions:
                where_clause = "WHERE " + " AND ".join(conditions)
            
            cursor.execute(f"""
                SELECT * FROM session_features
                {where_clause}
                ORDER BY window_end DESC
                LIMIT ?
            """, params + [limit])
            
            rows = cursor.fetchall()
            return [
                {
                    "id": row["id"],
                    "session_id": row["session_id"],
                    "entity_id": row["entity_id"],
                    "entity_type": row["entity_type"],
                    "window_start": row["window_start"],
                    "window_end": row["window_end"],
                    "features": json.loads(row["features"]),
                    "feature_version": row["feature_version"]
                }
                for row in rows
            ]
    
    def get_session_count(self, entity_id: str, entity_type: str) -> int:
        """Get count of sessions for an entity (for cold-start detection)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) FROM session_features
                WHERE entity_id = ? AND entity_type = ?
            """, (entity_id.lower(), entity_type.lower()))
            return cursor.fetchone()[0]
    
    # ============================================
    # Models Table Methods
    # ============================================
    
    def store_model_metadata(
        self,
        model_type: str,
        model_path: str,
        trained_at: datetime,
        training_samples: int,
        entity_id: Optional[str] = None,
        entity_type: Optional[str] = None,
        feature_version: str = "v1",
        metrics: Optional[Dict[str, Any]] = None
    ) -> int:
        """Store model training metadata."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Mark any existing models of same type/entity as superseded
                cursor.execute("""
                    UPDATE models SET status = 'superseded'
                    WHERE model_type = ? AND entity_id IS ? AND entity_type IS ? AND status = 'active'
                """, (model_type, entity_id, entity_type))
                
                cursor.execute("""
                    INSERT INTO models
                    (model_type, entity_id, entity_type, model_path, feature_version,
                     trained_at, training_samples, metrics, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', datetime('now'))
                """, (
                    model_type,
                    entity_id.lower() if entity_id else None,
                    entity_type.lower() if entity_type else None,
                    model_path, feature_version,
                    trained_at.isoformat(), training_samples,
                    json.dumps(metrics) if metrics else None
                ))
                
                conn.commit()
                return cursor.lastrowid
    
    def get_active_model(
        self,
        model_type: str,
        entity_id: Optional[str] = None,
        entity_type: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Get the currently active model for a type/entity."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if entity_id:
                cursor.execute("""
                    SELECT * FROM models
                    WHERE model_type = ? AND entity_id = ? AND entity_type = ? AND status = 'active'
                    ORDER BY trained_at DESC
                    LIMIT 1
                """, (model_type, entity_id.lower(), entity_type.lower() if entity_type else None))
            else:
                cursor.execute("""
                    SELECT * FROM models
                    WHERE model_type = ? AND entity_id IS NULL AND status = 'active'
                    ORDER BY trained_at DESC
                    LIMIT 1
                """, (model_type,))
            
            row = cursor.fetchone()
            if row:
                return {
                    "id": row["id"],
                    "model_type": row["model_type"],
                    "entity_id": row["entity_id"],
                    "entity_type": row["entity_type"],
                    "model_path": row["model_path"],
                    "feature_version": row["feature_version"],
                    "trained_at": row["trained_at"],
                    "training_samples": row["training_samples"],
                    "metrics": json.loads(row["metrics"]) if row["metrics"] else None,
                    "status": row["status"]
                }
            return None
    
    # ============================================
    # Helper Methods for UEBA
    # ============================================
    
    def get_events_for_baseline(
        self,
        entity_id: str,
        entity_type: str,
        window_start: datetime,
        window_end: datetime,
        limit: int = 50000
    ) -> List[Dict[str, Any]]:
        """
        Get events for baseline computation.
        
        Returns lightweight event data needed for baseline calculations.
        Uses ingested_at for window filtering to ensure reliable SQLite datetime comparison.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if entity_type == "user":
                filter_col = "user"
            else:
                filter_col = "host"
            
            # Use ingested_at for window filtering (more reliable server-side timestamp)
            # but still return timestamp for event processing
            cursor.execute(f"""
                SELECT id, timestamp, ingested_at, event_id, category, process_name, 
                       dest_ip, dest_port, source_ip, target_filename, command_line
                FROM events
                WHERE {filter_col} = ? 
                  AND ingested_at >= ? AND ingested_at < ?
                ORDER BY ingested_at
                LIMIT ?
            """, (entity_id.lower(), window_start.isoformat(), window_end.isoformat(), limit))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_unique_entities(
        self,
        entity_type: str,
        since: datetime
    ) -> List[str]:
        """Get list of unique entities active since a given time."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Use ingested_at for window filtering (more reliable server-side timestamp)
            if entity_type == "user":
                cursor.execute("""
                    SELECT DISTINCT user FROM events
                    WHERE ingested_at >= ? AND user != 'unknown' AND user != ''
                """, (since.isoformat(),))
            else:
                cursor.execute("""
                    SELECT DISTINCT host FROM events
                    WHERE ingested_at >= ? AND host != 'unknown' AND host != ''
                """, (since.isoformat(),))
            
            return [row[0] for row in cursor.fetchall()]
    
    def get_first_seen(self, entity_id: str, entity_type: str) -> Optional[datetime]:
        """Get first event timestamp for an entity (for cold-start detection)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if entity_type == "user":
                cursor.execute("""
                    SELECT MIN(timestamp) FROM events WHERE user = ?
                """, (entity_id.lower(),))
            else:
                cursor.execute("""
                    SELECT MIN(timestamp) FROM events WHERE host = ?
                """, (entity_id.lower(),))
            
            row = cursor.fetchone()
            if row and row[0]:
                return datetime.fromisoformat(row[0])
            return None
    
    # ============================================
    # App Settings Methods (MVP: Baseline Window Control)
    # ============================================
    
    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get a setting value by key."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM app_settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row[0] if row else default
    
    def get_all_settings(self) -> Dict[str, Any]:
        """Get all settings as a dictionary."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT key, value, description FROM app_settings")
            return {
                row[0]: {
                    "value": row[1],
                    "description": row[2]
                }
                for row in cursor.fetchall()
            }
    
    def set_setting(self, key: str, value: str, description: Optional[str] = None) -> None:
        """Set or update a setting."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                if description:
                    cursor.execute("""
                        INSERT OR REPLACE INTO app_settings (key, value, description, updated_at)
                        VALUES (?, ?, ?, datetime('now'))
                    """, (key, value, description))
                else:
                    cursor.execute("""
                        INSERT OR REPLACE INTO app_settings (key, value, updated_at)
                        VALUES (?, ?, datetime('now'))
                    """, (key, value))
                conn.commit()
                logger.info(f"Updated setting: {key} = {value}")
    
    # ============================================
    # Alert Evidence Methods (MVP: Evidence Timeline)
    # ============================================
    
    def get_alert_evidence(
        self,
        alert_id: int,
        window_minutes: int = 5,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get related events for an alert (evidence timeline).
        
        Returns events ±window_minutes around alert timestamp for the same user or host.
        
        Args:
            alert_id: Alert ID
            window_minutes: Time window in minutes (default: 5)
            limit: Maximum number of events to return (default: 50)
            
        Returns:
            List of event dictionaries
        """
        alert = self.get_alert(alert_id)
        if not alert:
            return []
        
        window_delta = timedelta(minutes=window_minutes)
        window_start = alert.timestamp - window_delta
        window_end = alert.timestamp + window_delta
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM events
                WHERE (user = ? OR host = ?)
                  AND timestamp >= ? AND timestamp <= ?
                ORDER BY timestamp ASC
                LIMIT ?
            """, (
                alert.user,
                alert.host,
                window_start.isoformat(),
                window_end.isoformat(),
                limit
            ))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def get_alerts_filtered(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        user: Optional[str] = None,
        host: Optional[str] = None,
        limit: int = 20,
        offset: int = 0
    ) -> tuple[List[Alert], int]:
        """
        Get alerts with filtering for UI.
        
        Args:
            severity: Filter by risk_level (CRITICAL, HIGH, MEDIUM, LOW)
            status: Filter by status (open, closed, acknowledged)
            user: Filter by user
            host: Filter by host
            limit: Maximum number of alerts
            offset: Pagination offset
            
        Returns:
            Tuple of (alerts list, total count)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Build WHERE clause
            conditions = []
            params = []
            
            if severity:
                # Map severity to risk_score ranges
                severity_map = {
                    "CRITICAL": (80, 100),
                    "HIGH": (60, 79),
                    "MEDIUM": (40, 59),
                    "LOW": (0, 39)
                }
                if severity in severity_map:
                    min_score, max_score = severity_map[severity]
                    conditions.append("risk_score >= ? AND risk_score <= ?")
                    params.extend([min_score, max_score])
            
            if status:
                conditions.append("status = ?")
                params.append(status)
            
            if user:
                conditions.append("user = ?")
                params.append(user.lower())
            
            if host:
                conditions.append("host = ?")
                params.append(host.lower())
            
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            
            # Get total count
            cursor.execute(f"SELECT COUNT(*) FROM alerts WHERE {where_clause}", params)
            total_count = cursor.fetchone()[0]
            
            # Get paginated results
            cursor.execute(f"""
                SELECT * FROM alerts
                WHERE {where_clause}
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """, params + [limit, offset])
            
            alerts = [self._row_to_alert(row) for row in cursor.fetchall()]
            return alerts, total_count
    
    def update_alert_status(self, alert_id: int, status: str) -> bool:
        """
        Update alert status (for feedback: FALSE_POSITIVE, TRUE_POSITIVE, etc.).
        
        Args:
            alert_id: Alert ID
            status: New status (e.g., 'FALSE_POSITIVE', 'TRUE_POSITIVE', 'closed')
            
        Returns:
            True if updated, False if alert not found
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE alerts SET status = ? WHERE id = ?
                """, (status, alert_id))
                conn.commit()
                return cursor.rowcount > 0
    
    # ============================================
    # UEBA Storage Methods
    # ============================================
    
    def store_rule_hits(self, hits: list) -> List[int]:
        """
        Store multiple rule hits from UEBA scoring.
        
        Args:
            hits: List of RuleHit objects
            
        Returns:
            List of inserted IDs
        """
        if not hits:
            return []
        
        ids = []
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                for hit in hits:
                    cursor.execute("""
                        INSERT INTO rule_hits (
                            timestamp, event_id, event_uuid, user, host,
                            rule_id, base_score, final_event_score,
                            modifiers_applied, evidence_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        hit.timestamp.isoformat() if hasattr(hit.timestamp, 'isoformat') else str(hit.timestamp),
                        hit.event_id,
                        getattr(hit, 'event_uuid', None),
                        hit.user,
                        hit.host,
                        hit.rule_id,
                        hit.base_score,
                        hit.final_event_score,
                        json.dumps(hit.modifiers_applied) if hit.modifiers_applied else None,
                        json.dumps(hit.evidence_json) if hit.evidence_json else None
                    ))
                    ids.append(cursor.lastrowid)
                
                conn.commit()
        
        return ids
    
    def store_entity_risk(self, entity_type: str, entity_id: str, 
                          window: str, score: float, 
                          contributing_rules: List[str]) -> int:
        """
        Store or update entity risk score.
        
        Args:
            entity_type: 'user' or 'host'
            entity_id: Entity identifier
            window: '1h' or '24h'
            score: Risk score
            contributing_rules: List of rule IDs
            
        Returns:
            Row ID
        """
        from datetime import datetime
        
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Upsert
                cursor.execute("""
                    INSERT INTO entity_risk (
                        entity_type, entity_id, window, score,
                        contributing_rules, last_updated
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(entity_type, entity_id, window) DO UPDATE SET
                        score = excluded.score,
                        contributing_rules = excluded.contributing_rules,
                        last_updated = excluded.last_updated
                """, (
                    entity_type,
                    entity_id,
                    window,
                    score,
                    json.dumps(contributing_rules),
                    datetime.utcnow().isoformat()
                ))
                
                conn.commit()
                return cursor.lastrowid
    
    def get_entity_risk(self, entity_type: str, entity_id: str) -> Dict[str, Any]:
        """
        Get entity risk scores for all windows.
        
        Returns:
            Dict with 'score_1h', 'score_24h', 'contributing_rules'
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT window, score, contributing_rules, last_updated
                FROM entity_risk
                WHERE entity_type = ? AND entity_id = ?
            """, (entity_type, entity_id))
            
            result = {
                'entity_type': entity_type,
                'entity_id': entity_id,
                'score_1h': 0.0,
                'score_24h': 0.0,
                'contributing_rules': [],
                'last_updated': None
            }
            
            for row in cursor.fetchall():
                window = row['window']
                if window == '1h':
                    result['score_1h'] = row['score']
                elif window == '24h':
                    result['score_24h'] = row['score']
                
                if row['contributing_rules']:
                    try:
                        rules = json.loads(row['contributing_rules'])
                        result['contributing_rules'].extend(rules)
                    except:
                        pass
                
                if row['last_updated']:
                    result['last_updated'] = row['last_updated']
            
            # Deduplicate rules
            result['contributing_rules'] = list(set(result['contributing_rules']))
            
            return result
    
    def store_ueba_alert(self, alert) -> int:
        """
        Store a UEBA alert.
        
        Args:
            alert: UEBAAlert object
            
        Returns:
            Inserted alert ID
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO ueba_alerts (
                        created_at, entity_type, entity_id, score, severity,
                        title, summary, linked_rule_hits, evidence,
                        mitre_tactics, mitre_techniques, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert.created_at.isoformat() if hasattr(alert.created_at, 'isoformat') else str(alert.created_at),
                    alert.entity_type,
                    alert.entity_id,
                    alert.score,
                    alert.severity,
                    alert.title,
                    alert.summary,
                    json.dumps(alert.linked_rule_hits) if alert.linked_rule_hits else None,
                    json.dumps(alert.evidence) if alert.evidence else None,
                    json.dumps(alert.mitre_tactics) if alert.mitre_tactics else None,
                    json.dumps(alert.mitre_techniques) if alert.mitre_techniques else None,
                    alert.status
                ))
                
                conn.commit()
                return cursor.lastrowid
    
    def get_ueba_alerts(self, limit: int = 50, offset: int = 0,
                        severity: Optional[str] = None,
                        status: Optional[str] = None,
                        entity_type: Optional[str] = None,
                        entity_id: Optional[str] = None) -> Tuple[List[Dict], int]:
        """
        Get UEBA alerts with filtering.
        
        Returns:
            Tuple of (alerts list, total count)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            conditions = []
            params = []
            
            if severity:
                conditions.append("severity = ?")
                params.append(severity)
            
            if status:
                conditions.append("status = ?")
                params.append(status)
            
            if entity_type:
                conditions.append("entity_type = ?")
                params.append(entity_type)
            
            if entity_id:
                conditions.append("entity_id = ?")
                params.append(entity_id)
            
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            
            # Get total count
            cursor.execute(f"SELECT COUNT(*) FROM ueba_alerts WHERE {where_clause}", params)
            total_count = cursor.fetchone()[0]
            
            # Get paginated results
            cursor.execute(f"""
                SELECT * FROM ueba_alerts
                WHERE {where_clause}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """, params + [limit, offset])
            
            alerts = []
            for row in cursor.fetchall():
                alert_dict = dict(row)
                # Parse JSON fields
                for json_field in ['linked_rule_hits', 'evidence', 'mitre_tactics', 'mitre_techniques']:
                    if alert_dict.get(json_field):
                        try:
                            alert_dict[json_field] = json.loads(alert_dict[json_field])
                        except:
                            pass
                alerts.append(alert_dict)
            
            return alerts, total_count
    
    def get_rule_hits(self, limit: int = 100, 
                      user: Optional[str] = None,
                      host: Optional[str] = None,
                      rule_id: Optional[str] = None) -> List[Dict]:
        """
        Get rule hits with filtering.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            conditions = []
            params = []
            
            if user:
                conditions.append("user = ?")
                params.append(user)
            
            if host:
                conditions.append("host = ?")
                params.append(host)
            
            if rule_id:
                conditions.append("rule_id = ?")
                params.append(rule_id)
            
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            
            cursor.execute(f"""
                SELECT * FROM rule_hits
                WHERE {where_clause}
                ORDER BY timestamp DESC
                LIMIT ?
            """, params + [limit])
            
            hits = []
            for row in cursor.fetchall():
                hit_dict = dict(row)
                for json_field in ['modifiers_applied', 'evidence_json']:
                    if hit_dict.get(json_field):
                        try:
                            hit_dict[json_field] = json.loads(hit_dict[json_field])
                        except:
                            pass
                hits.append(hit_dict)
            
            return hits
    
    def get_top_risky_entities(self, entity_type: str, window: str = '1h', 
                                limit: int = 10) -> List[Dict]:
        """
        Get top risky entities by score.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT entity_type, entity_id, score, contributing_rules, last_updated
                FROM entity_risk
                WHERE entity_type = ? AND window = ?
                ORDER BY score DESC
                LIMIT ?
            """, (entity_type, window, limit))
            
            entities = []
            for row in cursor.fetchall():
                entity_dict = dict(row)
                if entity_dict.get('contributing_rules'):
                    try:
                        entity_dict['contributing_rules'] = json.loads(entity_dict['contributing_rules'])
                    except:
                        pass
                entities.append(entity_dict)
            
            return entities
    
    def ensure_ueba_tables(self) -> None:
        """
        Ensure UEBA tables exist in the database.
        This is called on startup to add tables to existing DBs.
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Rule Hits Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS rule_hits (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        event_id INTEGER,
                        event_uuid TEXT,
                        user TEXT NOT NULL,
                        host TEXT NOT NULL,
                        rule_id TEXT NOT NULL,
                        base_score INTEGER NOT NULL,
                        final_event_score INTEGER NOT NULL,
                        modifiers_applied TEXT,
                        evidence_json TEXT,
                        created_at TEXT NOT NULL DEFAULT (datetime('now'))
                    )
                """)
                
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_rule_hits_timestamp 
                    ON rule_hits(timestamp DESC)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_rule_hits_user 
                    ON rule_hits(user, timestamp DESC)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_rule_hits_host 
                    ON rule_hits(host, timestamp DESC)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_rule_hits_rule_id 
                    ON rule_hits(rule_id)
                """)
                
                # Entity Risk Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS entity_risk (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        entity_type TEXT NOT NULL,
                        entity_id TEXT NOT NULL,
                        window TEXT NOT NULL,
                        score REAL NOT NULL,
                        contributing_rules TEXT,
                        last_updated TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT (datetime('now')),
                        UNIQUE(entity_type, entity_id, window)
                    )
                """)
                
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_entity_risk_lookup 
                    ON entity_risk(entity_type, entity_id, window)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_entity_risk_score 
                    ON entity_risk(score DESC)
                """)
                
                # UEBA Alerts Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS ueba_alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_at TEXT NOT NULL,
                        entity_type TEXT NOT NULL,
                        entity_id TEXT NOT NULL,
                        score REAL NOT NULL,
                        severity TEXT NOT NULL,
                        title TEXT NOT NULL,
                        summary TEXT,
                        linked_rule_hits TEXT,
                        evidence TEXT,
                        mitre_tactics TEXT,
                        mitre_techniques TEXT,
                        status TEXT NOT NULL DEFAULT 'open'
                    )
                """)
                
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_ueba_alerts_created 
                    ON ueba_alerts(created_at DESC)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_ueba_alerts_entity 
                    ON ueba_alerts(entity_type, entity_id)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_ueba_alerts_severity 
                    ON ueba_alerts(severity)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_ueba_alerts_status 
                    ON ueba_alerts(status)
                """)
                
                conn.commit()
                logger.info("UEBA tables ensured (rule_hits, entity_risk, ueba_alerts)")


# Global storage instance
_storage: Optional[EventStorage] = None


def get_storage() -> EventStorage:
    """Get the global storage instance."""
    global _storage
    if _storage is None:
        _storage = EventStorage()
        # Ensure UEBA tables exist (for existing DBs)
        _storage.ensure_ueba_tables()
    return _storage


def set_storage(storage: EventStorage) -> None:
    """Set the global storage instance."""
    global _storage
    _storage = storage


def ensure_ueba_tables_exist():
    """
    Ensure UEBA tables exist in the database.
    Call this on server startup to add tables to existing DBs.
    """
    storage = get_storage()
    storage.ensure_ueba_tables()
    return True

