"""
UEBA Session Feature Aggregator.

Computes hourly session features for anomaly detection:
- process_count (Sysmon Event ID 1)
- unique_dest_ip_count (Sysmon Event ID 3)
- filecreate_count (Sysmon Event ID 11)
- rare_process_flag (based on global baseline)
- offhours_activity_flag (based on entity histogram)
- new_process_for_user_flag (process not in baseline)
- new_domain_for_host_flag (domain not in baseline)
- port_diversity (unique dest ports)
- failed_logon_count (Windows Event 4625)

Session features are stored in session_features table and used
for IsolationForest anomaly scoring.
"""

import hashlib
import json
import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

# Feature version for schema tracking
FEATURE_VERSION = "v1"


class SessionAggregator:
    """
    Aggregates session features for UEBA anomaly detection.
    
    Computes features for 1-hour windows per entity.
    """
    
    def __init__(self, storage):
        """
        Initialize session aggregator.
        
        Args:
            storage: EventStorage instance
        """
        self.storage = storage
        
        # Lazy-load baseline builder
        self._baseline_builder = None
    
    @property
    def baseline_builder(self):
        """Get baseline builder instance."""
        if self._baseline_builder is None:
            from .baseline_builder import BaselineBuilder
            self._baseline_builder = BaselineBuilder(self.storage)
        return self._baseline_builder
    
    def aggregate_session(
        self,
        entity_id: str,
        entity_type: str,
        window_start: datetime,
        window_end: datetime
    ) -> Optional[Dict[str, Any]]:
        """
        Aggregate features for a session window.
        
        Args:
            entity_id: User or host identifier
            entity_type: "user" or "host"
            window_start: Start of session window
            window_end: End of session window
            
        Returns:
            Dict with computed features, or None if no events
        """
        # Get events for this entity in the window
        events = self.storage.get_events_for_baseline(
            entity_id, entity_type, window_start, window_end
        )
        
        if not events:
            logger.debug(f"No events for {entity_type}:{entity_id} in session window")
            return None
        
        # Generate session ID
        session_id = self._generate_session_id(entity_id, entity_type, window_start)
        
        # Compute features
        features = self._compute_features(events, entity_id, entity_type, window_start)
        
        # Store session features
        self.storage.store_session_features(
            session_id=session_id,
            entity_id=entity_id,
            entity_type=entity_type,
            window_start=window_start,
            window_end=window_end,
            features=features,
            feature_version=FEATURE_VERSION
        )
        
        logger.debug(
            f"Session aggregated for {entity_type}:{entity_id}: "
            f"{len(events)} events, {len(features)} features"
        )
        
        return features
    
    def _generate_session_id(
        self,
        entity_id: str,
        entity_type: str,
        window_start: datetime
    ) -> str:
        """Generate unique session ID."""
        key = f"{entity_type}:{entity_id}:{window_start.isoformat()}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]
    
    def _compute_features(
        self,
        events: List[Dict],
        entity_id: str,
        entity_type: str,
        window_start: datetime
    ) -> Dict[str, Any]:
        """
        Compute all session features from events.
        
        Args:
            events: List of event dicts
            entity_id: Entity identifier
            entity_type: "user" or "host"
            window_start: Start of session window
            
        Returns:
            Dict with feature name -> value
        """
        features = {}
        
        # Count by event ID
        event_counts = Counter()
        processes = []
        dest_ips = set()
        dest_ports = set()
        source_ips = set()
        filenames = []
        command_lines = []
        
        for event in events:
            event_id = event.get("event_id")
            if event_id:
                event_counts[event_id] += 1
            
            # Collect processes (Event ID 1 = Process Create)
            if event.get("process_name"):
                processes.append(event["process_name"].lower())
            
            # Collect network info (Event ID 3 = Network Connect)
            if event.get("dest_ip"):
                dest_ips.add(event["dest_ip"])
            if event.get("dest_port"):
                dest_ports.add(event["dest_port"])
            if event.get("source_ip"):
                source_ips.add(event["source_ip"])
            
            # Collect file info (Event ID 11 = FileCreate)
            if event.get("target_filename"):
                filenames.append(event["target_filename"])
            
            # Collect command lines
            if event.get("command_line"):
                command_lines.append(event["command_line"])
        
        # ============================================
        # Core Count Features
        # ============================================
        
        # Process count (Sysmon Event ID 1)
        features["process_count"] = event_counts.get(1, 0)
        
        # Network connect count (Sysmon Event ID 3)
        features["network_connect_count"] = event_counts.get(3, 0)
        
        # FileCreate count (Sysmon Event ID 11)
        features["filecreate_count"] = event_counts.get(11, 0)
        
        # Registry events (Sysmon Event ID 12, 13, 14)
        features["registry_count"] = (
            event_counts.get(12, 0) + 
            event_counts.get(13, 0) + 
            event_counts.get(14, 0)
        )
        
        # Failed logon count (Windows Security Event 4625)
        features["failed_logon_count"] = event_counts.get(4625, 0)
        
        # Successful logon count (Windows Security Event 4624)
        features["successful_logon_count"] = event_counts.get(4624, 0)
        
        # ============================================
        # Diversity Features
        # ============================================
        
        # Unique destination IPs
        features["unique_dest_ip_count"] = len(dest_ips)
        
        # Port diversity
        features["port_diversity"] = len(dest_ports)
        
        # Unique source IPs
        features["unique_source_ip_count"] = len(source_ips)
        
        # Unique processes
        features["unique_process_count"] = len(set(processes))
        
        # ============================================
        # Baseline Comparison Features (Flags)
        # ============================================
        
        # Rare process flag
        rare_process_count = 0
        for proc in set(processes):
            if self.baseline_builder.is_rare_process(proc):
                rare_process_count += 1
        features["rare_process_count"] = rare_process_count
        features["rare_process_flag"] = 1 if rare_process_count > 0 else 0
        
        # New process for entity flag
        new_process_count = 0
        for proc in set(processes):
            if self.baseline_builder.is_new_process_for_entity(entity_id, entity_type, proc):
                new_process_count += 1
        features["new_process_count"] = new_process_count
        features["new_process_flag"] = 1 if new_process_count > 0 else 0
        
        # Off-hours activity flag
        hour = window_start.hour
        features["session_hour"] = hour
        features["offhours_flag"] = (
            1 if self.baseline_builder.is_offhours_activity(entity_id, entity_type, hour)
            else 0
        )
        
        # New domain/IP flag
        baselines = self.baseline_builder.get_baseline(entity_id, entity_type)
        common_domains = set(baselines.get("common_domains", []))
        new_domains = dest_ips - common_domains
        features["new_domain_count"] = len(new_domains)
        features["new_domain_flag"] = 1 if new_domains else 0
        
        # ============================================
        # Derived Features
        # ============================================
        
        # Total event count
        features["total_event_count"] = len(events)
        
        # Process chain depth indicator (rough heuristic)
        # Count processes that could be child processes
        features["process_diversity_ratio"] = (
            len(set(processes)) / len(processes) if processes else 0.0
        )
        
        # Suspicious path count (processes from non-standard paths)
        suspicious_paths = [
            "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
            "\\downloads\\", "\\public\\", "\\users\\public\\"
        ]
        suspicious_count = 0
        for cmd in command_lines:
            if cmd:
                cmd_lower = cmd.lower()
                if any(sp in cmd_lower for sp in suspicious_paths):
                    suspicious_count += 1
        features["suspicious_path_count"] = suspicious_count
        features["suspicious_path_flag"] = 1 if suspicious_count > 0 else 0
        
        return features
    
    def get_feature_vector(
        self,
        entity_id: str,
        entity_type: str,
        limit: int = 100
    ) -> List[List[float]]:
        """
        Get feature vectors for an entity's sessions.
        
        Used for IsolationForest training/inference.
        
        Returns:
            List of feature vectors (each vector is a list of floats)
        """
        sessions = self.storage.get_session_features(
            entity_id=entity_id,
            entity_type=entity_type,
            limit=limit
        )
        
        if not sessions:
            return []
        
        # Define feature order (must be consistent)
        feature_names = self.get_feature_names()
        
        vectors = []
        for session in sessions:
            features = session.get("features", {})
            vector = [float(features.get(name, 0)) for name in feature_names]
            vectors.append(vector)
        
        return vectors
    
    @staticmethod
    def get_feature_names() -> List[str]:
        """
        Get ordered list of feature names for vector conversion.
        
        Must be consistent for training and inference.
        """
        return [
            "process_count",
            "network_connect_count",
            "filecreate_count",
            "registry_count",
            "failed_logon_count",
            "successful_logon_count",
            "unique_dest_ip_count",
            "port_diversity",
            "unique_source_ip_count",
            "unique_process_count",
            "rare_process_count",
            "new_process_count",
            "new_domain_count",
            "suspicious_path_count",
            "total_event_count",
        ]


# Global session aggregator instance
_session_aggregator: Optional[SessionAggregator] = None


def get_session_aggregator() -> SessionAggregator:
    """Get or create global session aggregator instance."""
    global _session_aggregator
    
    if _session_aggregator is None:
        from ..storage import get_storage
        _session_aggregator = SessionAggregator(get_storage())
    
    return _session_aggregator
