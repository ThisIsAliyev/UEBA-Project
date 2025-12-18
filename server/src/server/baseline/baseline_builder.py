"""
UEBA Baseline Builder.

Computes and stores entity baselines for anomaly detection:
- Hourly activity histogram (0-23)
- Common process set (top-N processes)
- Common domain set (if available)
- Median/MAD for key counts (process_count, filecreate_count, unique_dest_ip_count)

Baselines are stored as JSON in the baseline_stats table.
"""

import json
import logging
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)


class BaselineBuilder:
    """
    Builds and manages entity baselines for UEBA anomaly detection.
    
    Computes statistical baselines from historical event data and
    persists them for use in real-time scoring.
    """
    
    # Top N processes/domains to track in baseline
    TOP_N = 50
    
    # Feature version for schema tracking
    FEATURE_VERSION = "v1"
    
    def __init__(self, storage):
        """
        Initialize baseline builder.
        
        Args:
            storage: EventStorage instance
        """
        self.storage = storage
    
    def update_baseline(
        self,
        entity_id: str,
        entity_type: str,
        window_start: datetime,
        window_end: datetime
    ) -> Dict[str, Any]:
        """
        Compute and store baselines for an entity.
        
        Args:
            entity_id: User or host identifier
            entity_type: "user" or "host"
            window_start: Start of lookback window
            window_end: End of lookback window
            
        Returns:
            Dict with computed baselines
        """
        # Get events for this entity in the window
        events = self.storage.get_events_for_baseline(
            entity_id, entity_type, window_start, window_end
        )
        
        if not events:
            logger.debug(f"No events for {entity_type}:{entity_id} in window")
            return {}
        
        logger.debug(
            f"Computing baseline for {entity_type}:{entity_id} "
            f"from {len(events)} events"
        )
        
        # Compute each baseline feature
        baselines = {}
        
        # 1. Hourly activity histogram
        hourly_hist = self._compute_hourly_histogram(events)
        self.storage.store_baseline(
            entity_id=entity_id,
            entity_type=entity_type,
            feature_name="hourly_histogram",
            feature_type="histogram",
            feature_value=json.dumps(hourly_hist),
            window_start=window_start,
            window_end=window_end,
            sample_count=len(events)
        )
        baselines["hourly_histogram"] = hourly_hist
        
        # 2. Common processes set
        process_set = self._compute_process_set(events)
        self.storage.store_baseline(
            entity_id=entity_id,
            entity_type=entity_type,
            feature_name="common_processes",
            feature_type="set",
            feature_value=json.dumps(process_set),
            window_start=window_start,
            window_end=window_end,
            sample_count=len(events)
        )
        baselines["common_processes"] = process_set
        
        # 3. Common domains set (from dest_ip or extracted from events)
        domain_set = self._compute_domain_set(events)
        self.storage.store_baseline(
            entity_id=entity_id,
            entity_type=entity_type,
            feature_name="common_domains",
            feature_type="set",
            feature_value=json.dumps(domain_set),
            window_start=window_start,
            window_end=window_end,
            sample_count=len(events)
        )
        baselines["common_domains"] = domain_set
        
        # 4. Daily counts (process_count, filecreate_count, unique_dest_ip_count)
        daily_stats = self._compute_daily_stats(events, window_start, window_end)
        self.storage.store_baseline(
            entity_id=entity_id,
            entity_type=entity_type,
            feature_name="daily_stats",
            feature_type="stats",
            feature_value=json.dumps(daily_stats),
            window_start=window_start,
            window_end=window_end,
            sample_count=len(events)
        )
        baselines["daily_stats"] = daily_stats
        
        logger.debug(f"Baseline computed for {entity_type}:{entity_id}")
        
        return baselines
    
    def update_global_baseline(
        self,
        window_start: datetime,
        window_end: datetime
    ) -> Dict[str, Any]:
        """
        Compute global baselines across all entities.
        
        Used for:
        - Rare process detection (process → host count)
        - Rare domain detection (domain → host count)
        - Cold-start fallback when entity-specific data is insufficient
        """
        # Get all users and hosts
        users = self.storage.get_unique_entities("user", window_start)
        hosts = self.storage.get_unique_entities("host", window_start)
        
        # Aggregate process counts across hosts
        process_host_counts = defaultdict(set)
        domain_host_counts = defaultdict(set)
        
        for host in hosts:
            events = self.storage.get_events_for_baseline(
                host, "host", window_start, window_end
            )
            
            for event in events:
                if event.get("process_name"):
                    process_host_counts[event["process_name"].lower()].add(host)
                if event.get("dest_ip"):
                    domain_host_counts[event["dest_ip"]].add(host)
        
        # Convert to counts
        process_rarity = {
            proc: len(hosts_set)
            for proc, hosts_set in process_host_counts.items()
        }
        domain_rarity = {
            domain: len(hosts_set)
            for domain, hosts_set in domain_host_counts.items()
        }
        
        # Store global baselines
        total_hosts = len(hosts)
        
        self.storage.store_baseline(
            entity_id="__global__",
            entity_type="global",
            feature_name="process_rarity",
            feature_type="rarity_map",
            feature_value=json.dumps(process_rarity),
            window_start=window_start,
            window_end=window_end,
            sample_count=total_hosts
        )
        
        self.storage.store_baseline(
            entity_id="__global__",
            entity_type="global",
            feature_name="domain_rarity",
            feature_type="rarity_map",
            feature_value=json.dumps(domain_rarity),
            window_start=window_start,
            window_end=window_end,
            sample_count=total_hosts
        )
        
        # Store global stats
        global_stats = {
            "total_hosts": total_hosts,
            "total_users": len(users),
            "unique_processes": len(process_rarity),
            "unique_domains": len(domain_rarity)
        }
        
        self.storage.store_baseline(
            entity_id="__global__",
            entity_type="global",
            feature_name="global_stats",
            feature_type="stats",
            feature_value=json.dumps(global_stats),
            window_start=window_start,
            window_end=window_end,
            sample_count=total_hosts
        )
        
        logger.info(
            f"Global baseline updated: {total_hosts} hosts, "
            f"{len(process_rarity)} processes, {len(domain_rarity)} domains"
        )
        
        return {
            "process_rarity": process_rarity,
            "domain_rarity": domain_rarity,
            "global_stats": global_stats
        }
    
    def get_baseline(
        self,
        entity_id: str,
        entity_type: str
    ) -> Dict[str, Any]:
        """
        Get all baselines for an entity.
        
        Returns parsed baseline values keyed by feature_name.
        """
        rows = self.storage.get_baseline(entity_id, entity_type)
        
        baselines = {}
        for row in rows:
            try:
                baselines[row["feature_name"]] = json.loads(row["feature_value"])
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON in baseline {row['feature_name']}")
                baselines[row["feature_name"]] = None
        
        return baselines
    
    def get_entity_maturity(self, entity_id: str, entity_type: str) -> Dict[str, Any]:
        """
        Get entity maturity info for cold-start handling.
        
        Returns:
            Dict with days_of_data, confidence_multiplier, is_mature
        """
        first_seen = self.storage.get_first_seen(entity_id, entity_type)
        
        if first_seen is None:
            return {
                "days_of_data": 0,
                "confidence_multiplier": 0.0,
                "is_mature": False
            }
        
        days = (datetime.utcnow() - first_seen).days
        
        # Confidence ramp-up schedule
        if days < 3:
            multiplier = 0.3
        elif days < 7:
            multiplier = 0.6
        elif days < 14:
            multiplier = 0.85
        else:
            multiplier = 1.0
        
        return {
            "days_of_data": days,
            "confidence_multiplier": multiplier,
            "is_mature": days >= 7,
            "first_seen": first_seen.isoformat()
        }
    
    def is_rare_process(self, process_name: str, threshold_pct: float = 0.05) -> bool:
        """
        Check if a process is rare globally.
        
        Args:
            process_name: Process name to check
            threshold_pct: Threshold as percentage of hosts (default 5%)
            
        Returns:
            True if process is rare (seen on < threshold_pct of hosts)
        """
        global_baseline = self.storage.get_global_baseline("process_rarity")
        
        if not global_baseline:
            return False
        
        try:
            process_rarity = json.loads(global_baseline["feature_value"])
            global_stats = self.storage.get_global_baseline("global_stats")
            
            if global_stats:
                stats = json.loads(global_stats["feature_value"])
                total_hosts = stats.get("total_hosts", 1)
            else:
                total_hosts = 1
            
            host_count = process_rarity.get(process_name.lower(), 0)
            pct = host_count / total_hosts if total_hosts > 0 else 0
            
            return pct < threshold_pct
            
        except (json.JSONDecodeError, KeyError):
            return False
    
    def is_new_process_for_entity(
        self,
        entity_id: str,
        entity_type: str,
        process_name: str
    ) -> bool:
        """Check if process is new for this entity (not in baseline)."""
        baselines = self.get_baseline(entity_id, entity_type)
        
        common_processes = baselines.get("common_processes", [])
        
        if not common_processes:
            return False  # No baseline = can't determine
        
        return process_name.lower() not in [p.lower() for p in common_processes]
    
    def is_offhours_activity(
        self,
        entity_id: str,
        entity_type: str,
        hour: int,
        threshold_pct: float = 0.02
    ) -> bool:
        """
        Check if activity at given hour is unusual for entity.
        
        Args:
            hour: Hour of day (0-23)
            threshold_pct: Activity below this % is considered off-hours
        """
        baselines = self.get_baseline(entity_id, entity_type)
        
        hourly_hist = baselines.get("hourly_histogram", {})
        
        if not hourly_hist:
            return False
        
        total = sum(hourly_hist.values())
        if total == 0:
            return False
        
        hour_count = hourly_hist.get(str(hour), 0)
        pct = hour_count / total
        
        return pct < threshold_pct
    
    # ============================================
    # Private computation methods
    # ============================================
    
    def _compute_hourly_histogram(self, events: List[Dict]) -> Dict[str, int]:
        """Compute hourly activity histogram (0-23)."""
        histogram = defaultdict(int)
        
        for event in events:
            try:
                ts = event.get("timestamp")
                if ts:
                    if isinstance(ts, str):
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    else:
                        dt = ts
                    histogram[str(dt.hour)] += 1
            except (ValueError, AttributeError):
                continue
        
        # Ensure all hours are present
        return {str(h): histogram.get(str(h), 0) for h in range(24)}
    
    def _compute_process_set(self, events: List[Dict]) -> List[str]:
        """Compute top-N common processes."""
        process_counts = Counter()
        
        for event in events:
            proc = event.get("process_name")
            if proc:
                process_counts[proc.lower()] += 1
        
        # Return top N
        return [proc for proc, _ in process_counts.most_common(self.TOP_N)]
    
    def _compute_domain_set(self, events: List[Dict]) -> List[str]:
        """Compute top-N common domains/IPs."""
        domain_counts = Counter()
        
        for event in events:
            # Use dest_ip as proxy for domain
            dest = event.get("dest_ip")
            if dest:
                domain_counts[dest] += 1
        
        return [domain for domain, _ in domain_counts.most_common(self.TOP_N)]
    
    def _compute_daily_stats(
        self,
        events: List[Dict],
        window_start: datetime,
        window_end: datetime
    ) -> Dict[str, Any]:
        """
        Compute daily statistics with median and MAD.
        
        Returns:
            Dict with median/mad for process_count, filecreate_count, unique_dest_ip_count
        """
        # Group events by day
        daily_process_counts = defaultdict(int)
        daily_filecreate_counts = defaultdict(int)
        daily_dest_ips = defaultdict(set)
        
        for event in events:
            try:
                ts = event.get("timestamp")
                if ts:
                    if isinstance(ts, str):
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    else:
                        dt = ts
                    day_key = dt.strftime("%Y-%m-%d")
                    
                    event_id = event.get("event_id")
                    
                    # Process Create (Sysmon Event ID 1)
                    if event_id == 1:
                        daily_process_counts[day_key] += 1
                    
                    # FileCreate (Sysmon Event ID 11)
                    if event_id == 11:
                        daily_filecreate_counts[day_key] += 1
                    
                    # Network Connect (Sysmon Event ID 3)
                    if event_id == 3 and event.get("dest_ip"):
                        daily_dest_ips[day_key].add(event["dest_ip"])
                        
            except (ValueError, AttributeError):
                continue
        
        # Compute median and MAD for each metric
        def compute_median_mad(values: List[float]) -> Tuple[float, float]:
            if not values:
                return (0.0, 0.0)
            med = statistics.median(values)
            mad = statistics.median([abs(v - med) for v in values]) if len(values) > 1 else 0.0
            return (med, mad)
        
        process_values = list(daily_process_counts.values()) or [0]
        filecreate_values = list(daily_filecreate_counts.values()) or [0]
        dest_ip_values = [len(ips) for ips in daily_dest_ips.values()] or [0]
        
        process_med, process_mad = compute_median_mad(process_values)
        filecreate_med, filecreate_mad = compute_median_mad(filecreate_values)
        dest_ip_med, dest_ip_mad = compute_median_mad(dest_ip_values)
        
        return {
            "process_count": {
                "median": process_med,
                "mad": process_mad,
                "days": len(daily_process_counts)
            },
            "filecreate_count": {
                "median": filecreate_med,
                "mad": filecreate_mad,
                "days": len(daily_filecreate_counts)
            },
            "unique_dest_ip_count": {
                "median": dest_ip_med,
                "mad": dest_ip_mad,
                "days": len(daily_dest_ips)
            }
        }


# Global baseline builder instance
_baseline_builder: Optional[BaselineBuilder] = None


def get_baseline_builder() -> BaselineBuilder:
    """Get or create global baseline builder instance."""
    global _baseline_builder
    
    if _baseline_builder is None:
        from ..storage import get_storage
        _baseline_builder = BaselineBuilder(get_storage())
    
    return _baseline_builder
