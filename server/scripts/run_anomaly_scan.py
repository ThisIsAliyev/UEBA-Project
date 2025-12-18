#!/usr/bin/env python3
"""
MVP P0: Anomaly Scan Script

Scans recent events for anomalies using baseline profiles and generates alerts.
Includes explainability: top 3 reasons why an event is anomalous.

Usage:
    python scripts/run_anomaly_scan.py --hours 1
    python scripts/run_anomaly_scan.py --hours 1 --threshold 0.7
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add server src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server.storage import EventStorage
from server.models import Alert, NormalizedEvent
from server.baseline.baseline_builder import BaselineBuilder

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def get_anomaly_reasons(
    event: NormalizedEvent,
    baseline: Optional[Dict[str, Any]],
    global_baseline: Optional[Dict[str, Any]],
    storage: EventStorage
) -> List[Dict[str, Any]]:
    """
    Generate explainability reasons for why an event is anomalous.
    
    Returns top 3 reasons (rare_process, unusual_hour, spike, etc.)
    """
    reasons = []
    
    # Use entity baseline or fallback to global
    effective_baseline = baseline or global_baseline or {}
    
    # Parse timestamp
    ts = event.timestamp
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts)
        except Exception:
            ts = datetime.utcnow()
    
    hour = ts.hour
    
    # Reason 1: Unusual hour
    hourly_hist = effective_baseline.get("hourly_histogram", [0] * 24)
    if isinstance(hourly_hist, str):
        hourly_hist = json.loads(hourly_hist)
    
    if len(hourly_hist) == 24:
        # Find typical hours (where activity > 10% of max)
        max_activity = max(hourly_hist) if hourly_hist else 1
        threshold = max(1, max_activity * 0.1)
        
        if hourly_hist[hour] < threshold:
            typical_hours = [i for i, v in enumerate(hourly_hist) if v >= threshold]
            if typical_hours:
                start_hour = min(typical_hours)
                end_hour = max(typical_hours)
                reasons.append({
                    "type": "unusual_hour",
                    "detail": f"Activity at {hour}:00 (baseline: {start_hour}:00-{end_hour}:00)",
                    "score": 30
                })
    
    # Reason 2: Rare process
    if event.process_name:
        common_processes = effective_baseline.get("common_processes", [])
        if isinstance(common_processes, str):
            common_processes = json.loads(common_processes)
        
        # common_processes is a list of [process_name, frequency] pairs or just process names
        process_names = []
        if common_processes:
            if isinstance(common_processes[0], list):
                process_names = [p[0].lower() for p in common_processes]
            else:
                process_names = [p.lower() for p in common_processes]
        
        if event.process_name.lower() not in process_names:
            reasons.append({
                "type": "rare_process",
                "detail": f"Process '{event.process_name}' not in baseline (seen {len(process_names)} common processes)",
                "score": 40
            })
    
    # Reason 3: Spike in activity (check recent events)
    try:
        cutoff = datetime.utcnow() - timedelta(hours=1)
        recent_count = storage.get_events(
            limit=1000,
            since_timestamp=cutoff,
            user=event.user
        )[0]
        
        daily_stats = effective_baseline.get("daily_stats", {})
        if isinstance(daily_stats, str):
            daily_stats = json.loads(daily_stats)
        
        median_events_per_hour = daily_stats.get("median_process_count", 10) / 24 if daily_stats else 10
        
        if len(recent_count) > median_events_per_hour * 3:
            reasons.append({
                "type": "spike",
                "detail": f"Event spike: {len(recent_count)} events in last hour (baseline median: {median_events_per_hour:.1f}/hour)",
                "score": 25
            })
    except Exception as e:
        logger.debug(f"Error computing spike reason: {e}")
    
    # Reason 4: Rare domain (if dest_ip is a domain)
    if event.dest_ip and "." in event.dest_ip:
        common_domains = effective_baseline.get("common_domains", [])
        if isinstance(common_domains, str):
            common_domains = json.loads(common_domains)
        
        domain_names = []
        if common_domains:
            if isinstance(common_domains[0], list):
                domain_names = [d[0].lower() for d in common_domains]
            else:
                domain_names = [d.lower() for d in common_domains]
        
        # Extract domain from dest_ip (simple heuristic)
        dest_lower = event.dest_ip.lower()
        if dest_lower not in domain_names and not dest_lower.startswith("192.168.") and not dest_lower.startswith("10."):
            reasons.append({
                "type": "rare_domain",
                "detail": f"Domain/IP '{event.dest_ip}' not in baseline top domains",
                "score": 20
            })
    
    # Sort by score and return top 3
    reasons.sort(key=lambda x: x["score"], reverse=True)
    return reasons[:3]


def compute_anomaly_score(
    event: NormalizedEvent,
    baseline: Optional[Dict[str, Any]],
    global_baseline: Optional[Dict[str, Any]]
) -> float:
    """
    Compute a simple anomaly score (0-1) based on baseline deviations.
    
    This is a simplified version. In production, use IsolationForest model.
    """
    score = 0.0
    effective_baseline = baseline or global_baseline or {}
    
    # Parse timestamp
    ts = event.timestamp
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts)
        except Exception:
            ts = datetime.utcnow()
    
    hour = ts.hour
    
    # Check 1: Unusual hour (weight: 0.3)
    hourly_hist = effective_baseline.get("hourly_histogram", [0] * 24)
    if isinstance(hourly_hist, str):
        hourly_hist = json.loads(hourly_hist)
    
    if len(hourly_hist) == 24:
        max_activity = max(hourly_hist) if hourly_hist else 1
        threshold = max(1, max_activity * 0.1)
        if hourly_hist[hour] < threshold:
            score += 0.3
    
    # Check 2: Rare process (weight: 0.4)
    if event.process_name:
        common_processes = effective_baseline.get("common_processes", [])
        if isinstance(common_processes, str):
            common_processes = json.loads(common_processes)
        
        process_names = []
        if common_processes:
            if isinstance(common_processes[0], list):
                process_names = [p[0].lower() for p in common_processes]
            else:
                process_names = [p.lower() for p in common_processes]
        
        if event.process_name.lower() not in process_names:
            score += 0.4
    
    # Check 3: Rare domain (weight: 0.3)
    if event.dest_ip and "." in event.dest_ip:
        common_domains = effective_baseline.get("common_domains", [])
        if isinstance(common_domains, str):
            common_domains = json.loads(common_domains)
        
        domain_names = []
        if common_domains:
            if isinstance(common_domains[0], list):
                domain_names = [d[0].lower() for d in common_domains]
            else:
                domain_names = [d.lower() for d in common_domains]
        
        dest_lower = event.dest_ip.lower()
        if dest_lower not in domain_names and not dest_lower.startswith("192.168.") and not dest_lower.startswith("10."):
            score += 0.3
    
    return min(1.0, score)


def main():
    parser = argparse.ArgumentParser(description="Run anomaly scan and generate alerts")
    parser.add_argument(
        "--hours",
        type=int,
        help="Scan window in hours (overrides settings if provided)"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        help="Anomaly score threshold (0-1, overrides settings if provided)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Don't create alerts, just print results"
    )
    
    args = parser.parse_args()
    
    # Initialize storage
    storage = EventStorage()
    builder = BaselineBuilder(storage)
    
    # Get settings
    if args.hours:
        scan_window_hours = args.hours
    else:
        scan_window_hours = int(storage.get_setting("scan_window_hours", "1"))
    
    if args.threshold:
        anomaly_threshold = args.threshold
    else:
        anomaly_threshold = float(storage.get_setting("anomaly_threshold", "0.7"))
    
    logger.info(f"Scanning events from last {scan_window_hours} hours")
    logger.info(f"Anomaly threshold: {anomaly_threshold}")
    
    # Calculate window
    window_end = datetime.utcnow()
    window_start = window_end - timedelta(hours=scan_window_hours)
    
    # Get events in window
    events, total = storage.get_events(
        limit=10000,
        since_timestamp=window_start
    )
    
    logger.info(f"Found {len(events)} events in window (total: {total})")
    
    # Get global baseline (for cold start)
    global_baseline = {}
    try:
        global_baseline_raw = storage.get_global_baseline("hourly_histogram")
        if global_baseline_raw:
            global_baseline = {
                "hourly_histogram": global_baseline_raw.get("feature_value"),
                "common_processes": storage.get_global_baseline("common_processes") or {},
                "common_domains": storage.get_global_baseline("common_domains") or {},
                "daily_stats": storage.get_global_baseline("daily_stats") or {}
            }
    except Exception as e:
        logger.warning(f"Could not load global baseline: {e}")
    
    # Scan events
    alerts_created = 0
    alerts_updated = 0
    
    for event in events:
        # Skip events without user
        if not event.user or event.user == "unknown":
            continue
        
        # Get entity baseline
        baseline = None
        try:
            baseline_raw = storage.get_baseline(event.user, "user", "hourly_histogram")
            if baseline_raw:
                baseline = {
                    "hourly_histogram": baseline_raw.get("feature_value"),
                    "common_processes": storage.get_baseline(event.user, "user", "common_processes") or {},
                    "common_domains": storage.get_baseline(event.user, "user", "common_domains") or {},
                    "daily_stats": storage.get_baseline(event.user, "user", "daily_stats") or {}
                }
        except Exception as e:
            logger.debug(f"Could not load baseline for {event.user}: {e}")
        
        # Compute anomaly score
        anomaly_score = compute_anomaly_score(event, baseline, global_baseline)
        
        if anomaly_score < anomaly_threshold:
            continue
        
        # Get reasons
        reasons = get_anomaly_reasons(event, baseline, global_baseline, storage)
        
        if not reasons:
            # Fallback reason
            reasons = [{
                "type": "anomaly",
                "detail": f"Anomaly score {anomaly_score:.2f} exceeds threshold {anomaly_threshold}",
                "score": 50
            }]
        
        # Determine risk level
        risk_score = int(anomaly_score * 100)
        if risk_score >= 80:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        # Create alert
        alert = Alert(
            timestamp=event.timestamp,
            behavior="ueba_anomaly",
            risk_score=risk_score,
            host=event.host,
            user=event.user,
            source_ip=event.source_ip,
            summary=f"Anomalous activity detected (score: {anomaly_score:.2f})",
            details=json.dumps({
                "anomaly_score": anomaly_score,
                "reasons": reasons,
                "event_id": event.id,
                "process_name": event.process_name,
                "dest_ip": event.dest_ip
            }),
            reasons=reasons,
            mitre_tactics=["TA0001"],  # Will be enriched by mapper
            mitre_techniques=["T1078"],  # Will be enriched by mapper
            evidence_event_ids=[event.id] if event.id else []
        )
        
        # Enrich with MITRE mapping
        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from server.mitre_mapper import enrich_alert
        alert = enrich_alert(alert)
        
        if args.dry_run:
            logger.info(
                f"DRY RUN: Would create alert for {event.user}@{event.host} "
                f"(score: {anomaly_score:.2f}, reasons: {len(reasons)})"
            )
            alerts_created += 1
        else:
            # Use deduplication-aware storage
            dedup_window = int(storage.get_setting("dedup_window_minutes", "60"))
            existing_id = storage.upsert_or_update_alert(alert, merge_window_minutes=dedup_window)
            
            if existing_id:
                alerts_updated += 1
            else:
                alerts_created += 1
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info(f"Scan complete!")
    logger.info(f"  Events scanned: {len(events)}")
    logger.info(f"  Alerts created: {alerts_created}")
    logger.info(f"  Alerts updated: {alerts_updated}")
    logger.info(f"  Threshold: {anomaly_threshold}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()

