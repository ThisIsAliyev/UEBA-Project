"""
Debug Script for IsolationForest Anomaly Detection.

Loads the trained IsolationForest model, computes anomaly scores for recent events,
and displays them sorted by anomaly score for manual inspection.

Usage:
    python -m server.scripts.debug_isoforest_scores --days 3 --limit 20
"""

import argparse
import logging
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Tuple

import yaml

from server.storage import EventStorage
from server.models import NormalizedEvent
from server.risk.anomaly_detector import IsolationForestAnomalyDetector

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_config() -> dict:
    """Load risk_engine.yaml configuration."""
    config_path = Path(__file__).parent.parent / "config" / "risk_engine.yaml"
    
    if not config_path.exists():
        logger.warning(f"Config not found at {config_path}, using defaults")
        return {
            "anomaly_detection": {
                "model_path": "data/risk_models/isolation_forest.pkl",
                "enabled": True
            }
        }
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    logger.info(f"Loaded config from {config_path}")
    return config


def sample_recent_events(storage: EventStorage, days: int, limit: int) -> List[NormalizedEvent]:
    """
    Sample recent events from the database.
    
    Args:
        storage: EventStorage instance
        days: Number of days to look back
        limit: Maximum number of events to return
        
    Returns:
        List of NormalizedEvent objects
    """
    cutoff = datetime.utcnow() - timedelta(days=days)
    
    logger.info(f"Sampling up to {limit} events from the last {days} days (since {cutoff.isoformat()})")
    
    events, total = storage.get_events(
        limit=limit,
        offset=0,
        since_timestamp=cutoff
    )
    
    logger.info(f"Sampled {len(events)} events (total available: {total})")
    return events


def compute_anomaly_scores(
    events: List[NormalizedEvent],
    detector: IsolationForestAnomalyDetector
) -> List[Tuple[NormalizedEvent, float]]:
    """
    Compute anomaly scores for a list of events.
    
    Args:
        events: List of NormalizedEvent objects
        detector: IsolationForestAnomalyDetector instance
        
    Returns:
        List of (event, anomaly_score) tuples
    """
    logger.info(f"Computing anomaly scores for {len(events)} events...")
    
    results = []
    for i, event in enumerate(events):
        if i % 10 == 0 and i > 0:
            logger.info(f"Processed {i}/{len(events)} events...")
        
        try:
            anomaly_score = detector.detect(event)
            results.append((event, anomaly_score))
        except Exception as e:
            logger.warning(f"Failed to score event {event.id}: {e}")
            results.append((event, 0.0))
    
    logger.info(f"Computed {len(results)} anomaly scores")
    return results


def print_report(results: List[Tuple[NormalizedEvent, float]]) -> None:
    """
    Print a sorted report of events and their anomaly scores.
    
    Args:
        results: List of (event, anomaly_score) tuples
    """
    # Sort by anomaly score descending (most anomalous first)
    sorted_results = sorted(results, key=lambda x: x[1], reverse=True)
    
    print("\n" + "=" * 120)
    print("ANOMALY DETECTION REPORT - Sorted by Anomaly Score (Highest First)")
    print("=" * 120)
    print(f"{'Timestamp':<22} {'User':<15} {'Host':<15} {'Source IP':<15} {'Event ID':<10} {'Anomaly':<10} {'Message':<30}")
    print("-" * 120)
    
    for event, score in sorted_results:
        timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if isinstance(event.timestamp, datetime) else str(event.timestamp)[:19]
        user = (event.user[:14] + "…") if len(event.user) > 15 else event.user
        host = (event.host[:14] + "…") if len(event.host) > 15 else event.host
        source_ip = event.source_ip if event.source_ip else "N/A"
        source_ip = (source_ip[:14] + "…") if len(source_ip) > 15 else source_ip
        event_id = str(event.event_id)
        message = (event.message[:29] + "…") if len(event.message) > 30 else event.message
        
        print(f"{timestamp:<22} {user:<15} {host:<15} {source_ip:<15} {event_id:<10} {score:>8.2f}   {message:<30}")
    
    print("=" * 120)
    
    # Statistics
    scores = [score for _, score in sorted_results]
    if scores:
        avg_score = sum(scores) / len(scores)
        max_score = max(scores)
        min_score = min(scores)
        
        print(f"\nStatistics:")
        print(f"  Total events: {len(scores)}")
        print(f"  Average anomaly score: {avg_score:.2f}")
        print(f"  Max anomaly score: {max_score:.2f}")
        print(f"  Min anomaly score: {min_score:.2f}")
        print(f"  High anomaly (>70): {sum(1 for s in scores if s > 70)}")
        print(f"  Medium anomaly (40-70): {sum(1 for s in scores if 40 <= s <= 70)}")
        print(f"  Low anomaly (<40): {sum(1 for s in scores if s < 40)}")
        print()


def main():
    """Main debug pipeline."""
    parser = argparse.ArgumentParser(description="Debug IsolationForest anomaly detection scores")
    parser.add_argument(
        "--days",
        type=int,
        default=3,
        help="Number of days to look back (default: 3)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of events to sample (default: 20)"
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Path to events database (default: data/events.db)"
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config()
    anomaly_config = config.get("anomaly_detection", {})
    
    # Get model path
    model_path = anomaly_config.get("model_path", "data/risk_models/isolation_forest.pkl")
    
    # Resolve model path relative to project root
    if not Path(model_path).is_absolute():
        model_path = str(Path(__file__).parent.parent.parent / model_path)
    
    # Database path
    if args.db_path:
        db_path = args.db_path
    else:
        db_path = str(Path(__file__).parent.parent.parent / "data" / "events.db")
    
    logger.info("=" * 60)
    logger.info("IsolationForest Debug Configuration")
    logger.info("=" * 60)
    logger.info(f"Model path: {model_path}")
    logger.info(f"Database: {db_path}")
    logger.info(f"Days to look back: {args.days}")
    logger.info(f"Sample limit: {args.limit}")
    logger.info("=" * 60)
    
    # Check if model exists
    if not Path(model_path).exists():
        logger.error(f"Model not found at {model_path}")
        logger.error("Please train the model first using: python -m server.scripts.train_isolation_forest")
        sys.exit(1)
    
    # Initialize storage
    logger.info("Initializing storage...")
    storage = EventStorage(db_path=db_path)
    
    # Initialize anomaly detector
    logger.info("Loading anomaly detector...")
    detector_config = {
        "default_score": 0.0,
        "raw_min": -0.5,
        "raw_max": 0.5,
    }
    detector = IsolationForestAnomalyDetector(
        model_path=model_path,
        storage=storage,
        config=detector_config
    )
    
    # Sample recent events
    events = sample_recent_events(storage, args.days, args.limit)
    
    if not events:
        logger.warning("No events found in the specified time range")
        sys.exit(0)
    
    # Compute anomaly scores
    results = compute_anomaly_scores(events, detector)
    
    # Print report
    print_report(results)
    
    logger.info("Debug complete!")


if __name__ == "__main__":
    main()
