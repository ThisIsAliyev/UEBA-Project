#!/usr/bin/env python3
"""
MVP P0: Baseline Training Script

Trains per-user and per-host baseline profiles from events in the database.
Supports configurable window duration (for demo: shorter windows like 2-6 hours).

Usage:
    python scripts/train_baselines.py --hours 6
    python scripts/train_baselines.py --days 7
    python scripts/train_baselines.py --update --hours 24
"""

import argparse
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add server src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server.storage import EventStorage
from server.baseline.baseline_builder import BaselineBuilder

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Train UEBA baselines")
    parser.add_argument(
        "--hours",
        type=int,
        help="Training window in hours (overrides settings if provided)"
    )
    parser.add_argument(
        "--days",
        type=int,
        help="Training window in days (overrides settings if provided)"
    )
    parser.add_argument(
        "--min-events",
        type=int,
        default=50,
        help="Minimum events required for baseline (default: 50)"
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Incremental update mode (only last N hours)"
    )
    parser.add_argument(
        "--entity-type",
        choices=["user", "host", "both"],
        default="both",
        help="Entity type to train (default: both)"
    )
    
    args = parser.parse_args()
    
    # Initialize storage
    storage = EventStorage()
    
    # Get window from settings if not provided via CLI
    if args.hours:
        window_hours = args.hours
    elif args.days:
        window_hours = args.days * 24
    else:
        # Read from settings
        window_hours = int(storage.get_setting("baseline_window_hours", "6"))
        logger.info(f"Using baseline window from settings: {window_hours} hours")
    
    min_events = args.min_events or int(storage.get_setting("baseline_min_events", "50"))
    
    # Calculate window
    window_end = datetime.utcnow()
    window_start = window_end - timedelta(hours=window_hours)
    
    logger.info(f"Training baselines for window: {window_start.isoformat()} to {window_end.isoformat()}")
    logger.info(f"Window duration: {window_hours} hours")
    logger.info(f"Minimum events required: {min_events}")
    
    # Initialize baseline builder
    builder = BaselineBuilder(storage)
    
    # Get unique entities
    entity_types = []
    if args.entity_type in ("user", "both"):
        entity_types.append("user")
    if args.entity_type in ("host", "both"):
        entity_types.append("host")
    
    total_trained = 0
    total_skipped = 0
    
    for entity_type in entity_types:
        logger.info(f"\n=== Training {entity_type} baselines ===")
        
        entities = storage.get_unique_entities(entity_type, window_start)
        logger.info(f"Found {len(entities)} {entity_type}s with events in window")
        
        for entity_id in entities:
            # Check if entity has enough events
            events = storage.get_events_for_baseline(
                entity_id, entity_type, window_start, window_end, limit=min_events + 1
            )
            
            if len(events) < min_events:
                logger.debug(f"Skipping {entity_type}:{entity_id} (only {len(events)} events, need {min_events})")
                total_skipped += 1
                continue
            
            try:
                baselines = builder.update_baseline(
                    entity_id=entity_id,
                    entity_type=entity_type,
                    window_start=window_start,
                    window_end=window_end
                )
                
                if baselines:
                    logger.info(
                        f"✓ Trained {entity_type}:{entity_id} "
                        f"({len(events)} events, {len(baselines)} features)"
                    )
                    total_trained += 1
                else:
                    logger.warning(f"✗ Failed to train {entity_type}:{entity_id}")
                    total_skipped += 1
                    
            except Exception as e:
                logger.error(f"Error training {entity_type}:{entity_id}: {e}", exc_info=True)
                total_skipped += 1
    
    # Train global baseline (for cold start)
    logger.info("\n=== Training global baseline ===")
    try:
        global_baselines = builder.update_global_baseline(window_start, window_end)
        if global_baselines:
            logger.info(f"✓ Global baseline trained ({len(global_baselines)} features)")
        else:
            logger.warning("✗ Failed to train global baseline")
    except Exception as e:
        logger.error(f"Error training global baseline: {e}", exc_info=True)
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info(f"Training complete!")
    logger.info(f"  Trained: {total_trained} entities")
    logger.info(f"  Skipped: {total_skipped} entities (insufficient data)")
    logger.info(f"  Window: {window_hours} hours")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()

