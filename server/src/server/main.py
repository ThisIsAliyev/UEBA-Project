"""
UEBA Server Main Entry Point.

This module starts both the web server and the TCP ingest server.
It serves as the single entry point for the entire application.

Usage:
    python -m src.server.main

Or with uvicorn directly:
    uvicorn src.server.app:app --host 0.0.0.0 --port 8080
"""

import sys
import os
import logging
import argparse
from pathlib import Path

# Add project root to path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


def setup_logging(log_level: str = "INFO", log_file: str = None):
    """Configure logging for the application."""
    # Use enhanced logging module with JSON format support
    from .core.logging import setup_logging as setup_structured_logging
    
    # Check for JSON format via environment variable
    json_format = os.getenv("JSON_LOGS", "false").lower() == "true"
    
    setup_structured_logging(
        level=log_level,
        log_file=log_file,
        json_format=json_format
    )


def bootstrap_isolation_forest_model(config, storage, logger):
    """
    Bootstrap IsolationForest model if it doesn't exist.
    
    Creates a minimal model from existing events if:
    - Model file doesn't exist
    - At least 50 events are available for training
    """
    import asyncio
    
    model_path = config.root_dir / "data" / "risk_models" / "isolation_forest.pkl"
    
    if model_path.exists():
        logger.info(f"IsolationForest model already exists: {model_path}")
        return
    
    logger.info("IsolationForest model not found, attempting bootstrap training...")
    
    try:
        # Check if we have enough events
        event_count = storage.get_event_count()
        
        if event_count < 50:
            logger.warning(
                f"Insufficient events for model training: {event_count} (need >= 50). "
                f"Model will be trained automatically when enough data is collected."
            )
            # Create a placeholder/dummy model for now
            _create_dummy_isolation_forest_model(model_path, logger)
            return
        
        # Get recent events for training
        logger.info(f"Found {event_count} events, training IsolationForest model...")
        
        # Use synchronous training for startup
        _train_bootstrap_model(storage, model_path, logger)
        
    except Exception as e:
        logger.warning(f"Failed to bootstrap IsolationForest model: {e}")
        # Create dummy model as fallback
        _create_dummy_isolation_forest_model(model_path, logger)


def _create_dummy_isolation_forest_model(model_path, logger):
    """Create a minimal dummy IsolationForest model for startup."""
    try:
        from sklearn.ensemble import IsolationForest
        import joblib
        import numpy as np
        
        # Create model with random normal data
        np.random.seed(42)
        X_dummy = np.random.randn(100, 10)  # 100 samples, 10 features
        
        model = IsolationForest(
            n_estimators=50,
            contamination=0.05,
            random_state=42
        )
        model.fit(X_dummy)
        
        # Ensure directory exists
        model_path.parent.mkdir(parents=True, exist_ok=True)
        
        joblib.dump(model, model_path)
        logger.info(f"Created bootstrap IsolationForest model at {model_path}")
        
    except ImportError:
        logger.warning("scikit-learn not available, cannot create IsolationForest model")
    except Exception as e:
        logger.warning(f"Failed to create dummy IsolationForest model: {e}")


def _train_bootstrap_model(storage, model_path, logger):
    """Train IsolationForest model from existing events."""
    try:
        from sklearn.ensemble import IsolationForest
        import joblib
        import numpy as np
        
        # Get events for training
        events = storage.get_events(limit=5000)  # Use up to 5000 recent events
        
        if len(events) < 50:
            logger.warning(f"Not enough events for training: {len(events)}")
            _create_dummy_isolation_forest_model(model_path, logger)
            return
        
        # Extract features from events
        feature_vectors = []
        for event in events:
            features = _extract_event_features(event)
            feature_vectors.append(features)
        
        X = np.array(feature_vectors)
        logger.info(f"Training IsolationForest on {X.shape[0]} events, {X.shape[1]} features")
        
        # Train model
        model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
            n_jobs=-1
        )
        model.fit(X)
        
        # Save model
        model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, model_path)
        logger.info(f"IsolationForest model trained and saved to {model_path}")
        
    except ImportError:
        logger.warning("scikit-learn not available, cannot train IsolationForest model")
        _create_dummy_isolation_forest_model(model_path, logger)
    except Exception as e:
        logger.warning(f"Failed to train IsolationForest model: {e}")
        _create_dummy_isolation_forest_model(model_path, logger)


def _extract_event_features(event) -> list:
    """Extract numerical features from an event for IsolationForest."""
    features = []
    
    # Time-based features
    if hasattr(event, 'timestamp') and event.timestamp:
        try:
            from datetime import datetime
            if isinstance(event.timestamp, str):
                ts = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
            else:
                ts = event.timestamp
            features.append(ts.hour)  # Hour of day
            features.append(ts.weekday())  # Day of week
        except:
            features.extend([12, 3])  # Default: noon, Wednesday
    else:
        features.extend([12, 3])
    
    # Event ID (normalized)
    event_id = getattr(event, 'event_id', 0) or 0
    features.append(min(event_id / 100.0, 10.0))  # Normalize
    
    # Process features
    cmd_len = len(getattr(event, 'command_line', '') or '') 
    features.append(min(cmd_len / 1000.0, 10.0))  # Command line length
    
    process_name = getattr(event, 'process_name', '') or ''
    features.append(len(process_name) / 50.0)  # Process name length
    
    # Network features
    dest_port = getattr(event, 'dest_port', 0) or 0
    features.append(dest_port / 65535.0)  # Normalized port
    
    source_port = getattr(event, 'source_port', 0) or 0
    features.append(source_port / 65535.0)
    
    # Risk scores (if available)
    risk_score = getattr(event, 'risk_score', 0) or 0
    features.append(risk_score / 100.0)
    
    rule_score = getattr(event, 'rule_score', 0) or 0
    features.append(rule_score / 100.0)
    
    anomaly_score = getattr(event, 'anomaly_score', 0) or 0
    features.append(anomaly_score / 100.0)
    
    return features


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="UEBA Event Viewer Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Start with default settings (port 8080 for web, port 9000 for ingest)
    python -m src.server.main

    # Specify custom ports
    python -m src.server.main --web-port 8080 --ingest-port 9000

    # Use custom config file
    python -m src.server.main --config /path/to/config.yaml
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        default=None,
        help='Path to configuration file (default: config/server_config.yaml)'
    )
    parser.add_argument(
        '--web-port', '-w',
        type=int,
        default=None,
        help='Web server port (overrides config)'
    )
    parser.add_argument(
        '--ingest-port', '-i',
        type=int,
        default=None,
        help='Ingest server port (overrides config)'
    )
    parser.add_argument(
        '--host',
        type=str,
        default='0.0.0.0',
        help='Host to bind to (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--log-level',
        type=str,
        default=None,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Logging level (overrides config)'
    )
    
    args = parser.parse_args()
    
    # Load configuration
    from src.server.config import load_config, set_config
    
    try:
        config = load_config(args.config)
    except FileNotFoundError as e:
        print(f"Warning: {e}")
        print("Using default configuration...")
        from src.server.config import ServerConfig, DatabaseConfig, LoggingConfig, WebUIConfig
        config = ServerConfig(
            ingest_port=9000,
            web_port=8080,
            database=DatabaseConfig(path="data/events.db", max_events=100000),
            logging=LoggingConfig(level="INFO", file="logs/server.log"),
            web_ui=WebUIConfig(events_per_page=100, refresh_interval_ms=2000),
            root_dir=project_root
        )
    
    # Override config with command line arguments
    if args.web_port:
        config.web_port = args.web_port
    if args.ingest_port:
        config.ingest_port = args.ingest_port
    if args.log_level:
        config.logging.level = args.log_level
    
    set_config(config)
    
    # Setup logging
    setup_logging(config.logging.level, config.logging.file)
    
    logger = logging.getLogger(__name__)
    
    # Print banner
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██╗   ██╗███████╗██████╗  █████╗                           ║
║   ██║   ██║██╔════╝██╔══██╗██╔══██╗                          ║
║   ██║   ██║█████╗  ██████╔╝███████║                          ║
║   ██║   ██║██╔══╝  ██╔══██╗██╔══██║                          ║
║   ╚██████╔╝███████╗██████╔╝██║  ██║                          ║
║    ╚═════╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝                          ║
║                                                               ║
║   Event Viewer - Normalization & Enrichment Layer             ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    print(f"  📡 Ingest Server: {args.host}:{config.ingest_port}")
    print(f"  🌐 Web Dashboard: http://{args.host}:{config.web_port}/")
    print(f"  📁 Database: {config.root_dir / config.database.path}")
    print()
    print("  Press Ctrl+C to stop the server")
    print()
    
    logger.info(f"Starting UEBA Event Viewer Server")
    logger.info(f"Ingest port: {config.ingest_port}, Web port: {config.web_port}")
    
    # Create data directory
    db_path = config.root_dir / config.database.path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Create risk_models directory
    risk_models_dir = config.root_dir / "data" / "risk_models"
    risk_models_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Risk models directory: {risk_models_dir}")
    
    # Initialize storage and ensure UEBA tables exist
    from src.server.storage import get_storage, ensure_ueba_tables_exist
    storage = get_storage()
    ensure_ueba_tables_exist()
    logger.info("UEBA tables initialized")
    
    # Bootstrap IsolationForest model if not exists
    bootstrap_isolation_forest_model(config, storage, logger)
    
    # Start the server with uvicorn
    import uvicorn
    
    uvicorn.run(
        "src.server.app:app",
        host=args.host,
        port=config.web_port,
        log_level=config.logging.level.lower(),
        access_log=False
    )


if __name__ == "__main__":
    main()

