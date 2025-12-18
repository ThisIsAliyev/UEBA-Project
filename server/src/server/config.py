"""
Configuration loader for UEBA Server.
Reads settings from YAML config file.
"""

import os
from pathlib import Path
from typing import Optional
import yaml
from dataclasses import dataclass


@dataclass
class DatabaseConfig:
    path: str
    max_events: int


@dataclass
class LoggingConfig:
    level: str
    file: Optional[str]


@dataclass
class WebUIConfig:
    events_per_page: int
    refresh_interval_ms: int


@dataclass
class TLSConfig:
    enabled: bool
    cert_path: str
    key_path: str


@dataclass
class SchedulerConfig:
    enabled: bool
    baseline_interval_minutes: int
    session_interval_minutes: int
    model_train_interval_hours: int
    baseline_lookback_days: int


@dataclass
class UEBAConfig:
    anomaly_alerts_enabled: bool
    anomaly_alert_threshold: int
    enrichment_enabled: bool
    enrichment_min_score: int
    enrichment_max_score: int


@dataclass
class SIEMConfig:
    enabled: bool
    elasticsearch_url: str
    use_logstash: bool = False
    logstash_url: Optional[str] = None
    batch_size: int = 100
    batch_interval_seconds: float = 5.0
    timeout_seconds: float = 10.0
    es_username: Optional[str] = None
    es_password: Optional[str] = None
    export_events: bool = False
    export_alerts: bool = True
    tls_verify: bool = True
    ca_cert_path: Optional[str] = None
    index_events: str = "ueba-events"
    index_alerts: str = "ueba-alerts"


@dataclass
class ServerConfig:
    ingest_port: int
    web_port: int
    database: DatabaseConfig
    logging: LoggingConfig
    web_ui: WebUIConfig
    tls: TLSConfig
    scheduler: SchedulerConfig
    ueba: UEBAConfig
    learning_mode: bool
    min_entity_age_days: int
    siem: Optional[SIEMConfig] = None
    
    # Project root directory
    root_dir: Path = None


def load_config(config_path: Optional[str] = None) -> ServerConfig:
    """
    Load configuration from YAML file.
    
    Args:
        config_path: Path to config file. If None, searches for config/server_config.yaml
                    relative to the project root.
    
    Returns:
        ServerConfig object with all settings.
    """
    # Determine project root (parent of src/)
    if config_path is None:
        # Try to find config relative to this file
        this_file = Path(__file__).resolve()
        project_root = this_file.parent.parent.parent
        config_path = project_root / "config" / "server_config.yaml"
    else:
        config_path = Path(config_path)
        project_root = config_path.parent.parent
    
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path, 'r') as f:
        raw_config = yaml.safe_load(f)
    
    # Build config objects
    db_config = DatabaseConfig(
        path=raw_config.get('database', {}).get('path', 'data/events.db'),
        max_events=raw_config.get('database', {}).get('max_events', 100000)
    )
    
    log_config = LoggingConfig(
        level=raw_config.get('logging', {}).get('level', 'INFO'),
        file=raw_config.get('logging', {}).get('file')
    )
    
    web_ui_config = WebUIConfig(
        events_per_page=raw_config.get('web_ui', {}).get('events_per_page', 100),
        refresh_interval_ms=raw_config.get('web_ui', {}).get('refresh_interval_ms', 2000)
    )
    
    # TLS config (optional, defaults to disabled)
    tls_config_raw = raw_config.get('tls', {})
    if not isinstance(tls_config_raw, dict):
        tls_config_raw = {}
    tls_config = TLSConfig(
        enabled=tls_config_raw.get('enabled', False),
        cert_path=tls_config_raw.get('cert_path', 'config/server.crt'),
        key_path=tls_config_raw.get('key_path', 'config/server.key')
    )
    
    # Scheduler config
    scheduler_config_raw = raw_config.get('scheduler', {})
    if not isinstance(scheduler_config_raw, dict):
        scheduler_config_raw = {}
    scheduler_config = SchedulerConfig(
        enabled=scheduler_config_raw.get('enabled', True),
        baseline_interval_minutes=scheduler_config_raw.get('baseline_interval_minutes', 360),
        session_interval_minutes=scheduler_config_raw.get('session_interval_minutes', 60),
        model_train_interval_hours=scheduler_config_raw.get('model_train_interval_hours', 24),
        baseline_lookback_days=scheduler_config_raw.get('baseline_lookback_days', 14)
    )
    
    # UEBA config
    ueba_config_raw = raw_config.get('ueba', {})
    if not isinstance(ueba_config_raw, dict):
        ueba_config_raw = {}
    ueba_config = UEBAConfig(
        anomaly_alerts_enabled=ueba_config_raw.get('anomaly_alerts_enabled', True),
        anomaly_alert_threshold=ueba_config_raw.get('anomaly_alert_threshold', 70),
        enrichment_enabled=ueba_config_raw.get('enrichment_enabled', True),
        enrichment_min_score=ueba_config_raw.get('enrichment_min_score', 40),
        enrichment_max_score=ueba_config_raw.get('enrichment_max_score', 75)
    )
    
    # SIEM config (optional)
    siem_config = None
    siem_raw = raw_config.get('siem', {})
    if siem_raw and isinstance(siem_raw, dict):
        # SECURITY: Read credentials from environment variables, not config file
        es_username = os.getenv('ES_USERNAME') or siem_raw.get('es_username')
        es_password = os.getenv('ES_PASSWORD') or siem_raw.get('es_password')
        
        # Warn if credentials are in config file (security risk)
        if siem_raw.get('es_password'):
            import logging
            logging.warning(
                "⚠️ SECURITY WARNING: Elasticsearch password found in config file. "
                "Use ES_PASSWORD environment variable instead."
            )
        
        siem_config = SIEMConfig(
            enabled=siem_raw.get('enabled', False),
            elasticsearch_url=siem_raw.get('elasticsearch_url', 'http://localhost:9200'),
            use_logstash=siem_raw.get('use_logstash', False),
            logstash_url=siem_raw.get('logstash_url'),
            batch_size=siem_raw.get('batch_size', 100),
            batch_interval_seconds=siem_raw.get('batch_interval_seconds', 5.0),
            timeout_seconds=siem_raw.get('timeout_seconds', 10.0),
            es_username=es_username,
            es_password=es_password,
            export_events=siem_raw.get('export_events', False),
            export_alerts=siem_raw.get('export_alerts', True),
            tls_verify=siem_raw.get('tls_verify', True),
            ca_cert_path=siem_raw.get('ca_cert_path'),
            index_events=siem_raw.get('index_events', 'ueba-events'),
            index_alerts=siem_raw.get('index_alerts', 'ueba-alerts')
        )
    
    return ServerConfig(
        ingest_port=raw_config.get('ingest_port', 9000),
        web_port=raw_config.get('web_port', 8080),
        database=db_config,
        logging=log_config,
        web_ui=web_ui_config,
        tls=tls_config,
        scheduler=scheduler_config,
        ueba=ueba_config,
        learning_mode=raw_config.get('learning_mode', False),
        min_entity_age_days=raw_config.get('min_entity_age_days', 3),
        siem=siem_config,
        root_dir=project_root
    )


# Global config instance (loaded lazily)
_config: Optional[ServerConfig] = None


def get_config() -> ServerConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def set_config(config: ServerConfig) -> None:
    """Set the global configuration instance."""
    global _config
    _config = config

