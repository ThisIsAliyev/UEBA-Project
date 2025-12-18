"""
SIEM Export Module for UEBA Platform.
Exports events and alerts to Elasticsearch (direct or via Logstash).

Environment Variables (SECURITY - never hardcode credentials):
- ELK_URL: Elasticsearch URL (e.g., https://10.10.4.151:9200)
- ELK_USERNAME or ES_USERNAME: Elasticsearch username
- ES_PASSWORD: Elasticsearch password
- ELK_CA_CERT: Path to CA certificate file (for self-signed certs)
- ELK_TLS_VERIFY: Set to 'false' to disable TLS verification (dev only)
"""

import asyncio
import json
import httpx
import logging
import os
import ssl
from typing import Optional, List, Dict, Any, Set
from datetime import datetime, timedelta
from collections import defaultdict

from ..models import NormalizedEvent, Alert

logger = logging.getLogger(__name__)


# Deduplication cache for events (channel, record_id) -> last_export_time
_event_dedup_cache: Dict[str, datetime] = {}
_DEDUP_WINDOW_MINUTES = 10

# Rate limiting per host
_host_rate_limits: Dict[str, List[datetime]] = defaultdict(list)
_MAX_DOCS_PER_HOST_PER_MINUTE = 100


def _should_export_event(event: NormalizedEvent) -> bool:
    """
    Determine if event should be exported to SIEM.
    
    Flood prevention rules:
    1. Export ALL events (Sysmon + Event Viewer) - no score filtering
    2. Deduplicate by (channel, record_id) within 10 minutes
    3. Rate limit per host (max 100 docs/host/minute)
    """
    # Rule 1: Export all events (removed score filtering to include all Sysmon/Event Viewer events)
    # This allows full visibility of security events in Elasticsearch
    pass
    
    # Rule 2: Deduplication by (channel, record_id)
    channel = getattr(event, 'channel', None) or ''
    record_id = getattr(event, 'record_id', None)
    
    if channel and record_id:
        dedup_key = f"{channel}:{record_id}"
        now = datetime.utcnow()
        
        if dedup_key in _event_dedup_cache:
            last_export = _event_dedup_cache[dedup_key]
            if (now - last_export).total_seconds() < _DEDUP_WINDOW_MINUTES * 60:
                return False
        
        _event_dedup_cache[dedup_key] = now
        
        # Cleanup old entries periodically
        if len(_event_dedup_cache) > 10000:
            cutoff = now - timedelta(minutes=_DEDUP_WINDOW_MINUTES)
            _event_dedup_cache.clear()  # Simple cleanup
    
    # Rule 3: Rate limit per host
    host = getattr(event, 'host', 'unknown')
    now = datetime.utcnow()
    cutoff = now - timedelta(minutes=1)
    
    # Clean old entries
    _host_rate_limits[host] = [t for t in _host_rate_limits[host] if t > cutoff]
    
    if len(_host_rate_limits[host]) >= _MAX_DOCS_PER_HOST_PER_MINUTE:
        return False
    
    _host_rate_limits[host].append(now)
    return True


class SIEMExporter:
    """
    Exports events and alerts to SIEM (Elasticsearch).
    
    Supports both direct Elasticsearch connection and Logstash HTTP input.
    """
    
    def __init__(
        self,
        elasticsearch_url: str,
        enabled: bool = True,
        batch_size: int = 100,
        batch_interval_seconds: float = 5.0,
        timeout_seconds: float = 10.0,
        use_logstash: bool = False,
        logstash_url: Optional[str] = None,
        es_username: Optional[str] = None,
        es_password: Optional[str] = None,
        export_events: bool = False,
        export_alerts: bool = True,
        tls_verify: bool = True,
        ca_cert_path: Optional[str] = None,
        index_events: str = "ueba-events",
        index_alerts: str = "ueba-alerts"
    ):
        """
        Initialize SIEM exporter.
        
        Args:
            elasticsearch_url: Elasticsearch URL (e.g., "https://10.10.4.151:9200")
            enabled: Enable/disable export
            batch_size: Number of documents to batch before sending
            batch_interval_seconds: Max time to wait before sending batch
            timeout_seconds: HTTP request timeout
            use_logstash: If True, send to Logstash instead of Elasticsearch
            logstash_url: Logstash HTTP input URL (if use_logstash=True)
            es_username: Elasticsearch username (if auth required)
            es_password: Elasticsearch password (if auth required)
            export_events: Whether to export events (default: False, alerts only)
            export_alerts: Whether to export alerts (default: True)
            tls_verify: Verify TLS certificates (default: True)
            ca_cert_path: Path to CA certificate file for self-signed certs
            index_events: Index name for events (default: ueba-events)
            index_alerts: Index name for alerts (default: ueba-alerts)
        """
        # Get URL from ENV if not provided or use default
        self.elasticsearch_url = (
            os.getenv('ELK_URL') or elasticsearch_url or ''
        ).rstrip('/')
        
        self.enabled = enabled
        self.batch_size = batch_size
        self.batch_interval_seconds = batch_interval_seconds
        self.timeout_seconds = timeout_seconds
        self.use_logstash = use_logstash
        self.logstash_url = logstash_url.rstrip('/') if logstash_url else None
        
        # SECURITY: Get credentials from ENV (never hardcode)
        self.es_username = os.getenv('ELK_USERNAME') or os.getenv('ES_USERNAME') or es_username
        self.es_password = os.getenv('ES_PASSWORD') or es_password
        
        self.export_events = export_events
        self.export_alerts = export_alerts
        self.index_events = index_events
        self.index_alerts = index_alerts
        
        # TLS configuration
        # ENV override: ELK_TLS_VERIFY=false disables verification (dev only)
        env_tls_verify = os.getenv('ELK_TLS_VERIFY', '').lower()
        if env_tls_verify == 'false':
            self.tls_verify = False
        else:
            self.tls_verify = tls_verify
        
        # CA cert path from ENV or config
        self.ca_cert_path = os.getenv('ELK_CA_CERT') or ca_cert_path
        
        self._event_queue: List[Dict[str, Any]] = []
        self._alert_queue: List[Dict[str, Any]] = []
        self._client: Optional[httpx.AsyncClient] = None
        self._last_event_send = datetime.utcnow()
        self._last_alert_send = datetime.utcnow()
        self._running = False
        
        if enabled:
            target = self.logstash_url if use_logstash else self.elasticsearch_url
            logger.info(f"SIEM exporter initialized: {target}")
            logger.info(f"SIEM export settings: events={export_events}, alerts={export_alerts}")
            logger.info(f"SIEM TLS: verify={self.tls_verify}, ca_cert={self.ca_cert_path or 'none'}")
            logger.info(f"SIEM indices: events={index_events}, alerts={index_alerts}")
    
    async def start(self):
        """Start background batch sender."""
        if not self.enabled:
            return
        
        # Setup HTTP client with auth if needed
        auth = None
        if self.es_username and self.es_password:
            auth = (self.es_username, self.es_password)
            logger.info(f"SIEM authentication configured: username={self.es_username}")
        else:
            logger.warning(
                "⚠️ SIEM authentication not configured - Elasticsearch may reject requests. "
                "Set ELK_USERNAME/ES_USERNAME and ES_PASSWORD environment variables."
            )
        
        # Handle TLS verification
        # Priority: 1) CA cert path, 2) tls_verify setting, 3) default based on URL
        verify_ssl: Any = True
        if self.ca_cert_path and os.path.exists(self.ca_cert_path):
            # Use custom CA certificate for self-signed certs
            verify_ssl = self.ca_cert_path
            logger.info(f"SIEM TLS: Using CA certificate from {self.ca_cert_path}")
        elif not self.tls_verify:
            # Disable verification (dev mode only)
            verify_ssl = False
            logger.warning("⚠️ SIEM TLS verification DISABLED - use only in development!")
        elif "https://" in self.elasticsearch_url:
            verify_ssl = self.tls_verify
        
        self._client = httpx.AsyncClient(
            timeout=self.timeout_seconds,
            auth=auth,
            verify=verify_ssl,
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
        )
        self._running = True
        
        # Test connection before starting
        try:
            response = await self._client.get(f"{self.elasticsearch_url}/_cluster/health")
            response.raise_for_status()
            logger.info(f"SIEM connection test successful: {self.elasticsearch_url}")
        except httpx.ConnectError as e:
            logger.error(f"SIEM connection test failed: Cannot reach {self.elasticsearch_url}")
            logger.error(f"Error: {e}")
            logger.error("Check: 1) Elasticsearch is running, 2) URL is correct, 3) Network connectivity")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                logger.error("SIEM connection test failed: Authentication failed - check credentials")
                logger.error(f"Username: {self.es_username if self.es_username else 'NOT SET'}")
                logger.error(f"Password: {'SET' if self.es_password else 'NOT SET'}")
                logger.error("Set ES_USERNAME and ES_PASSWORD environment variables")
            elif e.response.status_code == 403:
                logger.error("SIEM connection test failed: Access forbidden - check user permissions")
            else:
                logger.error(f"SIEM connection test failed: HTTP {e.response.status_code}")
                try:
                    error_body = e.response.text[:500]
                    logger.error(f"Error details: {error_body}")
                except:
                    pass
        except Exception as e:
            logger.error(f"SIEM connection test failed: {type(e).__name__}: {e}")
            logger.warning("SIEM exporter will continue but may fail to export")
        
        asyncio.create_task(self._batch_sender_loop())
        logger.info("SIEM exporter started")
    
    async def stop(self):
        """Stop exporter and flush remaining data."""
        self._running = False
        if self._client:
            await self._flush_all()
            await self._client.aclose()
            logger.info("SIEM exporter stopped")
    
    def export_event(self, event: NormalizedEvent):
        """Queue an event for export with flood prevention (synchronous - queues only)."""
        if not self.enabled or not self.export_events:
            return
        
        if not self._running:
            logger.warning("SIEM exporter not running - event not queued")
            return
        
        # Apply flood prevention filters
        if not _should_export_event(event):
            logger.debug(f"Event filtered by flood prevention: host={getattr(event, 'host', 'unknown')}, event_id={getattr(event, 'event_id', 'unknown')}")
            return
        
        try:
            doc = self._event_to_doc(event)
            self._event_queue.append(doc)
            logger.debug(f"Event queued for SIEM export (queue size: {len(self._event_queue)})")
        except Exception as e:
            # Don't let SIEM export errors block event processing
            logger.warning(f"SIEM export_event error (non-blocking): {e}")
    
    def export_alert(self, alert):
        """Queue an alert for export (synchronous - queues only).
        
        Args:
            alert: Alert object or dict with alert data
        """
        if not self.enabled or not self.export_alerts:
            return
        
        if not self._running:
            logger.warning("SIEM exporter not running - alert not queued")
            return
        
        try:
            # Support both Alert objects and dicts
            if isinstance(alert, dict):
                doc = self._dict_to_alert_doc(alert)
            else:
                doc = self._alert_to_doc(alert)
            self._alert_queue.append(doc)
            logger.info(f"Alert queued for SIEM export (queue size: {len(self._alert_queue)})")
        except Exception as e:
            # Don't let SIEM export errors block alert processing
            logger.warning(f"SIEM export_alert error (non-blocking): {e}")
    
    def _event_to_doc(self, event: NormalizedEvent) -> Dict[str, Any]:
        """Convert NormalizedEvent to Elasticsearch document."""
        doc = {
            "@timestamp": event.timestamp.isoformat(),
            "event": {
                "kind": "event",
                "category": event.category.value if hasattr(event.category, 'value') else str(event.category),
                "type": ["security", "ueba"],
                "id": str(event.id) if event.id else None,
                "provider": event.provider,
                "code": event.event_id,
                "severity": event.level.value if hasattr(event.level, 'value') else str(event.level),
            },
            "host": {
                "name": event.host,
            },
            "user": {
                "name": event.user,
            },
            "ueba": {
                "source_type": event.source.value if hasattr(event.source, 'value') else str(event.source),
                "risk_score": event.risk_score if event.risk_score is not None else 0.0,
                "risk_level": event.risk_level if event.risk_level else "info",
                "rule_score": event.rule_score if event.rule_score is not None else 0.0,
                "anomaly_score": event.anomaly_score if event.anomaly_score is not None else 0.0,
                "context_score": event.context_score if event.context_score is not None else 0.0,
            },
            "message": event.message,
        }
        
        # Add optional fields only if they exist
        if event.source_ip:
            doc["source"] = {"ip": event.source_ip}
            if event.source_port:
                doc["source"]["port"] = event.source_port
        
        if event.dest_ip:
            doc["destination"] = {"ip": event.dest_ip}
            if event.dest_port:
                doc["destination"]["port"] = event.dest_port
        
        if event.process_name:
            doc["process"] = {
                "name": event.process_name,
                "pid": event.process_id,
                "command_line": event.command_line,
                "executable": event.image_path,
            }
            if event.parent_process_name:
                doc["process"]["parent"] = {
                    "name": event.parent_process_name,
                    "pid": event.parent_process_id,
                }
        
        if event.target_filename:
            doc["file"] = {"path": event.target_filename}
            if event.file_hash:
                doc["file"]["hash"] = {"sha256": event.file_hash}
        
        if event.raw_json:
            doc["raw_json"] = event.raw_json
        
        return doc
    
    def _alert_to_doc(self, alert: Alert) -> Dict[str, Any]:
        """Convert Alert to Elasticsearch document with MITRE ATT&CK mapping."""
        doc = {
            "@timestamp": alert.timestamp.isoformat(),
            "event": {
                "kind": "alert",
                "category": ["security", "ueba", "behavior"],
                "type": ["alert"],
                "id": str(alert.id) if alert.id else None,
            },
            "host": {
                "name": alert.host,
            },
            "user": {
                "name": alert.user,
            },
            "ueba": {
                "alert": {
                    "behavior": alert.behavior,
                    "risk_score": alert.risk_score,
                    "status": alert.status,
                    "summary": alert.summary,
                    "occurrence_count": alert.occurrence_count,
                },
            },
            "message": alert.summary,
        }
        
        if alert.source_ip:
            doc["source"] = {"ip": alert.source_ip}
        
        if alert.details:
            doc["ueba"]["alert"]["details"] = alert.details
        
        if alert.first_seen:
            doc["ueba"]["alert"]["first_seen"] = alert.first_seen.isoformat()
        
        if alert.last_seen:
            doc["ueba"]["alert"]["last_seen"] = alert.last_seen.isoformat()
        
        # Add rule-specific fields
        rule_specific = {}
        if alert.fail_count is not None:
            rule_specific["fail_count"] = alert.fail_count
        if alert.file_event_count is not None:
            rule_specific["file_event_count"] = alert.file_event_count
        if alert.archive_process_name:
            rule_specific["archive_process_name"] = alert.archive_process_name
        if alert.target_path:
            rule_specific["target_path"] = alert.target_path
        
        if rule_specific:
            doc["ueba"]["rule_specific"] = rule_specific
        
        # MITRE ATT&CK mapping (PROBLEM-3)
        mitre_tactics = getattr(alert, 'mitre_tactics', None)
        mitre_techniques = getattr(alert, 'mitre_techniques', None)
        reasons = getattr(alert, 'reasons', None)
        evidence_event_ids = getattr(alert, 'evidence_event_ids', None)
        
        if mitre_tactics or mitre_techniques:
            doc["threat"] = {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": mitre_tactics if mitre_tactics else [],
                    "name": []  # Could be enriched with tactic names
                },
                "technique": {
                    "id": mitre_techniques if mitre_techniques else [],
                    "name": []  # Could be enriched with technique names
                }
            }
            # Also store in ueba namespace for compatibility
            doc["ueba"]["mitre_tactics"] = mitre_tactics or []
            doc["ueba"]["mitre_techniques"] = mitre_techniques or []
        
        # Explainability: reasons array
        if reasons:
            doc["ueba"]["reasons"] = reasons
        
        # Evidence: linked event IDs
        if evidence_event_ids:
            doc["ueba"]["evidence_event_ids"] = evidence_event_ids
        
        return doc
    
    def _dict_to_alert_doc(self, alert_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a dict to Elasticsearch alert document (for testing/manual alerts)."""
        from datetime import datetime as dt
        
        timestamp = alert_dict.get('timestamp')
        if isinstance(timestamp, str):
            timestamp_str = timestamp
        elif hasattr(timestamp, 'isoformat'):
            timestamp_str = timestamp.isoformat()
        else:
            timestamp_str = dt.utcnow().isoformat()
        
        doc = {
            "@timestamp": timestamp_str,
            "event": {
                "kind": "alert",
                "category": ["security", "ueba", "behavior"],
                "type": ["alert"],
                "id": str(alert_dict.get('id', '')),
            },
            "host": {
                "name": alert_dict.get('host', 'unknown'),
            },
            "user": {
                "name": alert_dict.get('username', alert_dict.get('user', 'unknown')),
            },
            "ueba": {
                "alert": {
                    "behavior": alert_dict.get('behavior', 'unknown'),
                    "risk_score": alert_dict.get('risk_score', 0),
                    "status": alert_dict.get('status', 'new'),
                    "summary": alert_dict.get('summary', alert_dict.get('message', '')),
                    "occurrence_count": alert_dict.get('occurrence_count', 1),
                },
            },
            "message": alert_dict.get('message', alert_dict.get('summary', '')),
        }
        
        if alert_dict.get('source_ip'):
            doc["source"] = {"ip": alert_dict['source_ip']}
        
        return doc
    
    async def _flush_events(self):
        """Send queued events to Elasticsearch/Logstash."""
        if not self._event_queue or not self._client:
            return
        
        batch = self._event_queue[:self.batch_size]
        self._event_queue = self._event_queue[self.batch_size:]
        
        try:
            if self.use_logstash and self.logstash_url:
                # Send to Logstash HTTP input
                body = "\n".join([json.dumps(doc, default=str) for doc in batch])
                response = await self._client.post(
                    f"{self.logstash_url}/ueba-events",
                    content=body,
                    headers={"Content-Type": "application/x-ndjson"}
                )
            else:
                # Send directly to Elasticsearch using Bulk API
                bulk_body = []
                for doc in batch:
                    # Index action metadata - use configurable index name
                    index_name = f"{self.index_events}-{datetime.utcnow().strftime('%Y.%m.%d')}"
                    bulk_body.append(json.dumps({"index": {"_index": index_name}}))
                    bulk_body.append(json.dumps(doc, default=str))
                
                body = "\n".join(bulk_body) + "\n"
                response = await self._client.post(
                    f"{self.elasticsearch_url}/_bulk",
                    content=body,
                    headers={"Content-Type": "application/x-ndjson"}
                )
            
            response.raise_for_status()
            
            # Check bulk API response for errors
            if response.status_code == 200:
                result = response.json()
                if result.get("errors"):
                    errors = result.get("items", [])
                    error_count = sum(1 for item in errors if "index" in item and "error" in item["index"])
                    if error_count > 0:
                        logger.warning(f"SIEM export: {error_count} events failed in bulk operation")
                        # Log first error for debugging
                        for item in errors:
                            if "index" in item and "error" in item["index"]:
                                logger.warning(f"SIEM bulk error: {item['index'].get('error')}")
                                break
            
            logger.info(f"✅ Exported {len(batch)} events to SIEM")
            self._last_event_send = datetime.utcnow()
        except httpx.ConnectError as e:
            logger.error(f"SIEM connection error (cannot reach Elasticsearch): {e}")
            logger.error(f"Check: 1) Elasticsearch URL: {self.elasticsearch_url}")
            logger.error(f"      2) Network connectivity")
            logger.error(f"      3) Firewall rules")
            # Don't re-queue on connection errors (will just fill up queue)
        except httpx.HTTPStatusError as e:
            error_detail = ""
            try:
                error_detail = e.response.text[:500]  # First 500 chars
            except:
                pass
            logger.error(f"SIEM export HTTP error {e.response.status_code}: {error_detail}")
            if e.response.status_code == 401:
                logger.error("Authentication failed - check es_username and es_password in config")
                logger.error(f"Current username: {self.es_username if self.es_username else 'NOT SET'}")
                logger.error(f"Current password: {'SET' if self.es_password else 'NOT SET'}")
                # Don't re-queue on auth errors - they won't resolve without config change
            elif e.response.status_code == 403:
                logger.error("Access forbidden - check user permissions")
                # Don't re-queue on permission errors
            else:
                # Re-queue on other HTTP errors (might be temporary)
                self._event_queue.extend(batch)
        except httpx.ReadTimeout as e:
            logger.error(f"SIEM export timeout: {e}")
            # Re-queue on timeout
            self._event_queue.extend(batch)
        except Exception as e:
            logger.error(f"Failed to export events to SIEM: {type(e).__name__}: {e}")
            # Re-queue on other errors
            self._event_queue.extend(batch)
    
    async def _flush_alerts(self):
        """Send queued alerts to Elasticsearch/Logstash."""
        if not self._alert_queue or not self._client:
            return
        
        batch = self._alert_queue[:self.batch_size]
        self._alert_queue = self._alert_queue[self.batch_size:]
        
        try:
            if self.use_logstash and self.logstash_url:
                # Send to Logstash HTTP input
                body = "\n".join([json.dumps(doc, default=str) for doc in batch])
                response = await self._client.post(
                    f"{self.logstash_url}/ueba-alerts",
                    content=body,
                    headers={"Content-Type": "application/x-ndjson"}
                )
            else:
                # Send directly to Elasticsearch using Bulk API
                bulk_body = []
                for doc in batch:
                    # Use configurable index name for alerts
                    index_name = f"{self.index_alerts}-{datetime.utcnow().strftime('%Y.%m.%d')}"
                    bulk_body.append(json.dumps({"index": {"_index": index_name}}))
                    bulk_body.append(json.dumps(doc, default=str))
                
                body = "\n".join(bulk_body) + "\n"
                response = await self._client.post(
                    f"{self.elasticsearch_url}/_bulk",
                    content=body,
                    headers={"Content-Type": "application/x-ndjson"}
                )
            
            response.raise_for_status()
            
            # Check bulk API response for errors
            if response.status_code == 200:
                result = response.json()
                if result.get("errors"):
                    errors = result.get("items", [])
                    error_count = sum(1 for item in errors if "index" in item and "error" in item["index"])
                    if error_count > 0:
                        logger.warning(f"SIEM export: {error_count} alerts failed in bulk operation")
                        # Log first error for debugging
                        for item in errors:
                            if "index" in item and "error" in item["index"]:
                                logger.warning(f"SIEM bulk error: {item['index'].get('error')}")
                                break
            
            logger.info(f"✅ Exported {len(batch)} alerts to SIEM (index: {index_name})")
            self._last_alert_send = datetime.utcnow()
        except httpx.ConnectError as e:
            logger.error(f"SIEM connection error (cannot reach Elasticsearch): {e}")
            logger.error(f"Check: 1) Elasticsearch URL: {self.elasticsearch_url}")
            logger.error(f"      2) Network connectivity")
            logger.error(f"      3) Firewall rules")
            # Don't re-queue on connection errors (will just fill up queue)
        except httpx.HTTPStatusError as e:
            error_detail = ""
            try:
                error_detail = e.response.text[:500]  # First 500 chars
            except:
                pass
            logger.error(f"SIEM export HTTP error {e.response.status_code}: {error_detail}")
            if e.response.status_code == 401:
                logger.error("Authentication failed - check es_username and es_password in config")
                logger.error(f"Current username: {self.es_username if self.es_username else 'NOT SET'}")
                logger.error(f"Current password: {'SET' if self.es_password else 'NOT SET'}")
                # Don't re-queue on auth errors - they won't resolve without config change
            elif e.response.status_code == 403:
                logger.error("Access forbidden - check user permissions")
                # Don't re-queue on permission errors
            else:
                # Re-queue on other HTTP errors (might be temporary)
                self._alert_queue.extend(batch)
        except httpx.ReadTimeout as e:
            logger.error(f"SIEM export timeout: {e}")
            # Re-queue on timeout
            self._alert_queue.extend(batch)
        except Exception as e:
            logger.error(f"Failed to export alerts to SIEM: {type(e).__name__}: {e}")
            # Re-queue on other errors
            self._alert_queue.extend(batch)
    
    async def _batch_sender_loop(self):
        """Background loop to send batches periodically."""
        while self._running:
            await asyncio.sleep(self.batch_interval_seconds)
            
            now = datetime.utcnow()
            if (now - self._last_event_send).total_seconds() >= self.batch_interval_seconds:
                if self._event_queue:
                    await self._flush_events()
            
            if (now - self._last_alert_send).total_seconds() >= self.batch_interval_seconds:
                if self._alert_queue:
                    await self._flush_alerts()
    
    async def _flush_all(self):
        """Flush all queued data."""
        await self._flush_events()
        await self._flush_alerts()


# Global exporter instance
_siem_exporter: Optional[SIEMExporter] = None


def get_siem_exporter() -> Optional[SIEMExporter]:
    """Get global SIEM exporter instance."""
    return _siem_exporter


def create_siem_exporter(config_dict: dict) -> Optional[SIEMExporter]:
    """
    Create and initialize SIEM exporter from config dict.
    
    Config keys:
    - enabled: bool
    - elasticsearch_url: str (or use ELK_URL env var)
    - es_username: str (or use ELK_USERNAME/ES_USERNAME env var)
    - es_password: str (or use ES_PASSWORD env var)
    - tls_verify: bool (or use ELK_TLS_VERIFY env var)
    - ca_cert_path: str (or use ELK_CA_CERT env var)
    - index_events: str (default: ueba-events)
    - index_alerts: str (default: ueba-alerts)
    - export_events: bool (default: False)
    - export_alerts: bool (default: True)
    - batch_size: int
    - batch_interval_seconds: float
    - timeout_seconds: float
    - use_logstash: bool
    - logstash_url: str
    """
    if not config_dict or not config_dict.get('enabled', False):
        return None
    
    exporter = SIEMExporter(
        elasticsearch_url=config_dict.get('elasticsearch_url', 'http://localhost:9200'),
        enabled=config_dict.get('enabled', True),
        batch_size=config_dict.get('batch_size', 100),
        batch_interval_seconds=config_dict.get('batch_interval_seconds', 5.0),
        timeout_seconds=config_dict.get('timeout_seconds', 10.0),
        use_logstash=config_dict.get('use_logstash', False),
        logstash_url=config_dict.get('logstash_url'),
        es_username=config_dict.get('es_username'),
        es_password=config_dict.get('es_password'),
        export_events=config_dict.get('export_events', False),
        export_alerts=config_dict.get('export_alerts', True),
        tls_verify=config_dict.get('tls_verify', True),
        ca_cert_path=config_dict.get('ca_cert_path'),
        index_events=config_dict.get('index_events', 'ueba-events'),
        index_alerts=config_dict.get('index_alerts', 'ueba-alerts')
    )
    
    global _siem_exporter
    _siem_exporter = exporter
    return exporter
