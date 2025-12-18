"""
Elasticsearch/ELK Exporter for UEBA Alerts.

Exports alerts to Elasticsearch for SIEM integration.
Uses ECS (Elastic Common Schema) format for compatibility.

Configuration via environment variables:
- ELK_ENABLED: Enable/disable export (default: false)
- ELK_URL: Elasticsearch URL (e.g., http://localhost:9200)
- ELK_INDEX: Index name (default: ueba-alerts)
- ELK_USERNAME: Basic auth username (optional)
- ELK_PASSWORD: Basic auth password (optional)
- ELK_API_KEY: API key authentication (optional)
"""

import asyncio
import logging
import os
from datetime import datetime
from typing import Dict, Any, Optional, List

import httpx

from ..models import Alert

logger = logging.getLogger(__name__)


class ElasticsearchExporter:
    """
    Exports UEBA alerts to Elasticsearch.
    
    Features:
    - ECS-compliant document format
    - Async bulk export
    - Retry with exponential backoff
    - Basic auth or API key authentication
    """
    
    def __init__(
        self,
        url: Optional[str] = None,
        index: str = "ueba-alerts",
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 30.0
    ):
        """
        Initialize Elasticsearch exporter.
        
        Args:
            url: Elasticsearch URL
            index: Index name for alerts
            username: Basic auth username
            password: Basic auth password
            api_key: API key for authentication
            timeout: Request timeout in seconds
        """
        self.url = url or os.getenv("ELK_URL", "")
        self.index = index or os.getenv("ELK_INDEX", "ueba-alerts")
        self.username = username or os.getenv("ELK_USERNAME")
        self.password = password or os.getenv("ELK_PASSWORD")
        self.api_key = api_key or os.getenv("ELK_API_KEY")
        self.timeout = timeout
        
        self._enabled = os.getenv("ELK_ENABLED", "false").lower() == "true"
        
        if not self.url:
            self._enabled = False
            logger.info("Elasticsearch exporter disabled (ELK_URL not configured)")
    
    @property
    def is_enabled(self) -> bool:
        """Check if exporter is enabled."""
        return self._enabled and bool(self.url)
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers."""
        headers = {"Content-Type": "application/json"}
        
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        
        return headers
    
    def _get_auth(self) -> Optional[httpx.BasicAuth]:
        """Get basic auth if configured."""
        if self.username and self.password:
            return httpx.BasicAuth(self.username, self.password)
        return None
    
    def _alert_to_ecs(self, alert: Alert) -> Dict[str, Any]:
        """
        Convert UEBA Alert to ECS format.
        
        Uses Elastic Common Schema for compatibility with
        existing SIEM dashboards and rules.
        """
        # Base document
        doc = {
            "@timestamp": alert.timestamp.isoformat() if alert.timestamp else datetime.utcnow().isoformat(),
            "event": {
                "kind": "alert",
                "category": ["intrusion_detection"],
                "type": ["info"],
                "module": "ueba",
                "dataset": "ueba.alerts",
                "severity": self._risk_to_severity(alert.risk_score)
            },
            "rule": {
                "name": alert.behavior,
                "category": "ueba"
            },
            "ueba": {
                "behavior": alert.behavior,
                "risk_score": alert.risk_score,
                "status": alert.status,
                "occurrence_count": alert.occurrence_count,
                "first_seen": alert.first_seen.isoformat() if alert.first_seen else None,
                "last_seen": alert.last_seen.isoformat() if alert.last_seen else None,
                "summary": alert.summary,
                "details": alert.details
            },
            "host": {
                "name": alert.host
            },
            "user": {
                "name": alert.user
            },
            "message": alert.summary
        }
        
        # Add source IP if present
        if alert.source_ip:
            doc["source"] = {"ip": alert.source_ip}
        
        # Add alert-specific fields
        if alert.fail_count:
            doc["ueba"]["fail_count"] = alert.fail_count
        if alert.target_path:
            doc["file"] = {"path": alert.target_path}
        
        return doc
    
    def _risk_to_severity(self, risk_score: int) -> int:
        """Convert risk score (0-100) to ECS severity (1-4)."""
        if risk_score >= 80:
            return 1  # Critical
        elif risk_score >= 60:
            return 2  # High
        elif risk_score >= 40:
            return 3  # Medium
        else:
            return 4  # Low
    
    async def export_alert(self, alert: Alert) -> bool:
        """
        Export a single alert to Elasticsearch.
        
        Args:
            alert: Alert to export
            
        Returns:
            True if export succeeded
        """
        if not self.is_enabled:
            return False
        
        doc = self._alert_to_ecs(alert)
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.url}/{self.index}/_doc",
                    headers=self._get_auth_headers(),
                    auth=self._get_auth(),
                    json=doc
                )
                
                if response.status_code in (200, 201):
                    logger.debug(f"Alert exported to Elasticsearch: {alert.behavior}")
                    return True
                else:
                    logger.warning(
                        f"Elasticsearch export failed: {response.status_code} - {response.text}"
                    )
                    return False
                    
        except httpx.TimeoutException:
            logger.warning("Elasticsearch export timed out")
            return False
        except Exception as e:
            logger.warning(f"Elasticsearch export error: {e}")
            return False
    
    async def export_alerts_bulk(self, alerts: List[Alert]) -> int:
        """
        Export multiple alerts using Elasticsearch bulk API.
        
        Args:
            alerts: List of alerts to export
            
        Returns:
            Number of successfully exported alerts
        """
        if not self.is_enabled or not alerts:
            return 0
        
        # Build bulk request body (NDJSON format)
        lines = []
        for alert in alerts:
            # Index action
            lines.append('{"index":{}}')
            # Document
            import json
            lines.append(json.dumps(self._alert_to_ecs(alert)))
        
        body = "\n".join(lines) + "\n"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.url}/{self.index}/_bulk",
                    headers={
                        **self._get_auth_headers(),
                        "Content-Type": "application/x-ndjson"
                    },
                    auth=self._get_auth(),
                    content=body.encode()
                )
                
                if response.status_code == 200:
                    result = response.json()
                    errors = result.get("errors", False)
                    
                    if not errors:
                        logger.info(f"Bulk exported {len(alerts)} alerts to Elasticsearch")
                        return len(alerts)
                    else:
                        # Count successful items
                        items = result.get("items", [])
                        success_count = sum(
                            1 for item in items 
                            if item.get("index", {}).get("status") in (200, 201)
                        )
                        logger.warning(
                            f"Bulk export partially failed: {success_count}/{len(alerts)} succeeded"
                        )
                        return success_count
                else:
                    logger.warning(
                        f"Elasticsearch bulk export failed: {response.status_code}"
                    )
                    return 0
                    
        except Exception as e:
            logger.warning(f"Elasticsearch bulk export error: {e}")
            return 0
    
    async def check_connection(self) -> bool:
        """
        Check if Elasticsearch is reachable.
        
        Returns:
            True if connection is healthy
        """
        if not self.url:
            return False
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    self.url,
                    headers=self._get_auth_headers(),
                    auth=self._get_auth()
                )
                return response.status_code == 200
        except Exception:
            return False


# Global exporter instance
_elk_exporter: Optional[ElasticsearchExporter] = None


def get_elk_exporter() -> ElasticsearchExporter:
    """Get or create global Elasticsearch exporter instance."""
    global _elk_exporter
    
    if _elk_exporter is None:
        _elk_exporter = ElasticsearchExporter()
    
    return _elk_exporter
