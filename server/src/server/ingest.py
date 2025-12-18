"""
TCP Ingest Server for UEBA System.

Listens for incoming Sysmon events from Windows agents,
normalizes them, and stores them in the database.
"""

import asyncio
import logging
import json
import ssl
from pathlib import Path
from typing import Optional, Callable, Awaitable, Dict, Any
from datetime import datetime

from pydantic import BaseModel, ValidationError, Field

from .normalizer import normalize_event
from .storage import get_storage, EventStorage
from .models import NormalizedEvent, Alert
from .config import get_config
from .behaviors import run_all_detectors
from .ueba import get_ueba_scorer, AlertManager

logger = logging.getLogger(__name__)

# Global UEBA components
_ueba_scorer = None
_ueba_alert_manager = None

# Maximum payload size per line (1MB)
MAX_LINE_SIZE = 1024 * 1024  # 1MB

# Maximum total buffer size per connection (10MB)
MAX_BUFFER_SIZE = 10 * 1024 * 1024  # 10MB


class EventEnvelope(BaseModel):
    """
    Pydantic model for validating event envelope format.
    
    Supports both new envelope format: {"source": "sysmon", "event": {...}}
    And legacy format: {"Id": 1, "TimeCreated": "...", ...}
    """
    source: Optional[str] = Field(default=None, description="Event source (sysmon, windows_event)")
    event: Optional[Dict[str, Any]] = Field(default=None, description="Event data in envelope format")
    
    # Legacy format fields (for backward compatibility)
    Id: Optional[int] = Field(default=None, alias="Id")
    TimeCreated: Optional[str] = Field(default=None)
    ProviderName: Optional[str] = Field(default=None)
    
    class Config:
        extra = "allow"  # Allow additional fields for legacy format


class IngestServer:
    """
    Async TCP server for ingesting raw Sysmon events.
    
    Listens on a configurable port and processes incoming
    newline-delimited JSON events from Windows agents.
    """
    
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 9000,
        storage: Optional[EventStorage] = None,
        on_event: Optional[Callable[[NormalizedEvent], Awaitable[None]]] = None,
        on_alert: Optional[Callable[[Alert], Awaitable[None]]] = None,
        ssl_context: Optional[ssl.SSLContext] = None
    ):
        """
        Initialize the ingest server.
        
        Args:
            host: Host to bind to
            port: Port to listen on
            storage: EventStorage instance (uses global if None)
            on_event: Optional async callback for each new event
            on_alert: Optional async callback for each new alert
            ssl_context: Optional SSL context for TLS encryption
        """
        self.host = host
        self.port = port
        self.storage = storage or get_storage()
        self.on_event = on_event
        self.on_alert = on_alert
        self.ssl_context = ssl_context
        
        self._server: Optional[asyncio.Server] = None
        self._running = False
        self._event_count = 0
        self._error_count = 0
        self._alert_count = 0
        self._connected_clients = 0
    
    async def start(self):
        """Start the TCP server (with TLS if SSL context is provided)."""
        self._server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
            ssl=self.ssl_context
        )
        
        self._running = True
        
        protocol = "TLS" if self.ssl_context else "TCP"
        addrs = ', '.join(str(sock.getsockname()) for sock in self._server.sockets)
        logger.info(f"Ingest server listening on {addrs} ({protocol})")
        
        async with self._server:
            await self._server.serve_forever()
    
    async def stop(self):
        """Stop the TCP server."""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("Ingest server stopped")
    
    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ):
        """
        Handle a connected client.
        
        Reads newline-delimited JSON and processes each event.
        
        First message must contain agent_token for authentication.
        """
        addr = writer.get_extra_info('peername')
        self._connected_clients += 1
        logger.info(f"Client connected from {addr} (total: {self._connected_clients})")
        
        # Authentication state
        agent_id: Optional[int] = None
        authenticated = False
        
        buffer = ""
        
        try:
            # First, read authentication message (with timeout)
            try:
                auth_data = await asyncio.wait_for(
                    reader.read(4096),  # 4KB should be enough for auth
                    timeout=10.0  # 10 second timeout for auth
                )
                if not auth_data:
                    logger.warning(f"Client {addr} disconnected before authentication")
                    return
                
                buffer += auth_data.decode('utf-8', errors='replace')
                
                # Look for newline-delimited auth message
                if '\n' in buffer:
                    auth_line, buffer = buffer.split('\n', 1)
                    auth_line = auth_line.strip()
                    
                    if auth_line:
                        try:
                            import json
                            auth_msg = json.loads(auth_line)
                            agent_token = auth_msg.get('agent_token')
                            
                            # Validate agent token and track agent_id for status updates
                            if agent_token:
                                from .admin import get_admin_storage
                                admin_storage = get_admin_storage()
                                agent_id = admin_storage.validate_agent_token(agent_token)
                                if agent_id:
                                    agent = admin_storage.get_connected_agent(agent_id)
                                    # Allow approved, online, and offline agents to authenticate
                                    # Offline agents should be able to reconnect and become online
                                    if agent and agent.status in ('approved', 'online', 'offline'):
                                        authenticated = True
                                        logger.info(
                                            f"Agent {agent_id} ({agent.hostname}) authenticated from {addr}, "
                                            f"status: {agent.status}"
                                        )
                                    else:
                                        status = agent.status if agent else 'unknown'
                                        logger.warning(
                                            f"Agent {agent_id} rejected - status: {status}. "
                                            f"Only approved/online/offline agents can send events."
                                        )
                                        writer.write(json.dumps({
                                            "error": "Agent not approved",
                                            "status": status
                                        }).encode() + b'\n')
                                        await writer.drain()
                                        return
                                else:
                                    logger.warning(f"Invalid agent token from {addr}")
                                    writer.write(b'{"error": "Invalid or expired token"}\n')
                                    await writer.drain()
                                    return
                            else:
                                # No token provided - reject connection
                                logger.warning(f"No agent token provided from {addr}")
                                writer.write(b'{"error": "No agent token provided"}\n')
                                await writer.drain()
                                return
                        except json.JSONDecodeError:
                            logger.warning(f"Invalid JSON in auth message from {addr}")
                            writer.write(b'{"error": "Invalid JSON"}\n')
                            await writer.drain()
                            return
                else:
                    logger.warning(f"Client {addr} did not send complete auth message")
                    return
                    
            except asyncio.TimeoutError:
                logger.warning(f"Client {addr} did not authenticate within timeout")
                return
            
            if not authenticated:
                logger.warning(f"Client {addr} failed authentication")
                return
            
            # Now process event stream
            while self._running:
                try:
                    # Check buffer size limit
                    if len(buffer) > MAX_BUFFER_SIZE:
                        logger.warning(f"Buffer size exceeded {MAX_BUFFER_SIZE} bytes for {addr}, closing connection")
                        error_msg = json.dumps({
                            "error": "Buffer size limit exceeded",
                            "message": f"Maximum buffer size is {MAX_BUFFER_SIZE} bytes"
                        }).encode() + b'\n'
                        try:
                            writer.write(error_msg)
                            await writer.drain()
                        except:
                            pass
                        break
                    
                    # Read data with timeout
                    data = await asyncio.wait_for(
                        reader.read(65536),  # 64KB chunks
                        timeout=300.0  # 5 minute timeout
                    )
                except asyncio.TimeoutError:
                    # Keep connection alive, just no data
                    continue
                
                if not data:
                    # Client disconnected
                    break
                
                # Decode and add to buffer
                try:
                    buffer += data.decode('utf-8', errors='replace')
                except Exception as e:
                    logger.warning(f"Decode error: {e}")
                    continue
                
                # Process complete lines
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    line = line.strip()
                    
                    if not line:
                        continue
                    
                    # Check line size limit
                    if len(line) > MAX_LINE_SIZE:
                        logger.warning(f"Line size exceeded {MAX_LINE_SIZE} bytes for {addr}, skipping")
                        error_msg = json.dumps({
                            "error": "Line size limit exceeded",
                            "message": f"Maximum line size is {MAX_LINE_SIZE} bytes"
                        }).encode() + b'\n'
                        try:
                            writer.write(error_msg)
                            await writer.drain()
                        except:
                            pass
                        continue
                    
                    await self._process_line(line, addr, agent_id)
        
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.exception(f"Error handling client {addr}: {e}")
        finally:
            self._connected_clients -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
            logger.info(f"Client disconnected from {addr} (total: {self._connected_clients})")
    
    async def _process_line(self, line: str, addr: tuple, agent_id: Optional[int] = None):
        """
        Process a single line (JSON event).
        
        Validates JSON structure with Pydantic, normalizes the event,
        stores it, runs behavior detection, and stores any generated alerts.
        
        Includes latency logging for performance monitoring.
        
        Args:
            line: Raw JSON string
            addr: Client address for logging
            agent_id: Authenticated agent ID (for tracking)
        """
        receive_time = datetime.now()
        try:
            # Validate JSON structure with Pydantic
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as e:
                self._error_count += 1
                logger.warning(f"Invalid JSON from {addr}: {e}")
                return
            
            # Validate with Pydantic model (allows both envelope and legacy formats)
            try:
                EventEnvelope(**parsed)
            except ValidationError as e:
                self._error_count += 1
                logger.warning(f"JSON validation failed from {addr}: {e}")
                return
            
            # Log raw envelope for debugging
            try:
                parsed_envelope = json.loads(line)
                envelope_source = parsed_envelope.get("source", "unknown")
                logger.debug(f"Received event from {addr}: envelope_source={envelope_source}")
            except:
                pass
            
            # Normalize the event
            event = normalize_event(line)
            
            if event is None:
                self._error_count += 1
                logger.warning(f"Failed to normalize event from {addr}")
                return
            
            # Log normalized source for debugging
            normalized_source = event.source.value if hasattr(event.source, 'value') else str(event.source)
            logger.debug(f"Normalized event: source={normalized_source}, event_id={event.event_id}, host={event.host}")
            
            # Run AI Risk Engine assessment
            try:
                from .risk import get_risk_engine
                risk_engine = get_risk_engine(storage=self.storage)
                risk_result = risk_engine.assess_risk(event)
                
                # Attach risk scores to event
                event.risk_score = risk_result.risk_score
                event.risk_level = risk_result.risk_level
                event.rule_score = risk_result.rule_score
                event.anomaly_score = risk_result.anomaly_score
                event.context_score = risk_result.context_score
            except Exception as e:
                logger.warning(f"Risk engine assessment failed: {e}")
                # Continue without risk scores if engine fails
            
            # Run UEBA Detection Rules scoring
            try:
                await self._process_ueba_scoring(event)
            except Exception as e:
                logger.warning(f"UEBA scoring failed: {e}")
            
            # Store event in database
            store_start = datetime.now()
            event_id = self.storage.store_event(event)
            event.id = event_id
            store_duration_ms = (datetime.now() - store_start).total_seconds() * 1000
            
            self._event_count += 1
            
            # Export event to SIEM (if configured)
            try:
                from .siem.export import get_siem_exporter
                exporter = get_siem_exporter()
                if exporter:
                    exporter.export_event(event)
            except Exception as e:
                logger.debug(f"SIEM event export error (non-blocking): {e}")
            
            # MVP P0: Real-time alert creation (if risk score exceeds threshold)
            try:
                if hasattr(event, 'risk_score') and event.risk_score is not None:
                    # Get alert threshold from settings (default: 80)
                    alert_threshold = int(self.storage.get_setting("realtime_alert_threshold", "80"))
                    
                    if event.risk_score >= alert_threshold:
                        # Rate limit: max 10 alerts per user per hour
                        from datetime import timedelta
                        cutoff = datetime.utcnow() - timedelta(hours=1)
                        recent_alerts, _ = self.storage.get_alerts(
                            limit=11,
                            since=cutoff,
                            user=event.user
                        )
                        
                        if len(recent_alerts) < 10:  # Allow up to 10
                            # Build reasons from risk result
                            reasons = []
                            if hasattr(event, 'rule_score') and event.rule_score and event.rule_score > 0:
                                reasons.append({
                                    "type": "rule_hit",
                                    "detail": f"Rule-based score: {event.rule_score:.1f}",
                                    "score": int(event.rule_score)
                                })
                            if hasattr(event, 'anomaly_score') and event.anomaly_score and event.anomaly_score > 0:
                                reasons.append({
                                    "type": "high_anomaly",
                                    "detail": f"Anomaly score: {event.anomaly_score:.1f}",
                                    "score": int(event.anomaly_score)
                                })
                            # Check risk_result for feature_score (not stored on event)
                            if hasattr(risk_result, 'feature_score') and risk_result.feature_score and risk_result.feature_score > 0:
                                reasons.append({
                                    "type": "suspicious_feature",
                                    "detail": f"Feature-based score: {risk_result.feature_score:.1f}",
                                    "score": int(risk_result.feature_score)
                                })
                            
                            if not reasons:
                                reasons = [{
                                    "type": "high_risk",
                                    "detail": f"Risk score {event.risk_score:.1f} exceeds threshold {alert_threshold}",
                                    "score": int(event.risk_score)
                                }]
                            
                            # Determine risk level
                            risk_level_str = "CRITICAL" if event.risk_score >= 80 else "HIGH" if event.risk_score >= 60 else "MEDIUM" if event.risk_score >= 40 else "LOW"
                            
                            # Create alert
                            from .models import Alert
                            alert = Alert(
                                timestamp=event.timestamp,
                                behavior="realtime_risk_event",
                                risk_score=int(event.risk_score),
                                host=event.host,
                                user=event.user,
                                source_ip=event.source_ip,
                                summary=f"High-risk event detected (score: {event.risk_score:.1f})",
                                details=None,
                                reasons=reasons[:3],  # Top 3 reasons
                                evidence_event_ids=[event_id] if event_id else []
                            )
                            
                            # Enrich with MITRE mapping
                            from .mitre_mapper import enrich_alert
                            alert = enrich_alert(alert)
                            
                            # Store with deduplication
                            dedup_window = int(self.storage.get_setting("dedup_window_minutes", "60"))
                            self.storage.upsert_or_update_alert(alert, merge_window_minutes=dedup_window)
                            
                            logger.info(
                                f"Real-time alert created: user={event.user}, host={event.host}, "
                                f"risk_score={event.risk_score}, risk_level={risk_level_str}"
                            )
            except Exception as e:
                logger.warning(f"Real-time alert creation failed: {e}", exc_info=True)
                # Don't block event processing if alert creation fails
            
            # Log processing latency periodically
            if self._event_count % 50 == 0:
                total_latency_ms = (datetime.now() - receive_time).total_seconds() * 1000
                logger.debug(f"Event processing latency: total={total_latency_ms:.1f}ms, db_store={store_duration_ms:.1f}ms")
            
            # Update agent status based on event - use hostname as fallback if agent_id unknown
            # CRITICAL INVARIANT: If events are being ingested, agent MUST be trackable
            try:
                from .admin import get_admin_storage
                admin_storage = get_admin_storage()
                
                # Extract client IP from connection address for security validation
                client_ip = addr[0] if addr else None
                
                # Log every event processing for debugging (can be reduced to every 10th in production)
                if self._event_count % 10 == 0:
                    logger.info(
                        f"[INGEST] Event #{self._event_count}: host={event.host}, "
                        f"client_ip={client_ip}, agent_id={agent_id}"
                    )
                
                if agent_id:
                    # PRIMARY PATH: Token-based tracking (preferred)
                    # This path is used when agent authenticated successfully with valid token
                    admin_storage.increment_agent_events(agent_id, 1)
                    logger.debug(
                        f"[TOKEN] Agent {agent_id}: events +1, status→online, "
                        f"host={event.host}, client_ip={client_ip}"
                    )
                elif event.host:
                    # FALLBACK PATH: Update by hostname + IP from event (secure fallback)
                    # This path is used when:
                    # - Token validation failed (expired/invalid token)
                    # - agent_id is None but events are still arriving
                    # - Agent was authenticated initially but token expired during connection
                    # This ensures agent status updates even when token resolution fails
                    logger.info(
                        f"[FALLBACK] Attempting hostname-based update: "
                        f"host={event.host}, client_ip={client_ip}, agent_id=None"
                    )
                    updated = admin_storage.update_agent_by_hostname(event.host, client_ip, 1)
                    
                    if not updated:
                        logger.warning(
                            f"[FALLBACK FAILED] Could not update agent status: "
                            f"host={event.host}, client_ip={client_ip}. "
                            f"Possible reasons: agent not in connected_agents, "
                            f"agent is declined/revoked, or hostname mismatch. "
                            f"Events are being ingested but status tracking is broken!"
                        )
                else:
                    logger.warning(
                        f"[INGEST] No host in event, cannot update agent status. "
                        f"Event host field is missing or empty."
                    )
            except Exception as e:
                logger.error(
                    f"[CRITICAL] Failed to update agent status: {e}. "
                    f"Events are being ingested but status tracking may be broken!",
                    exc_info=True
                )
            
            # Run behavior detection
            try:
                alerts = run_all_detectors(event, db=self.storage, config=None)
                
                # Store and broadcast any alerts
                for alert in alerts:
                    try:
                        # Enrich medium-risk alerts with n8n (if configured)
                        alert = await self._enrich_alert_if_needed(alert, event)
                        
                        # Use upsert_or_update_alert for deduplication/aggregation
                        alert_id = self.storage.upsert_or_update_alert(alert)
                        alert.id = alert_id
                        self._alert_count += 1
                        
                        # Export to SIEM (if configured)
                        await self._export_alert_to_siem(alert)
                        
                        # Call alert callback if registered
                        if self.on_alert:
                            try:
                                await self.on_alert(alert)
                            except Exception as e:
                                logger.warning(f"Alert callback error: {e}")
                                
                    except Exception as e:
                        logger.warning(f"Failed to store alert: {e}")
                        
            except Exception as e:
                logger.warning(f"Behavior detection error: {e}")
            
            # Check for UEBA anomaly alert (in addition to behavior rules)
            try:
                ueba_alert = await self._check_ueba_anomaly_alert(event)
                if ueba_alert:
                    # Enrich medium-risk alerts with n8n
                    ueba_alert = await self._enrich_alert_if_needed(ueba_alert, event)
                    
                    alert_id = self.storage.upsert_or_update_alert(ueba_alert)
                    ueba_alert.id = alert_id
                    self._alert_count += 1
                    
                    # Export to SIEM (if configured)
                    await self._export_alert_to_siem(ueba_alert)
                    
                    if self.on_alert:
                        try:
                            await self.on_alert(ueba_alert)
                        except Exception as e:
                            logger.warning(f"Alert callback error: {e}")
            except Exception as e:
                logger.warning(f"UEBA anomaly check error: {e}")
            
            if self._event_count % 100 == 0:
                logger.info(
                    f"Processed {self._event_count} events, "
                    f"{self._alert_count} alerts, "
                    f"{self._error_count} errors"
                )
            
            # Call event callback if registered (for WebSocket broadcast)
            if self.on_event:
                try:
                    await self.on_event(event)
                except Exception as e:
                    logger.warning(f"Event callback error: {e}")
        
        except Exception as e:
            self._error_count += 1
            logger.exception(f"Error processing event: {e}")
    
    async def _enrich_alert_if_needed(self, alert: Alert, event: NormalizedEvent) -> Alert:
        """
        Enrich medium-risk alerts with n8n if configured.
        
        Only enriches alerts with risk_score between enrichment_min_score and enrichment_max_score.
        Updates alert.details with enrichment results.
        """
        try:
            from .config import get_config
            config = get_config()
            
            # Check if enrichment is enabled
            if not config.ueba.enrichment_enabled:
                return alert
            
            # Check if alert is in the enrichment score range
            min_score = config.ueba.enrichment_min_score
            max_score = config.ueba.enrichment_max_score
            
            if not (min_score <= alert.risk_score <= max_score):
                return alert
            
            # Try to enrich with n8n
            from .ai.n8n_client import get_n8n_client
            from .ai.models import EnrichmentRequest
            
            n8n_client = get_n8n_client()
            
            if not n8n_client.is_configured:
                return alert
            
            # Build enrichment request
            request = EnrichmentRequest(
                request_id=f"alert_{alert.id or 'new'}_{datetime.now().timestamp()}",
                file_hash=event.file_hash,
                ip_address=event.dest_ip or event.source_ip,
                domain=None,  # Would need DNS resolution
                url=None
            )
            
            # Check rate limit before calling
            if n8n_client.rate_limit_remaining <= 0:
                logger.debug("n8n rate limit reached, skipping enrichment")
                return alert
            
            # Enrich with timeout
            try:
                enrichment = await asyncio.wait_for(
                    n8n_client.enrich(request),
                    timeout=10.0  # 10 second timeout
                )
                
                if enrichment and not enrichment.error:
                    # Apply risk delta
                    if hasattr(enrichment, 'score') and enrichment.score:
                        risk_delta = enrichment.score - 50  # Center around 50
                        alert.risk_score = max(0, min(100, alert.risk_score + (risk_delta // 2)))
                    
                    # Store enrichment in details
                    import json
                    details = {}
                    if alert.details:
                        try:
                            details = json.loads(alert.details)
                        except json.JSONDecodeError:
                            details = {"original": alert.details}
                    
                    details["enrichment"] = {
                        "source": "n8n",
                        "label": enrichment.label.value if hasattr(enrichment.label, 'value') else str(enrichment.label),
                        "score": enrichment.score,
                        "reason": enrichment.reason,
                        "confidence": enrichment.confidence
                    }
                    
                    alert.details = json.dumps(details)
                    logger.debug(f"Alert enriched: risk_score={alert.risk_score}, label={enrichment.label}")
                    
            except asyncio.TimeoutError:
                logger.warning("n8n enrichment timed out")
            except Exception as e:
                logger.warning(f"n8n enrichment failed: {e}")
                
        except ImportError:
            pass  # n8n client not available
        except Exception as e:
            logger.warning(f"Alert enrichment error: {e}")
        
        return alert
    
    async def _export_alert_to_siem(self, alert: Alert) -> None:
        """
        Export alert to SIEM (Elasticsearch) if configured.
        
        Non-blocking - failures are logged but don't affect alert processing.
        """
        try:
            from .siem.export import get_siem_exporter
            
            exporter = get_siem_exporter()
            
            if not exporter:
                return
            
            # Export synchronously (SIEM exporter queues internally, flush is async)
            exporter.export_alert(alert)
                
        except ImportError:
            pass  # SIEM exporter not available
        except Exception as e:
            logger.warning(f"SIEM export error: {e}")
    
    async def _check_ueba_anomaly_alert(self, event: NormalizedEvent) -> Optional[Alert]:
        """
        Check if event should trigger a UEBA anomaly alert.
        
        Creates alert if:
        - anomaly_score is high (above threshold), OR
        - rule_score is high, OR
        - significant baseline deviation
        
        Respects learning_mode setting.
        """
        try:
            from .config import get_config
            config = get_config()
            
            # Check if UEBA anomaly alerts are enabled
            if not config.ueba.anomaly_alerts_enabled:
                return None
            
            # Check learning mode - suppress alerts during learning
            if config.learning_mode:
                logger.debug("Learning mode active, UEBA anomaly alerts suppressed")
                return None
            
            # Get risk scores from event
            anomaly_score = event.anomaly_score or 0
            rule_score = event.rule_score or 0
            risk_score = event.risk_score or 0
            
            threshold = config.ueba.anomaly_alert_threshold
            
            # Check if we should create an alert
            should_alert = False
            reasons = []
            
            if anomaly_score >= threshold:
                should_alert = True
                reasons.append(f"anomaly_score={anomaly_score:.1f}")
            
            if rule_score >= threshold:
                should_alert = True
                reasons.append(f"rule_score={rule_score:.1f}")
            
            if risk_score >= threshold and not should_alert:
                should_alert = True
                reasons.append(f"risk_score={risk_score:.1f}")
            
            if not should_alert:
                return None
            
            # Check entity maturity (cold-start handling)
            try:
                from .baseline.baseline_builder import get_baseline_builder
                builder = get_baseline_builder()
                
                user_maturity = builder.get_entity_maturity(event.user, "user")
                
                # Reduce confidence for immature entities
                if not user_maturity.get("is_mature", False):
                    # Only alert for very high scores on immature entities
                    if risk_score < 85:
                        logger.debug(
                            f"Suppressing UEBA alert for immature entity: "
                            f"user={event.user}, days={user_maturity.get('days_of_data', 0)}"
                        )
                        return None
            except Exception:
                pass  # Continue without maturity check
            
            # Create UEBA anomaly alert
            import json
            
            summary = f"UEBA Anomaly: {', '.join(reasons)} for {event.user}@{event.host}"
            if event.process_name:
                summary += f" ({event.process_name})"
            
            details = {
                "anomaly_score": anomaly_score,
                "rule_score": rule_score,
                "risk_score": risk_score,
                "risk_level": event.risk_level,
                "process_name": event.process_name,
                "command_line": event.command_line,
                "event_id": event.event_id,
                "category": str(event.category) if event.category else None
            }
            
            alert = Alert(
                timestamp=event.timestamp,
                behavior="ueba_anomaly",
                risk_score=int(risk_score),
                host=event.host,
                user=event.user,
                source_ip=event.source_ip,
                summary=summary[:500],
                details=json.dumps(details),
                status="open"
            )
            
            logger.info(
                f"UEBA anomaly alert: user={event.user}, host={event.host}, "
                f"risk={risk_score:.1f}, reasons={reasons}"
            )
            
            return alert
            
        except Exception as e:
            logger.warning(f"UEBA anomaly check error: {e}")
            return None

    async def _process_ueba_scoring(self, event: NormalizedEvent) -> None:
        """
        Process event through UEBA detection rules scoring pipeline.
        
        - Evaluates event against detection rules
        - Stores rule hits
        - Aggregates entity scores
        - Generates alerts when thresholds are crossed
        """
        global _ueba_scorer, _ueba_alert_manager
        
        try:
            # Initialize UEBA components lazily
            if _ueba_scorer is None:
                from pathlib import Path
                rules_path = Path(__file__).parent.parent.parent / "config" / "rules"
                _ueba_scorer = get_ueba_scorer(str(rules_path))
                logger.info(f"UEBA scorer initialized with rules from {rules_path}")
            
            if _ueba_alert_manager is None:
                _ueba_alert_manager = AlertManager(storage=self.storage)
                logger.info("UEBA alert manager initialized")
            
            # Score the event against detection rules
            event_score, user_score, host_score = _ueba_scorer.process_event(event)
            
            # If no rules matched, skip storage
            if not event_score.matched_rules:
                return
            
            # Log rule matches
            rule_ids = [m.rule.id for m in event_score.matched_rules]
            logger.info(
                f"UEBA rules matched: {rule_ids}, "
                f"event_score={event_score.final_score}, "
                f"user={event.user}, host={event.host}"
            )
            
            # Store rule hits
            rule_hits = _ueba_alert_manager.create_rule_hit(event, event_score)
            if rule_hits:
                try:
                    self.storage.store_rule_hits(rule_hits)
                except Exception as e:
                    logger.warning(f"Failed to store rule hits: {e}")
            
            # Store entity risk scores
            if user_score and user_score.entity_id and user_score.entity_id != 'unknown':
                try:
                    self.storage.store_entity_risk(
                        'user', user_score.entity_id, '1h',
                        user_score.score_1h, user_score.contributing_rules
                    )
                    self.storage.store_entity_risk(
                        'user', user_score.entity_id, '24h',
                        user_score.score_24h, user_score.contributing_rules
                    )
                except Exception as e:
                    logger.warning(f"Failed to store user entity risk: {e}")
            
            if host_score and host_score.entity_id and host_score.entity_id != 'unknown':
                try:
                    self.storage.store_entity_risk(
                        'host', host_score.entity_id, '1h',
                        host_score.score_1h, host_score.contributing_rules
                    )
                    self.storage.store_entity_risk(
                        'host', host_score.entity_id, '24h',
                        host_score.score_24h, host_score.contributing_rules
                    )
                except Exception as e:
                    logger.warning(f"Failed to store host entity risk: {e}")
            
            # Check for alerts
            alerts = _ueba_alert_manager.evaluate_for_alert(event_score, user_score, host_score)
            
            for alert in alerts:
                # Fill in entity_id if missing
                if not alert.entity_id:
                    alert.entity_id = event.user if alert.entity_type == 'user' else event.host
                
                try:
                    alert_id = self.storage.store_ueba_alert(alert)
                    alert.id = alert_id
                    self._alert_count += 1
                    
                    logger.info(
                        f"UEBA alert created: [{alert.severity}] {alert.title}, "
                        f"entity={alert.entity_type}:{alert.entity_id}, score={alert.score:.1f}"
                    )
                except Exception as e:
                    logger.warning(f"Failed to store UEBA alert: {e}")
                    
        except Exception as e:
            logger.warning(f"UEBA scoring pipeline error: {e}", exc_info=True)

    @property
    def stats(self) -> dict:
        """Get server statistics."""
        return {
            "running": self._running,
            "host": self.host,
            "port": self.port,
            "event_count": self._event_count,
            "alert_count": self._alert_count,
            "error_count": self._error_count,
            "connected_clients": self._connected_clients
        }


# Global ingest server instance
_ingest_server: Optional[IngestServer] = None


def get_ingest_server() -> Optional[IngestServer]:
    """Get the global ingest server instance."""
    return _ingest_server


def create_ssl_context(cert_path: str, key_path: str, root_dir: Path) -> Optional[ssl.SSLContext]:
    """
    Create SSL context for TLS encryption.
    
    Args:
        cert_path: Path to server certificate file (relative to root_dir)
        key_path: Path to server private key file (relative to root_dir)
        root_dir: Project root directory
        
    Returns:
        SSLContext if certificates exist, None otherwise
    """
    cert_file = root_dir / cert_path
    key_file = root_dir / key_path
    
    if not cert_file.exists() or not key_file.exists():
        logger.warning(f"TLS enabled but certificates not found: cert={cert_file}, key={key_file}")
        return None
    
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(str(cert_file), str(key_file))
        logger.info(f"TLS enabled: loaded certificate from {cert_file}")
        return context
    except Exception as e:
        logger.error(f"Failed to load TLS certificates: {e}")
        return None


def create_ingest_server(
    host: str = "0.0.0.0",
    port: Optional[int] = None,
    storage: Optional[EventStorage] = None,
    on_event: Optional[Callable[[NormalizedEvent], Awaitable[None]]] = None,
    on_alert: Optional[Callable[[Alert], Awaitable[None]]] = None
) -> IngestServer:
    """
    Create and set the global ingest server.
    
    Args:
        host: Host to bind to
        port: Port to listen on (uses config if None)
        storage: EventStorage instance
        on_event: Optional callback for new events
        on_alert: Optional callback for new alerts
        
    Returns:
        IngestServer instance
    """
    global _ingest_server
    
    config = get_config()
    if port is None:
        port = config.ingest_port
    
    # Create SSL context if TLS is enabled
    ssl_context = None
    if config.tls.enabled:
        ssl_context = create_ssl_context(
            config.tls.cert_path,
            config.tls.key_path,
            config.root_dir
        )
        if ssl_context is None:
            logger.warning("TLS enabled in config but SSL context creation failed, starting without TLS")
    
    _ingest_server = IngestServer(
        host=host,
        port=port,
        storage=storage,
        on_event=on_event,
        on_alert=on_alert,
        ssl_context=ssl_context
    )
    
    return _ingest_server


async def run_ingest_server_standalone(
    host: str = "0.0.0.0",
    port: int = 9000
):
    """
    Run the ingest server as a standalone process.
    Useful for testing or running separately from the web server.
    """
    from .storage import EventStorage
    
    storage = EventStorage()
    server = IngestServer(host=host, port=port, storage=storage)
    
    print(f"Starting ingest server on {host}:{port}")
    print("Press Ctrl+C to stop")
    
    try:
        await server.start()
    except KeyboardInterrupt:
        await server.stop()


if __name__ == "__main__":
    # Allow running this module directly for testing
    import sys
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
    asyncio.run(run_ingest_server_standalone(port=port))

