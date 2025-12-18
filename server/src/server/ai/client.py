"""
Async HTTP client for AI Server communication.

Features:
- Async HTTP requests with configurable timeout
- Circuit breaker to prevent cascade failures
- Automatic retry with exponential backoff
- Graceful fallback when AI Server is unavailable
"""

import asyncio
import logging
import os
import time
from typing import Optional
from dataclasses import dataclass

import httpx

from .models import EnrichmentRequest, EnrichmentResponse, RiskLabel

logger = logging.getLogger(__name__)


@dataclass
class CircuitBreakerState:
    """Circuit breaker state tracking."""
    failure_count: int = 0
    last_failure_time: float = 0.0
    is_open: bool = False


class AIClient:
    """
    Async client for AI Server with circuit breaker pattern.
    
    The circuit breaker prevents cascade failures by stopping requests
    to a failing AI Server and allowing it time to recover.
    
    States:
    - CLOSED: Normal operation, requests flow through
    - OPEN: Too many failures, requests are rejected immediately
    - HALF-OPEN: After recovery timeout, one request is allowed through
    
    Configuration via environment variables:
    - AI_SERVER_URL: Base URL of AI Server (required)
    - AI_SERVER_API_KEY: API key for authentication (required)
    - AI_SERVER_TIMEOUT: Request timeout in seconds (default: 30)
    """
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
        max_retries: int = 2,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0
    ):
        """
        Initialize AI client.
        
        Args:
            base_url: AI Server URL (or from AI_SERVER_URL env var)
            api_key: API key (or from AI_SERVER_API_KEY env var)
            timeout: Request timeout in seconds
            max_retries: Number of retry attempts
            failure_threshold: Failures before circuit opens
            recovery_timeout: Seconds before circuit half-opens
        """
        self.base_url = (base_url or os.getenv("AI_SERVER_URL", "")).rstrip("/")
        self.api_key = api_key or os.getenv("AI_SERVER_API_KEY", "")
        self.timeout = timeout
        self.max_retries = max_retries
        
        # Circuit breaker configuration
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._circuit = CircuitBreakerState()
        
        # Validate configuration
        if not self.base_url:
            logger.warning("AI_SERVER_URL not configured - AI analysis disabled")
        if not self.api_key:
            logger.warning("AI_SERVER_API_KEY not configured - AI analysis disabled")
    
    @property
    def is_configured(self) -> bool:
        """Check if client is properly configured."""
        return bool(self.base_url and self.api_key)
    
    def _is_circuit_open(self) -> bool:
        """
        Check if circuit breaker is open.
        
        Returns True if requests should be blocked.
        """
        if not self._circuit.is_open:
            return False
        
        # Check if recovery timeout has passed
        elapsed = time.time() - self._circuit.last_failure_time
        if elapsed >= self.recovery_timeout:
            # Half-open: allow one request through
            logger.info("AI Server circuit breaker half-open, allowing test request")
            return False
        
        return True
    
    def _record_success(self):
        """Record successful request, reset circuit breaker."""
        if self._circuit.failure_count > 0:
            logger.info("AI Server recovered, resetting circuit breaker")
        self._circuit.failure_count = 0
        self._circuit.is_open = False
    
    def _record_failure(self):
        """Record failed request, potentially open circuit."""
        self._circuit.failure_count += 1
        self._circuit.last_failure_time = time.time()
        
        if self._circuit.failure_count >= self.failure_threshold:
            self._circuit.is_open = True
            logger.warning(
                f"AI Server circuit breaker OPEN after {self._circuit.failure_count} failures. "
                f"Will retry in {self.recovery_timeout}s"
            )
    
    async def analyze(self, request: EnrichmentRequest) -> EnrichmentResponse:
        """
        Send analysis request to AI Server.
        
        Implements retry logic and circuit breaker pattern.
        Returns fallback response on failure (never raises).
        
        Args:
            request: EnrichmentRequest with event data
            
        Returns:
            EnrichmentResponse with analysis results or fallback
        """
        if not self.is_configured:
            return EnrichmentResponse.create_fallback(
                request_id=request.request_id,
                source="ai_server",
                error="AI Server not configured"
            )
        
        # Check circuit breaker
        if self._is_circuit_open():
            logger.debug(f"Circuit breaker open, skipping AI request {request.request_id}")
            return EnrichmentResponse.create_fallback(
                request_id=request.request_id,
                source="ai_server",
                error="Circuit breaker open"
            )
        
        # Prepare request payload
        payload = {
            "request_id": request.request_id,
            "events": request.events,
            "context": request.context.model_dump(),
            "rule_score": request.rule_score,
        }
        
        if request.baseline_deviation:
            payload["baseline_deviation"] = request.baseline_deviation.model_dump()
        if request.threat_intel:
            payload["threat_intel"] = request.threat_intel.model_dump()
        
        # Retry loop
        last_error = None
        for attempt in range(self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.post(
                        f"{self.base_url}/api/v1/analyze",
                        json=payload,
                        headers={"X-API-Key": self.api_key}
                    )
                    
                    if response.status_code == 200:
                        self._record_success()
                        data = response.json()
                        return EnrichmentResponse(
                            request_id=data.get("request_id", request.request_id),
                            label=RiskLabel(data.get("label", "SUSPICIOUS")),
                            score=data.get("score", 50),
                            confidence=data.get("confidence", 0.5),
                            reason=data.get("reason", "AI analysis complete"),
                            comment=data.get("comment", ""),
                            source="ai_server",
                            error=data.get("error")
                        )
                    else:
                        last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                        logger.warning(f"AI Server error (attempt {attempt + 1}): {last_error}")
                        
            except httpx.TimeoutException:
                last_error = "Request timeout"
                logger.warning(f"AI Server timeout (attempt {attempt + 1})")
            except httpx.ConnectError:
                last_error = "Connection failed"
                logger.warning(f"AI Server connection failed (attempt {attempt + 1})")
            except Exception as e:
                last_error = str(e)
                logger.exception(f"AI Server error (attempt {attempt + 1}): {e}")
            
            # Wait before retry (exponential backoff)
            if attempt < self.max_retries:
                await asyncio.sleep(1.0 * (2 ** attempt))
        
        # All retries failed
        self._record_failure()
        return EnrichmentResponse.create_fallback(
            request_id=request.request_id,
            source="ai_server",
            error=last_error or "Unknown error"
        )
    
    async def health_check(self) -> bool:
        """
        Check if AI Server is healthy.
        
        Returns:
            True if AI Server is responding, False otherwise
        """
        if not self.is_configured:
            return False
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.base_url}/health")
                return response.status_code == 200
        except Exception:
            return False


# Global client instance
_ai_client: Optional[AIClient] = None


def get_ai_client() -> AIClient:
    """
    Get or create global AI client instance.
    
    Configuration is loaded from environment variables:
    - AI_SERVER_URL
    - AI_SERVER_API_KEY
    - AI_SERVER_TIMEOUT (optional, default 30)
    """
    global _ai_client
    
    if _ai_client is None:
        timeout = float(os.getenv("AI_SERVER_TIMEOUT", "30"))
        _ai_client = AIClient(timeout=timeout)
    
    return _ai_client


def reset_ai_client():
    """Reset the global AI client (for testing)."""
    global _ai_client
    _ai_client = None
