"""
Async client for n8n webhook workflows.

Handles communication with n8n.cloud IOC reputation workflows
(VirusTotal, AbuseIPDB) and returns results in the canonical
EnrichmentResponse format.

Features:
- Result caching to minimize API calls
- Rate limiting for free tier compliance
- Graceful fallback on errors
"""

import asyncio
import logging
import os
import time
import hashlib
from typing import Optional, Dict, Any
from dataclasses import dataclass, field

import httpx

from .models import EnrichmentRequest, EnrichmentResponse, RiskLabel

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Cached enrichment result."""
    response: EnrichmentResponse
    expires_at: float


@dataclass
class RateLimiter:
    """Simple rate limiter for API calls."""
    max_calls: int = 100
    window_seconds: float = 3600.0  # 1 hour
    calls: list = field(default_factory=list)
    
    def allow(self) -> bool:
        """Check if a call is allowed under rate limit."""
        now = time.time()
        # Remove old calls outside window
        self.calls = [t for t in self.calls if now - t < self.window_seconds]
        
        if len(self.calls) >= self.max_calls:
            return False
        
        self.calls.append(now)
        return True
    
    @property
    def remaining(self) -> int:
        """Get remaining calls in current window."""
        now = time.time()
        self.calls = [t for t in self.calls if now - t < self.window_seconds]
        return max(0, self.max_calls - len(self.calls))


class N8NClient:
    """
    Async client for n8n webhook workflows.
    
    Sends IOC data (hashes, IPs, URLs, domains) to n8n workflows
    for enrichment via VirusTotal, AbuseIPDB, etc.
    
    Configuration via environment variables:
    - N8N_WEBHOOK_URL: Webhook URL for IOC reputation workflow
    - N8N_WEBHOOK_TIMEOUT: Request timeout (default: 30s)
    - N8N_RATE_LIMIT: Max calls per hour (default: 100)
    """
    
    def __init__(
        self,
        webhook_url: Optional[str] = None,
        timeout: float = 30.0,
        rate_limit: int = 100,
        cache_ttl_clean: float = 3600.0,  # 1 hour for clean results
        cache_ttl_malicious: float = 86400.0  # 24 hours for malicious
    ):
        """
        Initialize n8n client.
        
        Args:
            webhook_url: n8n webhook URL (or from N8N_WEBHOOK_URL env var)
            timeout: Request timeout in seconds
            rate_limit: Maximum calls per hour
            cache_ttl_clean: Cache TTL for clean/benign results
            cache_ttl_malicious: Cache TTL for malicious results
        """
        self.webhook_url = webhook_url or os.getenv("N8N_WEBHOOK_URL", "")
        self.timeout = timeout
        self.cache_ttl_clean = cache_ttl_clean
        self.cache_ttl_malicious = cache_ttl_malicious
        
        self._cache: Dict[str, CacheEntry] = {}
        self._rate_limiter = RateLimiter(max_calls=rate_limit)
        
        if not self.webhook_url:
            logger.warning("N8N_WEBHOOK_URL not configured - IOC enrichment disabled")
    
    @property
    def is_configured(self) -> bool:
        """Check if client is properly configured."""
        return bool(self.webhook_url)
    
    def _make_cache_key(self, request: EnrichmentRequest) -> str:
        """Generate cache key from IOC data."""
        parts = []
        if request.file_hash:
            parts.append(f"hash:{request.file_hash}")
        if request.ip_address:
            parts.append(f"ip:{request.ip_address}")
        if request.url:
            parts.append(f"url:{request.url}")
        if request.domain:
            parts.append(f"domain:{request.domain}")
        
        if not parts:
            return ""
        
        key_str = "|".join(sorted(parts))
        return hashlib.sha256(key_str.encode()).hexdigest()[:32]
    
    def _get_cached(self, cache_key: str) -> Optional[EnrichmentResponse]:
        """Get cached result if valid."""
        if not cache_key or cache_key not in self._cache:
            return None
        
        entry = self._cache[cache_key]
        if time.time() > entry.expires_at:
            del self._cache[cache_key]
            return None
        
        logger.debug(f"Cache hit for {cache_key[:8]}...")
        return entry.response
    
    def _cache_result(self, cache_key: str, response: EnrichmentResponse):
        """Cache enrichment result."""
        if not cache_key:
            return
        
        # Use longer TTL for malicious results
        if response.label == RiskLabel.MALICIOUS:
            ttl = self.cache_ttl_malicious
        else:
            ttl = self.cache_ttl_clean
        
        self._cache[cache_key] = CacheEntry(
            response=response,
            expires_at=time.time() + ttl
        )
        
        # Cleanup old entries (simple LRU-like behavior)
        if len(self._cache) > 1000:
            oldest_key = min(self._cache, key=lambda k: self._cache[k].expires_at)
            del self._cache[oldest_key]
    
    async def enrich(self, request: EnrichmentRequest) -> EnrichmentResponse:
        """
        Send IOC data to n8n for enrichment.
        
        Args:
            request: EnrichmentRequest with IOC data
            
        Returns:
            EnrichmentResponse with reputation results
        """
        if not self.is_configured:
            return EnrichmentResponse.create_fallback(
                request_id=request.request_id,
                source="n8n",
                error="n8n webhook not configured"
            )
        
        # Check cache first
        cache_key = self._make_cache_key(request)
        cached = self._get_cached(cache_key)
        if cached:
            # Return cached result with updated request_id
            return EnrichmentResponse(
                request_id=request.request_id,
                label=cached.label,
                score=cached.score,
                confidence=cached.confidence,
                reason=cached.reason,
                comment=cached.comment + " (cached)",
                source=cached.source,
                sources=cached.sources,
                error=None
            )
        
        # Check rate limit
        if not self._rate_limiter.allow():
            logger.warning(
                f"n8n rate limit exceeded ({self._rate_limiter.max_calls}/hour). "
                f"Remaining: {self._rate_limiter.remaining}"
            )
            return EnrichmentResponse.create_fallback(
                request_id=request.request_id,
                source="n8n",
                error="Rate limit exceeded"
            )
        
        # Prepare payload for n8n webhook
        payload = {
            "request_id": request.request_id,
            "hash": request.file_hash,
            "ip": request.ip_address,
            "url": request.url,
            "domain": request.domain,
        }
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.webhook_url,
                    json=payload
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Parse n8n response into canonical format
                    result = self._parse_n8n_response(data, request.request_id)
                    
                    # Cache the result
                    self._cache_result(cache_key, result)
                    
                    return result
                else:
                    logger.warning(f"n8n webhook error: HTTP {response.status_code}")
                    return EnrichmentResponse.create_fallback(
                        request_id=request.request_id,
                        source="n8n",
                        error=f"HTTP {response.status_code}"
                    )
                    
        except httpx.TimeoutException:
            logger.warning("n8n webhook timeout")
            return EnrichmentResponse.create_fallback(
                request_id=request.request_id,
                source="n8n",
                error="Request timeout"
            )
        except Exception as e:
            logger.exception(f"n8n webhook error: {e}")
            return EnrichmentResponse.create_fallback(
                request_id=request.request_id,
                source="n8n",
                error=str(e)
            )
    
    def _parse_n8n_response(
        self,
        data: Dict[str, Any],
        request_id: str
    ) -> EnrichmentResponse:
        """
        Parse n8n webhook response into canonical EnrichmentResponse.
        
        Expected n8n response format:
        {
            "request_id": "...",
            "label": "MALICIOUS|SUSPICIOUS|BENIGN",
            "score": 0-100,
            "sources": {
                "virustotal": {...},
                "abuseipdb": {...}
            },
            "comment": "..."
        }
        """
        try:
            label_str = data.get("label", "SUSPICIOUS").upper()
            if label_str not in ["MALICIOUS", "SUSPICIOUS", "BENIGN"]:
                label_str = "SUSPICIOUS"
            
            score = int(data.get("score", 50))
            score = max(0, min(100, score))
            
            # Build reason from sources
            sources = data.get("sources", {})
            reason_parts = []
            
            if "virustotal" in sources:
                vt = sources["virustotal"]
                if vt.get("positives"):
                    reason_parts.append(f"VT: {vt['positives']}/{vt.get('total', '?')} detections")
            
            if "abuseipdb" in sources:
                abuse = sources["abuseipdb"]
                if abuse.get("confidence_score"):
                    reason_parts.append(f"AbuseIPDB: {abuse['confidence_score']}% confidence")
            
            reason = "; ".join(reason_parts) if reason_parts else "IOC reputation check complete"
            comment = data.get("comment", "Enrichment results from VirusTotal and AbuseIPDB")
            
            return EnrichmentResponse(
                request_id=request_id,
                label=RiskLabel(label_str),
                score=score,
                confidence=0.8 if label_str == "MALICIOUS" else 0.6,
                reason=reason[:200],
                comment=comment[:1000],
                source="n8n",
                sources=sources,
                error=None
            )
            
        except Exception as e:
            logger.warning(f"Failed to parse n8n response: {e}")
            return EnrichmentResponse.create_fallback(
                request_id=request_id,
                source="n8n",
                error=f"Parse error: {e}"
            )
    
    @property
    def rate_limit_remaining(self) -> int:
        """Get remaining API calls in current window."""
        return self._rate_limiter.remaining
    
    def clear_cache(self):
        """Clear the result cache."""
        self._cache.clear()


# Global client instance
_n8n_client: Optional[N8NClient] = None


def get_n8n_client() -> N8NClient:
    """Get or create global n8n client instance."""
    global _n8n_client
    
    if _n8n_client is None:
        timeout = float(os.getenv("N8N_WEBHOOK_TIMEOUT", "30"))
        rate_limit = int(os.getenv("N8N_RATE_LIMIT", "100"))
        _n8n_client = N8NClient(timeout=timeout, rate_limit=rate_limit)
    
    return _n8n_client


def reset_n8n_client():
    """Reset the global n8n client (for testing)."""
    global _n8n_client
    _n8n_client = None
