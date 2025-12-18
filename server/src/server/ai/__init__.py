"""
AI Integration Module for UEBA Web Server.

Provides async client and queue for communicating with the AI Server
and n8n enrichment workflows.
"""

from .models import (
    EnrichmentRequest,
    EnrichmentResponse,
    RiskLabel,
    EventContext,
    BaselineDeviation,
    ThreatIntelResult,
)
from .client import AIClient, get_ai_client
from .queue import AIAnalysisQueue, get_analysis_queue
from .n8n_client import N8NClient, get_n8n_client

__all__ = [
    # Models
    "EnrichmentRequest",
    "EnrichmentResponse",
    "RiskLabel",
    "EventContext",
    "BaselineDeviation",
    "ThreatIntelResult",
    # Clients
    "AIClient",
    "get_ai_client",
    "N8NClient",
    "get_n8n_client",
    # Queue
    "AIAnalysisQueue",
    "get_analysis_queue",
]
