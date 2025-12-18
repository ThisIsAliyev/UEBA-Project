"""
Unified enrichment data models.

These models define the CANONICAL SCHEMA for all enrichment sources:
- AI Server (Ollama)
- n8n IOC workflows (VirusTotal, AbuseIPDB)
- Future enrichment services

All enrichment responses conform to EnrichmentResponse for uniform handling.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class RiskLabel(str, Enum):
    """
    Risk classification label.
    
    Used by all enrichment sources for consistent risk categorization.
    """
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"


class EventContext(BaseModel):
    """Context about the event being analyzed."""
    user: str = Field(..., description="Username associated with the event")
    host: str = Field(..., description="Hostname where event occurred")
    process_name: Optional[str] = Field(None, description="Process name")
    command_line: Optional[str] = Field(None, description="Command line arguments")
    parent_process: Optional[str] = Field(None, description="Parent process name")
    image_path: Optional[str] = Field(None, description="Full path to executable")
    event_id: Optional[int] = Field(None, description="Windows/Sysmon Event ID")
    category: Optional[str] = Field(None, description="Event category")


class BaselineDeviation(BaseModel):
    """Baseline deviation information."""
    is_new_process: bool = Field(False, description="Process not seen before")
    is_unusual_hour: bool = Field(False, description="Outside typical working hours")
    is_rare_parent_child: bool = Field(False, description="Unusual process chain")
    events_last_5min: int = Field(0, description="Event count in last 5 minutes")
    deviation_score: float = Field(0.0, ge=0, le=100, description="Overall deviation score")


class ThreatIntelResult(BaseModel):
    """Threat intelligence results from n8n/VirusTotal/AbuseIPDB."""
    hash_reputation: Optional[str] = Field(None, description="File hash reputation")
    ip_reputation: Optional[str] = Field(None, description="IP reputation")
    domain_reputation: Optional[str] = Field(None, description="Domain reputation")
    vt_positives: Optional[int] = Field(None, description="VirusTotal positive detections")
    vt_total: Optional[int] = Field(None, description="VirusTotal total scanners")
    abuse_confidence: Optional[int] = Field(None, description="AbuseIPDB confidence 0-100")


class EnrichmentRequest(BaseModel):
    """
    Request payload for enrichment services.
    
    Used for both AI Server and n8n workflows.
    """
    request_id: str = Field(..., description="Unique request ID for correlation")
    events: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Recent events to analyze (max 10)",
        max_length=10
    )
    context: EventContext = Field(..., description="Event context")
    baseline_deviation: Optional[BaselineDeviation] = Field(None)
    threat_intel: Optional[ThreatIntelResult] = Field(None)
    rule_score: float = Field(0.0, ge=0, le=100, description="Preliminary rule score")
    
    # IOC fields for n8n workflows
    file_hash: Optional[str] = Field(None, description="File hash for VT lookup")
    ip_address: Optional[str] = Field(None, description="IP for reputation lookup")
    url: Optional[str] = Field(None, description="URL for reputation lookup")
    domain: Optional[str] = Field(None, description="Domain for reputation lookup")


class EnrichmentResponse(BaseModel):
    """
    CANONICAL RESPONSE SCHEMA for all enrichment sources.
    
    All enrichment services (AI Server, n8n, future services) MUST return
    responses conforming to this schema for uniform handling in the risk engine.
    
    Fields:
        request_id: Correlation ID from the original request
        label: Risk classification (MALICIOUS/SUSPICIOUS/BENIGN)
        score: Risk score 0-100
        confidence: Confidence in the assessment 0.0-1.0
        reason: Short explanation for logs/alerts (max 200 chars)
        comment: Detailed explanation for analysts (max 1000 chars)
        source: Which service produced this response
        sources: Detailed results from multiple sources (for aggregated responses)
        error: Error message if enrichment failed
    """
    request_id: str = Field(..., description="Request ID for correlation")
    label: RiskLabel = Field(..., description="Risk classification")
    score: int = Field(..., ge=0, le=100, description="Risk score 0-100")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence 0.0-1.0")
    reason: str = Field(..., max_length=200, description="Short explanation")
    comment: str = Field(..., max_length=1000, description="Detailed explanation")
    source: str = Field(..., description="Service that produced this response")
    sources: Optional[Dict[str, Any]] = Field(
        None,
        description="Detailed results from multiple sources"
    )
    error: Optional[str] = Field(None, description="Error message if failed")
    
    @classmethod
    def create_fallback(
        cls,
        request_id: str,
        source: str,
        error: str
    ) -> "EnrichmentResponse":
        """
        Create a fallback response when enrichment fails.
        
        Returns a neutral SUSPICIOUS response that doesn't affect scoring.
        """
        return cls(
            request_id=request_id,
            label=RiskLabel.SUSPICIOUS,
            score=50,
            confidence=0.0,
            reason=f"Enrichment unavailable: {error[:100]}",
            comment=f"The {source} enrichment service was unavailable. "
                    f"Using rule-based score only. Error: {error}",
            source=source,
            error=error
        )
    
    class Config:
        json_schema_extra = {
            "example": {
                "request_id": "evt_12345",
                "label": "SUSPICIOUS",
                "score": 65,
                "confidence": 0.75,
                "reason": "Encoded PowerShell spawned by Office application",
                "comment": "The event shows winword.exe spawning powershell.exe...",
                "source": "ai_server",
                "sources": None,
                "error": None
            }
        }
