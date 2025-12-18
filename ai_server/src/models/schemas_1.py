"""
Pydantic models for AI Server API.

Defines the canonical JSON schema for AI analysis requests and responses.
This schema is shared with the Web Server for consistent communication.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class RiskLabel(str, Enum):
    """
    Risk classification label.
    
    - MALICIOUS: High confidence threat, requires immediate action
    - SUSPICIOUS: Warrants investigation, may be false positive
    - BENIGN: Normal activity, no action needed
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
    category: Optional[str] = Field(None, description="Event category (process, network, auth, etc.)")


class BaselineDeviation(BaseModel):
    """Baseline deviation information from Web Server."""
    is_new_process: bool = Field(False, description="Process not seen before for this user/host")
    is_unusual_hour: bool = Field(False, description="Activity outside typical working hours")
    is_rare_parent_child: bool = Field(False, description="Unusual process chain")
    events_last_5min: int = Field(0, description="Number of events in last 5 minutes")
    deviation_score: float = Field(0.0, ge=0, le=100, description="Overall baseline deviation score")


class ThreatIntelResult(BaseModel):
    """Threat intelligence lookup results (from n8n/VirusTotal/AbuseIPDB)."""
    hash_reputation: Optional[str] = Field(None, description="File hash reputation: clean/suspicious/malicious")
    ip_reputation: Optional[str] = Field(None, description="IP reputation: clean/suspicious/malicious")
    domain_reputation: Optional[str] = Field(None, description="Domain reputation")
    vt_positives: Optional[int] = Field(None, description="VirusTotal positive detections")
    vt_total: Optional[int] = Field(None, description="VirusTotal total scanners")
    abuse_confidence: Optional[int] = Field(None, description="AbuseIPDB confidence score 0-100")


class AnalyzeRequest(BaseModel):
    """
    Request payload for /api/v1/analyze endpoint.
    
    Contains event data, context, and enrichment results for AI analysis.
    """
    request_id: str = Field(..., description="Unique request ID for correlation")
    events: List[Dict[str, Any]] = Field(
        ..., 
        description="Recent events to analyze (max 10)",
        max_length=10
    )
    context: EventContext = Field(..., description="Event context information")
    baseline_deviation: Optional[BaselineDeviation] = Field(
        None, 
        description="Baseline deviation data"
    )
    threat_intel: Optional[ThreatIntelResult] = Field(
        None, 
        description="Threat intelligence results"
    )
    rule_score: float = Field(
        0.0, 
        ge=0, 
        le=100, 
        description="Preliminary rule-based score from Web Server"
    )


class AnalyzeResponse(BaseModel):
    """
    Response from /api/v1/analyze endpoint.
    
    This is the CANONICAL RESPONSE SCHEMA for all enrichment sources:
    - AI Server (Ollama)
    - n8n IOC workflows (VirusTotal, AbuseIPDB)
    - Future enrichment services
    
    All enrichment responses MUST conform to this schema for uniform handling.
    """
    request_id: str = Field(..., description="Request ID for correlation with Web Server")
    label: RiskLabel = Field(..., description="Risk classification: MALICIOUS/SUSPICIOUS/BENIGN")
    score: int = Field(..., ge=0, le=100, description="Risk score 0-100")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in the assessment 0.0-1.0")
    reason: str = Field(..., max_length=200, description="Short explanation (for logs/alerts)")
    comment: str = Field(..., max_length=1000, description="Detailed human-readable explanation")
    source: str = Field(default="ai_server", description="Which service produced this response")
    sources: Optional[Dict[str, Any]] = Field(
        None, 
        description="Detailed results from multiple sources (for n8n aggregated responses)"
    )
    error: Optional[str] = Field(None, description="Error message if analysis failed")

    class Config:
        json_schema_extra = {
            "example": {
                "request_id": "evt_12345",
                "label": "SUSPICIOUS",
                "score": 65,
                "confidence": 0.75,
                "reason": "Encoded PowerShell spawned by Office application",
                "comment": "The event shows winword.exe spawning powershell.exe with base64-encoded command. This is a common technique used in macro-based attacks. The encoded payload should be decoded and analyzed. Recommend investigating the source document.",
                "source": "ai_server",
                "sources": None,
                "error": None
            }
        }
