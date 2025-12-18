"""
AI Risk Engine for UEBA System.

Provides real-time risk assessment for security events using:
- Rule-based scoring
- ML anomaly detection (Phase 2)
- Embedding-based context analysis (Phase 3)
- Optional LLM explanations (Phase 5)
"""

from .risk_engine import RiskEngine, RiskResult, get_risk_engine

__all__ = [
    "RiskEngine",
    "RiskResult",
    "get_risk_engine",
]

