"""
Analysis endpoint for LLM-based security event assessment.

POST /api/v1/analyze - Analyze security events using Ollama LLM
"""

import logging
import time
from fastapi import APIRouter, HTTPException, Depends

from ..models.schemas import AnalyzeRequest, AnalyzeResponse
from ..services.ollama_client import analyze_with_ollama
from ..middleware.auth import verify_api_key

logger = logging.getLogger(__name__)

router = APIRouter(tags=["analysis"])


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Analyze security events",
    description="Send security events to the LLM for risk analysis. Returns a structured verdict.",
    responses={
        200: {"description": "Analysis completed successfully"},
        401: {"description": "Invalid or missing API key"},
        403: {"description": "IP not in allowed list"},
        500: {"description": "Analysis failed"},
    }
)
async def analyze_events(
    request: AnalyzeRequest,
    api_key: str = Depends(verify_api_key)
) -> AnalyzeResponse:
    """
    Analyze security events using LLM.
    
    Accepts a batch of recent events with context and returns a structured
    verdict with label (MALICIOUS/SUSPICIOUS/BENIGN), score (0-100),
    and human-readable explanation.
    
    The response follows the canonical enrichment schema used by all
    enrichment sources (AI Server, n8n workflows, etc.).
    """
    start_time = time.time()
    
    logger.info(
        f"Analysis request {request.request_id}: "
        f"{len(request.events)} events, "
        f"user={request.context.user}, "
        f"host={request.context.host}, "
        f"rule_score={request.rule_score}"
    )
    
    try:
        result = await analyze_with_ollama(request)
        
        elapsed = time.time() - start_time
        logger.info(
            f"Analysis complete {request.request_id}: "
            f"label={result.label}, score={result.score}, "
            f"elapsed={elapsed:.2f}s"
        )
        
        return result
        
    except Exception as e:
        logger.exception(f"Analysis failed for {request.request_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )
