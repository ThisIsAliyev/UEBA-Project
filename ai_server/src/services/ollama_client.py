"""
Ollama LLM client for security analysis.

Handles communication with the local Ollama instance and response parsing.
"""

import logging
import httpx
from typing import Optional

from ..config import get_settings
from ..models.schemas import AnalyzeRequest, AnalyzeResponse, RiskLabel
from .prompt_builder import build_analysis_prompt, parse_llm_response

logger = logging.getLogger(__name__)


async def check_ollama_health() -> bool:
    """
    Check if Ollama is running and responsive.
    
    Returns:
        True if Ollama is healthy, False otherwise
    """
    settings = get_settings()
    
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{settings.ollama_url}/api/tags")
            return response.status_code == 200
    except Exception as e:
        logger.warning(f"Ollama health check failed: {e}")
        return False


async def analyze_with_ollama(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Send analysis request to Ollama and parse response.
    
    Args:
        request: AnalyzeRequest with events and context
        
    Returns:
        AnalyzeResponse with label, score, and explanation
        
    Raises:
        httpx.TimeoutException: If Ollama doesn't respond in time
        httpx.ConnectError: If Ollama is not reachable
    """
    settings = get_settings()
    
    # Build the prompt
    prompt = build_analysis_prompt(request)
    
    logger.debug(f"Sending analysis request {request.request_id} to Ollama")
    
    # Prepare Ollama API payload
    payload = {
        "model": settings.ollama_model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,  # Low temperature for consistent, deterministic output
            "num_predict": 512,  # Limit response length
            "top_p": 0.9,
            "repeat_penalty": 1.1,
        }
    }
    
    try:
        async with httpx.AsyncClient(timeout=settings.ollama_timeout) as client:
            response = await client.post(
                f"{settings.ollama_url}/api/generate",
                json=payload
            )
            response.raise_for_status()
            result = response.json()
        
        # Extract the response text
        raw_response = result.get("response", "")
        
        logger.debug(f"Ollama response for {request.request_id}: {raw_response[:200]}...")
        
        # Parse LLM response into structured format
        parsed = parse_llm_response(raw_response, request.request_id)
        
        return AnalyzeResponse(
            request_id=parsed["request_id"],
            label=RiskLabel(parsed["label"]),
            score=parsed["score"],
            confidence=parsed["confidence"],
            reason=parsed["reason"],
            comment=parsed["comment"],
            source="ai_server",
            error=parsed.get("error")
        )
        
    except httpx.TimeoutException:
        logger.error(f"Ollama timeout for request {request.request_id}")
        return AnalyzeResponse(
            request_id=request.request_id,
            label=RiskLabel.SUSPICIOUS,
            score=50,
            confidence=0.0,
            reason="AI analysis timed out",
            comment="The AI analysis request timed out. The preliminary rule-based score should be used.",
            source="ai_server",
            error="Ollama timeout"
        )
        
    except httpx.ConnectError:
        logger.error(f"Cannot connect to Ollama for request {request.request_id}")
        return AnalyzeResponse(
            request_id=request.request_id,
            label=RiskLabel.SUSPICIOUS,
            score=50,
            confidence=0.0,
            reason="AI server unavailable",
            comment="Cannot connect to Ollama. Ensure Ollama is running on localhost:11434.",
            source="ai_server",
            error="Ollama connection failed"
        )
        
    except Exception as e:
        logger.exception(f"Ollama analysis failed for {request.request_id}: {e}")
        return AnalyzeResponse(
            request_id=request.request_id,
            label=RiskLabel.SUSPICIOUS,
            score=50,
            confidence=0.0,
            reason="AI analysis error",
            comment=f"An error occurred during AI analysis: {str(e)[:200]}",
            source="ai_server",
            error=str(e)
        )
