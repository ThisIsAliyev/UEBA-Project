"""
API key and IP whitelist authentication middleware.

Validates:
1. X-API-Key header matches configured secret
2. Client IP is in allowed list (if configured)
"""

import secrets
import logging
from fastapi import Request, HTTPException, Security
from fastapi.security import APIKeyHeader

from ..config import get_settings

logger = logging.getLogger(__name__)

# Define the API key header
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_client_ip(request: Request) -> str:
    """
    Extract client IP from request.
    
    Handles X-Forwarded-For header for reverse proxy scenarios.
    """
    # Check for forwarded header first (if behind reverse proxy)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take the first IP in the chain
        return forwarded.split(",")[0].strip()
    
    # Fall back to direct client IP
    if request.client:
        return request.client.host
    
    return "unknown"


async def verify_api_key(
    request: Request,
    api_key: str = Security(api_key_header)
) -> str:
    """
    Verify API key and optionally check source IP.
    
    This dependency should be added to protected routes.
    
    Args:
        request: FastAPI request object
        api_key: API key from X-API-Key header
        
    Returns:
        The validated API key
        
    Raises:
        HTTPException 401: Missing or invalid API key
        HTTPException 403: IP not in allowed list
    """
    settings = get_settings()
    client_ip = get_client_ip(request)
    
    # Check API key presence
    if not api_key:
        logger.warning(f"Missing API key from {client_ip}")
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Include X-API-Key header."
        )
    
    # Constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(api_key, settings.api_key):
        logger.warning(f"Invalid API key from {client_ip}")
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    
    # Check IP whitelist (if configured)
    allowed_ips = settings.allowed_ip_list
    if allowed_ips:
        if client_ip not in allowed_ips:
            logger.warning(
                f"Request from unauthorized IP: {client_ip}. "
                f"Allowed: {allowed_ips}"
            )
            raise HTTPException(
                status_code=403,
                detail=f"IP {client_ip} not in allowed list"
            )
    
    logger.debug(f"Authenticated request from {client_ip}")
    return api_key
