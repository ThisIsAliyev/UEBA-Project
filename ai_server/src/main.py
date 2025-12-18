"""
UEBA AI Server - FastAPI wrapper for Ollama LLM analysis.

This microservice provides LLM-based security event analysis for the UEBA platform.
It receives events from the Web Server, analyzes them using a local Ollama instance,
and returns structured verdicts.

Usage:
    uvicorn src.main:app --host 0.0.0.0 --port 8000
    
Environment Variables:
    AI_SERVER_API_KEY: Required. Secret key for authentication.
    AI_SERVER_ALLOWED_IPS: Optional. Comma-separated list of allowed client IPs.
    AI_SERVER_HOST: Optional. Host to bind to (default: 0.0.0.0)
    AI_SERVER_PORT: Optional. Port to listen on (default: 8000)
    OLLAMA_URL: Optional. Ollama API URL (default: http://127.0.0.1:11434)
    OLLAMA_MODEL: Optional. Model to use (default: llama3.2:3b)
"""

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings, validate_settings
from .routes.analyze import router as analyze_router
from .services.ollama_client import check_ollama_health

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.
    
    Runs startup checks and cleanup on shutdown.
    """
    # Startup
    logger.info("=" * 50)
    logger.info("UEBA AI Server starting up...")
    
    try:
        validate_settings()
        settings = get_settings()
        
        logger.info(f"Host: {settings.host}:{settings.port}")
        logger.info(f"Ollama URL: {settings.ollama_url}")
        logger.info(f"Ollama Model: {settings.ollama_model}")
        logger.info(f"Allowed IPs: {settings.allowed_ip_list or 'ALL (no restriction)'}")
        
        # Check Ollama connectivity
        ollama_ok = await check_ollama_health()
        if ollama_ok:
            logger.info("Ollama connection: OK")
        else:
            logger.warning("Ollama connection: FAILED - AI analysis will not work!")
        
        logger.info("AI Server ready to accept requests")
        logger.info("=" * 50)
        
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("AI Server shutting down...")


# Create FastAPI app
app = FastAPI(
    title="UEBA AI Analysis Server",
    description="LLM-based security event analysis for UEBA platform",
    version="1.0.0",
    lifespan=lifespan,
    # Disable docs in production for security
    # docs_url=None,
    # redoc_url=None,
)

# Add CORS middleware (restrictive - only for internal use)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to Web Server origin
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(
    analyze_router,
    prefix="/api/v1"
)


@app.get("/health", tags=["health"])
async def health_check():
    """
    Health check endpoint.
    
    Does NOT require authentication - used for monitoring/load balancing.
    
    Returns:
        status: "healthy" if server is running
        ollama: "connected" or "disconnected"
    """
    ollama_ok = await check_ollama_health()
    
    return {
        "status": "healthy",
        "ollama": "connected" if ollama_ok else "disconnected",
        "model": get_settings().ollama_model
    }


@app.get("/", tags=["health"])
async def root():
    """Root endpoint - basic info."""
    return {
        "service": "UEBA AI Analysis Server",
        "version": "1.0.0",
        "docs": "/docs"
    }


if __name__ == "__main__":
    import uvicorn
    
    settings = get_settings()
    uvicorn.run(
        "src.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        log_level="info"
    )
