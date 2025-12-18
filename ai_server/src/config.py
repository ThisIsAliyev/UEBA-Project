"""
Configuration management for AI Server.

Loads settings from environment variables with sensible defaults.
Required variables: AI_SERVER_API_KEY
"""

import os
from functools import lru_cache
from typing import List, Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    Environment variables are prefixed with AI_SERVER_ (except OLLAMA_*).
    Example: AI_SERVER_PORT=8000
    """
    
    # Server configuration
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Ollama configuration
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2:3b"
    ollama_timeout: float = 60.0  # seconds
    
    # Security - API key is REQUIRED
    api_key: str  # No default - must be set
    allowed_ips: str = ""  # Comma-separated list, e.g., "192.168.213.136,10.0.0.1"
    
    # Logging
    log_level: str = "INFO"
    
    # Rate limiting
    max_requests_per_minute: int = 30
    
    class Config:
        env_file = ".env"
        env_prefix = "AI_SERVER_"
        # Allow OLLAMA_* without prefix
        extra = "ignore"
    
    @property
    def allowed_ip_list(self) -> List[str]:
        """Parse allowed IPs into a list."""
        if not self.allowed_ips:
            return []
        return [ip.strip() for ip in self.allowed_ips.split(",") if ip.strip()]


# Override for OLLAMA_* variables (no prefix)
class OllamaSettings(BaseSettings):
    """Ollama-specific settings without prefix."""
    url: str = "http://127.0.0.1:11434"
    model: str = "llama3.2:3b"
    
    class Config:
        env_prefix = "OLLAMA_"


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Settings are loaded once and cached for performance.
    """
    # Load base settings
    settings = Settings()
    
    # Override Ollama settings if OLLAMA_* env vars are set
    ollama = OllamaSettings()
    if os.getenv("OLLAMA_URL"):
        settings.ollama_url = ollama.url
    if os.getenv("OLLAMA_MODEL"):
        settings.ollama_model = ollama.model
    
    return settings


def validate_settings() -> None:
    """
    Validate that all required settings are present.
    
    Raises ValueError if required settings are missing.
    """
    settings = get_settings()
    
    if not settings.api_key:
        raise ValueError("AI_SERVER_API_KEY environment variable is required")
    
    if len(settings.api_key) < 16:
        raise ValueError("AI_SERVER_API_KEY must be at least 16 characters")
