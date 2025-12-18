"""
Security utilities for UEBA platform.

Provides password hashing, token generation, and cryptographic functions.

NOTE: bcrypt is an OPTIONAL dependency. If not installed, password auth
features will raise HTTPException(503) at runtime, but server will still boot.
"""

import secrets
import hashlib
from typing import Optional

from .optional_deps import require_bcrypt, BCRYPT_AVAILABLE, bcrypt


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    
    Args:
        password: Plain text password
        
    Returns:
        Bcrypt hash string
        
    Raises:
        HTTPException: 503 if bcrypt is not installed
    """
    require_bcrypt()
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a password against a bcrypt hash.
    
    Args:
        password: Plain text password to verify
        password_hash: Bcrypt hash to verify against
        
    Returns:
        True if password matches, False otherwise
        
    Raises:
        HTTPException: 503 if bcrypt is not installed
    """
    require_bcrypt()
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception:
        return False


def generate_token(length: int = 32) -> str:
    """
    Generate a secure random token.
    
    Args:
        length: Token length in bytes (default: 32)
        
    Returns:
        URL-safe base64 encoded token
    """
    return secrets.token_urlsafe(length)


def generate_agent_token() -> str:
    """
    Generate a token for agent authentication.
    
    Returns:
        256-bit random token (URL-safe base64)
    """
    return secrets.token_urlsafe(32)


def hash_legacy_password(password: str) -> str:
    """
    Legacy password hashing (SHA256) for migration purposes.
    
    ⚠️ DEPRECATED: Only use for verifying old passwords during migration.
    New passwords should use bcrypt via hash_password().
    
    Args:
        password: Plain text password
        
    Returns:
        SHA256 hex digest
    """
    return hashlib.sha256(password.encode()).hexdigest()

