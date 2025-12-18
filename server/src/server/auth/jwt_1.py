"""
JWT token generation and validation for UEBA platform.

Implements access token and refresh token strategy from architecture spec.

NOTE: PyJWT is an OPTIONAL dependency. If not installed, JWT auth features
will raise HTTPException(503) at runtime, but server will still boot.
"""

import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from enum import Enum

from ..core.optional_deps import require_jwt, JWT_AVAILABLE, jwt


# JWT secret key - in production, this should be loaded from environment/config
# For now, we'll generate a random one on startup
_JWT_SECRET: Optional[str] = None
_JWT_ALGORITHM = "HS256"


class TokenType(str, Enum):
    """Token type for JWT."""
    ACCESS = "access"
    REFRESH = "refresh"


def get_jwt_secret() -> str:
    """
    Get or generate JWT secret key.
    
    In production, this should be loaded from environment variable or config.
    """
    global _JWT_SECRET
    if _JWT_SECRET is None:
        # Generate a random secret (in production, use a fixed secret from config)
        _JWT_SECRET = secrets.token_urlsafe(32)
    return _JWT_SECRET


def set_jwt_secret(secret: str):
    """Set JWT secret key (for testing or config loading)."""
    global _JWT_SECRET
    _JWT_SECRET = secret


def create_access_token(
    user_id: int,
    username: str,
    roles: list[str],
    permissions: list[str],
    tenant_id: Optional[str] = None,
    expires_in: int = 3600  # 1 hour
) -> str:
    """
    Create a JWT access token.
    
    Args:
        user_id: User ID
        username: Username
        roles: List of role names
        permissions: List of permission strings
        tenant_id: Optional tenant ID (for multi-tenant)
        expires_in: Token expiration in seconds (default: 1 hour)
        
    Returns:
        Encoded JWT token string
    """
    now = datetime.utcnow()
    payload: Dict[str, Any] = {
        "sub": str(user_id),  # Subject (user ID)
        "username": username,
        "roles": roles,
        "permissions": permissions,
        "iat": int(now.timestamp()),  # Issued at
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),  # Expires
        "jti": secrets.token_urlsafe(16),  # Unique token ID for revocation
        "type": TokenType.ACCESS.value
    }
    
    if tenant_id:
        payload["tenant_id"] = tenant_id
    
    require_jwt()
    return jwt.encode(payload, get_jwt_secret(), algorithm=_JWT_ALGORITHM)


def create_refresh_token(
    user_id: int,
    tenant_id: Optional[str] = None,
    expires_in: int = 604800  # 7 days
) -> str:
    """
    Create a JWT refresh token.
    
    Args:
        user_id: User ID
        tenant_id: Optional tenant ID
        expires_in: Token expiration in seconds (default: 7 days)
        
    Returns:
        Encoded JWT refresh token string
    """
    now = datetime.utcnow()
    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "jti": secrets.token_urlsafe(16),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
        "type": TokenType.REFRESH.value
    }
    
    if tenant_id:
        payload["tenant_id"] = tenant_id
    
    require_jwt()
    return jwt.encode(payload, get_jwt_secret(), algorithm=_JWT_ALGORITHM)


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode and validate a JWT token.
    
    Args:
        token: JWT token string
        
    Returns:
        Decoded payload dict, or None if invalid/expired
    """
    require_jwt()
    try:
        payload = jwt.decode(
            token,
            get_jwt_secret(),
            algorithms=[_JWT_ALGORITHM]
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_token_type(payload: Dict[str, Any]) -> Optional[TokenType]:
    """Get token type from payload."""
    token_type = payload.get("type")
    if token_type == TokenType.ACCESS.value:
        return TokenType.ACCESS
    elif token_type == TokenType.REFRESH.value:
        return TokenType.REFRESH
    return None

