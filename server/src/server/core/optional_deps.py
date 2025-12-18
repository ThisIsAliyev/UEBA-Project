"""
Centralized Optional Dependency Management for UEBA Platform.

This module provides a single source of truth for optional dependency
availability checks. All optional dependencies (bcrypt, PyJWT, TensorFlow)
are handled here to avoid duplication and ensure consistent error handling.

Usage:
    from .core.optional_deps import require_bcrypt, require_jwt, require_tf
    
    # In endpoint handlers:
    @router.post("/login")
    def login():
        require_bcrypt()  # Raises HTTPException(503) if missing
        ...

Dependencies are checked at import time but only raise errors when
actually used, allowing the server to boot without them installed.
"""

import logging
from typing import Dict, Any, Optional

from fastapi import HTTPException

logger = logging.getLogger(__name__)

# =============================================================================
# BCRYPT - Password Hashing
# =============================================================================

BCRYPT_AVAILABLE: bool = False
bcrypt: Optional[Any] = None

try:
    import bcrypt as _bcrypt
    bcrypt = _bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    logger.warning(
        "bcrypt not installed. Password authentication features will be unavailable. "
        "Install with: pip install bcrypt"
    )


def require_bcrypt() -> None:
    """
    Require bcrypt to be available. Call at start of any endpoint needing bcrypt.
    
    Raises:
        HTTPException: 503 Service Unavailable if bcrypt is not installed
    """
    if not BCRYPT_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="bcrypt is required for password hashing but is not installed. "
                   "Install with: pip install bcrypt"
        )


# =============================================================================
# PYJWT - JSON Web Tokens
# =============================================================================

JWT_AVAILABLE: bool = False
jwt: Optional[Any] = None

try:
    import jwt as _jwt
    jwt = _jwt
    JWT_AVAILABLE = True
except ImportError:
    logger.warning(
        "PyJWT not installed. JWT authentication features will be unavailable. "
        "Install with: pip install PyJWT"
    )


def require_jwt() -> None:
    """
    Require PyJWT to be available. Call at start of any endpoint needing JWT.
    
    Raises:
        HTTPException: 503 Service Unavailable if PyJWT is not installed
    """
    if not JWT_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="PyJWT is required for JWT authentication but is not installed. "
                   "Install with: pip install PyJWT"
        )


# =============================================================================
# TENSORFLOW - Machine Learning
# =============================================================================

TF_AVAILABLE: bool = False
# Note: We do NOT import tensorflow here to avoid slow startup.
# We only check if it's importable.

try:
    import importlib.util
    _tf_spec = importlib.util.find_spec("tensorflow")
    TF_AVAILABLE = _tf_spec is not None
    if not TF_AVAILABLE:
        logger.warning(
            "TensorFlow not installed. ML model features will be unavailable. "
            "Install with: pip install tensorflow"
        )
except Exception:
    logger.warning(
        "TensorFlow not installed. ML model features will be unavailable. "
        "Install with: pip install tensorflow"
    )


def require_tf() -> None:
    """
    Require TensorFlow to be available. Call at start of any ML endpoint.
    
    Raises:
        HTTPException: 503 Service Unavailable if TensorFlow is not installed
    """
    if not TF_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="TensorFlow is required for ML features but is not installed. "
                   "Install with: pip install tensorflow"
        )


def get_tensorflow():
    """
    Lazily import and return TensorFlow module.
    Call require_tf() first to get proper HTTP error handling.
    
    Returns:
        The tensorflow module
        
    Raises:
        ImportError: If TensorFlow is not installed
    """
    import tensorflow as tf
    return tf


# =============================================================================
# DEPENDENCY STATUS FOR HEALTH CHECKS
# =============================================================================

def deps_status() -> Dict[str, Any]:
    """
    Get status of all optional dependencies for health checks.
    
    Returns:
        Dict with availability status and messages for each optional dependency
    """
    return {
        "bcrypt": {
            "available": BCRYPT_AVAILABLE,
            "feature": "Password authentication",
            "install": "pip install bcrypt"
        },
        "jwt": {
            "available": JWT_AVAILABLE,
            "feature": "JWT authentication", 
            "install": "pip install PyJWT"
        },
        "tensorflow": {
            "available": TF_AVAILABLE,
            "feature": "ML anomaly detection",
            "install": "pip install tensorflow"
        }
    }


def all_optional_deps_available() -> bool:
    """Check if all optional dependencies are available."""
    return BCRYPT_AVAILABLE and JWT_AVAILABLE and TF_AVAILABLE


def core_deps_available() -> bool:
    """Check if core auth dependencies (bcrypt + jwt) are available."""
    return BCRYPT_AVAILABLE and JWT_AVAILABLE


# =============================================================================
# CUSTOM EXCEPTION FOR NON-HTTP CONTEXTS
# =============================================================================

class MissingOptionalDependency(Exception):
    """
    Exception for missing optional dependencies in non-HTTP contexts.
    
    This should be caught by app-level exception handlers and converted
    to HTTPException(503) when in a request context.
    """
    def __init__(self, dependency: str, feature: str, install_cmd: str):
        self.dependency = dependency
        self.feature = feature
        self.install_cmd = install_cmd
        super().__init__(
            f"{dependency} is required for {feature} but is not installed. "
            f"Install with: {install_cmd}"
        )
