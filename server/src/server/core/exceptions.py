"""
Custom exception classes for UEBA platform.
"""


class UEBAException(Exception):
    """Base exception for UEBA platform."""
    pass


class AuthenticationError(UEBAException):
    """Authentication failed."""
    pass


class AuthorizationError(UEBAException):
    """Authorization failed - insufficient permissions."""
    pass


class ValidationError(UEBAException):
    """Input validation failed."""
    pass


class NotFoundError(UEBAException):
    """Resource not found."""
    pass


class ConflictError(UEBAException):
    """Resource conflict (e.g., duplicate username)."""
    pass

