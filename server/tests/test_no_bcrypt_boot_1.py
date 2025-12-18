"""
Test that UEBA server imports without bcrypt/PyJWT installed.

This test ensures that bcrypt and PyJWT are optional dependencies and
the core server functionality can boot without them installed.
Auth features will fail gracefully at runtime if dependencies are missing.
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_app_imports_without_bcrypt():
    """Test that app.py imports without bcrypt."""
    import importlib
    # This should not raise ImportError
    app_module = importlib.import_module("server.app")
    assert app_module.app is not None


def test_admin_imports_without_bcrypt():
    """Test that admin module imports without bcrypt."""
    from server.admin import AdminStorage, BCRYPT_AVAILABLE
    assert AdminStorage is not None
    # BCRYPT_AVAILABLE should be a boolean
    assert isinstance(BCRYPT_AVAILABLE, bool)


def test_security_imports_without_bcrypt():
    """Test that core.security imports without bcrypt."""
    from server.core.optional_deps import BCRYPT_AVAILABLE
    from server.core.security import hash_password, verify_password
    assert isinstance(BCRYPT_AVAILABLE, bool)
    
    # If bcrypt is not available, functions should raise HTTPException(503)
    if not BCRYPT_AVAILABLE:
        import pytest
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            hash_password("test")
        assert exc_info.value.status_code == 503


def test_jwt_imports_without_pyjwt():
    """Test that auth.jwt imports without PyJWT."""
    from server.core.optional_deps import JWT_AVAILABLE
    from server.auth.jwt import create_access_token
    assert isinstance(JWT_AVAILABLE, bool)
    
    # If JWT is not available, functions should raise HTTPException(503)
    if not JWT_AVAILABLE:
        import pytest
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            create_access_token(1, "test", [], [])
        assert exc_info.value.status_code == 503


def test_storage_imports():
    """Test that storage module imports correctly."""
    from server.storage import EventStorage, get_storage
    assert EventStorage is not None


def test_models_imports():
    """Test that models (schemas) import correctly."""
    from server.models import NormalizedEvent, Alert, EventCategory
    assert NormalizedEvent is not None
    assert Alert is not None


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
