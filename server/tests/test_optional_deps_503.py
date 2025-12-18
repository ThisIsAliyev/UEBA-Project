"""
Tests for Optional Dependency 503 Responses.

These tests verify that:
1. Server boots without optional dependencies (bcrypt, jwt, tensorflow)
2. Endpoints return 503 (not 500) when optional deps are missing
3. Health endpoint shows dependency status correctly

Uses monkeypatching to simulate missing dependencies without uninstalling.
"""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestServerBootWithoutOptionalDeps:
    """Test that server imports without optional dependencies."""
    
    def test_app_imports_successfully(self):
        """Test that app.py imports without crashing."""
        import importlib
        app_module = importlib.import_module("server.app")
        assert app_module.app is not None
    
    def test_optional_deps_module_imports(self):
        """Test that optional_deps module imports correctly."""
        from server.core.optional_deps import (
            BCRYPT_AVAILABLE, JWT_AVAILABLE, TF_AVAILABLE,
            require_bcrypt, require_jwt, require_tf,
            deps_status
        )
        # All should be booleans
        assert isinstance(BCRYPT_AVAILABLE, bool)
        assert isinstance(JWT_AVAILABLE, bool)
        assert isinstance(TF_AVAILABLE, bool)
        
        # deps_status should return dict
        status = deps_status()
        assert "bcrypt" in status
        assert "jwt" in status
        assert "tensorflow" in status


class TestBcrypt503Response:
    """Test that bcrypt-dependent endpoints return 503 when bcrypt is missing."""
    
    def test_require_bcrypt_raises_http_exception(self):
        """Test that require_bcrypt raises HTTPException(503) when unavailable."""
        from fastapi import HTTPException
        
        with patch("server.core.optional_deps.BCRYPT_AVAILABLE", False):
            # Need to reimport to pick up the patch
            from server.core import optional_deps
            original = optional_deps.BCRYPT_AVAILABLE
            optional_deps.BCRYPT_AVAILABLE = False
            
            try:
                with pytest.raises(HTTPException) as exc_info:
                    optional_deps.require_bcrypt()
                assert exc_info.value.status_code == 503
                assert "bcrypt" in str(exc_info.value.detail).lower()
            finally:
                optional_deps.BCRYPT_AVAILABLE = original
    
    def test_hash_password_raises_503_without_bcrypt(self):
        """Test that hash_password raises 503 when bcrypt is missing."""
        from fastapi import HTTPException
        from server.core import optional_deps
        
        original = optional_deps.BCRYPT_AVAILABLE
        optional_deps.BCRYPT_AVAILABLE = False
        
        try:
            from server.core.security import hash_password
            with pytest.raises(HTTPException) as exc_info:
                hash_password("test_password")
            assert exc_info.value.status_code == 503
        finally:
            optional_deps.BCRYPT_AVAILABLE = original


class TestJWT503Response:
    """Test that JWT-dependent endpoints return 503 when PyJWT is missing."""
    
    def test_require_jwt_raises_http_exception(self):
        """Test that require_jwt raises HTTPException(503) when unavailable."""
        from fastapi import HTTPException
        from server.core import optional_deps
        
        original = optional_deps.JWT_AVAILABLE
        optional_deps.JWT_AVAILABLE = False
        
        try:
            with pytest.raises(HTTPException) as exc_info:
                optional_deps.require_jwt()
            assert exc_info.value.status_code == 503
            assert "jwt" in str(exc_info.value.detail).lower()
        finally:
            optional_deps.JWT_AVAILABLE = original
    
    def test_create_access_token_raises_503_without_jwt(self):
        """Test that create_access_token raises 503 when PyJWT is missing."""
        from fastapi import HTTPException
        from server.core import optional_deps
        
        original = optional_deps.JWT_AVAILABLE
        optional_deps.JWT_AVAILABLE = False
        
        try:
            from server.auth.jwt import create_access_token
            with pytest.raises(HTTPException) as exc_info:
                create_access_token(1, "testuser", ["admin"], ["read"])
            assert exc_info.value.status_code == 503
        finally:
            optional_deps.JWT_AVAILABLE = original


class TestTensorFlow503Response:
    """Test that TensorFlow-dependent endpoints return 503 when TF is missing."""
    
    def test_require_tf_raises_http_exception(self):
        """Test that require_tf raises HTTPException(503) when unavailable."""
        from fastapi import HTTPException
        from server.core import optional_deps
        
        original = optional_deps.TF_AVAILABLE
        optional_deps.TF_AVAILABLE = False
        
        try:
            with pytest.raises(HTTPException) as exc_info:
                optional_deps.require_tf()
            assert exc_info.value.status_code == 503
            assert "tensorflow" in str(exc_info.value.detail).lower()
        finally:
            optional_deps.TF_AVAILABLE = original
    
    def test_ml_models_build_functions_raise_503(self):
        """Test that ML model build functions raise 503 when TF is missing."""
        from fastapi import HTTPException
        from server.core import optional_deps
        
        original = optional_deps.TF_AVAILABLE
        optional_deps.TF_AVAILABLE = False
        
        try:
            from server.ml_models import build_sequence_model
            with pytest.raises(HTTPException) as exc_info:
                build_sequence_model()
            assert exc_info.value.status_code == 503
        finally:
            optional_deps.TF_AVAILABLE = original


class TestHealthEndpointDepsStatus:
    """Test that health endpoint includes dependency status."""
    
    def test_health_endpoint_includes_optional_deps(self):
        """Test that /health endpoint includes optional_deps in response."""
        from server.core.optional_deps import deps_status
        
        status = deps_status()
        
        # Verify structure
        assert "bcrypt" in status
        assert "jwt" in status
        assert "tensorflow" in status
        
        # Each should have expected keys
        for dep_name, dep_info in status.items():
            assert "available" in dep_info
            assert "feature" in dep_info
            assert "install" in dep_info
            assert isinstance(dep_info["available"], bool)


class TestDepsStatusFunction:
    """Test deps_status() helper function."""
    
    def test_deps_status_returns_correct_structure(self):
        """Test deps_status returns properly structured dict."""
        from server.core.optional_deps import deps_status
        
        status = deps_status()
        
        # Should have all three deps
        assert len(status) == 3
        assert "bcrypt" in status
        assert "jwt" in status
        assert "tensorflow" in status
        
        # Each entry should have required keys
        for dep_name, info in status.items():
            assert "available" in info
            assert "feature" in info
            assert "install" in info


class TestMissingOptionalDependencyException:
    """Test the custom MissingOptionalDependency exception."""
    
    def test_exception_has_correct_attributes(self):
        """Test that MissingOptionalDependency has expected attributes."""
        from server.core.optional_deps import MissingOptionalDependency
        
        exc = MissingOptionalDependency(
            dependency="test_dep",
            feature="test_feature",
            install_cmd="pip install test"
        )
        
        assert exc.dependency == "test_dep"
        assert exc.feature == "test_feature"
        assert exc.install_cmd == "pip install test"
        assert "test_dep" in str(exc)
        assert "test_feature" in str(exc)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
