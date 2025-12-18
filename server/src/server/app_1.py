"""
FastAPI Web Application for UEBA Server.

Provides REST API and WebSocket endpoints for the dashboard.
Includes authentication, onboarding, and endpoint management.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Optional, List, Set
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException, Form, Cookie, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from starlette.responses import Response
from pydantic import BaseModel

from .config import get_config, load_config, set_config
from .storage import EventStorage, get_storage, set_storage
from .models import NormalizedEvent, EventResponse, EventStats, Alert, AlertResponse, AlertStats, BEHAVIOR_LABELS, EventSource, SOURCE_LABELS, EventLevel, EventCategory
from .ingest import IngestServer, create_ingest_server
from .admin import (
    AdminStorage, get_admin_storage, set_admin_storage, 
    AVAILABLE_RULES, RULE_LABELS, User, AgentUser, ConnectedAgent
)
from .auth.jwt import (
    create_access_token, create_refresh_token, decode_token,
    get_token_type, TokenType, set_jwt_secret
)
from .core.optional_deps import deps_status, MissingOptionalDependency

logger = logging.getLogger(__name__)

# Import ML endpoints router (optional - requires TensorFlow)
try:
    from .api.ml_endpoints import router as ml_router
    ML_ENDPOINTS_AVAILABLE = True
except (ImportError, Exception) as e:
    ML_ENDPOINTS_AVAILABLE = False
    logger.warning(f"ML endpoints not available: {e}")

# Import Feedback endpoints router
try:
    from .api.feedback import router as feedback_router
    FEEDBACK_ENDPOINTS_AVAILABLE = True
except ImportError as e:
    FEEDBACK_ENDPOINTS_AVAILABLE = False
    logger.warning(f"Feedback endpoints not available: {e}")

# Import UEBA endpoints router
try:
    from .api.ueba_endpoints import router as ueba_router
    UEBA_ENDPOINTS_AVAILABLE = True
except ImportError as e:
    UEBA_ENDPOINTS_AVAILABLE = False
    logger.warning(f"UEBA endpoints not available: {e}")

# FastAPI application
app = FastAPI(
    title="UEBA Event Viewer",
    description="Real-time Sysmon Event Dashboard",
    version="1.0.0"
)


# ============================================
# Global Exception Handlers for Optional Dependencies
# ============================================

@app.exception_handler(MissingOptionalDependency)
async def missing_optional_dep_handler(request, exc: MissingOptionalDependency):
    """Convert MissingOptionalDependency to HTTP 503 response."""
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=503,
        content={
            "detail": str(exc),
            "dependency": exc.dependency,
            "feature": exc.feature,
            "install": exc.install_cmd
        }
    )


# ============================================
# Security Headers Middleware
# ============================================

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # HSTS (only if using HTTPS)
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    # Content Security Policy - Allow CDN for Chart.js and Google Fonts
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "img-src 'self' data:; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self'"
    )
    
    # Referrer Policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Remove server header (MutableHeaders doesn't have pop method)
    try:
        del response.headers["server"]
    except KeyError:
        pass
    
    return response


# Template directory
TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

# Static files directory
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# JWT token cookie names
ACCESS_TOKEN_COOKIE = "ueba_access_token"
REFRESH_TOKEN_COOKIE = "ueba_refresh_token"

# Legacy session cookie (for backward compatibility during migration)
SESSION_COOKIE = "ueba_session"


# ============================================
# JWT Authentication Helpers
# ============================================

def get_jwt_token_from_request(request: Request) -> Optional[str]:
    """
    Get JWT token from request (Authorization header or cookie).
    
    Checks Authorization header first, then falls back to cookie.
    """
    # Check Authorization header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.replace("Bearer ", "")
    
    # Check cookie
    token = request.cookies.get(ACCESS_TOKEN_COOKIE)
    return token


def get_current_user_jwt(
    access_token: Optional[str] = None,
    request: Optional[Request] = None
) -> Optional[User]:
    """
    Get current user from JWT access token.
    
    Args:
        access_token: JWT token string (optional, will be extracted from request if not provided)
        request: FastAPI request object (used if access_token not provided)
        
    Returns:
        User object if token is valid, None otherwise
    """
    # Get token from request if not provided
    if not access_token and request:
        access_token = get_jwt_token_from_request(request)
    
    if not access_token:
        return None
    
    # Decode and validate token
    payload = decode_token(access_token)
    if not payload:
        return None
    
    # Check token type
    token_type = get_token_type(payload)
    if token_type != TokenType.ACCESS:
        return None
    
    # Get user from database
    try:
        user_id = int(payload.get("sub"))
        admin_storage = get_admin_storage()
        user = admin_storage.get_user(user_id)
        return user
    except (ValueError, TypeError, AttributeError):
        return None


def require_auth_jwt(
    request: Request,
    access_token: Optional[str] = None
) -> User:
    """
    Require JWT authentication, raise 401 if not authenticated.
    
    Args:
        request: FastAPI request object
        access_token: Optional JWT token (will be extracted from request if not provided)
        
    Returns:
        User object if authenticated
        
    Raises:
        HTTPException(401) if not authenticated
    """
    user = get_current_user_jwt(access_token, request)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user


# Legacy session-based auth (for backward compatibility)
def get_current_user(session_token: Optional[str] = Cookie(None, alias=SESSION_COOKIE)) -> Optional[User]:
    """Get current user from session cookie (legacy, use get_current_user_jwt instead)."""
    if not session_token:
        return None
    admin_storage = get_admin_storage()
    return admin_storage.validate_session(session_token)


def require_auth(request: Request, session_token: Optional[str] = Cookie(None, alias=SESSION_COOKIE)) -> User:
    """Require authentication (legacy session-based, use require_auth_jwt instead)."""
    # Try JWT first
    user = get_current_user_jwt(request=request)
    if user:
        return user
    
    # Fall back to session cookie
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

# WebSocket connection manager
class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""
    
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)
            logger.info(f"WebSocket connected. Total: {len(self.active_connections)}")
    
    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            self.active_connections.discard(websocket)
            logger.info(f"WebSocket disconnected. Total: {len(self.active_connections)}")
    
    async def broadcast_event(self, event: NormalizedEvent):
        """Broadcast a new event to all connected clients."""
        # Take snapshot of connections to avoid iteration during modification
        async with self._lock:
            if not self.active_connections:
                return
            connections = list(self.active_connections)
        
        # Serialize event to JSON
        event_data = event.model_dump()
        # Convert datetime objects to strings
        event_data['timestamp'] = event.timestamp.isoformat()
        event_data['ingested_at'] = event.ingested_at.isoformat()
        
        message = json.dumps({"type": "new_event", "event": event_data})
        
        # Send to all connections (outside lock to avoid blocking)
        disconnected = set()
        for connection in connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.warning(f"Failed to send to WebSocket: {e!r}", exc_info=True)
                disconnected.add(connection)
        
        # Remove disconnected clients
        if disconnected:
            async with self._lock:
                self.active_connections -= disconnected
    
    async def broadcast_alert(self, alert):
        """Broadcast a new alert to all connected clients."""
        # Take snapshot of connections to avoid iteration during modification
        async with self._lock:
            if not self.active_connections:
                return
            connections = list(self.active_connections)
        
        # Serialize alert to JSON
        alert_data = alert.model_dump()
        # Convert datetime objects to strings
        alert_data['timestamp'] = alert.timestamp.isoformat()
        
        message = json.dumps({"type": "new_alert", "alert": alert_data})
        
        # Send to all connections (outside lock to avoid blocking)
        disconnected = set()
        for connection in connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.warning(f"Failed to send alert to WebSocket: {e!r}", exc_info=True)
                disconnected.add(connection)
        
        # Remove disconnected clients
        if disconnected:
            async with self._lock:
                self.active_connections -= disconnected


# Global connection manager
manager = ConnectionManager()

# Global ingest server reference
ingest_server: Optional[IngestServer] = None


async def on_new_event(event: NormalizedEvent):
    """Callback for new events - broadcasts to WebSocket clients."""
    await manager.broadcast_event(event)


async def on_new_alert(alert):
    """Callback for new alerts - broadcasts to WebSocket clients."""
    await manager.broadcast_alert(alert)


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    global ingest_server
    
    # Load configuration
    try:
        config = load_config()
        set_config(config)
    except FileNotFoundError:
        logger.warning("Config file not found, using defaults")
        from .config import (
            ServerConfig, DatabaseConfig, LoggingConfig, WebUIConfig, 
            TLSConfig, SchedulerConfig, UEBAConfig, SIEMConfig
        )
        config = ServerConfig(
            ingest_port=9000,
            web_port=8080,
            database=DatabaseConfig(path="data/events.db", max_events=100000),
            logging=LoggingConfig(level="INFO", file=None),
            web_ui=WebUIConfig(events_per_page=100, refresh_interval_ms=2000),
            tls=TLSConfig(enabled=False, cert_path="config/server.crt", key_path="config/server.key"),
            scheduler=SchedulerConfig(
                enabled=True,
                baseline_interval_minutes=360,
                session_interval_minutes=60,
                model_train_interval_hours=24,
                baseline_lookback_days=14
            ),
            ueba=UEBAConfig(
                anomaly_alerts_enabled=True,
                anomaly_alert_threshold=70,
                enrichment_enabled=True,
                enrichment_min_score=40,
                enrichment_max_score=75
            ),
            learning_mode=False,
            min_entity_age_days=3,
            siem=None,  # SIEM config optional
            root_dir=Path(__file__).parent.parent.parent
        )
        set_config(config)
    
    # Initialize storage
    db_path = str(config.root_dir / config.database.path)
    storage = EventStorage(db_path)
    set_storage(storage)
    
    # Initialize admin storage (uses same DB path)
    admin_storage = AdminStorage(db_path)
    set_admin_storage(admin_storage)
    logger.info("Admin storage initialized")
    
    # Set JWT secret from environment or generate one
    jwt_secret = os.getenv("JWT_SECRET")
    if jwt_secret:
        set_jwt_secret(jwt_secret)
        logger.info("JWT secret loaded from environment")
    else:
        # Generate and log (in production, should be set via environment variable)
        logger.warning("JWT_SECRET not set in environment - using generated secret (tokens will be invalid on restart)")
    
    # Create and start ingest server
    ingest_server = create_ingest_server(
        host="0.0.0.0",
        port=config.ingest_port,
        storage=storage,
        on_event=on_new_event,
        on_alert=on_new_alert
    )
    
    # Start ingest server in background with error handling
    async def start_ingest_with_retry():
        """Start ingest server with error logging."""
        try:
            await ingest_server.start()
        except OSError as e:
            if e.errno == 10048:  # Windows: Address already in use
                logger.error(f"Ingest port {config.ingest_port} already in use. Kill existing process or use different port.")
            else:
                logger.error(f"Failed to start ingest server: {e}")
        except Exception as e:
            logger.error(f"Ingest server error: {e}")
    
    asyncio.create_task(start_ingest_with_retry())
    logger.info(f"Starting ingest server on port {config.ingest_port}...")
    
    # Start background scheduler for UEBA tasks
    try:
        from .scheduler import start_scheduler, run_initial_jobs_if_needed
        scheduler = start_scheduler()
        if scheduler:
            logger.info("UEBA background scheduler started")
            # Run initial jobs if no baseline data exists
            asyncio.create_task(run_initial_jobs_if_needed())
        else:
            logger.warning("UEBA scheduler not started (disabled or APScheduler not available)")
    except Exception as e:
        logger.warning(f"Failed to start UEBA scheduler: {e}")
    
    # Initialize SIEM exporter (non-blocking - failures won't prevent server startup)
    try:
        from .siem.export import create_siem_exporter
        siem_config_dict = {}
        if config.siem:
            siem_config_dict = {
                'enabled': config.siem.enabled,
                'elasticsearch_url': config.siem.elasticsearch_url,
                'use_logstash': config.siem.use_logstash,
                'logstash_url': config.siem.logstash_url,
                'batch_size': config.siem.batch_size,
                'batch_interval_seconds': config.siem.batch_interval_seconds,
                'timeout_seconds': config.siem.timeout_seconds,
                'es_username': config.siem.es_username,
                'es_password': config.siem.es_password,
                'export_events': config.siem.export_events,
                'export_alerts': config.siem.export_alerts,
                'tls_verify': config.siem.tls_verify,
                'ca_cert_path': config.siem.ca_cert_path,
                'index_events': config.siem.index_events,
                'index_alerts': config.siem.index_alerts
            }
            # Log SIEM configuration status
            if config.siem.enabled:
                logger.info(f"SIEM export enabled: URL={config.siem.elasticsearch_url}")
                if config.siem.es_username and config.siem.es_password:
                    logger.info(f"SIEM authentication: username={config.siem.es_username}, password=SET")
                elif config.siem.es_username:
                    logger.error("SIEM authentication: Username set but password is missing!")
                    logger.error("Set ES_PASSWORD environment variable")
                elif config.siem.es_password:
                    logger.error("SIEM authentication: Password set but username is missing!")
                    logger.error("Set ES_USERNAME environment variable")
                else:
                    logger.warning("SIEM authentication: No credentials configured!")
                    logger.warning("Set ES_USERNAME and ES_PASSWORD environment variables if Elasticsearch requires authentication")
        exporter = create_siem_exporter(siem_config_dict)
        if exporter:
            await exporter.start()
            logger.info("SIEM exporter started successfully")
        else:
            logger.info("SIEM export disabled or not configured")
    except Exception as e:
        logger.error(f"SIEM exporter initialization failed (server will continue): {e}", exc_info=True)
        logger.warning("Events will still be stored in database, but SIEM export is disabled")


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up on shutdown."""
    global ingest_server
    if ingest_server:
        await ingest_server.stop()
    
    # Stop background scheduler
    try:
        from .scheduler import stop_scheduler
        stop_scheduler()
        logger.info("UEBA background scheduler stopped")
    except Exception as e:
        logger.warning(f"Error stopping scheduler: {e}")
    
    # Stop SIEM exporter
    try:
        from .siem.export import get_siem_exporter
        exporter = get_siem_exporter()
        if exporter:
            await exporter.stop()
            logger.info("SIEM exporter stopped")
    except Exception as e:
        logger.warning(f"SIEM exporter shutdown error: {e}")


# ============================================
# Authentication Routes
# ============================================

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[str] = None):
    """Login page."""
    # If already logged in, redirect appropriately
    session_token = request.cookies.get(SESSION_COOKIE)
    if session_token:
        user = get_current_user(session_token)
        if user:
            admin_storage = get_admin_storage()
            if admin_storage.is_setup_completed():
                return RedirectResponse(url="/", status_code=302)
            else:
                return RedirectResponse(url="/onboarding", status_code=302)
    
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": error}
    )


@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(..., max_length=255),
    password: str = Form(..., max_length=512)
):
    """Handle login form submission - returns JWT tokens."""
    admin_storage = get_admin_storage()
    user = admin_storage.authenticate(username, password)
    
    if not user:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid username or password"}
        )
    
    # Create JWT tokens (access token: 15 minutes, refresh token: 7 days)
    # For now, default role is "admin" (RBAC will be added in next task)
    access_token = create_access_token(
        user_id=user.id,
        username=user.username,
        roles=["admin"],  # Default role, will be from DB in RBAC task
        permissions=["*"],  # All permissions for admin
        expires_in=900  # 15 minutes
    )
    
    refresh_token = create_refresh_token(
        user_id=user.id,
        expires_in=604800  # 7 days
    )
    
    # Also create legacy session for backward compatibility (can be removed after full JWT migration)
    session_token = admin_storage.create_session(user.id)
    
    # Redirect based on setup status
    if admin_storage.is_setup_completed():
        response = RedirectResponse(url="/", status_code=302)
    else:
        response = RedirectResponse(url="/onboarding", status_code=302)
    
    # Determine if we should use secure cookies (HTTPS only)
    use_secure_cookies = os.getenv("SECURE_COOKIES", "false").lower() == "true"
    
    # Set JWT tokens as cookies
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=access_token,
        httponly=True,
        secure=use_secure_cookies,
        max_age=900,  # 15 minutes
        samesite="strict"
    )
    
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE,
        value=refresh_token,
        httponly=True,
        secure=use_secure_cookies,
        max_age=604800,  # 7 days
        samesite="strict"
    )
    
    # Also set legacy session cookie for backward compatibility
    response.set_cookie(
        key=SESSION_COOKIE,
        value=session_token,
        httponly=True,
        secure=use_secure_cookies,
        max_age=86400,  # 24 hours
        samesite="strict"
    )
    
    return response


@app.post("/api/auth/refresh")
async def refresh_token(request: Request):
    """
    Refresh access token using refresh token.
    
    Returns new access token if refresh token is valid.
    """
    refresh_token_value = request.cookies.get(REFRESH_TOKEN_COOKIE)
    if not refresh_token_value:
        # Try Authorization header
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            refresh_token_value = auth_header.replace("Bearer ", "")
    
    if not refresh_token_value:
        raise HTTPException(status_code=401, detail="No refresh token provided")
    
    # Decode and validate refresh token
    payload = decode_token(refresh_token_value)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    
    # Check token type
    token_type = get_token_type(payload)
    if token_type != TokenType.REFRESH:
        raise HTTPException(status_code=401, detail="Invalid token type")
    
    # Get user
    try:
        user_id = int(payload.get("sub"))
        admin_storage = get_admin_storage()
        user = admin_storage.get_user(user_id)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid token payload")
    
    # Create new access token
    # For now, default role is "admin" (RBAC will be added in next task)
    new_access_token = create_access_token(
        user_id=user.id,
        username=user.username,
        roles=["admin"],
        permissions=["*"],
        expires_in=900  # 15 minutes
    )
    
    use_secure_cookies = os.getenv("SECURE_COOKIES", "false").lower() == "true"
    
    response = Response(status_code=200)
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=new_access_token,
        httponly=True,
        secure=use_secure_cookies,
        max_age=900,  # 15 minutes
        samesite="strict"
    )
    
    return {
        "success": True,
        "access_token": new_access_token,
        "expires_in": 900
    }


@app.get("/logout")
async def logout(request: Request):
    """Logout and clear JWT tokens and session."""
    # Clear legacy session
    session_token = request.cookies.get(SESSION_COOKIE)
    if session_token:
        admin_storage = get_admin_storage()
        admin_storage.delete_session(session_token)
    
    # Determine secure flag for cookie deletion (must match creation)
    use_secure_cookies = os.getenv("SECURE_COOKIES", "false").lower() == "true"
    
    response = RedirectResponse(url="/login", status_code=302)
    
    # Delete JWT cookies
    response.delete_cookie(
        ACCESS_TOKEN_COOKIE,
        httponly=True,
        secure=use_secure_cookies,
        samesite="strict"
    )
    response.delete_cookie(
        REFRESH_TOKEN_COOKIE,
        httponly=True,
        secure=use_secure_cookies,
        samesite="strict"
    )
    
    # Delete legacy session cookie
    response.delete_cookie(
        SESSION_COOKIE,
        httponly=True,
        secure=use_secure_cookies,
        samesite="strict"
    )
    
    return response


# ============================================
# Onboarding Routes
# ============================================

@app.get("/onboarding", response_class=HTMLResponse)
async def onboarding_page(request: Request):
    """Onboarding wizard page."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    
    return templates.TemplateResponse(
        "onboarding.html",
        {"request": request, "user": user}
    )


@app.post("/onboarding/workstation")
async def onboarding_workstation(
    request: Request,
    os_type: str = Form(..., max_length=50)
):
    """Handle workstation selection in onboarding."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    
    # Redirect to agent users page to create credentials
    return RedirectResponse(url="/agent-users?onboarding=1", status_code=302)


# ============================================
# Endpoint Management Routes
# ============================================

@app.get("/endpoints", response_class=HTMLResponse)
async def endpoints_page(
    request: Request,
    os_type: Optional[str] = None,
    onboarding: Optional[int] = None
):
    """Endpoint management page - shows connected agents."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    
    admin_storage = get_admin_storage()
    admin_storage.update_agent_status()  # Update agent statuses
    connected_agents = admin_storage.get_connected_agents()
    groups = admin_storage.get_groups()
    endpoint_stats = admin_storage.get_endpoint_stats()
    
    return templates.TemplateResponse(
        "endpoints.html",
        {
            "request": request,
            "user": user,
            "connected_agents": connected_agents,
            "groups": groups,
            "endpoint_stats": endpoint_stats,
            "default_os_type": os_type or "windows",
            "is_onboarding": bool(onboarding),
            "available_rules": AVAILABLE_RULES,
            "rule_labels": RULE_LABELS,
            "show_filters": False
        }
    )


@app.post("/api/endpoints")
async def create_endpoint(
    request: Request,
    name: str = Form(..., max_length=255),
    host_or_ip: str = Form(..., max_length=255),
    endpoint_type: str = Form("workstation", max_length=50),
    os_type: str = Form("windows", max_length=50),
    username: str = Form("", max_length=255),
    password: str = Form("", max_length=512),
    group_id: Optional[int] = Form(None)
):
    """Create a new endpoint."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    admin_storage = get_admin_storage()
    endpoint_id = admin_storage.create_endpoint(
        name=name,
        host_or_ip=host_or_ip,
        endpoint_type=endpoint_type,
        os_type=os_type,
        username=username,
        password=password,
        group_id=group_id if group_id and group_id > 0 else None
    )
    
    # Mark setup as completed if this is the first endpoint
    if not admin_storage.is_setup_completed():
        admin_storage.mark_setup_completed(user.id)
    
    return {"success": True, "endpoint_id": endpoint_id}


@app.get("/api/endpoints")
async def get_endpoints(
    request: Request,
    endpoint_type: Optional[str] = None
):
    """Get all endpoints."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    admin_storage = get_admin_storage()
    endpoints = admin_storage.get_endpoints(endpoint_type=endpoint_type)
    
    return {
        "endpoints": [
            {
                "id": e.id,
                "name": e.name,
                "host_or_ip": e.host_or_ip,
                "endpoint_type": e.endpoint_type,
                "os_type": e.os_type,
                "group_id": e.group_id,
                "group_name": e.group_name,
                "created_at": e.created_at
            }
            for e in endpoints
        ]
    }


@app.get("/api/endpoints/{endpoint_id}")
async def get_endpoint_detail(
    request: Request,
    endpoint_id: int
):
    """Get endpoint details including rules."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    admin_storage = get_admin_storage()
    endpoint = admin_storage.get_endpoint(endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    
    rules = admin_storage.get_effective_rules(endpoint_id)
    controlled_by = admin_storage.is_rule_controlled_by_group(endpoint_id)
    
    return {
        "endpoint": {
            "id": endpoint.id,
            "name": endpoint.name,
            "host_or_ip": endpoint.host_or_ip,
            "endpoint_type": endpoint.endpoint_type,
            "os_type": endpoint.os_type,
            "username": endpoint.username,
            "group_id": endpoint.group_id,
            "group_name": endpoint.group_name,
            "created_at": endpoint.created_at
        },
        "rules": rules,
        "rule_labels": RULE_LABELS,
        "controlled_by_group": controlled_by
    }


@app.put("/api/endpoints/{endpoint_id}")
async def update_endpoint(
    request: Request,
    endpoint_id: int
):
    """Update endpoint."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    body = await request.json()
    admin_storage = get_admin_storage()
    
    success = admin_storage.update_endpoint(endpoint_id, **body)
    if not success:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    
    return {"success": True}


@app.delete("/api/endpoints/{endpoint_id}")
async def delete_endpoint(
    request: Request,
    endpoint_id: int
):
    """Delete endpoint."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    admin_storage = get_admin_storage()
    success = admin_storage.delete_endpoint(endpoint_id)
    if not success:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    
    return {"success": True}


@app.post("/api/endpoints/{endpoint_id}/assign-group")
async def assign_endpoint_to_group(
    request: Request,
    endpoint_id: int
):
    """Assign endpoint to a group."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    body = await request.json()
    group_id = body.get("group_id")
    
    admin_storage = get_admin_storage()
    success = admin_storage.assign_endpoint_to_group(
        endpoint_id, 
        group_id if group_id and group_id > 0 else None
    )
    
    return {"success": success}


@app.put("/api/endpoints/{endpoint_id}/rules")
async def update_endpoint_rules(
    request: Request,
    endpoint_id: int
):
    """Update endpoint rules."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    body = await request.json()
    admin_storage = get_admin_storage()
    
    # Check if controlled by group
    if admin_storage.is_rule_controlled_by_group(endpoint_id):
        raise HTTPException(status_code=400, detail="Rules are controlled by group")
    
    admin_storage.set_endpoint_rules(endpoint_id, body)
    return {"success": True}


# ============================================
# Group Management Routes
# ============================================

@app.post("/api/groups")
async def create_group(
    request: Request,
    name: str = Form(..., max_length=255),
    apply_rules: bool = Form(False)
):
    """Create a new group."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    admin_storage = get_admin_storage()
    group_id = admin_storage.create_group(name=name, apply_rules=apply_rules)
    
    return {"success": True, "group_id": group_id}


@app.get("/api/groups")
async def get_groups(request: Request):
    """Get all groups."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    admin_storage = get_admin_storage()
    groups = admin_storage.get_groups()
    
    return {
        "groups": [
            {
                "id": g.id,
                "name": g.name,
                "apply_rules": g.apply_rules,
                "endpoint_count": g.endpoint_count,
                "created_at": g.created_at
            }
            for g in groups
        ]
    }


@app.get("/api/groups/{group_id}")
async def get_group_detail(
    request: Request,
    group_id: int
):
    """Get group details including rules."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    admin_storage = get_admin_storage()
    group = admin_storage.get_group(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    rules = admin_storage.get_group_rules(group_id)
    
    # Get endpoints in this group
    all_endpoints = admin_storage.get_endpoints()
    group_endpoints = [e for e in all_endpoints if e.group_id == group_id]
    
    return {
        "group": {
            "id": group.id,
            "name": group.name,
            "apply_rules": group.apply_rules,
            "endpoint_count": group.endpoint_count,
            "created_at": group.created_at
        },
        "rules": rules,
        "rule_labels": RULE_LABELS,
        "endpoints": [
            {"id": e.id, "name": e.name, "host_or_ip": e.host_or_ip}
            for e in group_endpoints
        ]
    }


@app.put("/api/groups/{group_id}")
async def update_group(
    request: Request,
    group_id: int
):
    """Update group."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    body = await request.json()
    admin_storage = get_admin_storage()
    
    success = admin_storage.update_group(group_id, **body)
    if not success:
        raise HTTPException(status_code=404, detail="Group not found")
    
    return {"success": True}


@app.put("/api/groups/{group_id}/rules")
async def update_group_rules(
    request: Request,
    group_id: int
):
    """Update group rules."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    body = await request.json()
    admin_storage = get_admin_storage()
    admin_storage.set_group_rules(group_id, body)
    
    return {"success": True}


@app.delete("/api/groups/{group_id}")
async def delete_group(
    request: Request,
    group_id: int
):
    """Delete group."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    admin_storage = get_admin_storage()
    success = admin_storage.delete_group(group_id)
    if not success:
        raise HTTPException(status_code=404, detail="Group not found")
    
    return {"success": True}


# ============================================
# Agent Users Management Routes
# ============================================

@app.get("/agent-users", response_class=HTMLResponse)
async def agent_users_page(request: Request):
    """Agent users management page."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    
    admin_storage = get_admin_storage()
    agent_users = admin_storage.get_agent_users()
    connected_agents = admin_storage.get_connected_agents()
    
    return templates.TemplateResponse(
        "agent_users.html",
        {
            "request": request,
            "user": user,
            "agent_users": agent_users,
            "connected_agents": connected_agents,
            "show_filters": False
        }
    )


@app.post("/api/agent-users")
async def create_agent_user(
    request: Request,
    username: str = Form(..., max_length=255),
    password: str = Form(..., max_length=512),
    description: str = Form("", max_length=1000)
):
    """Create a new agent user."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    admin_storage = get_admin_storage()
    
    try:
        agent_user_id = admin_storage.create_agent_user(
            username=username,
            password=password,
            description=description
        )
        return {"success": True, "agent_user_id": agent_user_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/agent-users")
async def get_agent_users_api(request: Request):
    """Get all agent users."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    admin_storage = get_admin_storage()
    agent_users = admin_storage.get_agent_users()
    
    return {
        "agent_users": [
            {
                "id": au.id,
                "username": au.username,
                "description": au.description,
                "enabled": au.enabled,
                "created_at": au.created_at
            }
            for au in agent_users
        ]
    }


@app.put("/api/agent-users/{agent_user_id}")
async def update_agent_user(
    request: Request,
    agent_user_id: int
):
    """Update agent user."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    body = await request.json()
    admin_storage = get_admin_storage()
    
    success = admin_storage.update_agent_user(agent_user_id, **body)
    if not success:
        raise HTTPException(status_code=404, detail="Agent user not found")
    
    return {"success": True}


@app.delete("/api/agent-users/{agent_user_id}")
async def delete_agent_user(
    request: Request,
    agent_user_id: int
):
    """Delete agent user."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    admin_storage = get_admin_storage()
    success = admin_storage.delete_agent_user(agent_user_id)
    if not success:
        raise HTTPException(status_code=404, detail="Agent user not found")
    
    return {"success": True}


# ============================================
# Connected Agents API Routes
# ============================================

@app.get("/api/connected-agents")
async def get_connected_agents_api(
    request: Request,
    status: Optional[str] = None
):
    """Get all connected agents."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    admin_storage = get_admin_storage()
    admin_storage.update_agent_status()  # Update statuses first
    agents = admin_storage.get_connected_agents(status=status)
    
    return {
        "agents": [
            {
                "id": a.id,
                "agent_username": a.agent_username,
                "hostname": a.hostname,
                "ip_address": a.ip_address,
                "os_type": a.os_type,
                "os_version": a.os_version,
                "agent_version": a.agent_version,
                "status": a.status,
                "last_seen": a.last_seen,
                "first_seen": a.first_seen,
                "events_sent": a.events_sent,
                "group_id": a.group_id,
                "group_name": a.group_name
            }
            for a in agents
        ]
    }


@app.get("/api/connected-agents/{agent_id}")
async def get_connected_agent_detail(
    request: Request,
    agent_id: int
):
    """Get connected agent details including rules."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    admin_storage = get_admin_storage()
    agent = admin_storage.get_connected_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    rules = admin_storage.get_agent_rules(agent_id)
    
    return {
        "agent": {
            "id": agent.id,
            "agent_username": agent.agent_username,
            "hostname": agent.hostname,
            "ip_address": agent.ip_address,
            "os_type": agent.os_type,
            "os_version": agent.os_version,
            "status": agent.status,
            "last_seen": agent.last_seen,
            "first_seen": agent.first_seen,
            "events_sent": agent.events_sent,
            "group_id": agent.group_id,
            "group_name": agent.group_name
        },
        "rules": rules,
        "rule_labels": RULE_LABELS
    }


@app.post("/api/connected-agents/{agent_id}/assign-group")
async def assign_agent_to_group(
    request: Request,
    agent_id: int
):
    """Assign agent to a group."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    body = await request.json()
    group_id = body.get("group_id")
    
    admin_storage = get_admin_storage()
    success = admin_storage.assign_agent_to_group(
        agent_id,
        group_id if group_id and group_id > 0 else None
    )
    
    return {"success": success}


@app.post("/api/connected-agents/{agent_id}/approve")
async def approve_endpoint(
    request: Request,
    agent_id: int
):
    """Approve an endpoint (change status from pending to approved)."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    admin_storage = get_admin_storage()
    success = admin_storage.approve_endpoint(agent_id)
    if not success:
        raise HTTPException(status_code=404, detail="Agent not found or not pending")
    
    return {"success": True, "message": "Endpoint approved"}


@app.post("/api/connected-agents/{agent_id}/decline")
async def decline_endpoint(
    request: Request,
    agent_id: int
):
    """Decline an endpoint (change status from pending to declined)."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    admin_storage = get_admin_storage()
    success = admin_storage.decline_endpoint(agent_id)
    if not success:
        raise HTTPException(status_code=404, detail="Agent not found or not pending")
    
    return {"success": True, "message": "Endpoint declined"}


@app.post("/api/connected-agents/{agent_id}/revoke")
async def revoke_endpoint(
    request: Request,
    agent_id: int
):
    """Revoke an endpoint (change status to revoked)."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    admin_storage = get_admin_storage()
    success = admin_storage.revoke_endpoint(agent_id)
    if not success:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return {"success": True, "message": "Endpoint revoked"}


@app.delete("/api/connected-agents/{agent_id}")
async def delete_connected_agent(
    request: Request,
    agent_id: int
):
    """Delete a connected agent."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    admin_storage = get_admin_storage()
    success = admin_storage.delete_connected_agent(agent_id)
    if not success:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return {"success": True}


# ============================================
# Agent Authentication API (for agents to call)
# ============================================

class AgentAuthRequest(BaseModel):
    username: str
    password: str
    hostname: str
    ip_address: str
    os_type: str = "windows"
    os_version: str = ""
    agent_version: str = "1.0.0"


@app.post("/api/agent/auth")
async def agent_authenticate(auth_request: AgentAuthRequest):
    """
    Authenticate an agent and get a token.
    
    This endpoint is called by the agent software when it starts.
    
    For new agents, returns status='pending' and no token - agent must wait for admin approval.
    For approved agents, returns status='approved' and a token.
    """
    admin_storage = get_admin_storage()
    
    result = admin_storage.authenticate_agent(
        username=auth_request.username,
        password=auth_request.password,
        hostname=auth_request.hostname,
        ip_address=auth_request.ip_address,
        os_type=auth_request.os_type,
        os_version=auth_request.os_version,
        agent_version=auth_request.agent_version
    )
    
    if not result:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # If agent is pending approval, return status without token
    if result.get('status') == 'pending':
        return {
            "success": True,
            "agent_id": result['agent_id'],
            "token": None,
            "status": "pending",
            "message": result.get('message', 'Waiting for admin approval')
        }
    
    # Approved agent - return token
    return {
        "success": True,
        "agent_id": result['agent_id'],
        "token": result['token'],
        "status": "approved",
        "message": "Agent authenticated successfully"
    }


@app.post("/api/agent/heartbeat")
async def agent_heartbeat(
    request: Request,
    authorization: Optional[str] = None
):
    """
    Agent heartbeat to keep connection alive.
    
    Called periodically by the agent to update last_seen.
    Also checks if agent is approved.
    """
    # Get token from header
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else None
    
    if not token:
        raise HTTPException(status_code=401, detail="No token provided")
    
    admin_storage = get_admin_storage()
    success = admin_storage.agent_heartbeat(token)
    
    if not success:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return {"success": True, "message": "Heartbeat received"}


@app.get("/api/agent/status")
async def get_agent_status(
    request: Request,
    agent_id: Optional[int] = None
):
    """
    Get agent approval status and agent user enabled status.
    
    Called by agents to check if they've been approved and if their agent user is still enabled.
    If agent_id is provided, checks that specific agent.
    Otherwise, uses token from Authorization header.
    """
    admin_storage = get_admin_storage()
    
    if agent_id:
        # Direct agent_id lookup
        agent = admin_storage.get_connected_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Check if agent user is enabled
        agent_user = admin_storage.get_agent_user(agent.agent_user_id)
        agent_user_enabled = agent_user.enabled if agent_user else False
        
        return {
            "success": True,
            "agent_id": agent.id,
            "status": agent.status,
            "approved": agent.status == "approved" and agent_user_enabled,
            "agent_user_enabled": agent_user_enabled,
            "message": "Agent user disabled" if not agent_user_enabled else None
        }
    else:
        # Token-based lookup
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else None
        
        if not token:
            raise HTTPException(status_code=401, detail="No token or agent_id provided")
        
        agent_id_from_token = admin_storage.validate_agent_token(token)
        if not agent_id_from_token:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        
        agent = admin_storage.get_connected_agent(agent_id_from_token)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Check if agent user is enabled
        agent_user = admin_storage.get_agent_user(agent.agent_user_id)
        agent_user_enabled = agent_user.enabled if agent_user else False
        
        return {
            "success": True,
            "agent_id": agent.id,
            "status": agent.status,
            "approved": agent.status == "approved" and agent_user_enabled,
            "agent_user_enabled": agent_user_enabled,
            "message": "Agent user disabled" if not agent_user_enabled else None
        }


@app.get("/api/agent/rules")
async def get_agent_rules(request: Request):
    """
    Get the rules configuration for the agent.
    
    Called by the agent to know which rules are enabled.
    """
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else None
    
    if not token:
        raise HTTPException(status_code=401, detail="No token provided")
    
    admin_storage = get_admin_storage()
    agent_id = admin_storage.validate_agent_token(token)
    
    if not agent_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    rules = admin_storage.get_agent_rules(agent_id)
    
    return {
        "success": True,
        "rules": rules
    }


# ============================================
# Web UI Routes (Protected)
# ============================================

@app.get("/overview", response_class=HTMLResponse)
async def overview_page(request: Request):
    """Overview dashboard page."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    
    admin_storage = get_admin_storage()
    if not admin_storage.is_setup_completed():
        return RedirectResponse(url="/onboarding", status_code=302)
    
    config = get_config()
    endpoint_stats = admin_storage.get_endpoint_stats()
    connected_agents = admin_storage.get_connected_agents()
    
    return templates.TemplateResponse(
        "overview.html",
        {
            "request": request,
            "user": user,
            "refresh_interval": config.web_ui.refresh_interval_ms,
            "endpoint_stats": endpoint_stats,
            "connected_agents": connected_agents,
            "show_filters": False
        }
    )


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Main alerts dashboard page."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    
    admin_storage = get_admin_storage()
    if not admin_storage.is_setup_completed():
        return RedirectResponse(url="/onboarding", status_code=302)
    
    config = get_config()
    endpoint_stats = admin_storage.get_endpoint_stats()
    
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": user,
            "refresh_interval": config.web_ui.refresh_interval_ms,
            "events_per_page": config.web_ui.events_per_page,
            "endpoint_stats": endpoint_stats
        }
    )


@app.get("/events", response_class=HTMLResponse)
async def events_page(request: Request):
    """Events viewer page - shows all raw events from all sources."""
    session_token = request.cookies.get(SESSION_COOKIE)
    user = get_current_user(session_token)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    
    admin_storage = get_admin_storage()
    if not admin_storage.is_setup_completed():
        return RedirectResponse(url="/onboarding", status_code=302)
    
    config = get_config()
    endpoint_stats = admin_storage.get_endpoint_stats()
    
    return templates.TemplateResponse(
        "events.html",
        {
            "request": request,
            "user": user,
            "refresh_interval": config.web_ui.refresh_interval_ms,
            "events_per_page": config.web_ui.events_per_page,
            "endpoint_stats": endpoint_stats
        }
    )


# ============================================
# API Routes
# ============================================

@app.get("/api/events", response_model=EventResponse)
async def get_events(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    since_id: Optional[int] = Query(default=None),
    host: Optional[str] = Query(default=None),
    level: Optional[str] = Query(default=None),
    event_id: Optional[int] = Query(default=None),
    source: Optional[str] = Query(default=None, description="Filter by event source (sysmon, windows_event)"),
    hours: Optional[int] = Query(default=None, ge=1, le=720, description="Time range filter in hours (e.g., 1, 24, 168)")
):
    """
    Get normalized events with filtering and pagination.
    
    - **limit**: Maximum number of events to return (1-1000)
    - **offset**: Number of events to skip for pagination
    - **since_id**: Only return events with ID > since_id (for polling)
    - **host**: Filter by hostname
    - **level**: Filter by severity level
    - **event_id**: Filter by Windows Event ID
    - **source**: Filter by event source (sysmon, windows_event)
    - **hours**: Time range filter in hours (1=last hour, 24=last 24h, 168=last 7 days)
    """
    storage = get_storage()
    
    # Calculate timestamp filter from hours
    since_timestamp = None
    if hours:
        since_timestamp = datetime.utcnow() - timedelta(hours=hours)
    
    events, total = storage.get_events(
        limit=limit,
        offset=offset,
        since_id=since_id,
        since_timestamp=since_timestamp,
        host=host,
        level=level,
        event_id=event_id,
        source=source
    )
    
    return EventResponse(
        events=events,
        total_count=total,
        has_more=(offset + len(events)) < total
    )


@app.get("/api/events/summary")
async def get_events_summary(hours: int = Query(default=24, ge=1, le=168)):
    """
    Get summary data for events charts.
    
    Returns time-series data (hourly counts) and source breakdown.
    """
    storage = get_storage()
    return storage.get_events_summary(hours=hours)


# IMPORTANT: /api/events/export and /api/events/sources MUST be defined BEFORE 
# /api/events/{event_id} to avoid route conflict (FastAPI matches routes in order)
@app.get("/api/events/sources")
async def get_event_sources():
    """
    Get list of valid event source types with their labels.
    
    Useful for building filter dropdowns in the UI.
    """
    return {
        "sources": [
            {
                "id": source.value,
                "label": SOURCE_LABELS.get(source, source.value)
            }
            for source in EventSource
            if source != EventSource.UNKNOWN
        ]
    }


@app.get("/api/events/export")
async def export_events(
    request: Request,
    scope: str = Query(default="all", description="Export scope: 'page' or 'all'"),
    format: str = Query(default="csv", description="Export format: 'csv' or 'json'"),
    hours: Optional[int] = Query(default=None, description="Time range in hours (e.g., 1, 24, 168)"),
    source: Optional[str] = Query(default=None, description="Filter by event source"),
    search: Optional[str] = Query(default=None, description="Search query"),
    host: Optional[str] = Query(default=None, description="Filter by host"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=1000)
):
    """
    Export events as CSV or JSON with filtering.
    
    Supports two scopes:
    - 'page': Export only the current page (respects page/page_size)
    - 'all': Export all results matching filters (max 200,000 rows)
    
    Streams CSV for large exports to avoid memory issues.
    """
    from starlette.responses import StreamingResponse
    import io
    import csv
    
    storage = get_storage()
    
    # Calculate time filter
    from_timestamp = None
    if hours:
        from_timestamp = datetime.utcnow() - timedelta(hours=hours)
    
    # Determine limit based on scope
    MAX_EXPORT_ROWS = 200000
    
    if scope == "page":
        limit = page_size
        offset = (page - 1) * page_size
    else:  # 'all'
        limit = MAX_EXPORT_ROWS
        offset = 0
    
    # Fetch events from storage
    events, total = storage.get_events(
        limit=limit,
        offset=offset,
        source=source,
        host=host,
        since_timestamp=from_timestamp
    )
    
    # Apply search filter if provided (client-side filter since DB doesn't have full-text)
    if search:
        search_lower = search.lower()
        events = [e for e in events if (
            search_lower in (e.host or "").lower() or
            search_lower in (e.user or "").lower() or
            search_lower in (e.message or "").lower() or
            search_lower in (e.process_name or "").lower() or
            search_lower in str(e.event_id)
        )]
    
    if format == "json":
        # Return JSON array
        event_dicts = []
        for event in events:
            event_dict = event.model_dump()
            event_dict['timestamp'] = event.timestamp.isoformat()
            event_dict['ingested_at'] = event.ingested_at.isoformat()
            event_dicts.append(event_dict)
        
        return {
            "events": event_dicts,
            "total_exported": len(events),
            "total_matching": total,
            "scope": scope,
            "truncated": len(events) >= MAX_EXPORT_ROWS
        }
    
    else:  # CSV
        def generate_csv():
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            headers = [
                'ID', 'Timestamp', 'Source', 'Host', 'User', 'Event ID', 
                'Level', 'Category', 'Provider', 'Process Name', 
                'Command Line', 'Message', 'Risk Score', 'Risk Level'
            ]
            writer.writerow(headers)
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
            
            # Write rows in chunks
            for event in events:
                row = [
                    event.id,
                    event.timestamp.isoformat(),
                    event.source.value if hasattr(event.source, 'value') else str(event.source),
                    event.host,
                    event.user,
                    event.event_id,
                    event.level.value if hasattr(event.level, 'value') else str(event.level),
                    event.category.value if hasattr(event.category, 'value') else str(event.category) if event.category else '',
                    event.provider,
                    event.process_name or '',
                    event.command_line or '',
                    (event.message or '').replace('\n', ' ').replace('\r', ''),
                    event.risk_score if event.risk_score is not None else '',
                    event.risk_level or ''
                ]
                writer.writerow(row)
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)
        
        filename = f"events_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        
        return StreamingResponse(
            generate_csv(),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "X-Total-Exported": str(len(events)),
                "X-Total-Matching": str(total),
                "X-Truncated": str(len(events) >= MAX_EXPORT_ROWS).lower()
            }
        )


@app.get("/api/events/{event_id}")
async def get_event_by_id(event_id: int):
    """Get a single event by ID."""
    storage = get_storage()
    events, _ = storage.get_events(limit=1, since_id=event_id - 1)
    
    if not events or events[0].id != event_id:
        raise HTTPException(status_code=404, detail="Event not found")
    
    return events[0]


@app.get("/api/stats", response_model=EventStats)
async def get_stats():
    """Get event statistics."""
    storage = get_storage()
    return storage.get_stats()


@app.get("/api/latest-id")
async def get_latest_id():
    """Get the latest event ID (for polling)."""
    storage = get_storage()
    return {"latest_id": storage.get_latest_event_id()}


@app.get("/api/debug/sources")
async def debug_sources():
    """
    Data Source Coverage debug endpoint.
    Shows comprehensive information about what sources/channels are being collected,
    counts by source, providers, event IDs, and last seen timestamps.
    """
    import sqlite3
    from pathlib import Path
    from .config import get_config
    
    config = get_config()
    db_path = str(config.root_dir / config.database.path)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Get counts by source
        cursor.execute("""
            SELECT source, COUNT(*) as count, MAX(ingested_at) as last_seen, MIN(ingested_at) as first_seen
            FROM events
            GROUP BY source
            ORDER BY count DESC
        """)
        
        sources = []
        for row in cursor.fetchall():
            sources.append({
                "source": row[0],
                "count": row[1],
                "last_seen": row[2],
                "first_seen": row[3]
            })
        
        # Get total count
        cursor.execute("SELECT COUNT(*) FROM events")
        total = cursor.fetchone()[0]
        
        # Get counts by provider
        cursor.execute("""
            SELECT provider, COUNT(*) as count, MAX(ingested_at) as last_seen
            FROM events
            WHERE provider IS NOT NULL AND provider != ''
            GROUP BY provider
            ORDER BY count DESC
            LIMIT 20
        """)
        
        providers = []
        for row in cursor.fetchall():
            providers.append({
                "provider": row[0],
                "count": row[1],
                "last_seen": row[2]
            })
        
        # Get counts by event_id (top 20)
        cursor.execute("""
            SELECT event_id, source, provider, COUNT(*) as count
            FROM events
            GROUP BY event_id, source
            ORDER BY count DESC
            LIMIT 20
        """)
        
        event_ids = []
        for row in cursor.fetchall():
            event_ids.append({
                "event_id": row[0],
                "source": row[1],
                "provider": row[2],
                "count": row[3]
            })
        
        # Get counts by category
        cursor.execute("""
            SELECT category, COUNT(*) as count
            FROM events
            WHERE category IS NOT NULL
            GROUP BY category
            ORDER BY count DESC
        """)
        
        categories = []
        for row in cursor.fetchall():
            categories.append({
                "category": row[0],
                "count": row[1]
            })
        
        # Get unique hosts
        cursor.execute("SELECT COUNT(DISTINCT host) FROM events")
        unique_hosts = cursor.fetchone()[0]
        
        # Get unique users
        cursor.execute("SELECT COUNT(DISTINCT user) FROM events")
        unique_users = cursor.fetchone()[0]
        
        # Get time range of data
        cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM events")
        time_range = cursor.fetchone()
        
        # Get sample events by source
        cursor.execute("""
            SELECT source, id, ingested_at, host, event_id, provider
            FROM events
            ORDER BY ingested_at DESC
            LIMIT 20
        """)
        
        samples = []
        for row in cursor.fetchall():
            samples.append({
                "source": row[0],
                "id": row[1],
                "ingested_at": row[2],
                "host": row[3],
                "event_id": row[4],
                "provider": row[5]
            })
        
        return {
            "total_events": total,
            "unique_hosts": unique_hosts,
            "unique_users": unique_users,
            "data_time_range": {
                "earliest": time_range[0],
                "latest": time_range[1]
            },
            "by_source": sources,
            "by_provider": providers,
            "top_event_ids": event_ids,
            "by_category": categories,
            "recent_samples": samples,
            "coverage_notes": [
                "Sysmon: Process creation, network connections, file operations, registry changes",
                "Windows Security: Logon events (4624, 4625), privilege use, audit policy changes",
                "Windows Application: Application errors and warnings",
                "Windows System: Service state changes, system events",
                "To see Desktop file activity: Ensure Sysmon config monitors user profile paths",
                "To see browser/DNS: Enable DNS Client operational log or use Sysmon network events"
            ]
        }
    finally:
        conn.close()


@app.post("/api/test/inject-event")
async def inject_test_event():
    """
    Inject a test event for debugging purposes.
    
    Creates a synthetic process creation event and stores it in the database.
    Useful for verifying the pipeline works without a Windows agent.
    """
    from datetime import datetime
    storage = get_storage()
    
    # Create a test event
    test_event = NormalizedEvent(
        timestamp=datetime.utcnow(),
        ingested_at=datetime.utcnow(),
        source=EventSource.SYSMON,
        host="TEST-PC",
        user="testuser",
        event_id=1,  # Sysmon Process Create
        level=EventLevel.INFORMATION,
        provider="Microsoft-Windows-Sysmon",
        category=EventCategory.PROCESS,
        process_name="notepad.exe",
        process_id=1234,
        parent_process_name="explorer.exe",
        parent_process_id=5678,
        image_path="C:\\Windows\\System32\\notepad.exe",
        command_line="notepad.exe test.txt",
        message="Test process creation event"
    )
    
    # Store the event
    event_id = storage.store_event(test_event)
    test_event.id = event_id
    
    # Broadcast to websocket clients
    await manager.broadcast_event(test_event)
    
    logger.info(f"Injected test event with ID {event_id}")
    
    return {
        "success": True,
        "event_id": event_id,
        "message": "Test event injected successfully"
    }


@app.get("/api/ingest/status")
async def get_ingest_status():
    """Get ingest server status."""
    global ingest_server
    if ingest_server:
        return ingest_server.stats
    return {"running": False, "error": "Ingest server not initialized"}


# ============================================
# MVP P0: Alerts UI Routes
# ============================================

@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    """Alerts list page with filtering."""
    return templates.TemplateResponse("alerts.html", {
        "request": request,
        "page_title": "UEBA Alerts",
        "page_subtitle": "Insider threat detection and anomaly alerts"
    })


@app.get("/alerts/{alert_id}", response_class=HTMLResponse)
async def alert_detail_page(request: Request, alert_id: int):
    """Alert detail page with reasons and evidence timeline."""
    storage = get_storage()
    alert = storage.get_alert(alert_id)
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return templates.TemplateResponse("alert_detail.html", {
        "request": request,
        "alert": alert,
        "page_title": f"Alert #{alert_id}",
        "page_subtitle": alert.summary
    })


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Settings page for baseline window control."""
    storage = get_storage()
    settings = storage.get_all_settings()
    
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "settings": settings,
        "page_title": "Settings",
        "page_subtitle": "Configure baseline windows and scan intervals"
    })


# ============================================
# Alerts API Routes (UEBA Dashboard)
# ============================================

@app.get("/api/alerts", response_model=AlertResponse)
async def get_alerts(
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    behavior: Optional[str] = Query(default=None, description="Filter by behavior type"),
    min_risk: Optional[int] = Query(default=None, ge=0, le=100, description="Minimum risk score"),
    since: Optional[str] = Query(default=None, description="ISO timestamp - alerts after this time"),
    since_id: Optional[int] = Query(default=None, description="Return alerts with ID > this value"),
    # MVP P0: New filters
    severity: Optional[str] = Query(default=None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    status: Optional[str] = Query(default=None, description="Filter by status (open, closed, acknowledged)"),
    user: Optional[str] = Query(default=None, description="Filter by user"),
    host: Optional[str] = Query(default=None, description="Filter by host")
):
    """
    Get UEBA alerts with filtering and pagination.
    
    Supports both legacy filters (behavior, min_risk, since) and new MVP P0 filters (severity, status, user, host).
    """
    storage = get_storage()
    
    # Use new filtering if severity/status/user/host provided, else use legacy
    if severity or status or user or host:
        alerts, total = storage.get_alerts_filtered(
            severity=severity,
            status=status,
            user=user,
            host=host,
            limit=limit,
            offset=offset
        )
    else:
        # Legacy filtering
        since_dt = None
        if since:
            try:
                since_dt = datetime.fromisoformat(since.replace('Z', '+00:00'))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid timestamp format. Use ISO-8601.")
        
        alerts, total = storage.get_alerts(
            limit=limit,
            offset=offset,
            behavior=behavior,
            min_risk=min_risk,
            since=since_dt,
            since_id=since_id
        )
    
    return AlertResponse(
        alerts=alerts,
        total_count=total,
        has_more=(offset + len(alerts)) < total
    )
async def get_alerts(
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    behavior: Optional[str] = Query(default=None, description="Filter by behavior type"),
    min_risk: Optional[int] = Query(default=None, ge=0, le=100, description="Minimum risk score"),
    since: Optional[str] = Query(default=None, description="ISO timestamp - alerts after this time"),
    since_id: Optional[int] = Query(default=None, description="Return alerts with ID > this value")
):
    """
    Get UEBA alerts with filtering and pagination.
    
    Only returns alerts from the 5 registered behavior rules:
    - failed_login_burst: 5+ consecutive failed logons without success
    - suspicious_path_execution: Executable run from Downloads folder
    - security_log_clearing: Attempts to clear Windows event logs
    - restricted_hours_login: Login during restricted hours (13:00-20:00)
    - firewall_disabled: Windows Firewall turned off (Event ID 5025)
    
    - **limit**: Maximum number of alerts to return (1-1000)
    - **offset**: Number of alerts to skip for pagination
    - **behavior**: Filter by specific behavior type
    - **min_risk**: Minimum risk score (0-100)
    - **since**: ISO timestamp - return alerts after this time
    - **since_id**: Only return alerts with ID > since_id (for polling)
    """
    storage = get_storage()
    
    # Parse since timestamp if provided
    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace('Z', '+00:00'))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid timestamp format. Use ISO-8601.")
    
    alerts, total = storage.get_alerts(
        limit=limit,
        offset=offset,
        behavior=behavior,
        min_risk=min_risk,
        since=since_dt,
        since_id=since_id
    )
    
    return AlertResponse(
        alerts=alerts,
        total_count=total,
        has_more=(offset + len(alerts)) < total
    )


@app.get("/api/alerts/stats", response_model=AlertStats)
async def get_alert_stats():
    """
    Get alert statistics for the dashboard.
    
    Returns counts and metrics based on alerts only (not raw events).
    """
    storage = get_storage()
    return storage.get_alert_stats()


@app.get("/api/alerts/behaviors")
async def get_behavior_types():
    """
    Get list of valid behavior types with their labels.
    
    Useful for building filter dropdowns in the UI.
    """
    return {
        "behaviors": [
            {
                "id": behavior.value,
                "label": BEHAVIOR_LABELS.get(behavior, behavior.value)
            }
            for behavior in BEHAVIOR_LABELS.keys()
        ]
    }


@app.get("/api/alerts/latest-id")
async def get_latest_alert_id():
    """Get the latest alert ID (for polling)."""
    storage = get_storage()
    return {"latest_id": storage.get_latest_alert_id()}


@app.get("/api/alerts/summary")
async def get_alerts_summary(hours: int = Query(default=24, ge=1, le=168)):
    """
    Get summary data for alerts charts.
    
    Returns time-series data (hourly counts) and category breakdown.
    """
    storage = get_storage()
    return storage.get_alerts_summary(hours=hours)


# ============================================
# MVP P0: Settings API
# ============================================

@app.get("/api/settings")
async def get_settings():
    """Get all app settings (baseline window, scan intervals, etc.)."""
    storage = get_storage()
    settings = storage.get_all_settings()
    return {"settings": settings}


@app.post("/api/settings")
async def update_settings(request: Request):
    """Update app settings."""
    storage = get_storage()
    data = await request.json()
    
    # Validate and update each setting
    updated = {}
    for key, value in data.items():
        valid_settings = ["baseline_window_hours", "baseline_min_events", "scan_window_hours", 
                         "scan_interval_minutes", "anomaly_threshold", "dedup_window_minutes", "realtime_alert_threshold"]
        if key in valid_settings:
            # Validate ranges
            if key in ["baseline_window_hours", "scan_window_hours"]:
                if not (1 <= int(value) <= 168):  # 1 hour to 7 days
                    raise HTTPException(status_code=400, detail=f"{key} must be between 1 and 168 hours")
            elif key == "anomaly_threshold":
                if not (0.0 <= float(value) <= 1.0):
                    raise HTTPException(status_code=400, detail=f"{key} must be between 0.0 and 1.0")
            elif key == "realtime_alert_threshold":
                if not (0 <= int(value) <= 100):
                    raise HTTPException(status_code=400, detail=f"{key} must be between 0 and 100")
            elif key in ["baseline_min_events", "scan_interval_minutes", "dedup_window_minutes"]:
                if int(value) < 1:
                    raise HTTPException(status_code=400, detail=f"{key} must be >= 1")
            
            storage.set_setting(key, str(value))
            updated[key] = value
    
    return {"status": "updated", "settings": updated}


# ============================================
# MVP P0: SIEM Export Endpoint
# ============================================

@app.get("/api/alerts/export")
async def export_alerts(
    hours: int = Query(default=24, ge=1, le=168),
    format: str = Query(default="ndjson", regex="^(ndjson|json)$")
):
    """
    Export alerts for SIEM ingestion (NDJSON format).
    
    Returns ECS-compatible alert data for Filebeat/Elasticsearch.
    """
    storage = get_storage()
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    
    alerts, total = storage.get_alerts(
        limit=10000,
        since=cutoff
    )
    
    # Convert to NDJSON format
    lines = []
    for alert in alerts:
        # Build ECS-compatible structure
        export_alert = {
            "@timestamp": alert.timestamp.isoformat(),
            "alert.id": str(alert.id),
            "alert.severity": "CRITICAL" if alert.risk_score >= 80 else "HIGH" if alert.risk_score >= 60 else "MEDIUM" if alert.risk_score >= 40 else "LOW",
            "alert.category": "insider_threat",
            "user.name": alert.user,
            "host.name": alert.host,
            "message": alert.summary,
            "alert.reasons": alert.reasons or [],
            # MITRE ATT&CK ECS fields
            "threat.framework": "MITRE ATT&CK",
            "threat.tactic.id": alert.mitre_tactics or [],
            "threat.tactic.name": alert.mitre_tactics or [],
            "threat.technique.id": alert.mitre_techniques or [],
            "threat.technique.name": alert.mitre_techniques or [],
            "event.original": json.dumps({
                "id": alert.id,
                "behavior": alert.behavior,
                "risk_score": alert.risk_score,
                "status": alert.status,
                "occurrence_count": alert.occurrence_count,
                "evidence_event_ids": alert.evidence_event_ids or []
            })
        }
        
        if format == "ndjson":
            lines.append(json.dumps(export_alert))
        else:
            lines.append(export_alert)
    
    if format == "ndjson":
        return Response(
            content="\n".join(lines),
            media_type="application/x-ndjson",
            headers={"Content-Disposition": f"attachment; filename=alerts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.ndjson"}
        )
    else:
        return {"alerts": lines, "total": total}


# ============================================
# MVP P0: Alert Evidence Endpoint
# ============================================

@app.get("/api/alerts/{alert_id}/evidence")
async def get_alert_evidence(
    alert_id: int,
    window_minutes: int = Query(default=5, ge=1, le=60)
):
    """
    Get related events for an alert (evidence timeline).
    
    Returns events ±window_minutes around alert timestamp for the same user or host.
    """
    storage = get_storage()
    alert = storage.get_alert(alert_id)
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    events = storage.get_alert_evidence(alert_id, window_minutes=window_minutes)
    
    # Convert to dict format
    evidence = []
    for event in events:
        evidence.append({
            "id": event.get("id"),
            "timestamp": event.get("timestamp"),
            "event_id": event.get("event_id"),
            "action_type": event.get("action_type"),
            "process_name": event.get("process_name"),
            "source_ip": event.get("source_ip"),
            "dest_ip": event.get("dest_ip"),
            "command_line": event.get("command_line"),
            "category": event.get("category"),
            "raw_json": event.get("raw_json")
        })
    
    return {"alert_id": alert_id, "events": evidence, "count": len(evidence)}


# ============================================
# MVP P0: Alert Feedback Endpoint
# ============================================

@app.post("/api/alerts/{alert_id}/feedback")
async def update_alert_feedback(
    alert_id: int,
    request: Request
):
    """
    Update alert status (for analyst feedback: FALSE_POSITIVE, TRUE_POSITIVE, etc.).
    
    Body: {"status": "FALSE_POSITIVE", "notes": "Optional notes"}
    """
    storage = get_storage()
    data = await request.json()
    
    status = data.get("status")
    if not status:
        raise HTTPException(status_code=400, detail="status field required")
    
    # Validate status
    valid_statuses = ["FALSE_POSITIVE", "TRUE_POSITIVE", "closed", "open", "acknowledged"]
    if status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        )
    
    # Update alert status
    updated = storage.update_alert_status(alert_id, status)
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    # Store feedback in ground_truth_labels if it's FP/TP
    if status in ("FALSE_POSITIVE", "TRUE_POSITIVE"):
        label = "false_positive" if status == "FALSE_POSITIVE" else "true_positive"
        notes = data.get("notes", "")
        analyst_username = "system"  # TODO: Get from auth
        
        storage.store_feedback(
            alert_id=alert_id,
            label=label,
            analyst_username=analyst_username,
            notes=notes
        )
    
    return {"status": "updated", "alert_id": alert_id, "new_status": status}


# ============================================
# WebSocket Route
# ============================================

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """
    WebSocket endpoint for real-time event updates.
    
    Clients receive new events as they are ingested.
    """
    await manager.connect(websocket)
    
    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to event stream"
        })
        
        # Keep connection alive
        while True:
            try:
                # Wait for client messages (ping/pong, filters, etc.)
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0
                )
                
                # Handle client commands
                try:
                    msg = json.loads(data)
                    if msg.get("type") == "ping":
                        await websocket.send_json({"type": "pong"})
                except json.JSONDecodeError:
                    pass
                    
            except asyncio.TimeoutError:
                # Send keepalive ping
                try:
                    await websocket.send_json({"type": "ping"})
                except:
                    break
                    
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
    finally:
        manager.disconnect(websocket)


# ============================================
# Health Check
# ============================================

@app.get("/health")
async def health_check():
    """
    Health check endpoint for monitoring tools.
    
    Returns server status, database connectivity, and ingest server status.
    """
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "ingest_running": False,
        "database_connected": False,
        "version": "1.0.0",
        "optional_deps": deps_status()
    }
    
    # Check if any optional deps are missing - mark as degraded but not unhealthy
    opt_deps = health_status["optional_deps"]
    missing_deps = [k for k, v in opt_deps.items() if not v.get("available", False)]
    if missing_deps:
        health_status["missing_optional_deps"] = missing_deps
    
    # Check ingest server status
    global ingest_server
    if ingest_server:
        health_status["ingest_running"] = ingest_server.stats.get("running", False)
        health_status["ingest_stats"] = {
            "event_count": ingest_server.stats.get("event_count", 0),
            "alert_count": ingest_server.stats.get("alert_count", 0),
            "error_count": ingest_server.stats.get("error_count", 0),
            "connected_clients": ingest_server.stats.get("connected_clients", 0)
        }
    
    # Check database connectivity
    try:
        storage = get_storage()
        # Simple query to test connectivity
        storage.get_latest_event_id()
        health_status["database_connected"] = True
    except Exception as e:
        health_status["database_connected"] = False
        health_status["database_error"] = str(e)
        health_status["status"] = "degraded"
    
    # Check anomaly engine health
    try:
        from .risk.anomaly_detector import IsolationForestAnomalyDetector
        from .config import get_config
        config = get_config()
        model_path = config.get("risk_engine", {}).get("anomaly_detection", {}).get(
            "model_path", "data/risk_models/isolation_forest.pkl"
        )
        # Create detector just to check health (lightweight check)
        detector = IsolationForestAnomalyDetector(
            model_path=model_path,
            storage=storage,
            config={}
        )
        anomaly_health = detector.get_health_status()
        health_status["anomaly_engine"] = anomaly_health
        if not anomaly_health.get("model_available", False):
            # Anomaly engine degraded doesn't make overall status unhealthy
            # but we note it in the components
            if health_status["status"] == "healthy":
                health_status["status"] = "degraded"
    except Exception as e:
        health_status["anomaly_engine"] = {
            "status": "error",
            "model_available": False,
            "reason": str(e)
        }
    
    # Overall status
    if not health_status["database_connected"]:
        health_status["status"] = "unhealthy"
    elif not health_status["ingest_running"]:
        health_status["status"] = "degraded"
    
    return health_status


# ============================================
# Include ML Endpoints Router
# ============================================

if ML_ENDPOINTS_AVAILABLE:
    app.include_router(ml_router)
    logger.info("ML endpoints registered successfully")

# Include Feedback Endpoints Router
if FEEDBACK_ENDPOINTS_AVAILABLE:
    app.include_router(feedback_router)
    logger.info("Feedback endpoints registered successfully")

# Include UEBA Endpoints Router
if UEBA_ENDPOINTS_AVAILABLE:
    app.include_router(ueba_router)
    logger.info("UEBA endpoints registered successfully")

