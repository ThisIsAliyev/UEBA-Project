"""
Admin & Endpoint Management for UEBA Server.

Handles:
- User authentication (bcrypt password hashing)
- Endpoint (workstation/domain) management
- Groups and drag-drop assignment
- Rule configuration (group-level and endpoint-level)

Note: Passwords are hashed with bcrypt (cost factor 12).
Legacy SHA256 hashes are automatically upgraded on next login.
"""

import sqlite3
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum

from .core.optional_deps import require_bcrypt, BCRYPT_AVAILABLE, bcrypt

logger = logging.getLogger(__name__)


def utc_now_iso() -> str:
    """Generate UTC timestamp in ISO8601 format with Z suffix."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class EndpointType(str, Enum):
    """Type of endpoint."""
    WORKSTATION = "workstation"
    DOMAIN = "domain"


class OSType(str, Enum):
    """Operating system type."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


# Available rules in the system
AVAILABLE_RULES = [
    "failed_login_burst",
    "suspicious_path_execution",
    "security_log_clearing",
    "restricted_hours_login",
    "firewall_disabled"
]

RULE_LABELS = {
    "failed_login_burst": "Failed Login Burst",
    "suspicious_path_execution": "Suspicious Path Execution",
    "security_log_clearing": "Security Log Clearing",
    "restricted_hours_login": "Restricted Hours Login",
    "firewall_disabled": "Firewall Disabled"
}


@dataclass
class User:
    """User model."""
    id: int
    username: str
    password_hash: str
    setup_completed: bool
    created_at: str
    updated_at: str


@dataclass
class AgentUser:
    """Agent user credentials model - given to endpoint users to authenticate agents."""
    id: int
    username: str
    password_hash: str
    description: str
    enabled: bool
    created_at: str
    updated_at: str


@dataclass
class ConnectedAgent:
    """Connected agent model - tracks real-time agent connections."""
    id: int
    agent_user_id: int
    agent_username: str
    hostname: str
    ip_address: str
    os_type: str
    os_version: str
    agent_version: str
    status: str  # online, offline
    last_seen: str
    first_seen: str
    events_sent: int
    group_id: Optional[int] = None
    group_name: Optional[str] = None


@dataclass
class Endpoint:
    """Endpoint (workstation/domain computer) model."""
    id: int
    name: str
    host_or_ip: str
    endpoint_type: str
    os_type: str
    username: str
    password: str  # DEMO: stored as plain text, mark as not production-safe
    group_id: Optional[int]
    created_at: str
    updated_at: str
    group_name: Optional[str] = None  # Joined field


@dataclass
class Group:
    """Endpoint group model."""
    id: int
    name: str
    apply_rules: bool
    created_at: str
    updated_at: str
    endpoint_count: int = 0  # Computed field


@dataclass
class EndpointRule:
    """Per-endpoint rule configuration."""
    endpoint_id: int
    rule_name: str
    enabled: bool


@dataclass
class GroupRule:
    """Per-group rule configuration."""
    group_id: int
    rule_name: str
    enabled: bool


class AdminStorage:
    """
    SQLite-based storage for admin/endpoint management.
    Thread-safe implementation.
    """
    
    def __init__(self, db_path: str):
        """Initialize admin storage."""
        self.db_path = db_path
        self._init_db()
    
    @contextmanager
    def _get_connection(self):
        """Get a database connection with row factory."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def _init_db(self):
        """Initialize database schema for admin tables."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # ============================================
            # Users table
            # ============================================
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    setup_completed INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            
            # Create default admin user if not exists
            # Default password is 'admin', hashed with bcrypt (cost factor 12)
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
            if cursor.fetchone()[0] == 0:
                now = utc_now_iso()
                password_hash = self._hash_password("admin")
                cursor.execute("""
                    INSERT INTO users (username, password_hash, setup_completed, created_at, updated_at)
                    VALUES (?, ?, 0, ?, ?)
                """, ("admin", password_hash, now, now))
                logger.info("Created default admin user (username: admin, password: admin)")
            
            # ============================================
            # Sessions table (simple token-based sessions)
            # ============================================
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            # ============================================
            # Groups table
            # ============================================
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    apply_rules INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            
            # ============================================
            # Endpoints table
            # ============================================
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS endpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    host_or_ip TEXT NOT NULL,
                    endpoint_type TEXT NOT NULL DEFAULT 'workstation',
                    os_type TEXT NOT NULL DEFAULT 'windows',
                    username TEXT NOT NULL DEFAULT '',
                    password TEXT NOT NULL DEFAULT '',
                    group_id INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (group_id) REFERENCES groups(id)
                )
            """)
            
            # ============================================
            # Endpoint rules table
            # ============================================
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS endpoint_rules (
                    endpoint_id INTEGER NOT NULL,
                    rule_name TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (endpoint_id, rule_name),
                    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE CASCADE
                )
            """)
            
            # ============================================
            # Group rules table
            # ============================================
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS group_rules (
                    group_id INTEGER NOT NULL,
                    rule_name TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (group_id, rule_name),
                    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
                )
            """)
            
            # ============================================
            # Agent Users table - credentials for agents to authenticate
            # ============================================
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agent_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            
            # ============================================
            # Connected Agents table - tracks real-time agent connections
            # ============================================
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS connected_agents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_user_id INTEGER NOT NULL,
                    hostname TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT,
                    os_type TEXT NOT NULL DEFAULT 'windows',
                    os_version TEXT NOT NULL DEFAULT '',
                    agent_version TEXT NOT NULL DEFAULT '1.0.0',
                    status TEXT NOT NULL DEFAULT 'pending',
                    last_seen TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    events_sent INTEGER NOT NULL DEFAULT 0,
                    group_id INTEGER,
                    FOREIGN KEY (agent_user_id) REFERENCES agent_users(id),
                    FOREIGN KEY (group_id) REFERENCES groups(id),
                    UNIQUE(agent_user_id, hostname)
                )
            """)
            
            # Migration: Add mac_address column if it doesn't exist
            try:
                cursor.execute("ALTER TABLE connected_agents ADD COLUMN mac_address TEXT")
                logger.info("Added 'mac_address' column to connected_agents table")
            except sqlite3.OperationalError:
                pass  # Column already exists
            
            # Migration: Update status default for existing rows (if status is 'online' and no approval, set to 'pending')
            # This is a one-time migration for existing databases
            try:
                cursor.execute("""
                    UPDATE connected_agents 
                    SET status = 'pending' 
                    WHERE status = 'online' AND id NOT IN (
                        SELECT id FROM connected_agents WHERE status IN ('approved', 'declined', 'revoked')
                    )
                """)
            except sqlite3.OperationalError:
                pass  # Table might not exist yet or migration already applied
            
            # ============================================
            # Agent Tokens table - for agent session management
            # ============================================
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agent_tokens (
                    token TEXT PRIMARY KEY,
                    agent_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    FOREIGN KEY (agent_id) REFERENCES connected_agents(id) ON DELETE CASCADE
                )
            """)
            
            conn.commit()
            logger.info("Admin database schema initialized")
    
    def _hash_password(self, password: str) -> str:
        """
        Hash password with bcrypt (cost factor 12).
        
        Returns bcrypt hash as string (includes salt).
        
        Raises:
            HTTPException: 503 if bcrypt is not installed
        """
        require_bcrypt()
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """
        Verify password against hash.
        
        Supports both bcrypt (new) and SHA256 (legacy) for migration.
        If SHA256 hash is detected, returns True if match (allows re-hash on next login).
        
        Raises:
            HTTPException: 503 if bcrypt is not installed and hash is bcrypt format
        """
        # Check if this is a bcrypt hash (starts with $2b$)
        if password_hash.startswith('$2b$') or password_hash.startswith('$2a$'):
            require_bcrypt()
            try:
                return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
            except Exception as e:
                logger.warning(f"Bcrypt verification error: {e}")
                return False
        
        # Legacy SHA256 support (for migration)
        # If hash is 64 hex chars, it's likely SHA256
        if len(password_hash) == 64 and all(c in '0123456789abcdef' for c in password_hash.lower()):
            sha256_hash = hashlib.sha256(password.encode()).hexdigest()
            return sha256_hash == password_hash
        
        # Unknown hash format
        logger.warning(f"Unknown password hash format (length: {len(password_hash)})")
        return False
    
    def _needs_rehash(self, password_hash: str) -> bool:
        """
        Check if password hash needs to be upgraded (from SHA256 to bcrypt).
        
        Returns True if hash is legacy SHA256 format.
        """
        # SHA256 hashes are 64 hex characters
        if len(password_hash) == 64 and all(c in '0123456789abcdef' for c in password_hash.lower()):
            return True
        return False
    
    # ============================================
    # Authentication Methods
    # ============================================
    
    def get_user(self, user_id: int) -> Optional[User]:
        """
        Get user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            User object if found, None otherwise
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, username, password_hash, setup_completed, created_at, updated_at
                FROM users
                WHERE id = ?
            """, (user_id,))
            
            row = cursor.fetchone()
            if row:
                return User(
                    id=row['id'],
                    username=row['username'],
                    password_hash=row['password_hash'],
                    setup_completed=bool(row['setup_completed']),
                    created_at=row['created_at'],
                    updated_at=row['updated_at']
                )
            return None
    
    def authenticate(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate user and return User if valid.
        
        Supports migration from SHA256 to bcrypt: if user has old hash,
        verifies with SHA256, then upgrades to bcrypt on successful login.
        
        Returns None if authentication fails.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Get user by username (don't filter by password yet)
            cursor.execute("""
                SELECT id, username, password_hash, setup_completed, created_at, updated_at
                FROM users
                WHERE username = ?
            """, (username,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            stored_hash = row['password_hash']
            
            # Verify password (supports both bcrypt and legacy SHA256)
            if not self._verify_password(password, stored_hash):
                return None
            
            # If password is correct but hash is legacy SHA256, upgrade it
            if self._needs_rehash(stored_hash):
                logger.info(f"Upgrading password hash for user: {username}")
                new_hash = self._hash_password(password)
                now = utc_now_iso()
                cursor.execute("""
                    UPDATE users SET password_hash = ?, updated_at = ?
                    WHERE id = ?
                """, (new_hash, now, row['id']))
                conn.commit()
                stored_hash = new_hash
            
            return User(
                id=row['id'],
                username=row['username'],
                password_hash=stored_hash,
                setup_completed=bool(row['setup_completed']),
                created_at=row['created_at'],
                updated_at=row['updated_at']
            )
    
    def create_session(self, user_id: int, hours: int = 24) -> str:
        """
        Create a new session token for user.
        
        Returns the session token.
        """
        token = secrets.token_urlsafe(32)
        now = datetime.utcnow()
        expires = now + timedelta(hours=hours)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sessions (token, user_id, created_at, expires_at)
                VALUES (?, ?, ?, ?)
            """, (token, user_id, now.isoformat(), expires.isoformat()))
            conn.commit()
        
        return token
    
    def validate_session(self, token: str) -> Optional[User]:
        """
        Validate session token and return User if valid.
        
        Returns None if session is invalid or expired.
        """
        if not token:
            return None
            
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = utc_now_iso()
            
            cursor.execute("""
                SELECT u.id, u.username, u.password_hash, u.setup_completed, 
                       u.created_at, u.updated_at
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.token = ? AND s.expires_at > ?
            """, (token, now))
            
            row = cursor.fetchone()
            if row:
                return User(
                    id=row['id'],
                    username=row['username'],
                    password_hash=row['password_hash'],
                    setup_completed=bool(row['setup_completed']),
                    created_at=row['created_at'],
                    updated_at=row['updated_at']
                )
            return None
    
    def delete_session(self, token: str):
        """Delete a session (logout)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
    
    def mark_setup_completed(self, user_id: int):
        """Mark user's initial setup as completed."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = utc_now_iso()
            cursor.execute("""
                UPDATE users SET setup_completed = 1, updated_at = ?
                WHERE id = ?
            """, (now, user_id))
            conn.commit()
    
    def is_setup_completed(self) -> bool:
        """Check if initial setup is completed (agent user or connected agent exists)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Check if we have at least one agent user or connected agent
            cursor.execute("SELECT COUNT(*) FROM agent_users")
            agent_users = cursor.fetchone()[0]
            if agent_users > 0:
                return True
            
            cursor.execute("SELECT COUNT(*) FROM connected_agents")
            agents = cursor.fetchone()[0]
            if agents > 0:
                return True
            
            # Fallback: check old endpoints table
            cursor.execute("SELECT COUNT(*) FROM endpoints")
            return cursor.fetchone()[0] > 0
    
    # ============================================
    # Endpoint Methods
    # ============================================
    
    def create_endpoint(
        self,
        name: str,
        host_or_ip: str,
        endpoint_type: str = "workstation",
        os_type: str = "windows",
        username: str = "",
        password: str = "",
        group_id: Optional[int] = None
    ) -> int:
        """
        Create a new endpoint.
        
        Returns the endpoint ID.
        """
        now = utc_now_iso()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO endpoints (name, host_or_ip, endpoint_type, os_type, 
                                       username, password, group_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, host_or_ip, endpoint_type, os_type, username, password, 
                  group_id, now, now))
            conn.commit()
            endpoint_id = cursor.lastrowid
            
            # Create default rules for the endpoint (all enabled)
            for rule in AVAILABLE_RULES:
                cursor.execute("""
                    INSERT OR IGNORE INTO endpoint_rules (endpoint_id, rule_name, enabled)
                    VALUES (?, ?, 1)
                """, (endpoint_id, rule))
            conn.commit()
            
            logger.info(f"Created endpoint: {name} ({endpoint_type}/{os_type})")
            return endpoint_id
    
    def get_endpoints(self, endpoint_type: Optional[str] = None) -> List[Endpoint]:
        """Get all endpoints, optionally filtered by type."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if endpoint_type:
                cursor.execute("""
                    SELECT e.*, g.name as group_name
                    FROM endpoints e
                    LEFT JOIN groups g ON e.group_id = g.id
                    WHERE e.endpoint_type = ?
                    ORDER BY e.created_at DESC
                """, (endpoint_type,))
            else:
                cursor.execute("""
                    SELECT e.*, g.name as group_name
                    FROM endpoints e
                    LEFT JOIN groups g ON e.group_id = g.id
                    ORDER BY e.created_at DESC
                """)
            
            return [
                Endpoint(
                    id=row['id'],
                    name=row['name'],
                    host_or_ip=row['host_or_ip'],
                    endpoint_type=row['endpoint_type'],
                    os_type=row['os_type'],
                    username=row['username'],
                    password=row['password'],
                    group_id=row['group_id'],
                    created_at=row['created_at'],
                    updated_at=row['updated_at'],
                    group_name=row['group_name']
                )
                for row in cursor.fetchall()
            ]
    
    def get_endpoint(self, endpoint_id: int) -> Optional[Endpoint]:
        """Get a single endpoint by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT e.*, g.name as group_name
                FROM endpoints e
                LEFT JOIN groups g ON e.group_id = g.id
                WHERE e.id = ?
            """, (endpoint_id,))
            
            row = cursor.fetchone()
            if row:
                return Endpoint(
                    id=row['id'],
                    name=row['name'],
                    host_or_ip=row['host_or_ip'],
                    endpoint_type=row['endpoint_type'],
                    os_type=row['os_type'],
                    username=row['username'],
                    password=row['password'],
                    group_id=row['group_id'],
                    created_at=row['created_at'],
                    updated_at=row['updated_at'],
                    group_name=row['group_name']
                )
            return None
    
    def update_endpoint(self, endpoint_id: int, **kwargs) -> bool:
        """Update endpoint fields."""
        if not kwargs:
            return False
            
        allowed = ['name', 'host_or_ip', 'endpoint_type', 'os_type', 
                   'username', 'password', 'group_id']
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        
        if not updates:
            return False
        
        updates['updated_at'] = utc_now_iso()
        
        set_clause = ', '.join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [endpoint_id]
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE endpoints SET {set_clause} WHERE id = ?
            """, values)
            conn.commit()
            return cursor.rowcount > 0
    
    def delete_endpoint(self, endpoint_id: int) -> bool:
        """Delete an endpoint."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM endpoints WHERE id = ?", (endpoint_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    def assign_endpoint_to_group(self, endpoint_id: int, group_id: Optional[int]) -> bool:
        """Assign an endpoint to a group (or remove from group if None)."""
        return self.update_endpoint(endpoint_id, group_id=group_id)
    
    # ============================================
    # Group Methods
    # ============================================
    
    def create_group(self, name: str, apply_rules: bool = False) -> int:
        """
        Create a new group.
        
        Returns the group ID.
        """
        now = utc_now_iso()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO groups (name, apply_rules, created_at, updated_at)
                VALUES (?, ?, ?, ?)
            """, (name, int(apply_rules), now, now))
            conn.commit()
            group_id = cursor.lastrowid
            
            # Create default rules for the group (all enabled)
            for rule in AVAILABLE_RULES:
                cursor.execute("""
                    INSERT OR IGNORE INTO group_rules (group_id, rule_name, enabled)
                    VALUES (?, ?, 1)
                """, (group_id, rule))
            conn.commit()
            
            logger.info(f"Created group: {name}")
            return group_id
    
    def get_groups(self) -> List[Group]:
        """Get all groups with endpoint counts."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT g.*, COUNT(e.id) as endpoint_count
                FROM groups g
                LEFT JOIN endpoints e ON g.id = e.group_id
                GROUP BY g.id
                ORDER BY g.name
            """)
            
            return [
                Group(
                    id=row['id'],
                    name=row['name'],
                    apply_rules=bool(row['apply_rules']),
                    created_at=row['created_at'],
                    updated_at=row['updated_at'],
                    endpoint_count=row['endpoint_count']
                )
                for row in cursor.fetchall()
            ]
    
    def get_group(self, group_id: int) -> Optional[Group]:
        """Get a single group by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT g.*, COUNT(e.id) as endpoint_count
                FROM groups g
                LEFT JOIN endpoints e ON g.id = e.group_id
                WHERE g.id = ?
                GROUP BY g.id
            """, (group_id,))
            
            row = cursor.fetchone()
            if row:
                return Group(
                    id=row['id'],
                    name=row['name'],
                    apply_rules=bool(row['apply_rules']),
                    created_at=row['created_at'],
                    updated_at=row['updated_at'],
                    endpoint_count=row['endpoint_count']
                )
            return None
    
    def update_group(self, group_id: int, **kwargs) -> bool:
        """Update group fields."""
        if not kwargs:
            return False
            
        allowed = ['name', 'apply_rules']
        updates = {}
        for k, v in kwargs.items():
            if k in allowed:
                if k == 'apply_rules':
                    updates[k] = int(v)
                else:
                    updates[k] = v
        
        if not updates:
            return False
        
        updates['updated_at'] = utc_now_iso()
        
        set_clause = ', '.join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [group_id]
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE groups SET {set_clause} WHERE id = ?
            """, values)
            conn.commit()
            return cursor.rowcount > 0
    
    def delete_group(self, group_id: int) -> bool:
        """Delete a group (endpoints are not deleted, just unassigned)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # First, unassign all endpoints from this group
            cursor.execute("""
                UPDATE endpoints SET group_id = NULL WHERE group_id = ?
            """, (group_id,))
            # Then delete the group
            cursor.execute("DELETE FROM groups WHERE id = ?", (group_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    # ============================================
    # Rule Configuration Methods
    # ============================================
    
    def get_endpoint_rules(self, endpoint_id: int) -> Dict[str, bool]:
        """Get rules for an endpoint."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT rule_name, enabled FROM endpoint_rules
                WHERE endpoint_id = ?
            """, (endpoint_id,))
            
            rules = {rule: True for rule in AVAILABLE_RULES}  # Default all on
            for row in cursor.fetchall():
                rules[row['rule_name']] = bool(row['enabled'])
            return rules
    
    def set_endpoint_rule(self, endpoint_id: int, rule_name: str, enabled: bool) -> bool:
        """Set a single rule for an endpoint."""
        if rule_name not in AVAILABLE_RULES:
            return False
            
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO endpoint_rules (endpoint_id, rule_name, enabled)
                VALUES (?, ?, ?)
            """, (endpoint_id, rule_name, int(enabled)))
            conn.commit()
            return True
    
    def set_endpoint_rules(self, endpoint_id: int, rules: Dict[str, bool]):
        """Set multiple rules for an endpoint."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for rule_name, enabled in rules.items():
                if rule_name in AVAILABLE_RULES:
                    cursor.execute("""
                        INSERT OR REPLACE INTO endpoint_rules (endpoint_id, rule_name, enabled)
                        VALUES (?, ?, ?)
                    """, (endpoint_id, rule_name, int(enabled)))
            conn.commit()
    
    def get_group_rules(self, group_id: int) -> Dict[str, bool]:
        """Get rules for a group."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT rule_name, enabled FROM group_rules
                WHERE group_id = ?
            """, (group_id,))
            
            rules = {rule: True for rule in AVAILABLE_RULES}  # Default all on
            for row in cursor.fetchall():
                rules[row['rule_name']] = bool(row['enabled'])
            return rules
    
    def set_group_rule(self, group_id: int, rule_name: str, enabled: bool) -> bool:
        """Set a single rule for a group."""
        if rule_name not in AVAILABLE_RULES:
            return False
            
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO group_rules (group_id, rule_name, enabled)
                VALUES (?, ?, ?)
            """, (group_id, rule_name, int(enabled)))
            conn.commit()
            return True
    
    def set_group_rules(self, group_id: int, rules: Dict[str, bool]):
        """Set multiple rules for a group."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for rule_name, enabled in rules.items():
                if rule_name in AVAILABLE_RULES:
                    cursor.execute("""
                        INSERT OR REPLACE INTO group_rules (group_id, rule_name, enabled)
                        VALUES (?, ?, ?)
                    """, (group_id, rule_name, int(enabled)))
            conn.commit()
    
    def get_effective_rules(self, endpoint_id: int) -> Dict[str, bool]:
        """
        Get the effective rules for an endpoint.
        
        Priority:
        1. If endpoint is in a group with apply_rules=true, use group rules
        2. Otherwise, use endpoint rules
        """
        endpoint = self.get_endpoint(endpoint_id)
        if not endpoint:
            return {rule: True for rule in AVAILABLE_RULES}
        
        if endpoint.group_id:
            group = self.get_group(endpoint.group_id)
            if group and group.apply_rules:
                return self.get_group_rules(endpoint.group_id)
        
        return self.get_endpoint_rules(endpoint_id)
    
    def is_rule_controlled_by_group(self, endpoint_id: int) -> Optional[str]:
        """
        Check if endpoint rules are controlled by a group.
        
        Returns group name if controlled, None otherwise.
        """
        endpoint = self.get_endpoint(endpoint_id)
        if not endpoint or not endpoint.group_id:
            return None
        
        group = self.get_group(endpoint.group_id)
        if group and group.apply_rules:
            return group.name
        
        return None
    
    # ============================================
    # Agent User Management
    # ============================================
    
    def create_agent_user(self, username: str, password: str, description: str = "") -> int:
        """
        Create a new agent user credential.
        
        These credentials are given to endpoint users to authenticate their agents.
        Returns the agent user ID.
        """
        now = utc_now_iso()
        password_hash = self._hash_password(password)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO agent_users (username, password_hash, description, enabled, created_at, updated_at)
                VALUES (?, ?, ?, 1, ?, ?)
            """, (username, password_hash, description, now, now))
            conn.commit()
            logger.info(f"Created agent user: {username}")
            return cursor.lastrowid
    
    def get_agent_user(self, agent_user_id: int) -> Optional[AgentUser]:
        """Get a specific agent user by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, username, password_hash, description, enabled, created_at, updated_at
                FROM agent_users
                WHERE id = ?
            """, (agent_user_id,))
            row = cursor.fetchone()
            if row:
                return AgentUser(
                    id=row['id'],
                    username=row['username'],
                    password_hash=row['password_hash'],
                    description=row['description'],
                    enabled=bool(row['enabled']),
                    created_at=row['created_at'],
                    updated_at=row['updated_at']
                )
            return None
    
    def get_agent_users(self) -> List[AgentUser]:
        """Get all agent users."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, username, password_hash, description, enabled, created_at, updated_at
                FROM agent_users
                ORDER BY created_at DESC
            """)
            return [
                AgentUser(
                    id=row['id'],
                    username=row['username'],
                    password_hash=row['password_hash'],
                    description=row['description'],
                    enabled=bool(row['enabled']),
                    created_at=row['created_at'],
                    updated_at=row['updated_at']
                )
                for row in cursor.fetchall()
            ]
    
    def get_agent_user(self, agent_user_id: int) -> Optional[AgentUser]:
        """Get a single agent user by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, username, password_hash, description, enabled, created_at, updated_at
                FROM agent_users WHERE id = ?
            """, (agent_user_id,))
            row = cursor.fetchone()
            if row:
                return AgentUser(
                    id=row['id'],
                    username=row['username'],
                    password_hash=row['password_hash'],
                    description=row['description'],
                    enabled=bool(row['enabled']),
                    created_at=row['created_at'],
                    updated_at=row['updated_at']
                )
            return None
    
    def update_agent_user(self, agent_user_id: int, **kwargs) -> bool:
        """Update agent user fields."""
        allowed = ['description', 'enabled']
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        
        if 'password' in kwargs:
            updates['password_hash'] = self._hash_password(kwargs['password'])
        
        if not updates:
            return False
        
        updates['updated_at'] = utc_now_iso()
        
        set_clause = ', '.join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [agent_user_id]
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE agent_users SET {set_clause} WHERE id = ?", values)
            conn.commit()
            return cursor.rowcount > 0
    
    def delete_agent_user(self, agent_user_id: int) -> bool:
        """Delete an agent user and all connected agents."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Delete connected agents first
            cursor.execute("DELETE FROM connected_agents WHERE agent_user_id = ?", (agent_user_id,))
            # Delete agent user
            cursor.execute("DELETE FROM agent_users WHERE id = ?", (agent_user_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    # ============================================
    # Agent Authentication (for agents to call)
    # ============================================
    
    def authenticate_agent(self, username: str, password: str, 
                          hostname: str, ip_address: str,
                          os_type: str = "windows", os_version: str = "",
                          agent_version: str = "1.0.0",
                          mac_address: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Authenticate an agent and register/update its connection.
        
        For new agents, creates endpoint with status='pending' and requires admin approval.
        For existing approved agents, updates last_seen and returns token.
        
        Supports migration from SHA256 to bcrypt for agent user passwords.
        
        Returns agent info with token if successful, None otherwise.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Get agent user by username (don't filter by password yet)
            cursor.execute("""
                SELECT id, username, password_hash, enabled FROM agent_users
                WHERE username = ? AND enabled = 1
            """, (username,))
            
            user_row = cursor.fetchone()
            if not user_row:
                logger.warning(f"Agent auth failed for: {username}")
                return None
            
            stored_hash = user_row['password_hash']
            
            # Verify password (supports both bcrypt and legacy SHA256)
            if not self._verify_password(password, stored_hash):
                logger.warning(f"Agent auth failed for: {username} (invalid password)")
                return None
            
            # If password is correct but hash is legacy SHA256, upgrade it
            if self._needs_rehash(stored_hash):
                logger.info(f"Upgrading password hash for agent user: {username}")
                new_hash = self._hash_password(password)
                now = utc_now_iso()
                cursor.execute("""
                    UPDATE agent_users SET password_hash = ?, updated_at = ?
                    WHERE id = ?
                """, (new_hash, now, user_row['id']))
                conn.commit()
            
            agent_user_id = user_row['id']
            now = utc_now_iso()
            
            # Check if this agent already exists (by username + hostname)
            cursor.execute("""
                SELECT id, status FROM connected_agents
                WHERE agent_user_id = ? AND hostname = ?
            """, (agent_user_id, hostname))
            
            existing = cursor.fetchone()
            
            if existing:
                agent_id = existing['id']
                current_status = existing['status']
                
                # Only allow approved agents to get tokens
                if current_status not in ('approved', 'online'):
                    logger.info(f"Agent {username}@{hostname} is not approved (status: {current_status})")
                    return {
                        'agent_id': agent_id,
                        'token': None,
                        'status': current_status,
                        'message': 'Waiting for admin approval' if current_status == 'pending' else f'Status: {current_status}',
                        'username': username,
                        'hostname': hostname
                    }
                
                # Update existing approved agent
                cursor.execute("""
                    UPDATE connected_agents 
                    SET ip_address = ?, os_type = ?, os_version = ?, 
                        agent_version = ?, mac_address = ?, status = 'online', last_seen = ?
                    WHERE id = ?
                """, (ip_address, os_type, os_version, agent_version, mac_address, now, agent_id))
            else:
                # Create new connected agent with status='pending'
                cursor.execute("""
                    INSERT INTO connected_agents 
                    (agent_user_id, hostname, ip_address, mac_address, os_type, os_version, 
                     agent_version, status, last_seen, first_seen, events_sent)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, 0)
                """, (agent_user_id, hostname, ip_address, mac_address, os_type, os_version,
                      agent_version, now, now))
                agent_id = cursor.lastrowid
                
                logger.info(f"New agent registered (pending approval): {username}@{hostname} ({ip_address})")
                
                # Return without token - agent needs to wait for approval
                conn.commit()
                return {
                    'agent_id': agent_id,
                    'token': None,
                    'status': 'pending',
                    'message': 'Waiting for admin approval',
                    'username': username,
                    'hostname': hostname
                }
            
            # Create agent token (only for approved agents)
            token = secrets.token_urlsafe(32)
            expires = datetime.utcnow() + timedelta(hours=24)
            
            # Remove old tokens for this agent
            cursor.execute("DELETE FROM agent_tokens WHERE agent_id = ?", (agent_id,))
            
            # Create new token
            cursor.execute("""
                INSERT INTO agent_tokens (token, agent_id, created_at, expires_at)
                VALUES (?, ?, ?, ?)
            """, (token, agent_id, now, expires.isoformat()))
            
            conn.commit()
            
            logger.info(f"Agent authenticated: {username}@{hostname} ({ip_address})")
            
            return {
                'agent_id': agent_id,
                'token': token,
                'status': 'approved',
                'username': username,
                'hostname': hostname
            }
    
    def validate_agent_token(self, token: str) -> Optional[int]:
        """
        Validate agent token and update last_seen.
        
        Also checks if the agent user is still enabled.
        
        Returns agent_id if valid and agent user is enabled, None otherwise.
        """
        if not token:
            return None
            
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = utc_now_iso()
            
            # Check token validity AND agent user enabled status
            cursor.execute("""
                SELECT at.agent_id, ca.agent_user_id, au.enabled
                FROM agent_tokens at
                JOIN connected_agents ca ON at.agent_id = ca.id
                JOIN agent_users au ON ca.agent_user_id = au.id
                WHERE at.token = ? AND at.expires_at > ?
            """, (token, now))
            
            row = cursor.fetchone()
            if row:
                agent_id = row['agent_id']
                agent_user_enabled = row['enabled']
                
                # Check if agent user is still enabled
                if not agent_user_enabled:
                    logger.warning(f"Agent {agent_id} token rejected: agent user is disabled")
                    return None
                
                # Update last_seen
                cursor.execute("""
                    UPDATE connected_agents SET last_seen = ?, status = 'online'
                    WHERE id = ?
                """, (now, agent_id))
                conn.commit()
                return agent_id
            return None
    
    def agent_heartbeat(self, token: str) -> bool:
        """Update agent last_seen timestamp."""
        agent_id = self.validate_agent_token(token)
        return agent_id is not None
    
    def increment_agent_events(self, agent_id: int, count: int = 1):
        """
        Increment the events_sent counter for an agent (token-based tracking).
        
        Also updates last_seen and sets status to 'online'.
        This is the PRIMARY path for agent status tracking.
        
        Args:
            agent_id: The agent ID from token validation
            count: Number of events to add (default: 1)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = utc_now_iso()
            cursor.execute("""
                UPDATE connected_agents 
                SET events_sent = events_sent + ?, last_seen = ?, status = 'online'
                WHERE id = ? AND status NOT IN ('declined', 'revoked')
            """, (count, now, agent_id))
            conn.commit()
            
            if cursor.rowcount > 0:
                logger.debug(f"[TOKEN] Agent {agent_id}: events +{count}, last_seen={now}, status=online")
            else:
                logger.warning(
                    f"[TOKEN] Failed to update agent {agent_id}: "
                    f"agent not found or status is declined/revoked. "
                    f"Events are being ingested but status tracking failed!"
                )
    
    def update_agent_by_hostname(self, hostname: str, client_ip: Optional[str] = None, count: int = 1) -> bool:
        """
        Update agent status based on hostname from incoming events.
        
        This is a SECURE FALLBACK called when events arrive to mark the agent 
        as online and update last_seen/events_sent, even if token-based agent_id
        tracking isn't available.
        
        Security constraints:
        - Only updates agents already in connected_agents (known agents)
        - Updates agents in any status EXCEPT 'declined' and 'revoked' (security blocks)
        - If client_ip provided: updates IP address if it changed (handles NAT/DHCP)
        - Case-insensitive hostname matching
        - If events are arriving, agent MUST be trackable (invariant)
        
        Args:
            hostname: The hostname from the event (case-insensitive match)
            client_ip: Optional client IP (will update registered IP if different)
            count: Number of events to add to the counter
            
        Returns:
            True if an agent was found and updated, False otherwise
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = utc_now_iso()
            
            # Find agent by hostname (case-insensitive)
            # Exclude only declined/revoked agents (security blocks)
            # Allow pending/approved/online/offline - if events are arriving, agent should be trackable
            cursor.execute("""
                SELECT id, hostname, ip_address, status
                FROM connected_agents
                WHERE LOWER(hostname) = LOWER(?)
                  AND status NOT IN ('declined', 'revoked')
            """, (hostname,))
            
            agent_row = cursor.fetchone()
            
            if not agent_row:
                logger.warning(
                    f"[FALLBACK] No agent found for hostname={hostname} "
                    f"(or agent is declined/revoked). Events are arriving but status cannot be updated."
                )
                return False
            
            agent_id = agent_row['id']
            registered_ip = agent_row['ip_address']
            current_status = agent_row['status']
            
            # Build update query - always update events_sent, last_seen, and status
            # Also update IP if it changed (handles NAT/DHCP scenarios)
            update_fields = ["events_sent = events_sent + ?", "last_seen = ?", "status = 'online'"]
            update_values = [count, now]
            
            # Update IP address if client_ip is provided and different
            if client_ip and client_ip.strip():
                if not registered_ip or registered_ip.strip() != client_ip:
                    update_fields.append("ip_address = ?")
                    update_values.append(client_ip)
                    logger.info(
                        f"[FALLBACK] Updating IP for agent {agent_id}: "
                        f"{registered_ip} → {client_ip} (hostname={hostname})"
                    )
            
            update_values.append(agent_id)
            
            # Execute update
            update_query = f"""
                UPDATE connected_agents 
                SET {', '.join(update_fields)}
                WHERE id = ?
            """
            cursor.execute(update_query, update_values)
            
            conn.commit()
            updated = cursor.rowcount > 0
            
            if updated:
                logger.info(
                    f"[FALLBACK] Agent {agent_id} updated: hostname={hostname}, "
                    f"client_ip={client_ip}, registered_ip={registered_ip}, "
                    f"events +{count}, status: {current_status}→online"
                )
            else:
                logger.error(f"[FALLBACK] Update failed for agent {agent_id}, hostname={hostname}")
            
            return updated
    
    # ============================================
    # Connected Agents Management
    # ============================================
    
    def get_connected_agents(self, status: Optional[str] = None) -> List[ConnectedAgent]:
        """Get all connected agents, optionally filtered by status."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            query = """
                SELECT ca.*, au.username as agent_username, g.name as group_name
                FROM connected_agents ca
                JOIN agent_users au ON ca.agent_user_id = au.id
                LEFT JOIN groups g ON ca.group_id = g.id
            """
            params = []
            
            if status:
                query += " WHERE ca.status = ?"
                params.append(status)
            
            query += " ORDER BY ca.last_seen DESC"
            
            cursor.execute(query, params)
            
            return [
                ConnectedAgent(
                    id=row['id'],
                    agent_user_id=row['agent_user_id'],
                    agent_username=row['agent_username'],
                    hostname=row['hostname'],
                    ip_address=row['ip_address'],
                    os_type=row['os_type'],
                    os_version=row['os_version'],
                    agent_version=row['agent_version'],
                    status=row['status'],
                    last_seen=row['last_seen'],
                    first_seen=row['first_seen'],
                    events_sent=row['events_sent'],
                    group_id=row['group_id'],
                    group_name=row['group_name']
                )
                for row in cursor.fetchall()
            ]
    
    def approve_endpoint(self, agent_id: int) -> bool:
        """
        Approve an endpoint (change status from 'pending' to 'approved').
        
        Once approved, the agent can send events.
        
        Args:
            agent_id: Connected agent ID
            
        Returns:
            True if successful, False if agent not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = utc_now_iso()
            
            # Update status to approved
            cursor.execute("""
                UPDATE connected_agents 
                SET status = 'approved', last_seen = ?
                WHERE id = ? AND status = 'pending'
            """, (now, agent_id))
            
            if cursor.rowcount == 0:
                return False
            
            conn.commit()
            logger.info(f"Endpoint approved: agent_id={agent_id}")
            return True
    
    def decline_endpoint(self, agent_id: int) -> bool:
        """
        Decline an endpoint (change status from 'pending' to 'declined').
        
        Declined endpoints cannot send events.
        
        Args:
            agent_id: Connected agent ID
            
        Returns:
            True if successful, False if agent not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = utc_now_iso()
            
            # Update status to declined
            cursor.execute("""
                UPDATE connected_agents 
                SET status = 'declined', last_seen = ?
                WHERE id = ? AND status = 'pending'
            """, (now, agent_id))
            
            if cursor.rowcount == 0:
                return False
            
            # Revoke any existing tokens for this agent
            cursor.execute("DELETE FROM agent_tokens WHERE agent_id = ?", (agent_id,))
            
            conn.commit()
            logger.info(f"Endpoint declined: agent_id={agent_id}")
            return True
    
    def revoke_endpoint(self, agent_id: int) -> bool:
        """
        Revoke an endpoint (change status to 'revoked').
        
        Revoked endpoints cannot send events and must be re-approved.
        
        Args:
            agent_id: Connected agent ID
            
        Returns:
            True if successful, False if agent not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = utc_now_iso()
            
            # Update status to revoked
            cursor.execute("""
                UPDATE connected_agents 
                SET status = 'revoked', last_seen = ?
                WHERE id = ?
            """, (now, agent_id))
            
            if cursor.rowcount == 0:
                return False
            
            # Revoke any existing tokens for this agent
            cursor.execute("DELETE FROM agent_tokens WHERE agent_id = ?", (agent_id,))
            
            conn.commit()
            logger.info(f"Endpoint revoked: agent_id={agent_id}")
            return True
    
    def get_connected_agent(self, agent_id: int) -> Optional[ConnectedAgent]:
        """Get a single connected agent by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT ca.*, au.username as agent_username, g.name as group_name
                FROM connected_agents ca
                JOIN agent_users au ON ca.agent_user_id = au.id
                LEFT JOIN groups g ON ca.group_id = g.id
                WHERE ca.id = ?
            """, (agent_id,))
            
            row = cursor.fetchone()
            if row:
                return ConnectedAgent(
                    id=row['id'],
                    agent_user_id=row['agent_user_id'],
                    agent_username=row['agent_username'],
                    hostname=row['hostname'],
                    ip_address=row['ip_address'],
                    os_type=row['os_type'],
                    os_version=row['os_version'],
                    agent_version=row['agent_version'],
                    status=row['status'],
                    last_seen=row['last_seen'],
                    first_seen=row['first_seen'],
                    events_sent=row['events_sent'],
                    group_id=row['group_id'],
                    group_name=row['group_name']
                )
            return None
    
    def update_agent_status(self, ttl_seconds: int = 120):
        """
        Mark agents as offline if not seen within TTL.
        
        Args:
            ttl_seconds: Time-to-live in seconds (default 120 = 2 minutes)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Use Z suffix for consistent UTC comparison
            cutoff = (datetime.utcnow() - timedelta(seconds=ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            
            # Find agents to mark offline
            cursor.execute("""
                SELECT id, hostname, last_seen FROM connected_agents 
                WHERE last_seen < ? AND status = 'online'
            """, (cutoff,))
            agents_to_offline = cursor.fetchall()
            
            if agents_to_offline:
                for agent in agents_to_offline:
                    logger.info(f"Agent {agent['id']} ({agent['hostname']}) marked offline - last_seen: {agent['last_seen']}, cutoff: {cutoff}")
                
                cursor.execute("""
                    UPDATE connected_agents 
                    SET status = 'offline'
                    WHERE last_seen < ? AND status = 'online'
                """, (cutoff,))
                conn.commit()
                logger.info(f"Marked {cursor.rowcount} agent(s) as offline (TTL: {ttl_seconds}s)")
    
    def assign_agent_to_group(self, agent_id: int, group_id: Optional[int]) -> bool:
        """Assign an agent to a group."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE connected_agents SET group_id = ? WHERE id = ?
            """, (group_id if group_id and group_id > 0 else None, agent_id))
            conn.commit()
            return cursor.rowcount > 0
    
    def delete_connected_agent(self, agent_id: int) -> bool:
        """Delete a connected agent."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM agent_tokens WHERE agent_id = ?", (agent_id,))
            cursor.execute("DELETE FROM connected_agents WHERE id = ?", (agent_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    def get_agent_rules(self, agent_id: int) -> Dict[str, bool]:
        """Get the effective rules for an agent (based on group or defaults)."""
        agent = self.get_connected_agent(agent_id)
        if not agent:
            return {rule: True for rule in AVAILABLE_RULES}
        
        if agent.group_id:
            group = self.get_group(agent.group_id)
            if group and group.apply_rules:
                return self.get_group_rules(agent.group_id)
        
        # Default: all rules enabled
        return {rule: True for rule in AVAILABLE_RULES}
    
    # ============================================
    # Statistics Methods
    # ============================================
    
    def get_endpoint_stats(self) -> Dict[str, Any]:
        """Get endpoint and agent statistics."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Update agent statuses first
            self.update_agent_status()
            
            cursor.execute("SELECT COUNT(*) FROM endpoints")
            total = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM endpoints WHERE endpoint_type = 'workstation'")
            workstations = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM endpoints WHERE endpoint_type = 'domain'")
            domains = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM groups")
            groups = cursor.fetchone()[0]
            
            # Connected agents stats
            cursor.execute("SELECT COUNT(*) FROM connected_agents")
            total_agents = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM connected_agents WHERE status = 'online'")
            online_agents = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM agent_users")
            agent_users = cursor.fetchone()[0]
            
            return {
                'total_endpoints': total,
                'workstations': workstations,
                'domains': domains,
                'groups': groups,
                'total_agents': total_agents,
                'online_agents': online_agents,
                'offline_agents': total_agents - online_agents,
                'agent_users': agent_users
            }


# Global admin storage instance
_admin_storage: Optional[AdminStorage] = None


def get_admin_storage() -> AdminStorage:
    """Get the global admin storage instance."""
    global _admin_storage
    if _admin_storage is None:
        from .config import get_config
        config = get_config()
        db_path = str(config.root_dir / config.database.path)
        _admin_storage = AdminStorage(db_path)
    return _admin_storage


def set_admin_storage(storage: AdminStorage) -> None:
    """Set the global admin storage instance."""
    global _admin_storage
    _admin_storage = storage

