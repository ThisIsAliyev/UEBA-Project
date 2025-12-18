"""
Permission definitions and role-based access control for UEBA platform.

Implements the Permission model and ROLE_PERMISSIONS structure from the architecture spec.
"""

from enum import Enum
from typing import Dict, List


class Permission(str, Enum):
    """Permission model - Resource:Action format."""
    
    # Events
    EVENTS_VIEW = "events:view"
    EVENTS_EXPORT = "events:export"
    EVENTS_DELETE = "events:delete"  # Admin only
    
    # Alerts
    ALERTS_VIEW = "alerts:view"
    ALERTS_ACKNOWLEDGE = "alerts:acknowledge"
    ALERTS_CLOSE = "alerts:close"
    ALERTS_ASSIGN = "alerts:assign"
    
    # Rules
    RULES_VIEW = "rules:view"
    RULES_CREATE = "rules:create"
    RULES_EDIT = "rules:edit"
    RULES_DELETE = "rules:delete"
    RULES_TOGGLE = "rules:toggle"  # Enable/disable
    
    # Agents
    AGENTS_VIEW = "agents:view"
    AGENTS_APPROVE = "agents:approve"
    AGENTS_REVOKE = "agents:revoke"
    
    # Admin
    USERS_VIEW = "users:view"
    USERS_MANAGE = "users:manage"
    SETTINGS_VIEW = "settings:view"
    SETTINGS_MANAGE = "settings:manage"
    AUDIT_VIEW = "audit:view"
    INTEGRATIONS_MANAGE = "integrations:manage"
    
    # Super Admin (cross-tenant) - for future multi-tenant support
    TENANTS_VIEW = "tenants:view"
    TENANTS_MANAGE = "tenants:manage"


# Role Definitions
ROLE_PERMISSIONS: Dict[str, List[Permission]] = {
    "viewer": [
        Permission.EVENTS_VIEW,
        Permission.ALERTS_VIEW,
        Permission.RULES_VIEW,
    ],
    "analyst": [
        Permission.EVENTS_VIEW,
        Permission.EVENTS_EXPORT,
        Permission.ALERTS_VIEW,
        Permission.ALERTS_ACKNOWLEDGE,
        Permission.ALERTS_CLOSE,
        Permission.RULES_VIEW,
    ],
    "senior_analyst": [
        # Analyst permissions +
        Permission.EVENTS_VIEW,
        Permission.EVENTS_EXPORT,
        Permission.ALERTS_VIEW,
        Permission.ALERTS_ACKNOWLEDGE,
        Permission.ALERTS_CLOSE,
        Permission.ALERTS_ASSIGN,
        Permission.RULES_VIEW,
        Permission.RULES_CREATE,
        Permission.RULES_EDIT,
        Permission.RULES_TOGGLE,
        Permission.AGENTS_VIEW,
    ],
    "admin": [
        # Senior Analyst permissions +
        Permission.EVENTS_VIEW,
        Permission.EVENTS_EXPORT,
        Permission.EVENTS_DELETE,
        Permission.ALERTS_VIEW,
        Permission.ALERTS_ACKNOWLEDGE,
        Permission.ALERTS_CLOSE,
        Permission.ALERTS_ASSIGN,
        Permission.RULES_VIEW,
        Permission.RULES_CREATE,
        Permission.RULES_EDIT,
        Permission.RULES_DELETE,
        Permission.RULES_TOGGLE,
        Permission.AGENTS_VIEW,
        Permission.AGENTS_APPROVE,
        Permission.AGENTS_REVOKE,
        Permission.USERS_VIEW,
        Permission.USERS_MANAGE,
        Permission.SETTINGS_VIEW,
        Permission.SETTINGS_MANAGE,
        Permission.AUDIT_VIEW,
        Permission.INTEGRATIONS_MANAGE,
    ],
    "super_admin": [
        # All permissions + cross-tenant
        Permission.EVENTS_VIEW,
        Permission.EVENTS_EXPORT,
        Permission.EVENTS_DELETE,
        Permission.ALERTS_VIEW,
        Permission.ALERTS_ACKNOWLEDGE,
        Permission.ALERTS_CLOSE,
        Permission.ALERTS_ASSIGN,
        Permission.RULES_VIEW,
        Permission.RULES_CREATE,
        Permission.RULES_EDIT,
        Permission.RULES_DELETE,
        Permission.RULES_TOGGLE,
        Permission.AGENTS_VIEW,
        Permission.AGENTS_APPROVE,
        Permission.AGENTS_REVOKE,
        Permission.USERS_VIEW,
        Permission.USERS_MANAGE,
        Permission.SETTINGS_VIEW,
        Permission.SETTINGS_MANAGE,
        Permission.AUDIT_VIEW,
        Permission.INTEGRATIONS_MANAGE,
        Permission.TENANTS_VIEW,
        Permission.TENANTS_MANAGE,
    ],
}


def get_permissions_for_role(role: str) -> List[Permission]:
    """
    Get list of permissions for a given role.
    
    Args:
        role: Role name (viewer, analyst, senior_analyst, admin, super_admin)
        
    Returns:
        List of Permission enums
    """
    return ROLE_PERMISSIONS.get(role, [])


def has_permission(role: str, permission: Permission) -> bool:
    """
    Check if a role has a specific permission.
    
    Args:
        role: Role name
        permission: Permission to check
        
    Returns:
        True if role has permission, False otherwise
    """
    return permission in get_permissions_for_role(role)

