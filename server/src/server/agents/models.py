"""
Data models for agent management.
"""

from dataclasses import dataclass
from typing import Optional
from enum import Enum


class EndpointStatus(str, Enum):
    """Endpoint approval status."""
    PENDING = "pending"
    APPROVED = "approved"
    DECLINED = "declined"
    REVOKED = "revoked"
    OFFLINE = "offline"
    ONLINE = "online"


@dataclass
class AgentUser:
    """
    Agent user credentials model.
    
    These are machine accounts used by endpoint agents, not human users.
    """
    id: int
    username: str
    password_hash: str
    description: str
    tenant_id: Optional[int] = None  # For future multi-tenant support
    is_active: bool = True
    created_at: str = ""
    updated_at: str = ""


@dataclass
class Endpoint:
    """
    Endpoint model - represents a physical or virtual machine running an agent.
    
    Endpoints must be approved by an admin before they can send events.
    """
    id: int
    agent_user_id: int
    hostname: str
    ip_address: str
    mac_address: Optional[str] = None
    os: str = "windows"  # windows, linux, macos
    os_version: Optional[str] = None
    status: EndpointStatus = EndpointStatus.PENDING
    last_seen: Optional[str] = None
    description: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""
    
    # Computed/joined fields
    agent_username: Optional[str] = None
    group_id: Optional[int] = None
    group_name: Optional[str] = None


@dataclass
class AgentToken:
    """Agent authentication token."""
    token: str
    agent_id: int
    endpoint_id: int
    created_at: str
    expires_at: str

