"""
Context State Management for Risk Engine.

Maintains sliding window of events per (user, host) pair for context-aware risk assessment.
"""

import logging
import threading
from collections import deque
from datetime import datetime, timedelta
from typing import Dict, Optional, Set
from dataclasses import dataclass

from ..models import NormalizedEvent

logger = logging.getLogger(__name__)


@dataclass
class ContextFeatures:
    """Features extracted from context for risk assessment."""
    events_last_5min: int
    unique_processes_in_window: int
    is_new_process: bool
    process_frequency: float
    user_activity_level: float  # events per minute
    event_type_frequency: Dict[int, float]  # event_id -> frequency
    unique_parent_processes: int
    has_command_line: bool
    command_line_length: int


class ContextState:
    """
    Maintains sliding window of events for a (user, host) pair.
    
    Thread-safe implementation using locks for concurrent access.
    """
    
    def __init__(self, user: str, host: str, maxlen: int = 50, recent_window_minutes: int = 5):
        """
        Initialize context state.
        
        Args:
            user: User identifier
            host: Host identifier
            maxlen: Maximum number of events to keep in sliding window
            recent_window_minutes: Time window for "recent events" calculation
        """
        self.user = user
        self.host = host
        self.maxlen = maxlen
        self.recent_window_minutes = recent_window_minutes
        self._events: deque = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._created_at = datetime.utcnow()
        self._last_event_time: Optional[datetime] = None
    
    def add_event(self, event: NormalizedEvent) -> None:
        """
        Add an event to the sliding window.
        
        Args:
            event: NormalizedEvent to add
        """
        with self._lock:
            self._events.append(event)
            self._last_event_time = event.timestamp
    
    def get_features(self, current_event: NormalizedEvent) -> ContextFeatures:
        """
        Extract context features for risk assessment.
        
        Args:
            current_event: The event being assessed
            
        Returns:
            ContextFeatures object with extracted features
        """
        with self._lock:
            now = current_event.timestamp
            recent_cutoff = now - timedelta(minutes=self.recent_window_minutes)
            
            # Filter recent events
            recent_events = [
                e for e in self._events
                if e.timestamp >= recent_cutoff
            ]
            events_last_5min = len(recent_events)
            
            # Process statistics
            process_counts: Dict[str, int] = {}
            parent_process_counts: Dict[str, int] = {}
            event_id_counts: Dict[int, int] = {}
            total_events = len(self._events)
            
            for event in self._events:
                if event.process_name:
                    process_counts[event.process_name] = process_counts.get(event.process_name, 0) + 1
                if event.parent_process_name:
                    parent_process_counts[event.parent_process_name] = (
                        parent_process_counts.get(event.parent_process_name, 0) + 1
                    )
                event_id_counts[event.event_id] = event_id_counts.get(event.event_id, 0) + 1
            
            unique_processes = len(process_counts)
            unique_parent_processes = len(parent_process_counts)
            
            # Check if current process is new
            current_process = current_event.process_name or ""
            is_new_process = current_process not in process_counts if current_process else False
            
            # Process frequency (how often this process appears)
            process_frequency = process_counts.get(current_process, 0) / max(total_events, 1)
            
            # Event type frequency
            event_type_frequency = {
                eid: count / max(total_events, 1)
                for eid, count in event_id_counts.items()
            }
            
            # User activity level (events per minute over window)
            if self._last_event_time and self._created_at:
                window_duration_minutes = max(
                    (self._last_event_time - self._created_at).total_seconds() / 60.0,
                    0.1  # Avoid division by zero
                )
                user_activity_level = total_events / window_duration_minutes
            else:
                user_activity_level = 0.0
            
            # Command line features
            has_command_line = bool(current_event.command_line)
            command_line_length = len(current_event.command_line) if current_event.command_line else 0
            
            return ContextFeatures(
                events_last_5min=events_last_5min,
                unique_processes_in_window=unique_processes,
                is_new_process=is_new_process,
                process_frequency=process_frequency,
                user_activity_level=user_activity_level,
                event_type_frequency=event_type_frequency,
                unique_parent_processes=unique_parent_processes,
                has_command_line=has_command_line,
                command_line_length=command_line_length,
            )
    
    def get_recent_events(self, count: int = 10) -> list[NormalizedEvent]:
        """
        Get the most recent N events.
        
        Args:
            count: Number of recent events to return
            
        Returns:
            List of most recent events (newest first)
        """
        with self._lock:
            return list(self._events)[-count:]
    
    @property
    def event_count(self) -> int:
        """Get current number of events in window."""
        with self._lock:
            return len(self._events)
    
    @property
    def age_minutes(self) -> float:
        """Get age of context in minutes."""
        if self._last_event_time:
            return (datetime.utcnow() - self._last_event_time).total_seconds() / 60.0
        return (datetime.utcnow() - self._created_at).total_seconds() / 60.0


class ContextManager:
    """
    Manages ContextState instances for all (user, host) pairs.
    
    Thread-safe global manager for context state.
    """
    
    def __init__(self, maxlen: int = 50, recent_window_minutes: int = 5, max_age_minutes: int = 60):
        """
        Initialize context manager.
        
        Args:
            maxlen: Maximum events per context window
            recent_window_minutes: Time window for recent events
            max_age_minutes: Maximum age before pruning inactive contexts
        """
        self.maxlen = maxlen
        self.recent_window_minutes = recent_window_minutes
        self.max_age_minutes = max_age_minutes
        self._contexts: Dict[tuple[str, str], ContextState] = {}
        self._lock = threading.Lock()
    
    def get_context(self, user: str, host: str) -> ContextState:
        """
        Get or create context state for (user, host) pair.
        
        Args:
            user: User identifier
            host: Host identifier
            
        Returns:
            ContextState instance
        """
        key = (user, host)
        
        with self._lock:
            if key not in self._contexts:
                self._contexts[key] = ContextState(
                    user=user,
                    host=host,
                    maxlen=self.maxlen,
                    recent_window_minutes=self.recent_window_minutes
                )
                logger.debug(f"Created new context for user={user}, host={host}")
            
            return self._contexts[key]
    
    def prune_old_contexts(self) -> int:
        """
        Remove contexts that haven't been updated recently.
        
        Returns:
            Number of contexts pruned
        """
        with self._lock:
            now = datetime.utcnow()
            to_remove = []
            
            for key, context in self._contexts.items():
                if context.age_minutes > self.max_age_minutes:
                    to_remove.append(key)
            
            for key in to_remove:
                del self._contexts[key]
            
            if to_remove:
                logger.debug(f"Pruned {len(to_remove)} old contexts")
            
            return len(to_remove)
    
    @property
    def context_count(self) -> int:
        """Get number of active contexts."""
        with self._lock:
            return len(self._contexts)


# Global context manager instance
_context_manager: Optional[ContextManager] = None


def get_context_manager() -> ContextManager:
    """Get or create global context manager."""
    global _context_manager
    if _context_manager is None:
        _context_manager = ContextManager()
    return _context_manager

