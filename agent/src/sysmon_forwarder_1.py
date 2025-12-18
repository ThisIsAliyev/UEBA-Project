"""
Windows Event Collector and TCP Forwarder.

Collects events from:
- Sysmon (Microsoft-Windows-Sysmon/Operational)
- Windows Security Log (Authentication events: 4624, 4625, Firewall: 5025)

Forwards them as JSON over TCP to the UEBA server.
Supports server authentication for managed agent deployments.
"""

import json
import socket
import ssl
import subprocess
import sys
import time
import threading
import platform
import urllib.request
import urllib.error
import os
from pathlib import Path
from queue import Queue, Empty
from typing import List, Dict, Optional, Set
from datetime import datetime, timedelta

# Windows-specific: flag to hide console window when spawning subprocesses
# This prevents PowerShell windows from flashing when running as a frozen EXE
if sys.platform == "win32":
    CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW
else:
    CREATE_NO_WINDOW = 0

# ============================================
# HARD SAFETY CAPS (enforced regardless of config)
# These prevent server overload even if config is wrong
# ============================================
MAX_INITIAL_EVENTS_PER_CHANNEL = 500  # First poll cap per channel
MAX_EVENTS_PER_POLL = 200             # Subsequent polls cap
MAX_SPOOL_DRAIN_PER_BATCH = 50        # Max events drained from spool per batch
SPOOL_DRAIN_INTERVAL_SEC = 2.0        # Seconds between spool drain batches
TIME_DRIFT_WARNING_SECONDS = 300      # 5 minutes - warn if system time is off


# ============================================
# State Persistence and Spool Queue
# ============================================

class StateManager:
    """Manages persistent state (bookmarks) for event collectors."""
    
    def __init__(self, state_file: str):
        """
        Initialize state manager.
        
        Args:
            state_file: Path to JSON state file (supports %ProgramData% expansion)
        """
        # Expand environment variables in path
        state_file = os.path.expandvars(state_file)
        self.state_file = Path(state_file)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._state: Dict[str, Dict] = {}
        self._load_state()
    
    def _load_state(self):
        """Load state from disk."""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    self._state = json.load(f)
            except Exception as e:
                print(f"[WARN] Failed to load state from {self.state_file}: {e}")
                self._state = {}
        else:
            self._state = {}
    
    def _save_state(self):
        """Save state to disk."""
        try:
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(self._state, f, indent=2)
        except Exception as e:
            print(f"[WARN] Failed to save state to {self.state_file}: {e}")
    
    def get_bookmark(self, channel: str) -> Optional[int]:
        """Get last record ID for a channel."""
        with self._lock:
            channel_state = self._state.get(channel, {})
            return channel_state.get("last_record_id")
    
    def set_bookmark(self, channel: str, record_id: int):
        """Set last record ID for a channel."""
        with self._lock:
            if channel not in self._state:
                self._state[channel] = {}
            self._state[channel]["last_record_id"] = record_id
            self._state[channel]["updated_at"] = datetime.now().isoformat()
            self._save_state()


class SpoolQueue:
    """
    Durable spool queue for events when server is unavailable.
    
    ATOMIC DRAIN PATTERN:
    - dequeue_start() returns events and marks file as .sending
    - dequeue_commit() deletes the .sending file on success
    - dequeue_rollback() renames .sending back to .ndjson on failure
    This prevents duplicate events when send fails.
    """
    
    def __init__(self, spool_dir: str, max_size_mb: int = 200):
        """
        Initialize spool queue.
        
        Args:
            spool_dir: Directory for spool files (supports %ProgramData% expansion)
            max_size_mb: Maximum total spool size in MB
        """
        # Expand environment variables
        spool_dir = os.path.expandvars(spool_dir)
        self.spool_dir = Path(spool_dir)
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self._lock = threading.Lock()
        self._current_file: Optional[Path] = None
        self._current_file_size = 0
        self._file_counter = 0
        self._total_size = 0
        self._inflight_file: Optional[Path] = None  # Track file being processed
        self._load_spool_info()
        self._recover_inflight()  # Recover any .sending files from crash
    
    def _load_spool_info(self):
        """Load spool metadata and calculate total size."""
        if not self.spool_dir.exists():
            return
        
        # Find all spool files (both .ndjson and .sending)
        spool_files = sorted(self.spool_dir.glob("spool_*.ndjson"))
        sending_files = list(self.spool_dir.glob("spool_*.sending"))
        all_files = spool_files + sending_files
        
        if all_files:
            self._file_counter = len(all_files)
            # Calculate total size
            self._total_size = sum(f.stat().st_size for f in all_files if f.exists())
            # Set current file to last .ndjson one
            if spool_files:
                self._current_file = spool_files[-1]
                self._current_file_size = self._current_file.stat().st_size
    
    def _recover_inflight(self):
        """Recover any .sending files from previous crash - rename back to .ndjson."""
        try:
            for sending_file in self.spool_dir.glob("spool_*.sending"):
                original_name = sending_file.with_suffix('.ndjson')
                try:
                    sending_file.rename(original_name)
                    print(f"[*] Recovered inflight spool file: {sending_file.name} -> {original_name.name}")
                except Exception as e:
                    print(f"[WARN] Failed to recover {sending_file}: {e}")
        except Exception as e:
            print(f"[WARN] Failed to scan for inflight files: {e}")
    
    def _get_new_file(self) -> Path:
        """Get path for new spool file."""
        self._file_counter += 1
        return self.spool_dir / f"spool_{self._file_counter:06d}.ndjson"
    
    def _rotate_if_needed(self):
        """Rotate to new file if current file is getting large (10MB per file)."""
        if self._current_file_size > 10 * 1024 * 1024:  # 10MB per file
            self._current_file = None
            self._current_file_size = 0
    
    def _cleanup_old_files(self):
        """Remove oldest files if total size exceeds limit."""
        if self._total_size <= self.max_size_bytes:
            return
        
        # Get all spool files sorted by modification time
        spool_files = sorted(self.spool_dir.glob("spool_*.ndjson"), key=lambda p: p.stat().st_mtime)
        
        # Remove oldest files until under limit
        for spool_file in spool_files:
            if self._total_size <= self.max_size_bytes:
                break
            try:
                file_size = spool_file.stat().st_size
                spool_file.unlink()
                self._total_size -= file_size
            except Exception as e:
                print(f"[WARN] Failed to remove old spool file {spool_file}: {e}")
    
    def enqueue(self, events: List[Dict]):
        """
        Add events to spool queue.
        
        Args:
            events: List of event dictionaries
        """
        if not events:
            return
        
        with self._lock:
            # Get or create current file
            if self._current_file is None:
                self._current_file = self._get_new_file()
                self._current_file_size = 0
            
            # Write events as NDJSON
            try:
                with open(self._current_file, 'a', encoding='utf-8') as f:
                    for event in events:
                        line = json.dumps(event, ensure_ascii=False, default=str) + '\n'
                        f.write(line)
                        self._current_file_size += len(line.encode('utf-8'))
                        self._total_size += len(line.encode('utf-8'))
                
                # Rotate if needed
                self._rotate_if_needed()
                
                # Cleanup old files if needed
                self._cleanup_old_files()
            except Exception as e:
                print(f"[WARN] Failed to write to spool: {e}")
    
    def dequeue(self, max_events: int = 200) -> List[Dict]:
        """
        DEPRECATED: Use dequeue_start/commit/rollback for atomic operations.
        This method is kept for backward compatibility but uses atomic pattern internally.
        """
        events = self.dequeue_start(max_events)
        if events:
            self.dequeue_commit()
        return events
    
    def dequeue_start(self, max_events: int = 200) -> List[Dict]:
        """
        Start atomic dequeue - read events and mark file as .sending.
        
        MUST call dequeue_commit() on success or dequeue_rollback() on failure.
        
        Args:
            max_events: Maximum number of events to read
            
        Returns:
            List of event dictionaries
        """
        events = []
        
        with self._lock:
            # Don't start new dequeue if one is already in progress
            if self._inflight_file is not None:
                print(f"[WARN] Dequeue already in progress: {self._inflight_file}")
                return []
            
            # Get oldest spool file (not .sending)
            spool_files = sorted(self.spool_dir.glob("spool_*.ndjson"), key=lambda p: p.stat().st_mtime)
            
            if not spool_files:
                return []
            
            spool_file = spool_files[0]
            
            try:
                # Read all events from this file
                with open(spool_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if len(events) >= max_events:
                            break
                        line = line.strip()
                        if line:
                            try:
                                event = json.loads(line)
                                events.append(event)
                            except json.JSONDecodeError:
                                continue
                
                if events:
                    # Rename to .sending to mark as inflight
                    sending_file = spool_file.with_suffix('.sending')
                    spool_file.rename(sending_file)
                    self._inflight_file = sending_file
                    
            except Exception as e:
                print(f"[WARN] Failed to read from spool file {spool_file}: {e}")
        
        return events
    
    def dequeue_commit(self):
        """
        Commit atomic dequeue - delete the .sending file after successful send.
        """
        with self._lock:
            if self._inflight_file is None:
                return
            
            try:
                if self._inflight_file.exists():
                    file_size = self._inflight_file.stat().st_size
                    self._inflight_file.unlink()
                    self._total_size -= file_size
            except Exception as e:
                print(f"[WARN] Failed to delete inflight file {self._inflight_file}: {e}")
            finally:
                self._inflight_file = None
    
    def dequeue_rollback(self):
        """
        Rollback atomic dequeue - rename .sending back to .ndjson on send failure.
        Events will be retried on next dequeue.
        """
        with self._lock:
            if self._inflight_file is None:
                return
            
            try:
                if self._inflight_file.exists():
                    original_name = self._inflight_file.with_suffix('.ndjson')
                    self._inflight_file.rename(original_name)
            except Exception as e:
                print(f"[WARN] Failed to rollback inflight file {self._inflight_file}: {e}")
            finally:
                self._inflight_file = None
    
    def get_size_mb(self) -> float:
        """Get current spool size in MB."""
        with self._lock:
            return self._total_size / (1024 * 1024)
    
    def get_file_count(self) -> int:
        """Get number of spool files."""
        with self._lock:
            return len(list(self.spool_dir.glob("spool_*.ndjson")))


# ============================================
# Agent Authentication
# ============================================

class AgentAuth:
    """
    Handles agent authentication with the UEBA server.
    
    The agent authenticates using credentials created by the admin
    in the Agent Users management page.
    """
    
    def __init__(self, server_url: str, username: str, password: str):
        """
        Initialize agent authentication.
        
        Args:
            server_url: Base URL of the UEBA server (e.g., "http://192.168.1.100:8080")
            username: Agent username (created by admin)
            password: Agent password (created by admin)
        """
        self.server_url = server_url.rstrip('/')
        self.username = username
        self.password = password
        self.token: Optional[str] = None
        self.agent_id: Optional[int] = None
        self._hostname = platform.node()
        self._os_type = self._get_os_type()
        self._os_version = platform.version()
        self._ip_address = self._get_local_ip()
    
    def _get_os_type(self) -> str:
        """Get OS type string."""
        system = platform.system().lower()
        if system == "windows":
            return "windows"
        elif system == "linux":
            return "linux"
        elif system == "darwin":
            return "macos"
        return "unknown"
    
    def _get_local_ip(self) -> str:
        """Get local IP address."""
        try:
            # Create a socket to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def authenticate(self) -> bool:
        """
        Authenticate with the server and get a token.
        
        Returns:
            True if authentication successful and approved, False otherwise.
        """
        auth_url = f"{self.server_url}/api/agent/auth"
        
        auth_data = {
            "username": self.username,
            "password": self.password,
            "hostname": self._hostname,
            "ip_address": self._ip_address,
            "os_type": self._os_type,
            "os_version": self._os_version,
            "agent_version": "1.0.0"
        }
        
        try:
            data = json.dumps(auth_data).encode('utf-8')
            req = urllib.request.Request(
                auth_url,
                data=data,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode('utf-8'))
                
                if result.get('success'):
                    status = result.get('status', 'unknown')
                    self.agent_id = result.get('agent_id')
                    
                    if status == 'pending':
                        self.token = None
                        print(f"[!] Agent registered, waiting for admin approval (Agent ID: {self.agent_id})")
                        print(f"    Status: {result.get('message', 'Waiting for admin approval')}")
                        return False  # Not approved yet
                    elif status == 'approved':
                        self.token = result.get('token')
                        print(f"[+] Authentication successful! Agent ID: {self.agent_id}")
                        return True
                    else:
                        print(f"[-] Agent status: {status}")
                        return False
                else:
                    print(f"[-] Authentication failed: {result.get('message', 'Unknown error')}")
                    return False
                    
        except urllib.error.HTTPError as e:
            error_detail = None
            try:
                error_body = e.read().decode('utf-8')
                if error_body:
                    error_data = json.loads(error_body)
                    error_detail = error_data.get('detail', 'Unknown error')
            except:
                pass
            
            if e.code == 401:
                error_msg = f"❌ AUTHENTICATION FAILED: Invalid credentials"
                if error_detail:
                    error_msg += f"\n   Server message: {error_detail}"
                print(f"[-] {error_msg}")
                print(f"    Username: {self.username}")
                print(f"    Server: {self.server_url}")
            elif e.code == 404:
                error_msg = f"❌ Server endpoint not found (HTTP 404)"
                print(f"[-] {error_msg}")
                print(f"    Check server URL: {self.server_url}")
            else:
                error_msg = f"❌ Server error (HTTP {e.code})"
                if error_detail:
                    error_msg += f": {error_detail}"
                print(f"[-] {error_msg}")
            
            return False
        except urllib.error.URLError as e:
            error_msg = f"❌ Cannot connect to server: {e.reason}"
            print(f"[-] {error_msg}")
            print(f"    Server URL: {self.server_url}")
            print(f"    Check if server is running and accessible")
            return False
        except Exception as e:
            error_msg = f"❌ Authentication error: {e}"
            print(f"[-] {error_msg}")
            import traceback
            traceback.print_exc()
            return False
    
    def check_approval_status(self) -> Optional[bool]:
        """
        Check if agent has been approved and if agent user is still enabled.
        
        Returns:
            True if approved and enabled, False if declined/revoked/disabled, None if still pending or error.
        """
        if not self.agent_id:
            return None
        
        status_url = f"{self.server_url}/api/agent/status?agent_id={self.agent_id}"
        
        try:
            req = urllib.request.Request(status_url, method='GET')
            with urllib.request.urlopen(req, timeout=5) as response:
                result = json.loads(response.read().decode('utf-8'))
                
                if result.get('success'):
                    status = result.get('status', 'unknown')
                    agent_user_enabled = result.get('agent_user_enabled', True)
                    
                    # Check if agent user is disabled
                    if not agent_user_enabled:
                        error_msg = "Agent user has been disabled by administrator. Connection rejected."
                        print(f"[-] {error_msg}")
                        
                        # Show GUI notification
                        self._show_notification(
                            "Connection Rejected",
                            "Your agent user has been disabled by the administrator.\n\n"
                            "Please contact your admin or check the server dashboard.",
                            "error"
                        )
                        return False
                    
                    if status == 'approved':
                        # Get token by re-authenticating
                        if self.authenticate():
                            return True
                        else:
                            return None  # Re-auth failed
                    elif status in ('declined', 'revoked'):
                        error_msg = f"Agent has been {status} by admin. Connection rejected."
                        print(f"[-] {error_msg}")
                        
                        # Show GUI notification
                        self._show_notification(
                            "Connection Rejected",
                            f"Your agent connection has been {status} by the administrator.\n\n"
                            f"Please contact your admin or check the server dashboard.",
                            "error"
                        )
                        return False
                    else:
                        return None  # Still pending
                return None
        except urllib.error.HTTPError as e:
            print(f"[WARN] Failed to check approval status: HTTP {e.code}")
            return None
        except Exception as e:
            print(f"[WARN] Failed to check approval status: {e}")
            return None
    
    def _show_notification(self, title: str, message: str, type: str = "error"):
        """
        Show a notification to the user (GUI if available, otherwise console).
        
        Args:
            title: Notification title
            message: Notification message
            type: Notification type ("error", "warning", "info")
        """
        # Try GUI notification first
        try:
            import tkinter.messagebox as msgbox
            if type == "error":
                msgbox.showerror(title, message)
            elif type == "warning":
                msgbox.showwarning(title, message)
            else:
                msgbox.showinfo(title, message)
            return
        except:
            pass
        
        # Fallback to console
        print(f"\n{'='*70}")
        print(f"{title.upper()}")
        print(f"{'='*70}")
        print(message)
        print(f"{'='*70}\n")
    
    def heartbeat(self) -> bool:
        """
        Send heartbeat to keep the agent connection alive.
        
        Returns:
            True if heartbeat successful, False otherwise.
        """
        if not self.token:
            return False
        
        heartbeat_url = f"{self.server_url}/api/agent/heartbeat"
        
        try:
            req = urllib.request.Request(
                heartbeat_url,
                data=b'',
                headers={
                    'Authorization': f'Bearer {self.token}',
                    'Content-Type': 'application/json'
                },
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode('utf-8'))
                return result.get('success', False)
                
        except urllib.error.HTTPError as e:
            if e.code == 401:
                print(f"[-] Token expired, re-authenticating...")
                return self.authenticate()
            return False
        except Exception:
            return False
    
    def get_rules(self) -> Dict[str, bool]:
        """
        Get the enabled rules from the server.
        
        Returns:
            Dictionary of rule_name -> enabled status
        """
        if not self.token:
            return {}
        
        rules_url = f"{self.server_url}/api/agent/rules"
        
        try:
            req = urllib.request.Request(
                rules_url,
                headers={'Authorization': f'Bearer {self.token}'},
                method='GET'
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode('utf-8'))
                return result.get('rules', {})
                
        except Exception:
            return {}


class EventCollector:
    """
    Polls events from a Windows Event Log channel using PowerShell.
    Tracks which events have been seen using RecordId with persistent bookmarks.
    
    FLOOD PREVENTION:
    - Uses RecordId-based filtering at PowerShell level (source-side)
    - Enforces hard caps on events per poll
    - start_from_now mode skips all historical events on first run
    """
    
    def __init__(
        self,
        channel: str,
        max_events: int,
        source_name: str = "WINDOWS_EVENT",
        event_ids: Optional[Set[int]] = None,
        state_manager: Optional[StateManager] = None,
        start_from_now: bool = True,
        lookback_minutes: Optional[int] = None
    ):
        """
        Initialize the event collector.
        
        Args:
            channel: The Windows Event Log channel to read from.
            max_events: Maximum number of events to fetch per poll.
            source_name: Identifier for this source (e.g., "SYSMON", "WINDOWS_SECURITY")
            event_ids: Optional set of event IDs to filter (None = all events)
            state_manager: Optional StateManager for persistent bookmarks
            start_from_now: If True (default), skip historical events on first run
            lookback_minutes: If set, fetch only events from last N minutes on first run
        """
        self.channel = channel
        # Enforce hard cap on max_events
        self.max_events = min(max_events, MAX_EVENTS_PER_POLL)
        self.source_name = source_name
        self.event_ids = event_ids
        self.state_manager = state_manager
        self.start_from_now = start_from_now
        self.lookback_minutes = lookback_minutes
        self._time_drift_detected = False
        self._seen_record_ids: Set[int] = set()  # Dedup protection
        
        # Load bookmark from state if available
        if state_manager:
            self.last_record_id = state_manager.get_bookmark(channel)
            if self.last_record_id:
                print(f"[*] {source_name}: Resuming from RecordId {self.last_record_id} (from state)")
        else:
            self.last_record_id = None
        self._first_poll = self.last_record_id is None
    
    def poll(self) -> List[Dict]:
        """
        Poll for new events with FLOOD PREVENTION.
        
        First poll behavior depends on start_from_now:
        - start_from_now=True: Query current max RecordId, use as baseline, return NOTHING
        - start_from_now=False + lookback_minutes: Fetch only last N minutes
        - Otherwise: Fetch and set baseline (legacy behavior)
        
        Subsequent polls: Use RecordId cursor at source-level (PowerShell).
        
        Returns:
            List of new event dictionaries (empty on first poll if start_from_now=True).
        """
        # FIRST POLL: Handle start_from_now mode
        if self._first_poll:
            self._first_poll = False
            
            # Check time drift on first poll
            self._check_time_drift()
            
            if self.start_from_now:
                # Query current max RecordId WITHOUT fetching events
                max_rid = self._get_current_max_record_id()
                if max_rid:
                    self.last_record_id = max_rid
                    if self.state_manager:
                        self.state_manager.set_bookmark(self.channel, max_rid)
                    print(f"[*] {self.source_name}: start_from_now=True, baseline RecordId={max_rid}, NO historical events sent")
                else:
                    print(f"[*] {self.source_name}: start_from_now=True, no events in log yet")
                return []  # CRITICAL: Return empty, no historical flood
            
            elif self.lookback_minutes:
                # Fetch only last N minutes (with hard cap)
                print(f"[*] {self.source_name}: lookback_minutes={self.lookback_minutes}, fetching recent events only")
                events = self._fetch_events_with_lookback(self.lookback_minutes)
                # Apply hard cap
                if len(events) > MAX_INITIAL_EVENTS_PER_CHANNEL:
                    print(f"[!] {self.source_name}: Capping initial events from {len(events)} to {MAX_INITIAL_EVENTS_PER_CHANNEL}")
                    events = events[-MAX_INITIAL_EVENTS_PER_CHANNEL:]  # Keep most recent
                if events:
                    self.last_record_id = max(ev.get("RecordId", 0) for ev in events)
                    if self.state_manager:
                        self.state_manager.set_bookmark(self.channel, self.last_record_id)
                    for event in events:
                        event["Source"] = self.source_name
                    print(f"[+] {self.source_name}: Initial batch {len(events)} events (lookback={self.lookback_minutes}min)")
                return events
        
        # SUBSEQUENT POLLS: Fetch with RecordId cursor (source-side filtering)
        try:
            events = self._fetch_events()
        except Exception as e:
            print(f"[WARN] Failed to fetch events from {self.channel}: {e}")
            return []
        
        if not events:
            return []
        
        # Sort by RecordId to ensure proper ordering
        events.sort(key=lambda ev: ev.get("RecordId", 0))
        
        # Dedup protection - filter out already seen RecordIds
        new_events = []
        for ev in events:
            rid = ev.get("RecordId", 0)
            if rid and rid not in self._seen_record_ids:
                if self.last_record_id is None or rid > self.last_record_id:
                    new_events.append(ev)
                    self._seen_record_ids.add(rid)
        
        # Keep seen set from growing unbounded (keep last 10000)
        if len(self._seen_record_ids) > 10000:
            sorted_ids = sorted(self._seen_record_ids)
            self._seen_record_ids = set(sorted_ids[-5000:])

        # Update last_record_id and persist
        if new_events:
            self.last_record_id = max(ev.get("RecordId", 0) for ev in new_events)
            if self.state_manager:
                self.state_manager.set_bookmark(self.channel, self.last_record_id)
            print(f"[+] {self.source_name}: {len(new_events)} new event(s), cursor={self.last_record_id}")
        
        # Add source identifier
        for event in new_events:
            event["Source"] = self.source_name

        return new_events
    
    def _get_current_max_record_id(self) -> Optional[int]:
        """
        Query the current maximum RecordId from the channel WITHOUT fetching full events.
        This is used for start_from_now mode to set baseline without flood.
        """
        ps_command = f'''
$evt = Get-WinEvent -LogName "{self.channel}" -MaxEvents 1 -ErrorAction SilentlyContinue
if ($evt) {{ $evt.RecordId }} else {{ 0 }}
'''
        try:
            result = subprocess.check_output(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_command],
                stderr=subprocess.DEVNULL,
                timeout=10,
                creationflags=CREATE_NO_WINDOW
            )
            rid_str = result.decode("utf-8", errors="replace").strip()
            if rid_str and rid_str.isdigit():
                return int(rid_str)
        except Exception as e:
            print(f"[WARN] Failed to get max RecordId for {self.channel}: {e}")
        return None
    
    def _check_time_drift(self):
        """
        Check for time drift between Windows system clock and event log timestamps.
        If drift > 5 minutes, warn and mark drift detected.
        """
        try:
            # Get most recent event timestamp
            ps_command = f'''
$evt = Get-WinEvent -LogName "System" -MaxEvents 1 -ErrorAction SilentlyContinue
if ($evt) {{
    $local = $evt.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss")
    $now = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
    "$local|$now"
}}
'''
            result = subprocess.check_output(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_command],
                stderr=subprocess.DEVNULL,
                timeout=10,
                creationflags=CREATE_NO_WINDOW
            )
            output = result.decode("utf-8", errors="replace").strip()
            if "|" in output:
                event_time_str, system_time_str = output.split("|")
                event_time = datetime.strptime(event_time_str, "%Y-%m-%dT%H:%M:%S")
                system_time = datetime.strptime(system_time_str, "%Y-%m-%dT%H:%M:%S")
                drift_seconds = abs((system_time - event_time).total_seconds())
                
                if drift_seconds > TIME_DRIFT_WARNING_SECONDS:
                    print(f"[!] WARNING: System time may be incorrect!")
                    print(f"    System time: {system_time_str}")
                    print(f"    Last event:  {event_time_str}")
                    print(f"    Drift: {drift_seconds:.0f} seconds ({drift_seconds/60:.1f} minutes)")
                    print(f"    Using RecordId cursor (time-window filtering disabled)")
                    self._time_drift_detected = True
                    # Force RecordId-only mode
                    self.lookback_minutes = None
        except Exception as e:
            print(f"[WARN] Time drift check failed: {e}")
    
    def _fetch_events_with_lookback(self, minutes: int) -> List[Dict]:
        """
        Fetch events from the last N minutes using source-side StartTime filter.
        """
        # Calculate start time (use event log time, not system time if drift detected)
        start_time = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S")
        
        # Build filter with StartTime at source level
        if self.event_ids:
            ids_str = ",".join(str(eid) for eid in self.event_ids)
            filter_clause = f"-FilterHashtable @{{LogName='{self.channel}'; Id={ids_str}; StartTime='{start_time}'}}"
        else:
            filter_clause = f"-FilterHashtable @{{LogName='{self.channel}'; StartTime='{start_time}'}}"
        
        # PowerShell command to get events as JSON with full metadata
        # CRITICAL: Convert TimeCreated to UTC with ISO 8601 "Z" suffix to avoid timezone mismatch
        # The server expects UTC timestamps, and Windows events use local time by default
        # Includes raw XML for full event details
        ps_command = f'''
Get-WinEvent {filter_clause} -MaxEvents {MAX_INITIAL_EVENTS_PER_CHANNEL} -ErrorAction SilentlyContinue |
Sort-Object RecordId |
ForEach-Object {{
    $utcTime = $_.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $xml = $_.ToXml()
    [PSCustomObject]@{{
        TimeCreated = $utcTime
        Id = $_.Id
        LevelDisplayName = $_.LevelDisplayName
        Level = $_.Level
        Message = $_.Message
        RecordId = $_.RecordId
        ProviderName = $_.ProviderName
        MachineName = $_.MachineName
        UserId = $_.UserId
        Task = $_.Task
        TaskDisplayName = $_.TaskDisplayName
        Keywords = $_.Keywords
        KeywordsDisplayNames = $_.KeywordsDisplayNames
        LogName = $_.LogName
        ProcessId = $_.ProcessId
        ThreadId = $_.ThreadId
        Properties = $_.Properties
        RawEventXml = $xml
        Channel = $_.LogName
    }}
}} |
ConvertTo-Json -Depth 10 -Compress
'''
        try:
            result = subprocess.check_output(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_command],
                stderr=subprocess.STDOUT,
                timeout=60,
                creationflags=CREATE_NO_WINDOW
            )
            json_str = result.decode("utf-8", errors="replace").strip()
            if not json_str:
                return []
            parsed = json.loads(json_str)
            if isinstance(parsed, dict):
                return [parsed]
            return parsed if isinstance(parsed, list) else []
        except Exception as e:
            print(f"[WARN] Lookback fetch failed for {self.channel}: {e}")
            return []
    
    def _fetch_events(self) -> List[Dict]:
        """
        Fetch events from Windows Event Log using PowerShell.
        
        CRITICAL: Uses RecordId filtering at PowerShell level to prevent flood.
        Only fetches events with RecordId > last_record_id.
        
        Returns:
            List of event dictionaries.
        """
        # Build filter for specific event IDs if specified
        # Note: For multiple IDs, PowerShell requires array syntax: Id=@(4624,4625,...)
        # But too many IDs (>10) can cause "parameter is incorrect" error
        id_filter_clause = ""
        if self.event_ids:
            ids_list = list(self.event_ids) if isinstance(self.event_ids, set) else self.event_ids
            if len(ids_list) > 10:
                # Too many IDs - use Where-Object filter instead
                filter_clause = f"-FilterHashtable @{{LogName='{self.channel}'}}"
                # Build PowerShell array for -contains check
                ids_array = "@(" + ",".join(str(i) for i in ids_list) + ")"
                id_filter_clause = f"| Where-Object {{ {ids_array} -contains $_.Id }}"
            else:
                ids_str = ",".join(str(eid) for eid in ids_list)
                filter_clause = f"-FilterHashtable @{{LogName='{self.channel}'; Id=@({ids_str})}}"
        else:
            filter_clause = f"-FilterHashtable @{{LogName='{self.channel}'}}"
        
        # CRITICAL: RecordId filtering at source level in PowerShell
        # This prevents fetching historical events that would cause flood
        record_id_filter = ""
        if self.last_record_id:
            record_id_filter = f"| Where-Object {{ $_.RecordId -gt {self.last_record_id} }}"
        
        # Enforce hard cap
        max_to_fetch = min(self.max_events, MAX_EVENTS_PER_POLL)
        
        # PowerShell command with RecordId source-side filtering
        ps_command = f'''
Get-WinEvent {filter_clause} -MaxEvents {max_to_fetch * 2} -ErrorAction SilentlyContinue {id_filter_clause} {record_id_filter} |
Select-Object -First {max_to_fetch} |
Sort-Object RecordId |
ForEach-Object {{
    $utcTime = $_.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $xml = $_.ToXml()
    [PSCustomObject]@{{
        TimeCreated = $utcTime
        Id = $_.Id
        LevelDisplayName = $_.LevelDisplayName
        Level = $_.Level
        Message = $_.Message
        RecordId = $_.RecordId
        ProviderName = $_.ProviderName
        MachineName = $_.MachineName
        UserId = $_.UserId
        Task = $_.Task
        TaskDisplayName = $_.TaskDisplayName
        Keywords = $_.Keywords
        KeywordsDisplayNames = $_.KeywordsDisplayNames
        LogName = $_.LogName
        ProcessId = $_.ProcessId
        ThreadId = $_.ThreadId
        Properties = $_.Properties
        RawEventXml = $xml
        Channel = $_.LogName
    }}
}} |
ConvertTo-Json -Depth 10 -Compress
'''
        
        try:
            result = subprocess.check_output(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_command],
                stderr=subprocess.STDOUT,
                timeout=30,
                creationflags=CREATE_NO_WINDOW
            )
        except subprocess.CalledProcessError as e:
            error_output = e.output.decode(errors="ignore").strip() if e.output else "unknown error"
            if "No events were found" not in error_output:
                print(f"[WARN] Failed to fetch events from {self.channel}: {error_output}")
            return []
        except subprocess.TimeoutExpired:
            print(f"[WARN] PowerShell command timed out for {self.channel}")
            return []
        
        # Decode and parse JSON
        json_str = result.decode("utf-8", errors="replace").strip()
        
        if not json_str:
            return []
        
        try:
            parsed = json.loads(json_str)
        except json.JSONDecodeError as e:
            print(f"[WARN] Failed to parse JSON from PowerShell: {e}")
            return []
        
        if isinstance(parsed, dict):
            return [parsed]
        elif isinstance(parsed, list):
            return parsed
        else:
            return []


class SecurityEventCollector(EventCollector):
    """
    Specialized collector for Windows Security events.
    Enriches events with extracted authentication fields.
    
    Supports configurable event ID filtering or capturing all events.
    """
    
    # Optimized event IDs for UEBA - focused on critical security events only
    # Reduced from 30+ to 16 high-value events for better performance
    DEFAULT_EVENT_IDS = {
        # Authentication events (CRITICAL)
        4624,  # Successful Logon
        4625,  # Failed Logon
        4648,  # Explicit credential logon (RunAs)
        4672,  # Special privileges assigned (admin)
        
        # Account management (HIGH PRIORITY)
        4720,  # User account created
        4722,  # User account enabled
        4726,  # User account deleted
        4728,  # User added to global group
        4732,  # User added to local group
        4756,  # User added to universal group
        4740,  # Account locked out
        
        # Process and security events (CRITICAL for behavior detection)
        4688,  # Process creation (for log clearing detection)
        4719,  # System audit policy changed
        5025,  # Firewall service stopped
        4697,  # Service installed
        4698,  # Scheduled task created
    }
    
    def __init__(self, max_events: int = 100, event_ids: Optional[Set[int]] = None, capture_all: bool = False, 
                 state_manager: Optional[StateManager] = None, start_from_now: bool = True, lookback_minutes: Optional[int] = None):
        """
        Initialize Security event collector.
        
        Args:
            max_events: Maximum events to fetch per poll
            event_ids: Custom set of event IDs to capture (None = use defaults)
            capture_all: If True, capture ALL security events (overrides event_ids)
            state_manager: Optional StateManager for persistent bookmarks
            start_from_now: If True, skip historical events on first run
            lookback_minutes: If set, fetch only events from last N minutes on first run
        """
        # If capture_all, pass None to parent (no filtering)
        # Otherwise use provided event_ids or defaults
        if capture_all:
            filter_ids = None
            print("[*] Security collector: Capturing ALL Security events (no filter)")
        else:
            filter_ids = event_ids if event_ids else self.DEFAULT_EVENT_IDS
            print(f"[*] Security collector: Filtering to {len(filter_ids)} event IDs")
        
        super().__init__(
            channel="Security",
            max_events=max_events,
            source_name="WINDOWS_SECURITY",
            event_ids=filter_ids,
            state_manager=state_manager,
            start_from_now=start_from_now,
            lookback_minutes=lookback_minutes
        )
    
    def poll(self) -> List[Dict]:
        """Poll and enrich security events."""
        events = super().poll()
        
        # Enrich each event with extracted auth fields
        for event in events:
            self._enrich_auth_event(event)
        
        return events
    
    def _enrich_auth_event(self, event: Dict):
        """
        Extract and add authentication-specific fields from the event.
        """
        event_id = event.get("Id", 0)
        message = event.get("Message", "")
        properties = event.get("Properties", [])
        
        # Extract fields from Properties array (indexed values from Security events)
        # The order of properties varies by event type but common patterns exist
        
        if event_id == 4624:  # Successful logon
            event["AuthResult"] = "success"
            event["AuthEventType"] = "logon"
        elif event_id == 4625:  # Failed logon
            event["AuthResult"] = "failed"
            event["AuthEventType"] = "logon"
        elif event_id == 4634:  # Logoff
            event["AuthResult"] = "success"
            event["AuthEventType"] = "logoff"
        elif event_id == 4672:  # Special privileges assigned
            event["AuthResult"] = "success"
            event["AuthEventType"] = "privilege"
        
        # Try to extract common fields from message
        self._extract_from_message(event, message)
        
        # Also try to extract from Properties if available
        self._extract_from_properties(event, properties, event_id)
    
    def _extract_from_message(self, event: Dict, message: str):
        """Extract auth fields from the Message text."""
        if not message:
            return
        
        import re
        
        # Account Name patterns
        account_match = re.search(r"Account Name:\s*(\S+)", message, re.IGNORECASE)
        if account_match:
            event["TargetUserName"] = account_match.group(1)
        
        # Account Domain
        domain_match = re.search(r"Account Domain:\s*(\S+)", message, re.IGNORECASE)
        if domain_match:
            event["TargetDomainName"] = domain_match.group(1)
        
        # Logon Type
        logon_type_match = re.search(r"Logon Type:\s*(\d+)", message, re.IGNORECASE)
        if logon_type_match:
            event["LogonType"] = int(logon_type_match.group(1))
        
        # Source Network Address (IP)
        ip_match = re.search(r"Source Network Address:\s*(\S+)", message, re.IGNORECASE)
        if ip_match:
            ip = ip_match.group(1)
            if ip != "-" and ip != "::1" and ip != "127.0.0.1":
                event["IpAddress"] = ip
        
        # Workstation Name
        workstation_match = re.search(r"Workstation Name:\s*(\S+)", message, re.IGNORECASE)
        if workstation_match:
            ws = workstation_match.group(1)
            if ws != "-":
                event["WorkstationName"] = ws
        
        # Failure Reason (for 4625)
        failure_match = re.search(r"Failure Reason:\s*(.+?)(?:\r|\n|$)", message, re.IGNORECASE)
        if failure_match:
            event["FailureReason"] = failure_match.group(1).strip()
        
        # Status codes
        status_match = re.search(r"Status:\s*(0x[0-9A-Fa-f]+)", message, re.IGNORECASE)
        if status_match:
            event["Status"] = status_match.group(1)
        
        sub_status_match = re.search(r"Sub Status:\s*(0x[0-9A-Fa-f]+)", message, re.IGNORECASE)
        if sub_status_match:
            event["SubStatus"] = sub_status_match.group(1)
    
    def _extract_from_properties(self, event: Dict, properties: List, event_id: int):
        """Extract fields from the Properties array."""
        if not properties or not isinstance(properties, list):
            return
        
        # Get property values
        def get_prop_value(idx: int) -> Optional[str]:
            if idx < len(properties):
                prop = properties[idx]
                if isinstance(prop, dict):
                    return prop.get("Value")
                return prop
            return None
        
        # For 4624/4625 events, the properties follow a specific order
        # This may vary slightly between Windows versions
        if event_id in (4624, 4625):
            # Common indices for 4624/4625
            # 0: SubjectUserSid, 1: SubjectUserName, 2: SubjectDomainName
            # 3: SubjectLogonId, 4: TargetUserSid (4624) or empty
            # 5: TargetUserName, 6: TargetDomainName, 7: TargetLogonId
            # 8: LogonType, 9: LogonProcessName, etc.
            
            if not event.get("TargetUserName"):
                val = get_prop_value(5)
                if val and val != "-":
                    event["TargetUserName"] = val
            
            if not event.get("TargetDomainName"):
                val = get_prop_value(6)
                if val and val != "-":
                    event["TargetDomainName"] = val
            
            if not event.get("LogonType"):
                val = get_prop_value(8)
                if val:
                    try:
                        event["LogonType"] = int(val)
                    except (ValueError, TypeError):
                        pass
            
            # IP Address is usually at index 18 or 19
            if not event.get("IpAddress"):
                for idx in [18, 19]:
                    val = get_prop_value(idx)
                    if val and val != "-" and val != "::1" and val != "127.0.0.1":
                        event["IpAddress"] = val
                        break
            
            # Workstation is usually at index 11 or 13
            if not event.get("WorkstationName"):
                for idx in [11, 13]:
                    val = get_prop_value(idx)
                    if val and val != "-":
                        event["WorkstationName"] = val
                        break


class SysmonCollector(EventCollector):
    """
    Specialized collector for Sysmon events.
    Backward compatible with existing code.
    """
    
    def __init__(self, channel: str, max_events: int, state_manager: Optional[StateManager] = None,
                 start_from_now: bool = True, lookback_minutes: Optional[int] = None):
        """Initialize Sysmon collector."""
        super().__init__(
            channel=channel,
            max_events=max_events,
            source_name="SYSMON",
            event_ids=None,  # All Sysmon events
            state_manager=state_manager,
            start_from_now=start_from_now,
            lookback_minutes=lookback_minutes
        )


class ApplicationEventCollector(EventCollector):
    """
    Collector for Windows Application log events.
    
    The Application log contains events from applications and programs.
    This includes:
    - Application errors and warnings
    - Custom application events (including eventcreate test events)
    - Third-party software logs
    
    Does NOT require admin privileges to read.
    """
    
    def __init__(self, max_events: int = 100, event_ids: Optional[Set[int]] = None, state_manager: Optional[StateManager] = None,
                 start_from_now: bool = True, lookback_minutes: Optional[int] = None):
        """
        Initialize Application event collector.
        
        Args:
            max_events: Maximum events to fetch per poll
            event_ids: Optional set of event IDs to filter (None = all events)
            state_manager: Optional StateManager for persistent bookmarks
            start_from_now: If True, skip historical events on first run
            lookback_minutes: If set, fetch only events from last N minutes on first run
        """
        super().__init__(
            channel="Application",
            max_events=max_events,
            source_name="WINDOWS_APPLICATION",
            event_ids=event_ids,
            state_manager=state_manager,
            start_from_now=start_from_now,
            lookback_minutes=lookback_minutes
        )
        print(f"[*] Application collector: Capturing events from Application log")


class SystemEventCollector(EventCollector):
    """
    Collector for Windows System log events.
    
    The System log contains events from Windows system components:
    - Driver and hardware events
    - System services
    - Windows Update
    - Startup/shutdown events
    
    Does NOT require admin privileges to read.
    """
    
    def __init__(self, max_events: int = 100, event_ids: Optional[Set[int]] = None, state_manager: Optional[StateManager] = None,
                 start_from_now: bool = True, lookback_minutes: Optional[int] = None):
        """
        Initialize System event collector.
        
        Args:
            max_events: Maximum events to fetch per poll
            event_ids: Optional set of event IDs to filter (None = all events)
            state_manager: Optional StateManager for persistent bookmarks
            start_from_now: If True, skip historical events on first run
            lookback_minutes: If set, fetch only events from last N minutes on first run
        """
        super().__init__(
            channel="System",
            max_events=max_events,
            source_name="WINDOWS_SYSTEM",
            event_ids=event_ids,
            state_manager=state_manager,
            start_from_now=start_from_now,
            lookback_minutes=lookback_minutes
        )
        print(f"[*] System collector: Capturing events from System log")


def send_events_over_tcp(
    server_ip: str, 
    port: int, 
    events: List[Dict], 
    agent_token: Optional[str] = None,
    tls_enabled: bool = False,
    tls_cert_path: Optional[str] = None,
    tls_verify: bool = True
) -> bool:
    """
    Send events to remote server over TCP (or TLS) as newline-delimited JSON.
    
    Each event is wrapped in an envelope format:
    {
        "source": "sysmon" | "windows_event",
        "event": { ... original event data ... }
    }
    
    If agent_token is provided, sends it as the first message for authentication.
    
    Args:
        server_ip: Remote server IP or hostname.
        port: Remote server port.
        events: List of event dictionaries to send.
        agent_token: Optional agent authentication token.
        tls_enabled: If True, use TLS encryption for the connection.
        tls_cert_path: Path to server certificate file (for validation).
        tls_verify: If True, verify server certificate (set False for self-signed in dev).
        
    Returns:
        True if successful, False otherwise.
    """
    if not events:
        return True
    
    try:
        # Create TCP connection with timeout
        sock = socket.create_connection((server_ip, port), timeout=5)
        
        # Wrap with TLS if enabled
        if tls_enabled:
            try:
                context = ssl.create_default_context()
                if not tls_verify:
                    # For self-signed certificates in dev, disable verification
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                elif tls_cert_path and Path(tls_cert_path).exists():
                    # Load custom CA certificate
                    context.load_verify_locations(tls_cert_path)
                
                sock = context.wrap_socket(sock, server_hostname=server_ip)
            except Exception as e:
                sock.close()
                print(f"[WARN] TLS handshake failed: {e}")
                return False
        
        try:
            # Send authentication token first if provided
            if agent_token:
                auth_msg = json.dumps({"agent_token": agent_token}) + "\n"
                sock.sendall(auth_msg.encode('utf-8'))
            
            for event in events:
                # Wrap event in envelope format with source field
                envelope = wrap_event_in_envelope(event)
                # Serialize to JSON and add newline
                json_line = json.dumps(envelope, ensure_ascii=False, default=str)
                data = (json_line + "\n").encode("utf-8")
                sock.sendall(data)
            
            return True
            
        finally:
            sock.close()
            
    except socket.timeout:
        print(f"[WARN] Connection timed out to {server_ip}:{port}")
        return False
    except ConnectionRefusedError:
        print(f"[WARN] Connection refused by {server_ip}:{port}")
        return False
    except ssl.SSLError as e:
        print(f"[WARN] TLS error: {e}")
        return False
    except Exception as e:
        print(f"[WARN] Failed to send events to {server_ip}:{port} (error: {e})")
        return False


def wrap_event_in_envelope(event: Dict) -> Dict:
    """
    Wrap an event in the standard envelope format for the UEBA server.
    
    Enhanced envelope format with full metadata:
    {
        "source": "sysmon" | "windows_event",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "provider": "Microsoft-Windows-Sysmon",
        "event_id": 1,
        "level": "Information",
        "computer": "WORKSTATION-01",
        "record_id": 12345,
        "timestamp_utc": "2024-01-01T12:00:00.000Z",
        "host_metadata": {
            "hostname": "WORKSTATION-01",
            "os_version": "10.0.19041"
        },
        "event": { ... original event data with RawEventXml ... }
    }
    
    Args:
        event: Raw event dictionary with Source field and metadata
        
    Returns:
        Envelope dictionary with source, metadata, and event fields
    """
    # Extract the source identifier and normalize it
    raw_source = event.pop("Source", "SYSMON")  # Remove from event, default to SYSMON
    
    # Map internal source names to standard envelope source values
    source_mapping = {
        "SYSMON": "sysmon",
        "WINDOWS_SECURITY": "windows_event",
        "WINDOWS_EVENT": "windows_event",
        "WINDOWS_APPLICATION": "windows_event",
        "WINDOWS_SYSTEM": "windows_event",
        "POWERSHELL": "windows_event",
        "WMI": "windows_event",
        "TASKSCHEDULER": "windows_event",
        "DEFENDER": "windows_event",
        "FIREWALL": "windows_event",
        "RDP_LOCAL": "windows_event",
        "RDP_REMOTE": "windows_event",
        "BITS": "windows_event",
        "APPLOCKER_EXE": "windows_event",
        "APPLOCKER_MSI": "windows_event",
        "CODE_INTEGRITY": "windows_event",
    }

    source = source_mapping.get(raw_source.upper(), "windows_event")
    
    # Extract metadata fields
    channel = event.get("Channel") or event.get("LogName", "")
    provider = event.get("ProviderName", "")
    event_id = event.get("Id", 0)
    level = event.get("LevelDisplayName") or event.get("Level", "Information")
    computer = event.get("MachineName", platform.node())
    record_id = event.get("RecordId", 0)
    timestamp_utc = event.get("TimeCreated", datetime.utcnow().isoformat() + "Z")
    
    # Get host metadata
    host_metadata = {
        "hostname": platform.node(),
        "os_version": platform.version()
    }
    
    # Build enhanced envelope
    envelope = {
        "source": source,
        "channel": channel,
        "provider": provider,
        "event_id": event_id,
        "level": level,
        "computer": computer,
        "record_id": record_id,
        "timestamp_utc": timestamp_utc,
        "host_metadata": host_metadata,
        "event": event
    }
    
    return envelope


class MultiChannelForwarder:
    """
    Manages multiple event collectors and forwards all events to the server.
    Uses separate threads for each collector to avoid blocking.
    Supports durable spool queue and configurable send intervals.
    """
    
    def __init__(self, server_ip: str, port: int, config: dict, agent_token: Optional[str] = None):
        """
        Initialize the multi-channel forwarder.
        
        Args:
            server_ip: Remote server IP or hostname.
            port: Remote server port.
            config: Configuration dictionary.
            agent_token: Optional agent authentication token.
        """
        self.server_ip = server_ip
        self.port = port
        self.config = config
        self.agent_token = agent_token
        self.event_queue: Queue = Queue()
        self._running = False
        self._collectors: List[EventCollector] = []
        self._threads: List[threading.Thread] = []
        
        # Initialize state manager and spool queue from config
        telemetry_config = config.get("telemetry", {})
        state_file = telemetry_config.get("state_file", "%ProgramData%\\UEBAAgent\\state.json")
        self.state_manager = StateManager(state_file)
        
        spool_dir = telemetry_config.get("spool_dir", "%ProgramData%\\UEBAAgent\\spool")
        max_spool_mb = telemetry_config.get("max_spool_mb", 200)
        self.spool_queue = SpoolQueue(spool_dir, max_spool_mb)
        
        # REAL-TIME MODE: If spool_enabled=False, events are DROPPED when server is down
        # This prevents any backlog from building up during server downtime
        self.spool_enabled = telemetry_config.get("spool_enabled", True)
        if not self.spool_enabled:
            print(f"[!] SPOOL DISABLED: Events will be DROPPED if server is unreachable (pure real-time mode)")
        
        # Stats for GUI
        self._stats = {
            "events_read": 0,
            "events_sent": 0,
            "events_spooled": 0,
            "events_dropped": 0,  # New: track dropped events
            "spool_backlog_mb": 0.0,
            "last_send_error": None,
            "channels": {}  # Per-channel stats
        }
        self._stats_lock = threading.Lock()
    
    def add_collector(self, collector: EventCollector, poll_interval: float):
        """Add a collector with its poll interval."""
        self._collectors.append((collector, poll_interval))
    
    def start(self):
        """Start all collector threads and the sender."""
        self._running = True
        
        # Start collector threads
        for collector, interval in self._collectors:
            thread = threading.Thread(
                target=self._collector_loop,
                args=(collector, interval),
                daemon=True
            )
            thread.start()
            self._threads.append(thread)
        
        # Start sender thread (pass agent_auth if available for status checking)
        sender_thread = threading.Thread(
            target=self._sender_loop,
            args=(self.agent_token, getattr(self, '_agent_auth', None)),
            daemon=True
        )
        sender_thread.start()
        self._threads.append(sender_thread)
    
    def _collector_loop(self, collector: EventCollector, interval: float):
        """Loop that polls a collector and queues events."""
        # Initial poll to set baseline
        collector.poll()
        
        while self._running:
            try:
                events = collector.poll()
                event_count = len(events)
                if event_count > 0:
                    # Update stats
                    with self._stats_lock:
                        self._stats["events_read"] += event_count
                        channel_name = collector.channel
                        if channel_name not in self._stats["channels"]:
                            self._stats["channels"][channel_name] = {"events_read": 0}
                        self._stats["channels"][channel_name]["events_read"] += event_count
                    
                    # Queue events
                    for event in events:
                        self.event_queue.put(event)
            except Exception as e:
                print(f"[WARN] Collector error ({collector.source_name}): {e}")
            
            time.sleep(interval)
    
    def _sender_loop(self, agent_token: Optional[str] = None, agent_auth: Optional[AgentAuth] = None):
        """
        Loop that sends queued events to the server.
        
        Also periodically checks connection status and agent user enabled status.
        Supports spool queue for durability during network/server downtime.
        
        FLOOD PREVENTION:
        - Spool drain is rate-limited to MAX_SPOOL_DRAIN_PER_BATCH events
        - Delay between spool drain batches (SPOOL_DRAIN_INTERVAL_SEC)
        - Total batch size capped at MAX_EVENTS_PER_POLL
        
        RESILIENCE (Patch A):
        - Exponential backoff on send failure (1s -> 2s -> 4s -> ... -> 60s max)
        - Atomic spool drain (dequeue_start/commit/rollback) prevents duplicates
        - WinError 10054 handling with backoff
        """
        # Get configurable settings
        telemetry_config = self.config.get("telemetry", {})
        # Enforce hard cap on batch size
        batch_size = min(telemetry_config.get("batch_size", 200), MAX_EVENTS_PER_POLL)
        send_interval = telemetry_config.get("send_interval_seconds", 1.0)
        status_check_interval = 60  # Check status every 60 seconds
        last_status_check = 0
        last_spool_drain = 0  # Track last spool drain time for rate limiting
        
        # Exponential backoff state
        backoff_delay = 0.0  # Current backoff delay (0 = no backoff)
        max_backoff = 60.0   # Maximum backoff delay
        backoff_multiplier = 2.0
        consecutive_failures = 0
        
        print(f"[*] Sender started: batch_size={batch_size}, interval={send_interval}s")
        print(f"[*] Spool rate limit: max {MAX_SPOOL_DRAIN_PER_BATCH} events every {SPOOL_DRAIN_INTERVAL_SEC}s")
        
        while self._running:
            batch = []
            
            try:
                # Periodically check connection status
                current_time = time.time()
                if agent_auth and (current_time - last_status_check) >= status_check_interval:
                    last_status_check = current_time
                    status_result = agent_auth.check_approval_status()
                    if status_result is False:
                        # Agent was declined/revoked/disabled - stop sending
                        print(f"[-] Connection rejected. Stopping event forwarding.")
                        self._running = False
                        break
                
                # RATE-LIMITED spool drain (oldest events first)
                # Only drain if spool is enabled and enough time has passed since last drain
                if self.spool_enabled and (current_time - last_spool_drain) >= SPOOL_DRAIN_INTERVAL_SEC:
                    # Use smaller cap for spool drain to prevent burst
                    spooled_events = self.spool_queue.dequeue(max_events=MAX_SPOOL_DRAIN_PER_BATCH)
                    if spooled_events:
                        batch.extend(spooled_events)
                        last_spool_drain = current_time
                        with self._stats_lock:
                            self._stats["events_spooled"] -= len(spooled_events)
                        print(f"[*] Spool drain: {len(spooled_events)} events (backlog: {self.spool_queue.get_size_mb():.1f} MB)")
                
                # Collect new events from queue (up to remaining batch capacity)
                remaining_capacity = batch_size - len(batch)
                if remaining_capacity > 0:
                    deadline = time.time() + send_interval
                    while len(batch) < batch_size and time.time() < deadline:
                        try:
                            remaining = deadline - time.time()
                            if remaining <= 0:
                                break
                            event = self.event_queue.get(timeout=min(remaining, 0.1))
                            batch.append(event)
                        except Empty:
                            continue
                
                # Send batch if we have events
                if batch:
                    send_start_time = time.time()
                    
                    # Get TLS config from agent config
                    server_config = self.config.get("server", {})
                    tls_enabled = server_config.get("tls_enabled", False)
                    tls_cert_path = server_config.get("tls_cert_path", "")
                    tls_verify = server_config.get("tls_verify", True)
                    
                    success = send_events_over_tcp(
                        self.server_ip, 
                        self.port, 
                        batch, 
                        agent_token,
                        tls_enabled=tls_enabled,
                        tls_cert_path=tls_cert_path if tls_cert_path else None,
                        tls_verify=tls_verify
                    )
                    
                    send_duration_ms = (time.time() - send_start_time) * 1000
                    
                    if success:
                        protocol = "TLS" if tls_enabled else "TCP"
                        with self._stats_lock:
                            self._stats["events_sent"] += len(batch)
                            self._stats["last_send_error"] = None
                        print(f"[+] Sent {len(batch)} event(s) to {self.server_ip}:{self.port} ({protocol}) in {send_duration_ms:.0f}ms")
                    else:
                        # Send failed - spool or drop based on config
                        if self.spool_enabled:
                            self.spool_queue.enqueue(batch)
                            with self._stats_lock:
                                self._stats["events_spooled"] += len(batch)
                            print(f"[-] Failed to send {len(batch)} event(s), spooled for retry")
                        else:
                            # REAL-TIME MODE: Drop events instead of spooling
                            with self._stats_lock:
                                self._stats["events_dropped"] += len(batch)
                            print(f"[-] Failed to send {len(batch)} event(s), DROPPED (spool disabled)")
                        
                        error_msg = f"Connection failed to {self.server_ip}:{self.port}"
                        with self._stats_lock:
                            self._stats["last_send_error"] = error_msg
                        
                        # Check if connection failed due to authentication/authorization
                        if agent_auth:
                            status_result = agent_auth.check_approval_status()
                            if status_result is False:
                                print(f"[-] Connection rejected. Stopping event forwarding.")
                                self._running = False
                                break
                else:
                    # No events, sleep for send_interval to avoid busy-waiting
                    time.sleep(send_interval)
                
            except Exception as e:
                error_msg = f"Sender error: {e}"
                print(f"[WARN] {error_msg}")
                with self._stats_lock:
                    self._stats["last_send_error"] = error_msg
    
    def get_stats(self) -> Dict:
        """Get current statistics for GUI display."""
        with self._stats_lock:
            # Update spool size
            self._stats["spool_backlog_mb"] = self.spool_queue.get_size_mb()
            # Update per-channel stats
            for collector, _ in self._collectors:
                channel_name = collector.channel
                if channel_name not in self._stats["channels"]:
                    self._stats["channels"][channel_name] = {"events_read": 0}
            return self._stats.copy()
    
    def stop(self):
        """Stop all threads."""
        self._running = False
    
    def run_forever(self):
        """Run until interrupted."""
        self.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            self.stop()


def run_forwarder(server_ip: str, port: int, config: dict) -> None:
    """
    Main forwarder loop. Polls events from multiple channels and forwards them.
    
    Supports optional authentication with the UEBA server.
    
    Args:
        server_ip: Remote server IP or hostname.
        port: Remote server port.
        config: Configuration dictionary containing settings.
    """
    # Authentication configuration
    auth_config = config.get("auth", {})
    auth_enabled = auth_config.get("enabled", False)
    web_port = auth_config.get("web_port", 8080)
    agent_username = auth_config.get("username", "")
    agent_password = auth_config.get("password", "")
    
    agent_auth = None
    
    # Authentication is now MANDATORY
    if not agent_username or not agent_password:
        print(f"[!] ERROR: Authentication is required!")
        print(f"    Please configure agent credentials in the Agent Users page on the server.")
        print(f"    Then update your config with:")
        print(f"      auth:")
        print(f"        enabled: true")
        print(f"        username: <agent_username>")
        print(f"        password: <agent_password>")
        print()
        return
    
    print(f"[*] Authenticating with server...")
    server_url = f"http://{server_ip}:{web_port}"
    agent_auth = AgentAuth(server_url, agent_username, agent_password)
    
    authenticated = agent_auth.authenticate()
    
    if not authenticated:
        # Check if we got an agent_id (means credentials were valid but pending)
        if agent_auth.agent_id:
            # Agent is pending approval - poll for approval
            print(f"[*] Waiting for admin approval...")
            print(f"    Please approve this agent in the server dashboard.")
            print(f"    Polling for approval every 10 seconds...")
            print()
            
            # Poll for approval
            max_polls = 300  # Poll for up to 50 minutes (300 * 10 seconds)
            poll_count = 0
            while poll_count < max_polls:
                time.sleep(10)
                poll_count += 1
                approved = agent_auth.check_approval_status()
                if approved:
                    print(f"[+] Agent approved! Starting event forwarding...")
                    authenticated = True
                    break
                elif approved is False:
                    print(f"[-] Agent was declined or revoked. Exiting.")
                    return
                # Otherwise still pending, continue polling
                if poll_count % 6 == 0:  # Every minute
                    print(f"[*] Still waiting for approval... (checked {poll_count * 10}s ago)")
            
            if not authenticated:
                print(f"[-] Timeout waiting for approval. Exiting.")
                return
        else:
            # Authentication failed - invalid credentials
            error_msg = (
                f"❌ AUTHENTICATION FAILED!\n\n"
                f"Invalid username or password.\n\n"
                f"Server: {server_url}\n"
                f"Username: {agent_username}\n\n"
                f"Please check:\n"
                f"1. Username and password are correct\n"
                f"2. Agent user exists in server's Agent Users page\n"
                f"3. Agent user is enabled\n"
                f"4. Server is accessible at {server_ip}:{web_port}"
            )
            print()
            print("=" * 70)
            print(error_msg)
            print("=" * 70)
            print()
            
            # Try to show GUI error dialog if tkinter is available
            try:
                import tkinter.messagebox as msgbox
                msgbox.showerror(
                    "❌ Authentication Failed", 
                    f"Invalid username or password.\n\n"
                    f"Server: {server_url}\n"
                    f"Username: {agent_username}\n\n"
                    f"Please verify:\n"
                    f"• Username and password are correct\n"
                    f"• Agent user exists in server's 'Agent Users' page\n"
                    f"• Agent user is enabled (not disabled)\n"
                    f"• Server is accessible at {server_ip}:{web_port}"
                )
            except ImportError:
                # tkinter not available (running as EXE or headless)
                pass
            except Exception as e:
                # GUI error showing failed, console message is enough
                print(f"[WARN] Could not show GUI error dialog: {e}")
            
            # Exit with error code to stop the agent
            raise SystemExit(1)
    
    if authenticated:
        print(f"[+] Connected to server as: {agent_username}")
        print(f"[*] Event forwarding starting immediately...")
        print()
        
        # Start heartbeat thread
        def heartbeat_loop():
            while True:
                time.sleep(60)  # Heartbeat every 60 seconds
                if agent_auth and agent_auth.token:
                    agent_auth.heartbeat()
        
        heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=True)
        heartbeat_thread.start()
    
    # Sysmon configuration
    sysmon_config = config.get("sysmon", {})
    sysmon_channel = sysmon_config.get("channel", "Microsoft-Windows-Sysmon/Operational")
    sysmon_max_events = sysmon_config.get("max_events", 200)
    sysmon_poll_interval = sysmon_config.get("poll_interval_seconds", 5)
    
    # Security log configuration
    security_config = config.get("security", {})
    security_enabled = security_config.get("enabled", True)
    security_max_events = security_config.get("max_events", 100)
    security_poll_interval = security_config.get("poll_interval_seconds", 5)
    
    print(f"[*] Initializing event collectors...")
    print(f"    Ingest Server: {server_ip}:{port}")
    print()
    
    # FLOOD PREVENTION: Read collection config
    collection_config = config.get("collection", {})
    start_from_now = collection_config.get("start_from_now", True)  # Default: real-time only
    lookback_minutes = collection_config.get("lookback_minutes", None)
    
    print(f"[*] FLOOD PREVENTION SETTINGS:")
    print(f"    start_from_now: {start_from_now}")
    print(f"    lookback_minutes: {lookback_minutes}")
    print(f"    max_initial_events: {MAX_INITIAL_EVENTS_PER_CHANNEL}")
    print(f"    max_events_per_poll: {MAX_EVENTS_PER_POLL}")
    print()
    
    # Create multi-channel forwarder
    # Create forwarder with agent token and auth object for status checking
    agent_token = agent_auth.token if agent_auth else None
    forwarder = MultiChannelForwarder(server_ip, port, config, agent_token)
    # Store agent_auth for status checking
    forwarder._agent_auth = agent_auth
    
    # Get state_manager from forwarder (created during initialization)
    state_manager = forwarder.state_manager
    
    # Check if channels config exists (new format) or use legacy format
    channels_config = config.get("channels", [])
    use_channels_config = len(channels_config) > 0
    
    if use_channels_config:
        # New format: use channels config
        print(f"[*] Using channel-based configuration...")
        for channel_config in channels_config:
            channel_name = channel_config.get("name")
            channel_enabled = channel_config.get("enabled", True)
            
            if not channel_enabled:
                print(f"[*] Channel {channel_name}: DISABLED")
                continue
            
            # Get source_name from config or derive from channel
            source_name = channel_config.get("source_name", "WINDOWS_EVENT")
            max_events = channel_config.get("max_events", 100)
            poll_interval = channel_config.get("poll_interval_seconds", 5)
            
            # Determine collector type and settings based on channel name
            if "Sysmon" in channel_name:
                collector = SysmonCollector(channel_name, sysmon_max_events, state_manager,
                                           start_from_now=start_from_now, lookback_minutes=lookback_minutes)
                poll_interval = sysmon_poll_interval
            elif channel_name == "Security":
                # Check if capture_all is set in channel config or security config
                security_capture_all = channel_config.get("capture_all", security_config.get("capture_all", False))
                security_custom_ids = channel_config.get("event_ids", security_config.get("event_ids", None))
                if security_custom_ids and isinstance(security_custom_ids, list):
                    security_custom_ids = set(security_custom_ids)
                collector = SecurityEventCollector(
                    max_events=security_max_events,
                    event_ids=security_custom_ids,
                    capture_all=security_capture_all,
                    state_manager=state_manager,
                    start_from_now=start_from_now,
                    lookback_minutes=lookback_minutes
                )
                poll_interval = security_poll_interval
            elif channel_name == "Application":
                collector = ApplicationEventCollector(max_events=application_max_events, state_manager=state_manager,
                                                     start_from_now=start_from_now, lookback_minutes=lookback_minutes)
                poll_interval = application_poll_interval
            elif channel_name == "System":
                collector = SystemEventCollector(max_events=system_max_events, state_manager=state_manager,
                                                start_from_now=start_from_now, lookback_minutes=lookback_minutes)
                poll_interval = system_poll_interval
            else:
                # Generic collector for all other channels (PowerShell, WMI, Defender, etc.)
                collector = EventCollector(
                    channel=channel_name,
                    max_events=max_events,
                    source_name=source_name,
                    event_ids=None,  # Collect all events by default
                    state_manager=state_manager,
                    start_from_now=start_from_now,
                    lookback_minutes=lookback_minutes
                )
            
            print(f"[*] Channel: {channel_name}")
            print(f"    Max events per poll: {collector.max_events}")
            print(f"    Poll interval: {poll_interval} seconds")
            print(f"    start_from_now: {start_from_now}")
            forwarder.add_collector(collector, poll_interval)
    else:
        # Legacy format: use individual config sections
        # Add Sysmon collector
        print(f"[*] Sysmon Collector:")
        print(f"    Channel: {sysmon_channel}")
        print(f"    Max events per poll: {sysmon_max_events}")
        print(f"    Poll interval: {sysmon_poll_interval} seconds")
        
        sysmon_collector = SysmonCollector(sysmon_channel, sysmon_max_events,
                                           state_manager=state_manager,
                                           start_from_now=start_from_now, lookback_minutes=lookback_minutes)
        forwarder.add_collector(sysmon_collector, sysmon_poll_interval)
    
    # Add Security log collector if enabled
    if security_enabled:
        # Get optional configuration for security event filtering
        security_capture_all = security_config.get("capture_all", False)
        security_custom_ids = security_config.get("event_ids", None)
        
        # Convert list to set if provided
        if security_custom_ids and isinstance(security_custom_ids, list):
            security_custom_ids = set(security_custom_ids)
        
        print()
        print(f"[*] Security Log Collector:")
        print(f"    Channel: Security")
        if security_capture_all:
            print(f"    Event IDs: ALL (no filtering)")
        elif security_custom_ids:
            print(f"    Event IDs: {len(security_custom_ids)} custom IDs configured")
        else:
            print(f"    Event IDs: {len(SecurityEventCollector.DEFAULT_EVENT_IDS)} default security events")
        print(f"    Max events per poll: {security_max_events}")
        print(f"    Poll interval: {security_poll_interval} seconds")
        
        security_collector = SecurityEventCollector(
            max_events=security_max_events,
            event_ids=security_custom_ids,
            capture_all=security_capture_all,
            state_manager=state_manager,
            start_from_now=start_from_now,
            lookback_minutes=lookback_minutes
        )
        forwarder.add_collector(security_collector, security_poll_interval)
    else:
        print()
        print(f"[*] Security Log Collector: DISABLED")
    
    # Application log configuration
    application_config = config.get("application", {})
    application_enabled = application_config.get("enabled", True)  # Enabled by default
    application_max_events = application_config.get("max_events", 100)
    application_poll_interval = application_config.get("poll_interval_seconds", 5)
    
    if application_enabled:
        print()
        print(f"[*] Application Log Collector:")
        print(f"    Channel: Application")
        print(f"    Max events per poll: {application_max_events}")
        print(f"    Poll interval: {application_poll_interval} seconds")
        
        application_collector = ApplicationEventCollector(
            max_events=application_max_events,
            state_manager=state_manager,
            start_from_now=start_from_now,
            lookback_minutes=lookback_minutes
        )
        forwarder.add_collector(application_collector, application_poll_interval)
    else:
        print()
        print(f"[*] Application Log Collector: DISABLED")
    
    # System log configuration
    system_config = config.get("system_log", {})
    system_enabled = system_config.get("enabled", True)  # Enabled by default
    system_max_events = system_config.get("max_events", 100)
    system_poll_interval = system_config.get("poll_interval_seconds", 5)
    
    if system_enabled:
        print()
        print(f"[*] System Log Collector:")
        print(f"    Channel: System")
        print(f"    Max events per poll: {system_max_events}")
        print(f"    Poll interval: {system_poll_interval} seconds")
        
        system_collector = SystemEventCollector(
            max_events=system_max_events,
            state_manager=state_manager,
            start_from_now=start_from_now,
            lookback_minutes=lookback_minutes
        )
        forwarder.add_collector(system_collector, system_poll_interval)
    else:
        print()
        print(f"[*] System Log Collector: DISABLED")
    
    print()
    print(f"[*] Forwarder running. Waiting for new events...")
    print()
    
    # Run forever
    forwarder.run_forever()
