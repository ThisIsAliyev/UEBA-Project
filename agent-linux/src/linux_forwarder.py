"""
Linux Event Collector and TCP Forwarder.

Collects events from:
- Journalctl (systemd journal)
- Auth log (/var/log/auth.log or /var/log/secure)
- Syslog (/var/log/syslog or /var/log/messages)
- Auditd (/var/log/audit/audit.log)

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

# ============================================
# HARD SAFETY CAPS (enforced regardless of config)
# ============================================
MAX_INITIAL_EVENTS_PER_SOURCE = 500
MAX_EVENTS_PER_POLL = 200
MAX_SPOOL_DRAIN_PER_BATCH = 50
SPOOL_DRAIN_INTERVAL_SEC = 2.0
TIME_DRIFT_WARNING_SECONDS = 300


# ============================================
# State Persistence and Spool Queue
# ============================================

class StateManager:
    """Manages persistent state (bookmarks) for event collectors."""
    
    def __init__(self, state_file: str):
        self.state_file = Path(os.path.expandvars(state_file))
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._state: Dict[str, Dict] = {}
        self._load_state()
    
    def _load_state(self):
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
        try:
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(self._state, f, indent=2)
        except Exception as e:
            print(f"[WARN] Failed to save state to {self.state_file}: {e}")
    
    def get_bookmark(self, source: str) -> Optional[str]:
        with self._lock:
            source_state = self._state.get(source, {})
            return source_state.get("cursor")
    
    def set_bookmark(self, source: str, cursor: str):
        with self._lock:
            if source not in self._state:
                self._state[source] = {}
            self._state[source]["cursor"] = cursor
            self._state[source]["updated_at"] = datetime.now().isoformat()
            self._save_state()
    
    def get_line_number(self, source: str) -> int:
        with self._lock:
            source_state = self._state.get(source, {})
            return source_state.get("line_number", 0)
    
    def set_line_number(self, source: str, line_number: int):
        with self._lock:
            if source not in self._state:
                self._state[source] = {}
            self._state[source]["line_number"] = line_number
            self._state[source]["updated_at"] = datetime.now().isoformat()
            self._save_state()


class SpoolQueue:
    """Durable spool queue for events when server is unavailable."""
    
    def __init__(self, spool_dir: str, max_size_mb: int = 200):
        spool_dir = os.path.expandvars(spool_dir)
        self.spool_dir = Path(spool_dir)
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self._lock = threading.Lock()
        self._current_file: Optional[Path] = None
        self._current_file_size = 0
        self._file_counter = 0
        self._total_size = 0
        self._inflight_file: Optional[Path] = None
        self._load_spool_info()
        self._recover_inflight()
    
    def _load_spool_info(self):
        if not self.spool_dir.exists():
            return
        spool_files = sorted(self.spool_dir.glob("spool_*.ndjson"))
        sending_files = list(self.spool_dir.glob("spool_*.sending"))
        all_files = spool_files + sending_files
        if all_files:
            self._file_counter = len(all_files)
            self._total_size = sum(f.stat().st_size for f in all_files if f.exists())
            if spool_files:
                self._current_file = spool_files[-1]
                self._current_file_size = self._current_file.stat().st_size
    
    def _recover_inflight(self):
        try:
            for sending_file in self.spool_dir.glob("spool_*.sending"):
                original_name = sending_file.with_suffix('.ndjson')
                try:
                    sending_file.rename(original_name)
                    print(f"[*] Recovered inflight spool file: {sending_file.name}")
                except Exception as e:
                    print(f"[WARN] Failed to recover {sending_file}: {e}")
        except Exception as e:
            print(f"[WARN] Failed to scan for inflight files: {e}")
    
    def _get_new_file(self) -> Path:
        self._file_counter += 1
        return self.spool_dir / f"spool_{self._file_counter:06d}.ndjson"
    
    def _rotate_if_needed(self):
        if self._current_file_size > 10 * 1024 * 1024:
            self._current_file = None
            self._current_file_size = 0
    
    def _cleanup_old_files(self):
        if self._total_size <= self.max_size_bytes:
            return
        spool_files = sorted(self.spool_dir.glob("spool_*.ndjson"), key=lambda p: p.stat().st_mtime)
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
        if not events:
            return
        with self._lock:
            if self._current_file is None:
                self._current_file = self._get_new_file()
                self._current_file_size = 0
            try:
                with open(self._current_file, 'a', encoding='utf-8') as f:
                    for event in events:
                        line = json.dumps(event, ensure_ascii=False, default=str) + '\n'
                        f.write(line)
                        self._current_file_size += len(line.encode('utf-8'))
                        self._total_size += len(line.encode('utf-8'))
                self._rotate_if_needed()
                self._cleanup_old_files()
            except Exception as e:
                print(f"[WARN] Failed to write to spool: {e}")
    
    def dequeue(self, max_events: int = 200) -> List[Dict]:
        events = self.dequeue_start(max_events)
        if events:
            self.dequeue_commit()
        return events
    
    def dequeue_start(self, max_events: int = 200) -> List[Dict]:
        events = []
        with self._lock:
            if self._inflight_file is not None:
                return []
            spool_files = sorted(self.spool_dir.glob("spool_*.ndjson"), key=lambda p: p.stat().st_mtime)
            if not spool_files:
                return []
            spool_file = spool_files[0]
            try:
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
                    sending_file = spool_file.with_suffix('.sending')
                    spool_file.rename(sending_file)
                    self._inflight_file = sending_file
            except Exception as e:
                print(f"[WARN] Failed to read from spool file {spool_file}: {e}")
        return events
    
    def dequeue_commit(self):
        with self._lock:
            if self._inflight_file is None:
                return
            try:
                if self._inflight_file.exists():
                    file_size = self._inflight_file.stat().st_size
                    self._inflight_file.unlink()
                    self._total_size -= file_size
            except Exception as e:
                print(f"[WARN] Failed to delete inflight file: {e}")
            finally:
                self._inflight_file = None
    
    def dequeue_rollback(self):
        with self._lock:
            if self._inflight_file is None:
                return
            try:
                if self._inflight_file.exists():
                    original_name = self._inflight_file.with_suffix('.ndjson')
                    self._inflight_file.rename(original_name)
            except Exception as e:
                print(f"[WARN] Failed to rollback inflight file: {e}")
            finally:
                self._inflight_file = None
    
    def get_size_mb(self) -> float:
        with self._lock:
            return self._total_size / (1024 * 1024)
    
    def get_file_count(self) -> int:
        with self._lock:
            return len(list(self.spool_dir.glob("spool_*.ndjson")))


# ============================================
# Agent Authentication
# ============================================

class AgentAuth:
    """Handles agent authentication with the UEBA server."""
    
    def __init__(self, server_url: str, username: str, password: str):
        self.server_url = server_url.rstrip('/')
        self.username = username
        self.password = password
        self.token: Optional[str] = None
        self.agent_id: Optional[int] = None
        self._hostname = platform.node()
        self._os_type = "linux"
        self._os_version = self._get_os_version()
        self._ip_address = self._get_local_ip()
    
    def _get_os_version(self) -> str:
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('PRETTY_NAME='):
                        return line.split('=')[1].strip().strip('"')
        except:
            pass
        return platform.version()
    
    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def authenticate(self) -> bool:
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
                        return False
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
            if e.code == 401:
                print(f"[-] Authentication failed: Invalid credentials")
            else:
                print(f"[-] Server error (HTTP {e.code})")
            return False
        except urllib.error.URLError as e:
            print(f"[-] Cannot connect to server: {e.reason}")
            return False
        except Exception as e:
            print(f"[-] Authentication error: {e}")
            return False
    
    def check_approval_status(self) -> Optional[bool]:
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
                    if not agent_user_enabled:
                        print(f"[-] Agent user has been disabled")
                        return False
                    if status == 'approved':
                        if self.authenticate():
                            return True
                        return None
                    elif status in ('declined', 'revoked'):
                        print(f"[-] Agent has been {status}")
                        return False
                    else:
                        return None
                return None
        except Exception:
            return None
    
    def heartbeat(self) -> bool:
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
                return self.authenticate()
            return False
        except Exception:
            return False


# ============================================
# TCP Sender
# ============================================

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
    Send events to server over TCP/TLS as newline-delimited JSON.
    
    Each event is sent individually with Source field for identification.
    Same protocol as Windows agent for compatibility.
    """
    if not events:
        return True
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        
        if tls_enabled:
            context = ssl.create_default_context()
            if not tls_verify:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            elif tls_cert_path and os.path.exists(tls_cert_path):
                context.load_verify_locations(tls_cert_path)
            sock = context.wrap_socket(sock, server_hostname=server_ip)
        
        sock.connect((server_ip, port))
        
        try:
            # Send authentication token first if provided (same as Windows agent)
            if agent_token:
                auth_msg = json.dumps({"agent_token": agent_token}) + "\n"
                sock.sendall(auth_msg.encode('utf-8'))
            
            # Send each event as newline-delimited JSON (same as Windows agent)
            for event in events:
                # Ensure Source field is set for Linux event identification
                if "Source" not in event:
                    event["Source"] = "LINUX_EVENT"
                
                json_line = json.dumps(event, ensure_ascii=False, default=str)
                data = (json_line + "\n").encode("utf-8")
                sock.sendall(data)
            
            return True
            
        finally:
            sock.close()
        
    except socket.timeout:
        print(f"[WARN] Connection timed out to {server_ip}:{port}")
        return False
    except ConnectionRefusedError:
        print(f"[WARN] Connection refused to {server_ip}:{port}")
        return False
    except Exception as e:
        print(f"[WARN] Failed to send events: {e}")
        return False


# ============================================
# Linux Log Collectors
# ============================================

class JournalctlCollector:
    """Collects events from systemd journal using journalctl."""
    
    def __init__(
        self,
        max_events: int = 200,
        units: Optional[List[str]] = None,
        priority: int = 6,
        state_manager: Optional[StateManager] = None,
        start_from_now: bool = True
    ):
        self.max_events = min(max_events, MAX_EVENTS_PER_POLL)
        self.units = units or []
        self.priority = priority
        self.state_manager = state_manager
        self.start_from_now = start_from_now
        self.source_name = "JOURNALCTL"
        self._cursor: Optional[str] = None
        self._first_poll = True
        
        if state_manager:
            self._cursor = state_manager.get_bookmark("journalctl")
            if self._cursor:
                print(f"[*] JOURNALCTL: Resuming from cursor")
                self._first_poll = False
    
    def poll(self) -> List[Dict]:
        if self._first_poll:
            self._first_poll = False
            if self.start_from_now:
                # Get current cursor position
                cursor = self._get_current_cursor()
                if cursor:
                    self._cursor = cursor
                    if self.state_manager:
                        self.state_manager.set_bookmark("journalctl", cursor)
                    print(f"[*] JOURNALCTL: start_from_now=True, baseline set")
                return []
        
        events = self._fetch_events()
        
        if events:
            # Update cursor from last event
            last_cursor = events[-1].get("__CURSOR")
            if last_cursor:
                self._cursor = last_cursor
                if self.state_manager:
                    self.state_manager.set_bookmark("journalctl", last_cursor)
            
            print(f"[+] JOURNALCTL: {len(events)} new event(s)")
            
            # Add source tag
            for event in events:
                event["Source"] = self.source_name
        
        return events
    
    def _get_current_cursor(self) -> Optional[str]:
        try:
            cmd = ["journalctl", "-n", "1", "-o", "json", "--no-pager"]
            result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=10)
            output = result.decode('utf-8').strip()
            if output:
                data = json.loads(output)
                return data.get("__CURSOR")
        except Exception as e:
            print(f"[WARN] Failed to get journalctl cursor: {e}")
        return None
    
    def _fetch_events(self) -> List[Dict]:
        events = []
        try:
            cmd = ["journalctl", "-o", "json", "--no-pager", "-n", str(self.max_events)]
            
            # Add priority filter
            cmd.extend(["-p", str(self.priority)])
            
            # Add unit filters
            for unit in self.units:
                cmd.extend(["-u", unit])
            
            # Add cursor filter for incremental
            if self._cursor:
                cmd.extend(["--after-cursor", self._cursor])
            
            result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=30)
            
            for line in result.decode('utf-8').strip().split('\n'):
                if line.strip():
                    try:
                        event = json.loads(line)
                        # Normalize timestamp
                        if "__REALTIME_TIMESTAMP" in event:
                            ts = int(event["__REALTIME_TIMESTAMP"]) / 1000000
                            event["TimeCreated"] = datetime.utcfromtimestamp(ts).isoformat() + "Z"
                        events.append(event)
                    except json.JSONDecodeError:
                        continue
            
        except subprocess.TimeoutExpired:
            print(f"[WARN] Journalctl command timed out")
        except FileNotFoundError:
            print(f"[WARN] journalctl not found - is systemd installed?")
        except Exception as e:
            print(f"[WARN] Failed to fetch journalctl events: {e}")
        
        return events


class LogFileCollector:
    """Collects events from a log file by tailing it."""
    
    def __init__(
        self,
        log_path: str,
        source_name: str,
        max_lines: int = 100,
        state_manager: Optional[StateManager] = None,
        start_from_now: bool = True
    ):
        self.log_path = log_path
        self.source_name = source_name
        self.max_lines = min(max_lines, MAX_EVENTS_PER_POLL)
        self.state_manager = state_manager
        self.start_from_now = start_from_now
        self._line_number = 0
        self._first_poll = True
        
        if state_manager:
            saved_line = state_manager.get_line_number(source_name)
            if saved_line:
                self._line_number = saved_line
                print(f"[*] {source_name}: Resuming from line {saved_line}")
                self._first_poll = False
    
    def poll(self) -> List[Dict]:
        if not os.path.exists(self.log_path):
            return []
        
        if self._first_poll:
            self._first_poll = False
            if self.start_from_now:
                # Count current lines
                try:
                    with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        self._line_number = sum(1 for _ in f)
                    if self.state_manager:
                        self.state_manager.set_line_number(self.source_name, self._line_number)
                    print(f"[*] {self.source_name}: start_from_now=True, baseline at line {self._line_number}")
                except Exception as e:
                    print(f"[WARN] Failed to count lines in {self.log_path}: {e}")
                return []
        
        events = []
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Skip to our position
                for i, line in enumerate(f):
                    if i < self._line_number:
                        continue
                    if len(events) >= self.max_lines:
                        break
                    
                    line = line.strip()
                    if line:
                        event = self._parse_log_line(line)
                        event["Source"] = self.source_name
                        event["RawMessage"] = line
                        events.append(event)
                        self._line_number = i + 1
            
            if events:
                if self.state_manager:
                    self.state_manager.set_line_number(self.source_name, self._line_number)
                print(f"[+] {self.source_name}: {len(events)} new line(s)")
                
        except Exception as e:
            print(f"[WARN] Failed to read {self.log_path}: {e}")
        
        return events
    
    def _parse_log_line(self, line: str) -> Dict:
        """Parse a log line into a structured event."""
        event = {
            "TimeCreated": datetime.utcnow().isoformat() + "Z",
            "Message": line
        }
        
        # Try to parse syslog format: "Mon DD HH:MM:SS hostname process[pid]: message"
        try:
            parts = line.split(None, 5)
            if len(parts) >= 5:
                # Month Day Time
                timestamp_str = f"{parts[0]} {parts[1]} {parts[2]}"
                hostname = parts[3]
                process_info = parts[4].rstrip(':')
                message = parts[5] if len(parts) > 5 else ""
                
                event["Hostname"] = hostname
                event["Process"] = process_info
                event["Message"] = message
                
                # Parse process name and PID
                if '[' in process_info and ']' in process_info:
                    proc_name = process_info.split('[')[0]
                    pid = process_info.split('[')[1].rstrip(']')
                    event["ProcessName"] = proc_name
                    event["ProcessId"] = pid
        except:
            pass
        
        return event


class AuthLogCollector(LogFileCollector):
    """Collects authentication events from auth.log or secure log."""
    
    def __init__(
        self,
        max_lines: int = 100,
        state_manager: Optional[StateManager] = None,
        start_from_now: bool = True
    ):
        # Determine log path based on distro
        if os.path.exists('/var/log/auth.log'):
            log_path = '/var/log/auth.log'
        elif os.path.exists('/var/log/secure'):
            log_path = '/var/log/secure'
        else:
            log_path = '/var/log/auth.log'  # Default
        
        super().__init__(
            log_path=log_path,
            source_name="AUTH_LOG",
            max_lines=max_lines,
            state_manager=state_manager,
            start_from_now=start_from_now
        )


class SyslogCollector(LogFileCollector):
    """Collects system events from syslog or messages."""
    
    def __init__(
        self,
        max_lines: int = 100,
        state_manager: Optional[StateManager] = None,
        start_from_now: bool = True
    ):
        # Determine log path based on distro
        if os.path.exists('/var/log/syslog'):
            log_path = '/var/log/syslog'
        elif os.path.exists('/var/log/messages'):
            log_path = '/var/log/messages'
        else:
            log_path = '/var/log/syslog'  # Default
        
        super().__init__(
            log_path=log_path,
            source_name="SYSLOG",
            max_lines=max_lines,
            state_manager=state_manager,
            start_from_now=start_from_now
        )


class AuditdCollector:
    """Collects events from auditd (Linux Audit Framework)."""
    
    def __init__(
        self,
        max_events: int = 100,
        state_manager: Optional[StateManager] = None,
        start_from_now: bool = True
    ):
        self.log_path = '/var/log/audit/audit.log'
        self.source_name = "AUDITD"
        self.max_events = min(max_events, MAX_EVENTS_PER_POLL)
        self.state_manager = state_manager
        self.start_from_now = start_from_now
        self._line_number = 0
        self._first_poll = True
        
        if state_manager:
            saved_line = state_manager.get_line_number("auditd")
            if saved_line:
                self._line_number = saved_line
                print(f"[*] AUDITD: Resuming from line {saved_line}")
                self._first_poll = False
    
    def poll(self) -> List[Dict]:
        if not os.path.exists(self.log_path):
            return []
        
        if self._first_poll:
            self._first_poll = False
            if self.start_from_now:
                try:
                    with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        self._line_number = sum(1 for _ in f)
                    if self.state_manager:
                        self.state_manager.set_line_number("auditd", self._line_number)
                    print(f"[*] AUDITD: start_from_now=True, baseline at line {self._line_number}")
                except Exception as e:
                    print(f"[WARN] Failed to count lines in audit.log: {e}")
                return []
        
        events = []
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i < self._line_number:
                        continue
                    if len(events) >= self.max_events:
                        break
                    
                    line = line.strip()
                    if line:
                        event = self._parse_audit_line(line)
                        event["Source"] = self.source_name
                        event["RawMessage"] = line
                        events.append(event)
                        self._line_number = i + 1
            
            if events:
                if self.state_manager:
                    self.state_manager.set_line_number("auditd", self._line_number)
                print(f"[+] AUDITD: {len(events)} new event(s)")
                
        except PermissionError:
            pass  # Silent fail for permission issues
        except Exception as e:
            print(f"[WARN] Failed to read audit.log: {e}")
        
        return events
    
    def _parse_audit_line(self, line: str) -> Dict:
        """Parse an auditd log line."""
        event = {
            "TimeCreated": datetime.utcnow().isoformat() + "Z",
            "Message": line
        }
        
        # Parse audit format: type=X msg=audit(timestamp:serial): key=value ...
        try:
            # Extract type
            if 'type=' in line:
                type_start = line.index('type=') + 5
                type_end = line.index(' ', type_start) if ' ' in line[type_start:] else len(line)
                event["AuditType"] = line[type_start:type_end]
            
            # Extract timestamp from msg=audit(timestamp:serial)
            if 'msg=audit(' in line:
                ts_start = line.index('msg=audit(') + 10
                ts_end = line.index(':', ts_start)
                timestamp = float(line[ts_start:ts_end])
                event["TimeCreated"] = datetime.utcfromtimestamp(timestamp).isoformat() + "Z"
            
            # Extract key-value pairs
            for part in line.split():
                if '=' in part and not part.startswith('msg='):
                    key, value = part.split('=', 1)
                    event[key] = value.strip('"')
                    
        except Exception:
            pass
        
        return event


# ============================================
# Multi-Source Forwarder
# ============================================

class MultiSourceForwarder:
    """Manages multiple log collectors and forwards events to server."""
    
    def __init__(self, server_ip: str, port: int, config: dict, agent_token: Optional[str] = None):
        self.server_ip = server_ip
        self.port = port
        self.config = config
        self.agent_token = agent_token
        self.event_queue: Queue = Queue()
        self._running = False
        self._collectors: List = []
        self._threads: List[threading.Thread] = []
        
        # Initialize state manager and spool queue
        telemetry_config = config.get("telemetry", {})
        state_file = telemetry_config.get("state_file", "/var/lib/ueba-agent/state.json")
        self.state_manager = StateManager(state_file)
        
        spool_dir = telemetry_config.get("spool_dir", "/var/lib/ueba-agent/spool")
        max_spool_mb = telemetry_config.get("max_spool_mb", 200)
        self.spool_queue = SpoolQueue(spool_dir, max_spool_mb)
        
        self.spool_enabled = telemetry_config.get("spool_enabled", True)
        if not self.spool_enabled:
            print(f"[!] SPOOL DISABLED: Events will be DROPPED if server is unreachable")
        
        self._stats = {
            "events_read": 0,
            "events_sent": 0,
            "events_spooled": 0,
            "events_dropped": 0,
            "spool_backlog_mb": 0.0,
            "last_send_error": None,
            "sources": {}
        }
        self._stats_lock = threading.Lock()
    
    def add_collector(self, collector, poll_interval: float):
        self._collectors.append((collector, poll_interval))
    
    def start(self):
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
        
        # Start sender thread
        sender_thread = threading.Thread(
            target=self._sender_loop,
            daemon=True
        )
        sender_thread.start()
        self._threads.append(sender_thread)
    
    def _collector_loop(self, collector, interval: float):
        collector.poll()  # Initial poll
        while self._running:
            try:
                events = collector.poll()
                if events:
                    with self._stats_lock:
                        self._stats["events_read"] += len(events)
                        source = collector.source_name
                        if source not in self._stats["sources"]:
                            self._stats["sources"][source] = {"events_read": 0}
                        self._stats["sources"][source]["events_read"] += len(events)
                    for event in events:
                        self.event_queue.put(event)
            except Exception as e:
                print(f"[WARN] Collector error ({collector.source_name}): {e}")
            time.sleep(interval)
    
    def _sender_loop(self):
        telemetry_config = self.config.get("telemetry", {})
        batch_size = min(telemetry_config.get("batch_size", 200), MAX_EVENTS_PER_POLL)
        send_interval = telemetry_config.get("send_interval_seconds", 1.0)
        last_spool_drain = 0
        
        print(f"[*] Sender started: batch_size={batch_size}, interval={send_interval}s")
        
        while self._running:
            batch = []
            try:
                current_time = time.time()
                
                # Rate-limited spool drain
                if self.spool_enabled and (current_time - last_spool_drain) >= SPOOL_DRAIN_INTERVAL_SEC:
                    spooled_events = self.spool_queue.dequeue(max_events=MAX_SPOOL_DRAIN_PER_BATCH)
                    if spooled_events:
                        batch.extend(spooled_events)
                        last_spool_drain = current_time
                        with self._stats_lock:
                            self._stats["events_spooled"] -= len(spooled_events)
                
                # Collect new events
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
                
                if batch:
                    server_config = self.config.get("server", {})
                    tls_enabled = server_config.get("tls_enabled", False)
                    tls_cert_path = server_config.get("tls_cert_path", "")
                    tls_verify = server_config.get("tls_verify", True)
                    
                    success = send_events_over_tcp(
                        self.server_ip,
                        self.port,
                        batch,
                        self.agent_token,
                        tls_enabled=tls_enabled,
                        tls_cert_path=tls_cert_path if tls_cert_path else None,
                        tls_verify=tls_verify
                    )
                    
                    if success:
                        protocol = "TLS" if tls_enabled else "TCP"
                        with self._stats_lock:
                            self._stats["events_sent"] += len(batch)
                            self._stats["last_send_error"] = None
                        print(f"[+] Sent {len(batch)} event(s) to {self.server_ip}:{self.port} ({protocol})")
                    else:
                        if self.spool_enabled:
                            self.spool_queue.enqueue(batch)
                            with self._stats_lock:
                                self._stats["events_spooled"] += len(batch)
                            print(f"[-] Failed to send {len(batch)} event(s), spooled for retry")
                        else:
                            with self._stats_lock:
                                self._stats["events_dropped"] += len(batch)
                            print(f"[-] Failed to send {len(batch)} event(s), DROPPED")
                        
                        with self._stats_lock:
                            self._stats["last_send_error"] = f"Connection failed to {self.server_ip}:{self.port}"
                else:
                    time.sleep(send_interval)
                    
            except Exception as e:
                print(f"[WARN] Sender error: {e}")
                with self._stats_lock:
                    self._stats["last_send_error"] = str(e)
    
    def get_stats(self) -> Dict:
        with self._stats_lock:
            self._stats["spool_backlog_mb"] = self.spool_queue.get_size_mb()
            return self._stats.copy()
    
    def stop(self):
        self._running = False
    
    def run_forever(self):
        self.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            self.stop()


def run_forwarder(server_ip: str, port: int, config: dict) -> None:
    """Main forwarder loop."""
    
    # Authentication
    auth_config = config.get("auth", {})
    auth_enabled = auth_config.get("enabled", False)
    web_port = auth_config.get("web_port", 8080)
    agent_username = auth_config.get("username", "")
    agent_password = auth_config.get("password", "")
    
    agent_auth = None
    agent_token = None
    
    if auth_enabled and agent_username and agent_password:
        print(f"[*] Authenticating with server...")
        server_url = f"http://{server_ip}:{web_port}"
        agent_auth = AgentAuth(server_url, agent_username, agent_password)
        
        authenticated = agent_auth.authenticate()
        
        if not authenticated:
            if agent_auth.agent_id:
                print(f"[*] Waiting for admin approval...")
                max_polls = 300
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
                    if poll_count % 6 == 0:
                        print(f"[*] Still waiting for approval...")
                
                if not authenticated:
                    print(f"[-] Timeout waiting for approval. Exiting.")
                    return
            else:
                print(f"[-] Authentication failed. Check credentials.")
                return
        
        if authenticated:
            print(f"[+] Connected to server as: {agent_username}")
            agent_token = agent_auth.token
            
            # Start heartbeat thread
            def heartbeat_loop():
                while True:
                    time.sleep(60)
                    if agent_auth and agent_auth.token:
                        agent_auth.heartbeat()
            
            heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=True)
            heartbeat_thread.start()
    
    # Collection settings
    collection_config = config.get("collection", {})
    start_from_now = collection_config.get("start_from_now", True)
    
    print(f"[*] Initializing log collectors...")
    print(f"[*] Ingest Server: {server_ip}:{port}")
    print(f"[*] start_from_now: {start_from_now}")
    print()
    
    # Create forwarder
    forwarder = MultiSourceForwarder(server_ip, port, config, agent_token)
    state_manager = forwarder.state_manager
    
    # Add journalctl collector
    journalctl_config = config.get("journalctl", {})
    if journalctl_config.get("enabled", True):
        print(f"[*] Journalctl Collector: ENABLED")
        collector = JournalctlCollector(
            max_events=journalctl_config.get("max_events", 200),
            units=journalctl_config.get("units", []),
            priority=journalctl_config.get("priority", 6),
            state_manager=state_manager,
            start_from_now=start_from_now
        )
        forwarder.add_collector(collector, journalctl_config.get("poll_interval_seconds", 5))
    
    # Add auth log collector
    auth_log_config = config.get("auth_log", {})
    if auth_log_config.get("enabled", True):
        print(f"[*] Auth Log Collector: ENABLED")
        collector = AuthLogCollector(
            max_lines=auth_log_config.get("max_lines", 100),
            state_manager=state_manager,
            start_from_now=start_from_now
        )
        forwarder.add_collector(collector, auth_log_config.get("poll_interval_seconds", 5))
    
    # Add syslog collector
    syslog_config = config.get("syslog", {})
    if syslog_config.get("enabled", True):
        print(f"[*] Syslog Collector: ENABLED")
        collector = SyslogCollector(
            max_lines=syslog_config.get("max_lines", 100),
            state_manager=state_manager,
            start_from_now=start_from_now
        )
        forwarder.add_collector(collector, syslog_config.get("poll_interval_seconds", 5))
    
    # Add auditd collector
    auditd_config = config.get("auditd", {})
    if auditd_config.get("enabled", True):
        print(f"[*] Auditd Collector: ENABLED")
        collector = AuditdCollector(
            max_events=auditd_config.get("max_events", 100),
            state_manager=state_manager,
            start_from_now=start_from_now
        )
        forwarder.add_collector(collector, auditd_config.get("poll_interval_seconds", 5))
    
    print()
    print(f"[*] Forwarder running. Waiting for new events...")
    print()
    
    forwarder.run_forever()
