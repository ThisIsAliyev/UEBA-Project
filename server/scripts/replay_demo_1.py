#!/usr/bin/env python3
"""
MVP P0: Demo Replay Script

Injects pre-recorded/synthetic events into the database for demo purposes.
Safe alternative to running actual attacks.

Usage:
    python scripts/replay_demo.py --scenario after_hours
    python scripts/replay_demo.py --scenario privilege_escalation
    python scripts/replay_demo.py --scenario credential_dumping
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add server src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server.storage import EventStorage
from server.models import NormalizedEvent

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def inject_after_hours_exfil(storage: EventStorage, user: str = "john.doe", host: str = "DESKTOP-ABC"):
    """Inject events for after-hours data exfiltration scenario."""
    now = datetime.utcnow()
    
    events = [
        # 3am login
        NormalizedEvent(
            timestamp=now - timedelta(hours=1),
            event_id=4624,
            channel="Security",
            category="logon",
            process_name="winlogon.exe",
            user=user,
            host=host,
            source_ip="192.168.1.100",
            action_type="logon"
        ),
        # Chrome process
        NormalizedEvent(
            timestamp=now - timedelta(hours=1, minutes=1),
            event_id=1,
            channel="Microsoft-Windows-Sysmon/Operational",
            category="process",
            process_name="chrome.exe",
            user=user,
            host=host,
            action_type="process_create"
        ),
        # Rclone process (rare)
        NormalizedEvent(
            timestamp=now - timedelta(hours=1, minutes=2),
            event_id=1,
            channel="Microsoft-Windows-Sysmon/Operational",
            category="process",
            process_name="rclone.exe",
            user=user,
            host=host,
            action_type="process_create"
        ),
        # Network to dropbox
        NormalizedEvent(
            timestamp=now - timedelta(hours=1, minutes=3),
            event_id=3,
            channel="Microsoft-Windows-Sysmon/Operational",
            category="network",
            process_name="rclone.exe",
            user=user,
            host=host,
            dest_ip="dropbox.com",
            dest_port=443,
            action_type="network_connect"
        ),
        # File create
        NormalizedEvent(
            timestamp=now - timedelta(hours=1, minutes=4),
            event_id=11,
            channel="Microsoft-Windows-Sysmon/Operational",
            category="file",
            process_name="rclone.exe",
            user=user,
            host=host,
            target_filename="C:\\temp\\sensitive.zip",
            action_type="file_create"
        ),
    ]
    
    for event in events:
        storage.store_event(event)
    
    logger.info(f"Injected {len(events)} events for after-hours exfiltration scenario")
    return len(events)


def inject_privilege_escalation(storage: EventStorage, user: str = "alice.smith", host: str = "DESKTOP-XYZ"):
    """Inject events for privilege escalation scenario."""
    now = datetime.utcnow()
    
    events = [
        # CMD with registry command
        NormalizedEvent(
            timestamp=now - timedelta(minutes=30),
            event_id=4688,
            channel="Security",
            category="process",
            process_name="cmd.exe",
            user=user,
            host=host,
            command_line="reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            action_type="process_create"
        ),
        # Scheduled task creation
        NormalizedEvent(
            timestamp=now - timedelta(minutes=29),
            event_id=4698,
            channel="Security",
            category="process",
            process_name="schtasks.exe",
            user=user,
            host=host,
            action_type="task_created"
        ),
        # PowerShell encoded
        NormalizedEvent(
            timestamp=now - timedelta(minutes=28),
            event_id=1,
            channel="Microsoft-Windows-Sysmon/Operational",
            category="process",
            process_name="powershell.exe",
            user=user,
            host=host,
            command_line="powershell -encodedcommand RwBlAHQALQBEAGEAdABlAA==",
            action_type="ps_scriptblock"
        ),
    ]
    
    for event in events:
        storage.store_event(event)
    
    logger.info(f"Injected {len(events)} events for privilege escalation scenario")
    return len(events)


def inject_credential_dumping(storage: EventStorage, user: str = "bob.williams", host: str = "DESKTOP-IT"):
    """Inject events for credential dumping scenario (simulated)."""
    now = datetime.utcnow()
    
    events = [
        # Mimikatz process (simulated - not real execution)
        NormalizedEvent(
            timestamp=now - timedelta(minutes=15),
            event_id=1,
            channel="Microsoft-Windows-Sysmon/Operational",
            category="process",
            process_name="mimikatz.exe",
            user=user,
            host=host,
            action_type="process_create"
        ),
        # LSASS access
        NormalizedEvent(
            timestamp=now - timedelta(minutes=14),
            event_id=10,
            channel="Microsoft-Windows-Sysmon/Operational",
            category="process",
            process_name="mimikatz.exe",
            user=user,
            host=host,
            target_filename="lsass.exe",
            action_type="process_access"
        ),
    ]
    
    for event in events:
        storage.store_event(event)
    
    logger.info(f"Injected {len(events)} events for credential dumping scenario (simulated)")
    return len(events)


def main():
    parser = argparse.ArgumentParser(description="Replay demo scenarios")
    parser.add_argument(
        "--scenario",
        choices=["after_hours", "privilege_escalation", "credential_dumping"],
        required=True,
        help="Scenario to replay"
    )
    parser.add_argument(
        "--user",
        default=None,
        help="Override user (default: scenario-specific)"
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Override host (default: scenario-specific)"
    )
    
    args = parser.parse_args()
    
    storage = EventStorage()
    
    if args.scenario == "after_hours":
        user = args.user or "john.doe"
        host = args.host or "DESKTOP-ABC"
        count = inject_after_hours_exfil(storage, user, host)
    elif args.scenario == "privilege_escalation":
        user = args.user or "alice.smith"
        host = args.host or "DESKTOP-XYZ"
        count = inject_privilege_escalation(storage, user, host)
    elif args.scenario == "credential_dumping":
        user = args.user or "bob.williams"
        host = args.host or "DESKTOP-IT"
        count = inject_credential_dumping(storage, user, host)
    
    logger.info(f"✅ Injected {count} events for scenario: {args.scenario}")
    logger.info("Next steps:")
    logger.info("  1. Run: python scripts/train_baselines.py --hours 6")
    logger.info("  2. Run: python scripts/run_anomaly_scan.py --hours 1")
    logger.info("  3. Check dashboard: http://localhost:8080/alerts")


if __name__ == "__main__":
    main()

