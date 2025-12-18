#!/usr/bin/env python3
"""
Test script to verify agent status tracking behavior.

This script simulates:
1. Agent authentication and connection
2. Event ingestion with status updates
3. TTL expiry and offline marking
4. Agent restart and reconnection

Usage:
    python test_agent_status.py [--server-url http://localhost:8080]
"""

import argparse
import json
import socket
import time
import requests
from datetime import datetime, timedelta


def utc_now_iso() -> str:
    """Generate UTC timestamp in ISO8601 format with Z suffix."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def test_agent_authentication(server_url: str, username: str, password: str, 
                               hostname: str, ip_address: str):
    """Test agent authentication and get token."""
    print(f"\n[TEST] Agent Authentication")
    print(f"  Server: {server_url}")
    print(f"  Agent: {username}@{hostname}")
    
    response = requests.post(
        f"{server_url}/api/agent/auth",
        json={
            "username": username,
            "password": password,
            "hostname": hostname,
            "ip_address": ip_address,
            "os_type": "windows",
            "os_version": "10.0.19045",
            "agent_version": "1.0.0"
        }
    )
    
    if response.status_code == 200:
        data = response.json()
        print(f"  Status: {data.get('status')}")
        print(f"  Agent ID: {data.get('agent_id')}")
        print(f"  Token: {'[RECEIVED]' if data.get('token') else '[NONE - pending approval]'}")
        return data
    else:
        print(f"  ERROR: {response.status_code} - {response.text}")
        return None


def test_heartbeat(server_url: str, token: str):
    """Test agent heartbeat."""
    print(f"\n[TEST] Agent Heartbeat")
    
    response = requests.post(
        f"{server_url}/api/agent/heartbeat",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    if response.status_code == 200:
        print(f"  Result: SUCCESS - last_seen updated")
        return True
    else:
        print(f"  ERROR: {response.status_code} - {response.text}")
        return False


def test_agent_status(server_url: str, agent_id: int):
    """Check agent status via API."""
    print(f"\n[TEST] Check Agent Status (agent_id={agent_id})")
    
    response = requests.get(f"{server_url}/api/agent/status?agent_id={agent_id}")
    
    if response.status_code == 200:
        data = response.json()
        print(f"  Status: {data.get('status')}")
        print(f"  Approved: {data.get('approved')}")
        return data
    else:
        print(f"  ERROR: {response.status_code} - {response.text}")
        return None


def test_connected_agents(server_url: str, session_cookie: str):
    """Get all connected agents via API."""
    print(f"\n[TEST] List Connected Agents")
    
    response = requests.get(
        f"{server_url}/api/connected-agents",
        cookies={"session": session_cookie}
    )
    
    if response.status_code == 200:
        data = response.json()
        agents = data.get('agents', [])
        print(f"  Total agents: {len(agents)}")
        for agent in agents:
            print(f"    - {agent['hostname']}: status={agent['status']}, "
                  f"last_seen={agent['last_seen']}, events={agent['events_sent']}")
        return agents
    else:
        print(f"  ERROR: {response.status_code} - {response.text}")
        return []


def test_tcp_event_ingestion(tcp_host: str, tcp_port: int, token: str, num_events: int = 3):
    """Test TCP event ingestion with token."""
    print(f"\n[TEST] TCP Event Ingestion")
    print(f"  Target: {tcp_host}:{tcp_port}")
    print(f"  Events to send: {num_events}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((tcp_host, tcp_port))
        
        # Send auth message
        auth_msg = json.dumps({"agent_token": token}) + "\n"
        sock.sendall(auth_msg.encode())
        print(f"  Auth message sent")
        
        # Small delay to allow auth processing
        time.sleep(0.5)
        
        # Send test events
        for i in range(num_events):
            event = {
                "source": "sysmon",
                "event": {
                    "Id": 1,
                    "TimeCreated": utc_now_iso(),
                    "ProviderName": "Microsoft-Windows-Sysmon",
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "Computer": "TestHost",
                    "Message": f"Test event {i+1}",
                    "EventData": {
                        "Image": "C:\\Windows\\System32\\cmd.exe",
                        "CommandLine": f"test command {i+1}",
                        "User": "TEST\\User"
                    }
                }
            }
            event_line = json.dumps(event) + "\n"
            sock.sendall(event_line.encode())
            print(f"  Event {i+1} sent")
            time.sleep(0.1)
        
        sock.close()
        print(f"  Connection closed")
        return True
        
    except Exception as e:
        print(f"  ERROR: {e}")
        return False


def test_ttl_expiry(server_url: str, session_cookie: str, wait_seconds: int = 130):
    """Test that agent goes offline after TTL expiry."""
    print(f"\n[TEST] TTL Expiry (waiting {wait_seconds}s)")
    print(f"  This tests that agents are marked offline after no heartbeat")
    
    # Get initial status
    agents_before = test_connected_agents(server_url, session_cookie)
    
    print(f"\n  Waiting {wait_seconds} seconds for TTL to expire...")
    for i in range(wait_seconds // 10):
        time.sleep(10)
        print(f"    {(i+1)*10}s elapsed...")
    time.sleep(wait_seconds % 10)
    
    # Trigger status update by fetching agents
    print(f"\n  Checking agent status after TTL...")
    agents_after = test_connected_agents(server_url, session_cookie)
    
    return agents_before, agents_after


def admin_login(server_url: str, username: str = "admin", password: str = "admin"):
    """Login as admin and get session cookie."""
    print(f"\n[SETUP] Admin Login")
    
    session = requests.Session()
    response = session.post(
        f"{server_url}/login",
        data={"username": username, "password": password},
        allow_redirects=False
    )
    
    if response.status_code in (302, 303):
        session_cookie = session.cookies.get("session")
        print(f"  Login successful, session cookie obtained")
        return session_cookie
    else:
        print(f"  ERROR: Login failed - {response.status_code}")
        return None


def main():
    parser = argparse.ArgumentParser(description="Test agent status tracking")
    parser.add_argument("--server-url", default="http://localhost:8080",
                        help="UEBA server URL (default: http://localhost:8080)")
    parser.add_argument("--tcp-host", default="localhost",
                        help="TCP ingest host (default: localhost)")
    parser.add_argument("--tcp-port", type=int, default=9000,
                        help="TCP ingest port (default: 9000)")
    parser.add_argument("--agent-user", default="agent1",
                        help="Agent username (default: agent1)")
    parser.add_argument("--agent-pass", default="agent1pass",
                        help="Agent password (default: agent1pass)")
    parser.add_argument("--skip-ttl-test", action="store_true",
                        help="Skip the TTL expiry test (takes 2+ minutes)")
    args = parser.parse_args()
    
    print("=" * 60)
    print("  UEBA Agent Status Tracking Test")
    print("=" * 60)
    print(f"  Server URL: {args.server_url}")
    print(f"  TCP Ingest: {args.tcp_host}:{args.tcp_port}")
    print(f"  Timestamp: {utc_now_iso()}")
    
    # Step 1: Admin login
    session_cookie = admin_login(args.server_url)
    if not session_cookie:
        print("\nFATAL: Could not login as admin")
        return 1
    
    # Step 2: Check initial agent list
    test_connected_agents(args.server_url, session_cookie)
    
    # Step 3: Authenticate agent
    hostname = f"TestHost-{int(time.time()) % 10000}"
    auth_result = test_agent_authentication(
        args.server_url,
        args.agent_user,
        args.agent_pass,
        hostname,
        "192.168.1.100"
    )
    
    if not auth_result:
        print("\nFATAL: Agent authentication failed")
        return 1
    
    agent_id = auth_result.get('agent_id')
    token = auth_result.get('token')
    status = auth_result.get('status')
    
    if status == 'pending':
        print("\n[INFO] Agent is pending approval. Approve it in the UI and re-run this test.")
        print(f"       Agent ID: {agent_id}")
        return 0
    
    if not token:
        print("\nFATAL: No token received (agent may not be approved)")
        return 1
    
    # Step 4: Test heartbeat
    test_heartbeat(args.server_url, token)
    
    # Step 5: Check status after heartbeat
    test_agent_status(args.server_url, agent_id)
    
    # Step 6: Test TCP event ingestion
    test_tcp_event_ingestion(args.tcp_host, args.tcp_port, token, num_events=5)
    
    # Step 7: Check agent list after events
    print("\n[TEST] Verify events count updated")
    time.sleep(1)  # Allow time for event processing
    test_connected_agents(args.server_url, session_cookie)
    
    # Step 8: Optional TTL expiry test
    if not args.skip_ttl_test:
        print("\n" + "=" * 60)
        print("  TTL Expiry Test (this will take ~2 minutes)")
        print("=" * 60)
        test_ttl_expiry(args.server_url, session_cookie, wait_seconds=130)
        
        # Step 9: Reconnect and verify status recovery
        print("\n[TEST] Agent Reconnection (simulating restart)")
        auth_result2 = test_agent_authentication(
            args.server_url,
            args.agent_user,
            args.agent_pass,
            hostname,
            "192.168.1.100"
        )
        
        if auth_result2 and auth_result2.get('token'):
            test_heartbeat(args.server_url, auth_result2['token'])
            test_connected_agents(args.server_url, session_cookie)
    
    print("\n" + "=" * 60)
    print("  Test Complete")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    exit(main())
