#!/usr/bin/env python3
"""
Linux Event Forwarder - Main Entry Point

This script:
1. Opens a GUI to collect server settings (same as Windows agent)
2. Optionally saves settings to config file
3. Runs the Linux log forwarder loop until Ctrl+C
"""

import sys
import os
import argparse
from pathlib import Path

import yaml

from src.gui import open_settings_gui, load_config
from src.linux_forwarder import run_forwarder


def get_base_dir() -> Path:
    """Get the base directory for the application."""
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).resolve().parent
    else:
        return Path(__file__).resolve().parent


BASE_DIR = get_base_dir()
CONFIG_PATH = BASE_DIR / "config" / "agent_config.yaml"


def save_config(config: dict, config_path: Path) -> bool:
    """Save configuration to YAML file."""
    try:
        config_path = Path(config_path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, sort_keys=False, allow_unicode=True)
        return True
    except PermissionError as e:
        print(f"[WARN] Could not save config (permission denied): {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="UEBA Linux Agent")
    parser.add_argument("-c", "--config", type=str, default=str(CONFIG_PATH),
                        help="Path to configuration file")
    parser.add_argument("--no-gui", action="store_true",
                        help="Run without GUI (use config file or command line args)")
    parser.add_argument("--server", type=str, help="Server IP address")
    parser.add_argument("--port", type=int, help="Ingest port")
    parser.add_argument("--web-port", type=int, help="Web port for authentication")
    parser.add_argument("--username", type=str, help="Agent username")
    parser.add_argument("--password", type=str, help="Agent password")
    
    args = parser.parse_args()
    
    # Load existing config
    config = load_config(args.config)
    
    # Check if running with --no-gui or command line credentials
    use_gui = not args.no_gui
    
    # If command line args provided, use them directly
    if args.server or args.username:
        use_gui = False
        if args.server:
            config["server"]["ip"] = args.server
        if args.port:
            config["server"]["port"] = args.port
        if args.web_port:
            config["auth"]["web_port"] = args.web_port
        if args.username:
            config["auth"]["username"] = args.username
            config["auth"]["enabled"] = True
        if args.password:
            config["auth"]["password"] = args.password
    
    if use_gui:
        # Open GUI to get server settings (same as Windows)
        server_ip, port, remember, full_config = open_settings_gui(str(args.config))
        
        # Use the full config from GUI
        config = full_config
        
        # Save config if "Remember settings" is checked
        if remember:
            if save_config(config, args.config):
                print(f"[*] Settings saved to {args.config}")
    
    server_ip = config["server"]["ip"]
    port = config["server"]["port"]
    auth_enabled = config.get("auth", {}).get("enabled", False)
    auth_username = config.get("auth", {}).get("username", "")
    
    # Print banner
    print()
    print("=" * 50)
    print("  UEBA Agent - Linux Event Forwarder")
    print("=" * 50)
    print()
    print(f"[*] Event forwarder starting...")
    print(f"[*] Sending events to {server_ip}:{port}")
    if auth_enabled:
        print(f"[*] Authentication: ENABLED (user: {auth_username})")
    else:
        print(f"[*] Authentication: DISABLED (anonymous mode)")
    print(f"[*] Sources: journalctl, auth.log, syslog, auditd")
    print(f"[*] Press Ctrl+C to stop.")
    print()
    
    # Run the forwarder
    try:
        run_forwarder(server_ip, port, config)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        
        # Show GUI error if available
        try:
            import tkinter.messagebox as msgbox
            msgbox.showerror("Agent Error", f"Fatal error occurred:\n\n{e}")
        except:
            pass
        
        raise SystemExit(1)


if __name__ == "__main__":
    main()
