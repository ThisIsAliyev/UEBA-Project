"""
Sysmon Event Forwarder - Main Entry Point

This script:
1. Opens a GUI to collect server settings
2. Optionally saves settings to config file
3. Runs the Sysmon forwarder loop until Ctrl+C
"""

import sys
from pathlib import Path

import yaml

from src.gui import open_settings_gui, load_config
from src.sysmon_forwarder import run_forwarder


def get_base_dir() -> Path:
    """
    Get the base directory for the application.
    
    When running as a PyInstaller frozen EXE, returns the directory containing the EXE.
    When running as a normal Python script, returns the directory containing the script.
    """
    if getattr(sys, 'frozen', False):
        # Running as a frozen EXE (PyInstaller)
        return Path(sys.executable).resolve().parent
    else:
        # Running as a normal Python script
        return Path(__file__).resolve().parent


# Resolve config path relative to application location
BASE_DIR = get_base_dir()
CONFIG_PATH = BASE_DIR / "config" / "agent_config.yaml"


def save_config(config: dict, config_path: Path) -> bool:
    """
    Save configuration to YAML file.
    
    Returns:
        True if saved successfully, False if permission denied.
    """
    try:
        config_path = Path(config_path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, sort_keys=False, allow_unicode=True)
        return True
    except PermissionError as e:
        print(f"[WARN] Could not save config to {config_path} (permission denied): {e}")
        return False


def main():
    # Load existing config (or defaults)
    config = load_config(str(CONFIG_PATH))
    
    # Open GUI to get server settings (now returns full config)
    server_ip, port, remember, full_config = open_settings_gui(str(CONFIG_PATH))
    
    # Use the full config from GUI
    config = full_config
    
    # Save config if "Remember settings" is checked
    if remember:
        if save_config(config, CONFIG_PATH):
            print(f"[*] Settings saved to {CONFIG_PATH}")
    
    # Check if authentication is enabled
    auth_enabled = config.get("auth", {}).get("enabled", False)
    auth_username = config.get("auth", {}).get("username", "")
    
    # Print banner
    print()
    print("=" * 50)
    print("  UEBA Agent - Windows Event Forwarder")
    print("=" * 50)
    print()
    print(f"[*] Event forwarder starting...")
    print(f"[*] Sending events to {server_ip}:{port}")
    if auth_enabled:
        print(f"[*] Authentication: ENABLED (user: {auth_username})")
    else:
        print(f"[*] Authentication: DISABLED (anonymous mode)")
    print(f"[*] Sources: Sysmon + Windows Security (Event Viewer)")
    print(f"[*] Press Ctrl+C to stop.")
    print()
    
    # Run the forwarder (let exceptions bubble up)
    try:
        run_forwarder(server_ip, port, config)
    except SystemExit:
        # Authentication failed or other critical error - already handled
        raise
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        
        # Try to show GUI error if tkinter is available
        try:
            import tkinter.messagebox as msgbox
            msgbox.showerror("Agent Error", f"Fatal error occurred:\n\n{e}")
        except:
            pass
        
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[*] Stopped by user (Ctrl+C).")
    except Exception as e:
        print("[!] Unexpected error occurred:", e)
        import traceback
        traceback.print_exc()
        raise SystemExit(1)
