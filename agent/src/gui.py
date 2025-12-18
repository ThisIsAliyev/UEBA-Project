"""
Tkinter GUI for collecting server settings and agent authentication.
"""

import sys
import os
import platform
import tkinter as tk
from tkinter import messagebox
from typing import Tuple, Optional, Dict

import yaml


def load_config(config_path: str) -> dict:
    """Load configuration from YAML file, return defaults if not found."""
    defaults = {
        "server": {
            "ip": "127.0.0.1",
            "port": 9000,
            "remember": False
        },
        "auth": {
            "enabled": False,
            "web_port": 8080,
            "username": "",
            "password": ""
        },
        "sysmon": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "poll_interval_seconds": 5,
            "max_events": 200
        },
        "security": {
            "enabled": True,
            "poll_interval_seconds": 5,
            "max_events": 100
        }
    }
    
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if loaded:
                    # Merge loaded config with defaults
                    for key in defaults:
                        if key in loaded:
                            if isinstance(defaults[key], dict):
                                defaults[key].update(loaded[key])
                            else:
                                defaults[key] = loaded[key]
                    return defaults
        except Exception as e:
            print(f"[WARN] Could not load config: {e}")
    
    return defaults


def open_settings_gui(config_path: str) -> Tuple[str, int, bool, Dict]:
    """
    Open a Tkinter GUI to collect server settings and authentication.
    
    Args:
        config_path: Path to the YAML configuration file.
        
    Returns:
        Tuple of (server_ip, port, remember_settings, full_config)
        
    Raises:
        SystemExit: If user clicks Cancel.
    """
    config = load_config(config_path)
    server_config = config.get("server", {})
    auth_config = config.get("auth", {})
    
    result: Optional[Tuple[str, int, bool, Dict]] = None
    
    def on_start():
        nonlocal result
        
        ip = ip_entry.get().strip()
        port_str = port_entry.get().strip()
        remember = remember_var.get()
        
        # Auth settings (MANDATORY)
        auth_enabled = True  # Always enabled
        web_port_str = web_port_entry.get().strip()
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        
        # Validate IP/host
        if not ip:
            messagebox.showerror("Validation Error", "Server IP/Host cannot be empty.")
            return
        
        # Validate port
        try:
            port = int(port_str)
            if port < 1 or port > 65535:
                raise ValueError("Port out of range")
        except ValueError:
            messagebox.showerror("Validation Error", "Ingest port must be an integer between 1 and 65535.")
            return
        
        # Validate web port (required for authentication)
        try:
            web_port = int(web_port_str)
            if web_port < 1 or web_port > 65535:
                raise ValueError("Port out of range")
        except ValueError:
            messagebox.showerror("Validation Error", "Web port must be an integer between 1 and 65535.")
            return
        
        # Validate credentials (required)
        if not username:
            messagebox.showerror("Validation Error", "Username is required. Get credentials from admin in Agent Users page.")
            return
        if not password:
            messagebox.showerror("Validation Error", "Password is required. Get credentials from admin in Agent Users page.")
            return
        
        # Optional: Test authentication before starting (with user confirmation)
        # This can be slow, so we'll do it after user confirms
        test_auth = messagebox.askyesno(
            "Test Connection?",
            "Do you want to test the connection and credentials before starting?\n\n"
            "This will verify that:\n"
            "• Server is accessible\n"
            "• Credentials are valid\n"
            "• Agent can connect\n\n"
            "Click 'No' to skip and start anyway."
        )
        
        if test_auth:
            # Test authentication
            import urllib.request
            import urllib.error
            import json
            
            server_url = f"http://{ip}:{web_port}"
            auth_url = f"{server_url}/api/agent/auth"
            
            auth_data = {
                "username": username,
                "password": password,
                "hostname": platform.node(),
                "ip_address": "127.0.0.1",  # Test with local IP
                "os_type": "windows",
                "os_version": platform.version(),
                "agent_version": "1.0.0"
            }
            
            try:
                # Show progress
                root.config(cursor="wait")
                start_btn.config(state="disabled")
                
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
                        if status == 'pending':
                            messagebox.showinfo(
                                "Connection Test Successful",
                                f"✅ Credentials are valid!\n\n"
                                f"Agent registered successfully.\n"
                                f"Status: Waiting for admin approval\n\n"
                                f"The agent will start and wait for approval."
                            )
                        elif status == 'approved':
                            messagebox.showinfo(
                                "Connection Test Successful",
                                f"✅ Credentials are valid and agent is approved!\n\n"
                                f"Ready to start sending events."
                            )
                        else:
                            messagebox.showwarning(
                                "Connection Test - Warning",
                                f"Credentials are valid but status is: {status}\n\n"
                                f"The agent may not be able to send events."
                            )
                    else:
                        messagebox.showerror(
                            "Connection Test Failed",
                            f"❌ Authentication failed!\n\n"
                            f"Server: {server_url}\n"
                            f"Username: {username}\n\n"
                            f"Please check:\n"
                            f"• Username and password are correct\n"
                            f"• Agent user exists in server\n"
                            f"• Server is accessible"
                        )
                        root.config(cursor="")
                        start_btn.config(state="normal")
                        return
                        
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    error_msg = "❌ Invalid credentials!\n\nUsername or password is incorrect."
                else:
                    error_msg = f"❌ Server error (HTTP {e.code})"
                messagebox.showerror("Connection Test Failed", error_msg)
                root.config(cursor="")
                start_btn.config(state="normal")
                return
            except urllib.error.URLError as e:
                messagebox.showerror(
                    "Connection Test Failed",
                    f"❌ Cannot connect to server!\n\n"
                    f"Error: {e.reason}\n"
                    f"Server: {server_url}\n\n"
                    f"Please check:\n"
                    f"• Server is running\n"
                    f"• Server IP and port are correct\n"
                    f"• Network connectivity"
                )
                root.config(cursor="")
                start_btn.config(state="normal")
                return
            except Exception as e:
                messagebox.showerror("Connection Test Failed", f"Error: {e}")
                root.config(cursor="")
                start_btn.config(state="normal")
                return
            finally:
                root.config(cursor="")
                start_btn.config(state="normal")
        
        # Build full config
        full_config = {
            "server": {
                "ip": ip,
                "port": port,
                "remember": remember
            },
            "auth": {
                "enabled": auth_enabled,
                "web_port": web_port,
                "username": username,
                "password": password
            },
            "sysmon": config.get("sysmon", {}),
            "security": config.get("security", {})
        }
        
        result = (ip, port, remember, full_config)
        root.destroy()
    
    def on_cancel():
        root.destroy()
        sys.exit(0)
    
    # Auth fields are always enabled (authentication is mandatory)
    
    # Create main window
    root = tk.Tk()
    root.title("UEBA Agent - Settings")
    root.resizable(False, False)
    
    # Center the window
    window_width = 400
    window_height = 400
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width // 2) - (window_width // 2)
    y = (screen_height // 2) - (window_height // 2)
    root.geometry(f"{window_width}x{window_height}+{x}+{y}")
    
    # Main frame with padding
    frame = tk.Frame(root, padx=20, pady=15)
    frame.pack(fill=tk.BOTH, expand=True)
    
    # ============================================
    # Server Section
    # ============================================
    server_label = tk.Label(frame, text="Server Connection", font=("", 10, "bold"))
    server_label.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
    
    # Server IP/Host
    ip_label = tk.Label(frame, text="Server IP / Host:", anchor="w")
    ip_label.grid(row=1, column=0, sticky="w", pady=(0, 5))
    
    ip_entry = tk.Entry(frame, width=28)
    ip_entry.grid(row=1, column=1, pady=(0, 5), padx=(10, 0), sticky="e")
    ip_entry.insert(0, server_config.get("ip", "127.0.0.1"))
    
    # Ingest Port
    port_label = tk.Label(frame, text="Ingest Port:", anchor="w")
    port_label.grid(row=2, column=0, sticky="w", pady=(0, 5))
    
    port_entry = tk.Entry(frame, width=28)
    port_entry.grid(row=2, column=1, pady=(0, 5), padx=(10, 0), sticky="e")
    port_entry.insert(0, str(server_config.get("port", 9000)))
    
    # ============================================
    # Authentication Section (MANDATORY)
    # ============================================
    auth_label = tk.Label(frame, text="Authentication (Required)", font=("", 10, "bold"))
    auth_label.grid(row=3, column=0, columnspan=2, sticky="w", pady=(15, 5))
    
    auth_info = tk.Label(frame, text="Get credentials from admin in Agent Users page", 
                         fg="gray", font=("", 8))
    auth_info.grid(row=4, column=0, columnspan=2, sticky="w", pady=(0, 10))
    
    # Authentication is always enabled - no checkbox
    auth_var = tk.BooleanVar(value=True)  # Always True
    
    # Web Port
    web_port_label = tk.Label(frame, text="Web Port:", anchor="w")
    web_port_label.grid(row=5, column=0, sticky="w", pady=(0, 5))
    
    web_port_entry = tk.Entry(frame, width=28)
    web_port_entry.grid(row=5, column=1, pady=(0, 5), padx=(10, 0), sticky="e")
    web_port_entry.insert(0, str(auth_config.get("web_port", 8080)))
    
    # Username
    username_label = tk.Label(frame, text="Username:", anchor="w")
    username_label.grid(row=6, column=0, sticky="w", pady=(0, 5))
    
    username_entry = tk.Entry(frame, width=28)
    username_entry.grid(row=6, column=1, pady=(0, 5), padx=(10, 0), sticky="e")
    username_entry.insert(0, auth_config.get("username", ""))
    
    # Password
    password_label = tk.Label(frame, text="Password:", anchor="w")
    password_label.grid(row=7, column=0, sticky="w", pady=(0, 5))
    
    password_entry = tk.Entry(frame, width=28, show="*")
    password_entry.grid(row=7, column=1, pady=(0, 5), padx=(10, 0), sticky="e")
    password_entry.insert(0, auth_config.get("password", ""))
    
    # ============================================
    # Options Section
    # ============================================
    options_label = tk.Label(frame, text="Options", font=("", 10, "bold"))
    options_label.grid(row=9, column=0, columnspan=2, sticky="w", pady=(15, 5))
    
    # Remember settings checkbox
    remember_var = tk.BooleanVar(value=server_config.get("remember", False))
    remember_check = tk.Checkbutton(frame, text="Remember settings", variable=remember_var)
    remember_check.grid(row=10, column=0, columnspan=2, sticky="w", pady=(0, 10))
    
    # ============================================
    # Buttons
    # ============================================
    btn_frame = tk.Frame(frame)
    btn_frame.grid(row=11, column=0, columnspan=2, pady=(10, 0))
    
    start_btn = tk.Button(btn_frame, text="Start Agent", width=12, command=on_start)
    start_btn.pack(side=tk.LEFT, padx=(0, 10))
    
    cancel_btn = tk.Button(btn_frame, text="Cancel", width=12, command=on_cancel)
    cancel_btn.pack(side=tk.LEFT)
    
    # Auth fields are always enabled (authentication is mandatory)
    
    # Handle window close button (X)
    root.protocol("WM_DELETE_WINDOW", on_cancel)
    
    # Focus on IP entry
    ip_entry.focus_set()
    
    # Bind Enter key to Start
    root.bind("<Return>", lambda e: on_start())
    
    # Run the GUI
    root.mainloop()
    
    if result is None:
        sys.exit(0)
    
    return result

