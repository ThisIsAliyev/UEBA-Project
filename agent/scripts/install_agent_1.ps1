# UEBA Agent Installation Script for Windows
# Installs Python dependencies and creates Task Scheduler entry for auto-start

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# Colors for output
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

# Get script directory and project root
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

Write-ColorOutput Green "UEBA Agent Installation"
Write-Output "=========================="
Write-Output "Project root: $ProjectRoot"
Write-Output ""

# Check for Sysmon
Write-ColorOutput Yellow "Checking for Sysmon installation..."
$sysmonPath = Get-Command sysmon64.exe -ErrorAction SilentlyContinue
if (-not $sysmonPath) {
    Write-ColorOutput Yellow "Warning: Sysmon not found in PATH"
    Write-Output "Sysmon is required for event collection."
    Write-Output "Download from: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"
    Write-Output "Install with: sysmon64.exe -accepteula -i"
    Write-Output ""
    $continue = Read-Host "Continue anyway? (y/N)"
    if ($continue -ne "y" -and $continue -ne "Y") {
        exit 1
    }
} else {
    Write-ColorOutput Green "Sysmon found: $($sysmonPath.Source)"
}
Write-Output ""

# Check Python version
Write-ColorOutput Yellow "Checking Python version..."
try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Python not found"
    }
    Write-ColorOutput Green $pythonVersion
    
    # Extract version numbers
    $versionMatch = $pythonVersion -match "Python (\d+)\.(\d+)"
    if ($versionMatch) {
        $major = [int]$matches[1]
        $minor = [int]$matches[2]
        
        if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 8)) {
            Write-ColorOutput Red "Error: Python 3.8 or higher required. Found: $pythonVersion"
            exit 1
        }
    }
} catch {
    Write-ColorOutput Red "Error: Python not found. Please install Python 3.8 or higher."
    Write-Output "Download from: https://www.python.org/downloads/"
    exit 1
}
Write-Output ""

# Create virtual environment
Write-ColorOutput Yellow "Creating virtual environment..."
$venvPath = Join-Path $ProjectRoot "venv"
if (Test-Path $venvPath) {
    Write-Output "Virtual environment already exists, skipping..."
} else {
    python -m venv $venvPath
    Write-ColorOutput Green "Virtual environment created"
}
Write-Output ""

# Activate virtual environment and install dependencies
Write-ColorOutput Yellow "Installing Python dependencies..."
$activateScript = Join-Path $venvPath "Scripts\Activate.ps1"
& $activateScript
pip install --upgrade pip
pip install -r (Join-Path $ProjectRoot "requirements.txt")
Write-ColorOutput Green "Dependencies installed"
Write-Output ""

# Create config directory if missing
Write-ColorOutput Yellow "Checking configuration..."
$configDir = Join-Path $ProjectRoot "config"
if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir | Out-Null
    Write-ColorOutput Green "Config directory created"
}

$configFile = Join-Path $configDir "agent_config.yaml"
if (-not (Test-Path $configFile)) {
    Write-ColorOutput Yellow "Creating default configuration..."
    @"
server:
  ip: 127.0.0.1
  port: 9000
  remember: false

# Agent Authentication (get credentials from admin in Agent Users page)
auth:
  enabled: false
  web_port: 8080
  username: ""
  password: ""

# Sysmon event collection
sysmon:
  channel: Microsoft-Windows-Sysmon/Operational
  poll_interval_seconds: 5
  max_events: 200

# Windows Security event collection (Event Viewer logs)
security:
  enabled: true
  poll_interval_seconds: 5
  max_events: 100
"@ | Out-File -FilePath $configFile -Encoding UTF8
    Write-ColorOutput Green "Default configuration created at $configFile"
} else {
    Write-Output "Configuration file already exists: $configFile"
}
Write-Output ""

# Create Task Scheduler entry
Write-ColorOutput Yellow "Creating Task Scheduler entry..."
$taskName = "UEBA Agent"
$pythonExe = Join-Path $venvPath "Scripts\python.exe"
$scriptPath = Join-Path $ProjectRoot "run_agent.py"

# Check if task already exists
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Output "Task '$taskName' already exists."
    $replace = Read-Host "Replace existing task? (y/N)"
    if ($replace -eq "y" -or $replace -eq "Y") {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    } else {
        Write-Output "Skipping task creation."
        Write-Output ""
        Write-ColorOutput Green "Installation complete!"
        exit 0
    }
}

# Create task action
$action = New-ScheduledTaskAction -Execute $pythonExe -Argument "`"$scriptPath`"" -WorkingDirectory $ProjectRoot

# Create task trigger (at startup)
$trigger = New-ScheduledTaskTrigger -AtStartup

# Create task principal (run with highest privileges)
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -RunLevel Highest

# Create task settings
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable

# Register the task
try {
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "UEBA Sysmon Agent - Collects and forwards Windows events to UEBA server"
    Write-ColorOutput Green "Task Scheduler entry created: $taskName"
    Write-Output ""
    Write-Output "Task will run automatically at Windows startup."
    Write-Output "To start manually:"
    Write-Output "  Start-ScheduledTask -TaskName '$taskName'"
    Write-Output ""
    Write-Output "To stop:"
    Write-Output "  Stop-ScheduledTask -TaskName '$taskName'"
} catch {
    Write-ColorOutput Red "Error creating Task Scheduler entry: $_"
    Write-Output "You can manually create the task or run the agent directly:"
    Write-Output "  cd $ProjectRoot"
    Write-Output "  .\venv\Scripts\Activate.ps1"
    Write-Output "  python run_agent.py"
}
Write-Output ""

# Summary
Write-ColorOutput Green "Installation complete!"
Write-Output ""
Write-Output "Next steps:"
Write-Output "1. Review configuration: $configFile"
Write-Output "2. Configure server IP and authentication credentials"
Write-Output "3. The agent will start automatically at Windows startup"
Write-Output ""
Write-Output "To run manually:"
Write-Output "  cd $ProjectRoot"
Write-Output "  .\venv\Scripts\Activate.ps1"
Write-Output "  python run_agent.py"
Write-Output ""

