#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Configure Windows Event Log retention settings for UEBA deployment.

.DESCRIPTION
    This script configures Windows Event Log channels with fixed maximum sizes
    and automatic overwrite (circular logging) to prevent endless log growth.
    
    Designed for UEBA deployments where logs are forwarded to a central server,
    so local retention is primarily for buffering and troubleshooting.

.PARAMETER SysmonMaxSizeMB
    Maximum size for Sysmon Operational log in megabytes. Default: 128 MB.

.PARAMETER SecurityMaxSizeMB
    Maximum size for Security log in megabytes. Default: 256 MB.

.PARAMETER SystemMaxSizeMB
    Maximum size for System log in megabytes. Default: 64 MB.

.PARAMETER ApplicationMaxSizeMB
    Maximum size for Application log in megabytes. Default: 64 MB.

.EXAMPLE
    .\set_eventlog_retention.ps1
    Applies default retention settings to all configured logs.

.EXAMPLE
    .\set_eventlog_retention.ps1 -SysmonMaxSizeMB 256 -SecurityMaxSizeMB 512
    Applies custom sizes for Sysmon and Security logs.

.NOTES
    Author: UEBA Project Team
    Version: 1.0
    Requires: Administrator privileges, Windows 10/Server 2016 or later
    
    Size recommendations:
    - Sysmon: 128-256 MB (high event volume with ProcessCreate, FileCreate, Network)
    - Security: 256-512 MB (authentication, audit events)
    - System: 64-128 MB (service events, driver loads)
    - Application: 64-128 MB (application errors, warnings)
    
    Retention mode "true" means overwrite oldest events when full (circular).
    This prevents disk exhaustion while maintaining recent event availability.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(32, 4096)]
    [int]$SysmonMaxSizeMB = 128,

    [Parameter()]
    [ValidateRange(64, 4096)]
    [int]$SecurityMaxSizeMB = 256,

    [Parameter()]
    [ValidateRange(32, 4096)]
    [int]$SystemMaxSizeMB = 64,

    [Parameter()]
    [ValidateRange(32, 4096)]
    [int]$ApplicationMaxSizeMB = 64
)

# Convert MB to bytes for wevtutil
function ConvertTo-Bytes {
    param([int]$SizeMB)
    return $SizeMB * 1024 * 1024
}

# Configure a single event log channel
function Set-EventLogRetention {
    param(
        [string]$LogName,
        [string]$DisplayName,
        [int]$MaxSizeBytes,
        [bool]$Retention = $false  # false = overwrite oldest (circular)
    )

    Write-Host "Configuring: $DisplayName" -ForegroundColor Cyan

    # Check if log exists
    try {
        $logInfo = wevtutil gl $LogName 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "  Log '$LogName' not found or not accessible. Skipping."
            return $false
        }
    }
    catch {
        Write-Warning "  Failed to query log '$LogName': $_"
        return $false
    }

    # Set maximum size
    try {
        wevtutil sl $LogName /ms:$MaxSizeBytes
        if ($LASTEXITCODE -eq 0) {
            $sizeMB = [math]::Round($MaxSizeBytes / 1MB, 0)
            Write-Host "  Max size set to: $sizeMB MB" -ForegroundColor Green
        }
        else {
            Write-Warning "  Failed to set max size for $LogName"
            return $false
        }
    }
    catch {
        Write-Warning "  Error setting max size: $_"
        return $false
    }

    # Set retention policy (rt:false = overwrite oldest when full)
    try {
        $rtValue = if ($Retention) { "true" } else { "false" }
        wevtutil sl $LogName /rt:$rtValue
        if ($LASTEXITCODE -eq 0) {
            $policyDesc = if ($Retention) { "Archive (do not overwrite)" } else { "Overwrite oldest (circular)" }
            Write-Host "  Retention policy: $policyDesc" -ForegroundColor Green
        }
        else {
            Write-Warning "  Failed to set retention policy for $LogName"
            return $false
        }
    }
    catch {
        Write-Warning "  Error setting retention policy: $_"
        return $false
    }

    return $true
}

# Display current settings for a log
function Get-EventLogSettings {
    param([string]$LogName, [string]$DisplayName)

    try {
        $info = wevtutil gl $LogName 2>&1
        if ($LASTEXITCODE -eq 0) {
            $maxSize = ($info | Select-String "maxSize:").ToString() -replace ".*maxSize:\s*", ""
            $retention = ($info | Select-String "retention:").ToString() -replace ".*retention:\s*", ""
            $sizeMB = [math]::Round([int64]$maxSize / 1MB, 0)
            Write-Host "  $DisplayName : $sizeMB MB, Retention=$retention"
        }
    }
    catch {
        Write-Host "  $DisplayName : Unable to query" -ForegroundColor Yellow
    }
}

# Main execution
Write-Host ""
Write-Host "========================================" -ForegroundColor White
Write-Host "  Windows Event Log Retention Setup" -ForegroundColor White
Write-Host "  UEBA Deployment Configuration" -ForegroundColor White
Write-Host "========================================" -ForegroundColor White
Write-Host ""

# Verify admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

Write-Host "Current settings:" -ForegroundColor Yellow
Get-EventLogSettings -LogName "Microsoft-Windows-Sysmon/Operational" -DisplayName "Sysmon Operational"
Get-EventLogSettings -LogName "Security" -DisplayName "Security"
Get-EventLogSettings -LogName "System" -DisplayName "System"
Get-EventLogSettings -LogName "Application" -DisplayName "Application"
Write-Host ""

Write-Host "Applying new settings..." -ForegroundColor Yellow
Write-Host ""

$results = @{
    Sysmon = $false
    Security = $false
    System = $false
    Application = $false
}

# Configure Sysmon Operational log (primary UEBA data source)
$results.Sysmon = Set-EventLogRetention `
    -LogName "Microsoft-Windows-Sysmon/Operational" `
    -DisplayName "Sysmon Operational" `
    -MaxSizeBytes (ConvertTo-Bytes $SysmonMaxSizeMB) `
    -Retention $false

Write-Host ""

# Configure Security log (authentication, audit events)
$results.Security = Set-EventLogRetention `
    -LogName "Security" `
    -DisplayName "Security" `
    -MaxSizeBytes (ConvertTo-Bytes $SecurityMaxSizeMB) `
    -Retention $false

Write-Host ""

# Configure System log (services, drivers)
$results.System = Set-EventLogRetention `
    -LogName "System" `
    -DisplayName "System" `
    -MaxSizeBytes (ConvertTo-Bytes $SystemMaxSizeMB) `
    -Retention $false

Write-Host ""

# Configure Application log
$results.Application = Set-EventLogRetention `
    -LogName "Application" `
    -DisplayName "Application" `
    -MaxSizeBytes (ConvertTo-Bytes $ApplicationMaxSizeMB) `
    -Retention $false

Write-Host ""
Write-Host "========================================" -ForegroundColor White
Write-Host "  Configuration Summary" -ForegroundColor White
Write-Host "========================================" -ForegroundColor White
Write-Host ""

$successCount = ($results.Values | Where-Object { $_ -eq $true }).Count
$totalCount = $results.Count

if ($successCount -eq $totalCount) {
    Write-Host "All logs configured successfully." -ForegroundColor Green
}
elseif ($successCount -gt 0) {
    Write-Host "Partial success: $successCount of $totalCount logs configured." -ForegroundColor Yellow
}
else {
    Write-Host "Configuration failed for all logs." -ForegroundColor Red
}

Write-Host ""
Write-Host "Final settings:" -ForegroundColor Yellow
Get-EventLogSettings -LogName "Microsoft-Windows-Sysmon/Operational" -DisplayName "Sysmon Operational"
Get-EventLogSettings -LogName "Security" -DisplayName "Security"
Get-EventLogSettings -LogName "System" -DisplayName "System"
Get-EventLogSettings -LogName "Application" -DisplayName "Application"
Write-Host ""

# Return exit code based on Sysmon configuration (critical for UEBA)
if ($results.Sysmon) {
    Write-Host "UEBA event log retention configured." -ForegroundColor Green
    exit 0
}
else {
    Write-Warning "Sysmon log configuration failed. Verify Sysmon is installed."
    exit 1
}
