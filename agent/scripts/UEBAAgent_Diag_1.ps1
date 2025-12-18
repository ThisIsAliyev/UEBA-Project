<#
.SYNOPSIS
    UEBA Agent Diagnostic Script - Flood/Backlog Troubleshooter
    
.DESCRIPTION
    Comprehensive diagnostic tool for Windows UEBA Agent issues:
    - Agent health and discovery
    - Time/clock drift detection
    - Event log volume and flood detection
    - Spool/backlog monitoring
    - Network connectivity tests
    - Root cause classification
    
.NOTES
    Author: UEBA Team
    Version: 1.0
    READ-ONLY: This script does NOT modify any system settings
    
.EXAMPLE
    .\UEBAAgent_Diag.ps1
    # Runs full diagnostic and creates report files
#>

#Requires -Version 5.1

# ============================================================================
# CONFIGURATION - MODIFY THESE VALUES
# ============================================================================
$ServerIP = "192.168.213.136"
$ServerPort = 9000
$AgentHint = "ueba|sysmon|agent|forwarder"  # Regex pattern for process discovery
$ProgramDataRoot = "$env:ProgramData\UEBAAgent"
$AgentWorkDir = ""  # Optional: Set if agent runs from specific directory

# Thresholds
$DriftThresholdSeconds = 120
$HighEventRatePerMinute = 2000
$OldEventThresholdMinutes = 10
$SpoolMonitorSeconds = 60
$SpoolCheckIntervalSeconds = 5

# ============================================================================
# INITIALIZATION
# ============================================================================
$ErrorActionPreference = "Continue"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportTxt = ".\UEBAAgent_Diag_Report_$Timestamp.txt"
$ReportJson = ".\UEBAAgent_Diag_Report_$Timestamp.json"

# Report data structure
$DiagData = [ordered]@{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ServerIP = $ServerIP
    ServerPort = $ServerPort
    SystemSummary = @{}
    TimeHealth = @{}
    AgentDiscovery = @{}
    EventLogHealth = @{}
    FloodDetection = @{}
    BacklogMetrics = @{}
    NetworkTests = @{}
    RootCauseAnalysis = @{}
}

# Flags for root cause
$Flags = @{
    HighEventRate = $false
    HistoricalFlood = $false
    TimeDrift = $false
    SpoolGrowing = $false
    ServerConnectFail = $false
    ConnectionReset = $false
    SecurityAccessDenied = $false
    DuplicateEvents = $false
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
function Write-Section {
    param([string]$Title)
    $line = "=" * 70
    Write-Host "`n$line" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "$line" -ForegroundColor Cyan
    return "`n$line`n  $Title`n$line`n"
}

function Write-Status {
    param([string]$Message, [string]$Status = "INFO", [string]$Color = "White")
    $prefix = switch ($Status) {
        "OK"    { "[+]"; $Color = "Green" }
        "WARN"  { "[!]"; $Color = "Yellow" }
        "ERROR" { "[-]"; $Color = "Red" }
        "INFO"  { "[*]"; $Color = "White" }
        default { "[*]" }
    }
    Write-Host "$prefix $Message" -ForegroundColor $Color
    return "$prefix $Message`n"
}

function Get-SafeWmiObject {
    param([string]$Class, [string]$Filter = "")
    try {
        if ($Filter) {
            return Get-WmiObject -Class $Class -Filter $Filter -ErrorAction Stop
        }
        return Get-WmiObject -Class $Class -ErrorAction Stop
    } catch {
        return $null
    }
}

# ============================================================================
# SECTION 1: SYSTEM SUMMARY
# ============================================================================
function Get-SystemSummary {
    $report = Write-Section "SYSTEM SUMMARY"
    
    $os = Get-SafeWmiObject -Class Win32_OperatingSystem
    $cs = Get-SafeWmiObject -Class Win32_ComputerSystem
    
    $summary = [ordered]@{
        ComputerName = $env:COMPUTERNAME
        OSVersion = if ($os) { $os.Caption } else { "Unknown" }
        OSBuild = if ($os) { $os.BuildNumber } else { "Unknown" }
        Architecture = $env:PROCESSOR_ARCHITECTURE
        Domain = if ($cs) { $cs.Domain } else { "Unknown" }
        CurrentUser = "$env:USERDOMAIN\$env:USERNAME"
        IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        Uptime = if ($os) { 
            $boot = $os.ConvertToDateTime($os.LastBootUpTime)
            ((Get-Date) - $boot).ToString("d\.hh\:mm\:ss")
        } else { "Unknown" }
        TotalMemoryGB = if ($cs) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 2) } else { 0 }
    }
    
    $DiagData.SystemSummary = $summary
    
    foreach ($key in $summary.Keys) {
        $report += Write-Status "$key : $($summary[$key])"
    }
    
    if (-not $summary.IsAdmin) {
        $report += Write-Status "Running without Admin - some tests may fail" "WARN"
    }
    
    return $report
}

# ============================================================================
# SECTION 2: TIME / CLOCK HEALTH
# ============================================================================
function Get-TimeHealth {
    $report = Write-Section "TIME / CLOCK HEALTH"
    
    $timeData = [ordered]@{
        CurrentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TimeZone = (Get-TimeZone).DisplayName
        TimeZoneId = (Get-TimeZone).Id
        UTCOffset = (Get-Date).ToString("zzz")
        W32TimeStatus = @{}
        W32TimeConfig = @{}
        EventTimeDrift = @{}
        DriftRisk = "LOW"
    }
    
    $report += Write-Status "Current Time: $($timeData.CurrentTime)"
    $report += Write-Status "TimeZone: $($timeData.TimeZone)"
    $report += Write-Status "UTC Offset: $($timeData.UTCOffset)"
    
    # W32Time status
    $report += "`n--- W32Time Service Status ---`n"
    try {
        $w32status = w32tm /query /status 2>&1
        if ($LASTEXITCODE -eq 0) {
            $timeData.W32TimeStatus.Raw = $w32status -join "`n"
            $report += $w32status -join "`n"
            $report += "`n"
        } else {
            $timeData.W32TimeStatus.Error = "W32Time query failed: $w32status"
            $report += Write-Status "W32Time query failed - service may not be running" "WARN"
        }
    } catch {
        $timeData.W32TimeStatus.Error = $_.Exception.Message
        $report += Write-Status "W32Time error: $($_.Exception.Message)" "ERROR"
    }
    
    # Event time drift estimation
    $report += "`n--- Event Time Drift Estimation ---`n"
    $channels = @("Microsoft-Windows-Sysmon/Operational", "Security")
    $maxDrift = 0
    
    foreach ($channel in $channels) {
        try {
            $lastEvent = Get-WinEvent -LogName $channel -MaxEvents 1 -ErrorAction Stop
            if ($lastEvent) {
                $eventTime = $lastEvent.TimeCreated
                $now = Get-Date
                $drift = [math]::Abs(($now - $eventTime).TotalSeconds)
                
                $timeData.EventTimeDrift[$channel] = @{
                    LastEventTime = $eventTime.ToString("yyyy-MM-dd HH:mm:ss")
                    DriftSeconds = [math]::Round($drift, 2)
                }
                
                if ($drift -gt $maxDrift) { $maxDrift = $drift }
                
                $status = if ($drift -gt $DriftThresholdSeconds) { "WARN" } else { "OK" }
                $report += Write-Status "$channel : Last event $([math]::Round($drift, 0))s ago" $status
            }
        } catch {
            $timeData.EventTimeDrift[$channel] = @{ Error = $_.Exception.Message }
            $report += Write-Status "$channel : Cannot read - $($_.Exception.Message)" "WARN"
        }
    }
    
    if ($maxDrift -gt $DriftThresholdSeconds) {
        $timeData.DriftRisk = "HIGH"
        $Flags.TimeDrift = $true
        $report += Write-Status "HIGH RISK: Time drift > ${DriftThresholdSeconds}s detected! This can cause cursor/filtering issues." "ERROR"
    } else {
        $report += Write-Status "Time drift within acceptable range" "OK"
    }
    
    $DiagData.TimeHealth = $timeData
    return $report
}

# ============================================================================
# SECTION 3: AGENT DISCOVERY
# ============================================================================
function Get-AgentDiscovery {
    $report = Write-Section "AGENT DISCOVERY"
    
    $agentData = [ordered]@{
        Processes = @()
        Services = @()
        ConfigPaths = @()
        StateFile = @{}
        SpoolDir = @{}
    }
    
    # Process discovery
    $report += "`n--- Agent Processes ---`n"
    $patterns = $AgentHint -split '\|'
    $foundProcesses = @()
    
    try {
        $allProcs = Get-WmiObject Win32_Process -ErrorAction Stop | 
            Where-Object { $_.CommandLine -and ($patterns | Where-Object { $_.CommandLine -match $_ }) }
        
        foreach ($proc in $allProcs) {
            $procInfo = @{
                Name = $proc.Name
                PID = $proc.ProcessId
                CommandLine = $proc.CommandLine
                WorkingDir = $proc.ExecutablePath | Split-Path -Parent -ErrorAction SilentlyContinue
            }
            $foundProcesses += $procInfo
            $report += Write-Status "Found: $($proc.Name) (PID: $($proc.ProcessId))" "OK"
            $report += "    CMD: $($proc.CommandLine)`n"
        }
    } catch {
        $report += Write-Status "Process enumeration error: $($_.Exception.Message)" "WARN"
    }
    
    # Also check by process name
    $procNames = @("python", "python3", "pythonw", "sysmon_forwarder", "ueba_agent")
    foreach ($name in $procNames) {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            if ($foundProcesses.PID -notcontains $p.Id) {
                $foundProcesses += @{ Name = $p.Name; PID = $p.Id; CommandLine = "N/A" }
                $report += Write-Status "Found process: $($p.Name) (PID: $($p.Id))" "INFO"
            }
        }
    }
    
    if ($foundProcesses.Count -eq 0) {
        $report += Write-Status "No agent processes found matching pattern: $AgentHint" "WARN"
    }
    $agentData.Processes = $foundProcesses
    
    # Service discovery
    $report += "`n--- Agent Services ---`n"
    $svcPatterns = @("*ueba*", "*sysmon*forwarder*", "*agent*")
    $foundServices = @()
    
    foreach ($pattern in $svcPatterns) {
        $svcs = Get-Service -Name $pattern -ErrorAction SilentlyContinue
        foreach ($svc in $svcs) {
            $svcInfo = @{
                Name = $svc.Name
                DisplayName = $svc.DisplayName
                Status = $svc.Status.ToString()
                StartType = $svc.StartType.ToString()
            }
            $foundServices += $svcInfo
            $status = if ($svc.Status -eq "Running") { "OK" } else { "WARN" }
            $report += Write-Status "$($svc.DisplayName) : $($svc.Status)" $status
        }
    }
    
    if ($foundServices.Count -eq 0) {
        $report += Write-Status "No agent services found (may run as standalone process)" "INFO"
    }
    $agentData.Services = $foundServices
    
    # Config/State discovery
    $report += "`n--- Config/State Files ---`n"
    $searchPaths = @(
        $ProgramDataRoot,
        "$env:LOCALAPPDATA\UEBAAgent",
        "$env:APPDATA\UEBAAgent"
    )
    if ($AgentWorkDir) { $searchPaths += $AgentWorkDir }
    
    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            $report += Write-Status "Found directory: $path" "OK"
            $agentData.ConfigPaths += $path
            
            # Look for state.json
            $stateFile = Join-Path $path "state.json"
            if (Test-Path $stateFile) {
                $stateInfo = Get-Item $stateFile
                $agentData.StateFile = @{
                    Path = $stateFile
                    SizeKB = [math]::Round($stateInfo.Length / 1KB, 2)
                    LastModified = $stateInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                    ModifiedAgo = [math]::Round(((Get-Date) - $stateInfo.LastWriteTime).TotalMinutes, 1)
                }
                $report += Write-Status "  state.json: $([math]::Round($stateInfo.Length / 1KB, 2)) KB, modified $($agentData.StateFile.ModifiedAgo) min ago"
            }
            
            # Look for spool directory
            $spoolDir = Join-Path $path "spool"
            if (Test-Path $spoolDir) {
                $spoolFiles = Get-ChildItem $spoolDir -File -ErrorAction SilentlyContinue
                $totalSize = ($spoolFiles | Measure-Object -Property Length -Sum).Sum
                $agentData.SpoolDir = @{
                    Path = $spoolDir
                    FileCount = $spoolFiles.Count
                    TotalSizeMB = [math]::Round($totalSize / 1MB, 2)
                    OldestFile = if ($spoolFiles) { ($spoolFiles | Sort-Object LastWriteTime | Select-Object -First 1).LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                    NewestFile = if ($spoolFiles) { ($spoolFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                }
                $status = if ($agentData.SpoolDir.TotalSizeMB -gt 10) { "WARN" } else { "OK" }
                $report += Write-Status "  spool/: $($spoolFiles.Count) files, $($agentData.SpoolDir.TotalSizeMB) MB" $status
            }
        }
    }
    
    $DiagData.AgentDiscovery = $agentData
    return $report
}

# ============================================================================
# SECTION 4: EVENT LOG HEALTH & VOLUME
# ============================================================================
function Get-EventLogHealth {
    $report = Write-Section "EVENT LOG HEALTH & VOLUME"
    
    $channels = @(
        "Microsoft-Windows-Sysmon/Operational",
        "Security",
        "System",
        "Application"
    )
    
    $logHealth = [ordered]@{}
    
    foreach ($channel in $channels) {
        $report += "`n--- $channel ---`n"
        $channelData = [ordered]@{
            Exists = $false
            Enabled = $false
            RecordCount = 0
            MaxSizeKB = 0
            CurrentSizeKB = 0
            Events1Min = 0
            Events10Min = 0
            OldEventsPercent = 0
            DuplicateCheck = @{}
            Error = $null
        }
        
        try {
            # Check if log exists
            $logInfo = Get-WinEvent -ListLog $channel -ErrorAction Stop
            $channelData.Exists = $true
            $channelData.Enabled = $logInfo.IsEnabled
            $channelData.RecordCount = $logInfo.RecordCount
            $channelData.MaxSizeKB = [math]::Round($logInfo.MaximumSizeInBytes / 1KB, 0)
            $channelData.CurrentSizeKB = [math]::Round($logInfo.FileSize / 1KB, 0)
            
            $report += Write-Status "Enabled: $($logInfo.IsEnabled), Records: $($logInfo.RecordCount)" "OK"
            $report += Write-Status "Size: $($channelData.CurrentSizeKB) KB / $($channelData.MaxSizeKB) KB max"
            
            # Events in last 1 minute
            $now = Get-Date
            $oneMinAgo = $now.AddMinutes(-1)
            $tenMinAgo = $now.AddMinutes(-10)
            
            try {
                $events1Min = Get-WinEvent -FilterHashtable @{LogName=$channel; StartTime=$oneMinAgo} -ErrorAction Stop
                $channelData.Events1Min = $events1Min.Count
            } catch {
                if ($_.Exception.Message -notmatch "No events were found") {
                    throw
                }
                $channelData.Events1Min = 0
            }
            
            try {
                $events10Min = Get-WinEvent -FilterHashtable @{LogName=$channel; StartTime=$tenMinAgo} -ErrorAction Stop
                $channelData.Events10Min = $events10Min.Count
            } catch {
                if ($_.Exception.Message -notmatch "No events were found") {
                    throw
                }
                $channelData.Events10Min = 0
            }
            
            $status = if ($channelData.Events1Min -gt $HighEventRatePerMinute) { 
                $Flags.HighEventRate = $true
                "WARN" 
            } else { "OK" }
            $report += Write-Status "Events (1 min): $($channelData.Events1Min), (10 min): $($channelData.Events10Min)" $status
            
            # Old events analysis (last 200 events)
            try {
                $last200 = Get-WinEvent -LogName $channel -MaxEvents 200 -ErrorAction Stop
                $oldThreshold = $now.AddMinutes(-$OldEventThresholdMinutes)
                $oldEvents = $last200 | Where-Object { $_.TimeCreated -lt $oldThreshold }
                $channelData.OldEventsPercent = [math]::Round(($oldEvents.Count / $last200.Count) * 100, 1)
                
                if ($channelData.OldEventsPercent -gt 50) {
                    $Flags.HistoricalFlood = $true
                    $report += Write-Status "OLD EVENTS: $($channelData.OldEventsPercent)% of last 200 are >$OldEventThresholdMinutes min old" "WARN"
                } else {
                    $report += Write-Status "Old events: $($channelData.OldEventsPercent)% (>$OldEventThresholdMinutes min)" "OK"
                }
                
                # Duplicate check
                $recordIds = $last200 | Group-Object RecordId | Where-Object { $_.Count -gt 1 }
                if ($recordIds) {
                    $Flags.DuplicateEvents = $true
                    $channelData.DuplicateCheck.DuplicateRecordIds = $recordIds.Count
                    $report += Write-Status "DUPLICATE RecordIds found: $($recordIds.Count)" "ERROR"
                }
                
                $idTimeGroups = $last200 | Group-Object { "$($_.Id)_$($_.TimeCreated.ToString('yyyyMMddHHmmss'))" } | 
                    Where-Object { $_.Count -gt 1 }
                if ($idTimeGroups.Count -gt 5) {
                    $channelData.DuplicateCheck.DuplicateIdTime = $idTimeGroups.Count
                    $report += Write-Status "Suspicious: $($idTimeGroups.Count) duplicate Id+Time combinations" "WARN"
                }
                
            } catch {
                $report += Write-Status "Could not analyze last 200 events: $($_.Exception.Message)" "WARN"
            }
            
        } catch {
            $errMsg = $_.Exception.Message
            $channelData.Error = $errMsg
            
            if ($errMsg -match "Access.*denied|privilege") {
                $Flags.SecurityAccessDenied = $true
                $report += Write-Status "ACCESS DENIED - Run as Administrator" "ERROR"
            } elseif ($errMsg -match "not found|does not exist") {
                $report += Write-Status "Channel does not exist (Sysmon not installed?)" "WARN"
            } else {
                $report += Write-Status "Error: $errMsg" "ERROR"
            }
        }
        
        $logHealth[$channel] = $channelData
    }
    
    $DiagData.EventLogHealth = $logHealth
    return $report
}

# ============================================================================
# SECTION 5: FLOOD DETECTION METRICS
# ============================================================================
function Get-FloodDetection {
    $report = Write-Section "FLOOD DETECTION METRICS"
    
    $floodData = [ordered]@{
        HighRateChannels = @()
        HistoricalFloodChannels = @()
        TotalEvents1Min = 0
        TotalEvents10Min = 0
        FloodRisk = "LOW"
    }
    
    foreach ($channel in $DiagData.EventLogHealth.Keys) {
        $data = $DiagData.EventLogHealth[$channel]
        $floodData.TotalEvents1Min += $data.Events1Min
        $floodData.TotalEvents10Min += $data.Events10Min
        
        if ($data.Events1Min -gt $HighEventRatePerMinute) {
            $floodData.HighRateChannels += $channel
        }
        if ($data.OldEventsPercent -gt 50) {
            $floodData.HistoricalFloodChannels += $channel
        }
    }
    
    $report += Write-Status "Total events (1 min): $($floodData.TotalEvents1Min)"
    $report += Write-Status "Total events (10 min): $($floodData.TotalEvents10Min)"
    
    if ($floodData.HighRateChannels.Count -gt 0) {
        $floodData.FloodRisk = "HIGH"
        $report += Write-Status "HIGH RATE channels: $($floodData.HighRateChannels -join ', ')" "WARN"
    }
    
    if ($floodData.HistoricalFloodChannels.Count -gt 0) {
        $floodData.FloodRisk = "HIGH"
        $report += Write-Status "HISTORICAL FLOOD channels: $($floodData.HistoricalFloodChannels -join ', ')" "ERROR"
    }
    
    if ($floodData.FloodRisk -eq "LOW") {
        $report += Write-Status "No flood indicators detected" "OK"
    }
    
    $DiagData.FloodDetection = $floodData
    return $report
}

# ============================================================================
# SECTION 6: BACKLOG / SPOOL METRICS
# ============================================================================
function Get-BacklogMetrics {
    $report = Write-Section "BACKLOG / SPOOL METRICS"
    
    $backlogData = [ordered]@{
        SpoolPath = $null
        InitialFileCount = 0
        InitialSizeMB = 0
        MonitorResults = @()
        GrowthTrend = "STABLE"
        GrowthRateMBperMin = 0
    }
    
    $spoolPath = $DiagData.AgentDiscovery.SpoolDir.Path
    if (-not $spoolPath -or -not (Test-Path $spoolPath)) {
        $report += Write-Status "Spool directory not found or empty" "INFO"
        $DiagData.BacklogMetrics = $backlogData
        return $report
    }
    
    $backlogData.SpoolPath = $spoolPath
    
    # Initial measurement
    $initialFiles = Get-ChildItem $spoolPath -File -ErrorAction SilentlyContinue
    $initialSize = ($initialFiles | Measure-Object -Property Length -Sum).Sum / 1MB
    $backlogData.InitialFileCount = $initialFiles.Count
    $backlogData.InitialSizeMB = [math]::Round($initialSize, 2)
    
    $report += Write-Status "Initial spool: $($initialFiles.Count) files, $([math]::Round($initialSize, 2)) MB"
    
    if ($initialSize -gt 0) {
        $report += Write-Status "Monitoring spool for $SpoolMonitorSeconds seconds..."
        
        $measurements = @()
        $startTime = Get-Date
        $iterations = [math]::Ceiling($SpoolMonitorSeconds / $SpoolCheckIntervalSeconds)
        
        for ($i = 0; $i -lt $iterations; $i++) {
            Start-Sleep -Seconds $SpoolCheckIntervalSeconds
            $files = Get-ChildItem $spoolPath -File -ErrorAction SilentlyContinue
            $size = ($files | Measure-Object -Property Length -Sum).Sum / 1MB
            $elapsed = ((Get-Date) - $startTime).TotalSeconds
            
            $measurements += @{
                ElapsedSeconds = [math]::Round($elapsed, 0)
                FileCount = $files.Count
                SizeMB = [math]::Round($size, 2)
            }
            
            Write-Host "." -NoNewline
        }
        Write-Host ""
        
        $backlogData.MonitorResults = $measurements
        
        # Calculate growth trend
        $finalSize = $measurements[-1].SizeMB
        $growthMB = $finalSize - $initialSize
        $growthRate = ($growthMB / $SpoolMonitorSeconds) * 60  # MB per minute
        
        $backlogData.GrowthRateMBperMin = [math]::Round($growthRate, 3)
        
        if ($growthMB -gt 0.1) {
            $backlogData.GrowthTrend = "GROWING"
            $Flags.SpoolGrowing = $true
            $report += Write-Status "BACKLOG GROWING: +$([math]::Round($growthMB, 2)) MB in $SpoolMonitorSeconds sec ($([math]::Round($growthRate, 2)) MB/min)" "ERROR"
        } elseif ($growthMB -lt -0.1) {
            $backlogData.GrowthTrend = "DRAINING"
            $report += Write-Status "Backlog draining: $([math]::Round($growthMB, 2)) MB in $SpoolMonitorSeconds sec" "OK"
        } else {
            $report += Write-Status "Backlog stable (no significant change)" "OK"
        }
    } else {
        $report += Write-Status "Spool is empty - no backlog" "OK"
    }
    
    $DiagData.BacklogMetrics = $backlogData
    return $report
}

# ============================================================================
# SECTION 7: NETWORK / SERVER CONNECTIVITY
# ============================================================================
function Get-NetworkTests {
    $report = Write-Section "NETWORK / SERVER CONNECTIVITY"
    
    $netData = [ordered]@{
        ServerIP = $ServerIP
        ServerPort = $ServerPort
        TestNetConnection = @{}
        TcpSocketTests = @()
        ConnectionResetDetected = $false
        DNSInfo = @{}
    }
    
    # Test-NetConnection
    $report += "`n--- Test-NetConnection ---`n"
    try {
        $tnc = Test-NetConnection -ComputerName $ServerIP -Port $ServerPort -WarningAction SilentlyContinue
        $netData.TestNetConnection = @{
            TcpTestSucceeded = $tnc.TcpTestSucceeded
            PingSucceeded = $tnc.PingSucceeded
            RemoteAddress = $tnc.RemoteAddress.ToString()
            SourceAddress = if ($tnc.SourceAddress) { $tnc.SourceAddress.IPAddress } else { "N/A" }
        }
        
        if ($tnc.TcpTestSucceeded) {
            $report += Write-Status "TCP $ServerIP`:$ServerPort : REACHABLE" "OK"
        } else {
            $Flags.ServerConnectFail = $true
            $report += Write-Status "TCP $ServerIP`:$ServerPort : FAILED" "ERROR"
        }
        $report += Write-Status "Ping: $($tnc.PingSucceeded), Source: $($netData.TestNetConnection.SourceAddress)"
        
    } catch {
        $netData.TestNetConnection.Error = $_.Exception.Message
        $Flags.ServerConnectFail = $true
        $report += Write-Status "Test-NetConnection failed: $($_.Exception.Message)" "ERROR"
    }
    
    # TCP Socket stability test (3 attempts)
    $report += "`n--- TCP Socket Stability Test (3 attempts) ---`n"
    for ($i = 1; $i -le 3; $i++) {
        $testResult = @{
            Attempt = $i
            Connected = $false
            HeldMs = 0
            Error = $null
            ConnectionReset = $false
        }
        
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $connectTask = $client.ConnectAsync($ServerIP, $ServerPort)
            $connected = $connectTask.Wait(5000)  # 5 second timeout
            
            if ($connected -and $client.Connected) {
                $testResult.Connected = $true
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                
                # Hold connection for 2 seconds to detect reset
                Start-Sleep -Milliseconds 2000
                
                # Check if still connected
                if ($client.Client.Poll(0, [System.Net.Sockets.SelectMode]::SelectRead)) {
                    $buffer = New-Object byte[] 1
                    try {
                        $bytesRead = $client.Client.Receive($buffer, [System.Net.Sockets.SocketFlags]::Peek)
                        if ($bytesRead -eq 0) {
                            $testResult.ConnectionReset = $true
                            $Flags.ConnectionReset = $true
                        }
                    } catch {
                        if ($_.Exception.InnerException -and $_.Exception.InnerException.Message -match "10054|forcibly closed") {
                            $testResult.ConnectionReset = $true
                            $Flags.ConnectionReset = $true
                        }
                    }
                }
                
                $sw.Stop()
                $testResult.HeldMs = $sw.ElapsedMilliseconds
                $client.Close()
                
                if ($testResult.ConnectionReset) {
                    $report += Write-Status "Attempt $i : Connected but RESET detected (WinError 10054 pattern)" "WARN"
                } else {
                    $report += Write-Status "Attempt $i : Connected, held ${($testResult.HeldMs)}ms, stable" "OK"
                }
            } else {
                $testResult.Error = "Connection timeout"
                $report += Write-Status "Attempt $i : Connection timeout" "ERROR"
            }
        } catch {
            $testResult.Error = $_.Exception.Message
            if ($_.Exception.Message -match "10054|forcibly closed") {
                $testResult.ConnectionReset = $true
                $Flags.ConnectionReset = $true
                $report += Write-Status "Attempt $i : Connection reset by remote host (10054)" "ERROR"
            } else {
                $report += Write-Status "Attempt $i : $($_.Exception.Message)" "ERROR"
            }
        } finally {
            if ($client) { $client.Dispose() }
        }
        
        $netData.TcpSocketTests += $testResult
        Start-Sleep -Milliseconds 500
    }
    
    $netData.ConnectionResetDetected = $Flags.ConnectionReset
    
    # Brief network info
    $report += "`n--- Network Configuration (brief) ---`n"
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object Name, InterfaceDescription, MacAddress
        foreach ($adapter in $adapters) {
            $report += "  $($adapter.Name): $($adapter.InterfaceDescription)`n"
        }
    } catch {
        $report += "  (Could not enumerate adapters)`n"
    }
    
    $DiagData.NetworkTests = $netData
    return $report
}

# ============================================================================
# SECTION 8: ROOT CAUSE CLASSIFICATION
# ============================================================================
function Get-RootCauseAnalysis {
    $report = Write-Section "ROOT CAUSE CLASSIFICATION"
    
    $rcaData = [ordered]@{
        PrimaryRootCause = "UNKNOWN"
        SecondaryFactors = @()
        Confidence = "LOW"
        NextSteps = @()
    }
    
    $causes = @()
    $nextSteps = @()
    
    # Rule 1: Historical Flood / Cursor Bug
    if ($Flags.HistoricalFlood -or ($Flags.HighEventRate -and $DiagData.FloodDetection.HistoricalFloodChannels.Count -gt 0)) {
        $causes += @{
            Cause = "HISTORICAL_FLOOD_CURSOR_BUG"
            Description = "Agent is processing old/historical events instead of real-time. Likely cursor/RecordId bookmark issue."
            Confidence = "HIGH"
        }
        $nextSteps += "1. Delete state.json to reset cursor: Remove-Item '$ProgramDataRoot\state.json' -Force"
        $nextSteps += "2. Delete spool to clear backlog: Remove-Item '$ProgramDataRoot\spool\*' -Recurse -Force"
        $nextSteps += "3. Verify agent config has 'start_from_now: true'"
        $nextSteps += "4. Restart agent and monitor for real-time events only"
    }
    
    # Rule 2: Send Failure / Server Connection Reset
    if ($Flags.SpoolGrowing -and ($Flags.ServerConnectFail -or $Flags.ConnectionReset)) {
        $causes += @{
            Cause = "SEND_FAILURE_SERVER_RESET"
            Description = "Events are being collected but cannot be sent. Server is closing connections (WinError 10054 pattern)."
            Confidence = "HIGH"
        }
        $nextSteps += "1. Check server ingest service is running on port $ServerPort"
        $nextSteps += "2. Check server logs for connection/authentication errors"
        $nextSteps += "3. Verify agent authentication token is valid"
        $nextSteps += "4. Check firewall rules on both agent and server"
        $nextSteps += "5. If server is overloaded, consider rate limiting on agent side"
    }
    
    # Rule 3: Time Drift
    if ($Flags.TimeDrift) {
        $causes += @{
            Cause = "TIME_DRIFT_CONTRIBUTOR"
            Description = "System time drift >$DriftThresholdSeconds seconds. This can disable time-window filtering and cause cursor issues."
            Confidence = "MEDIUM"
        }
        $nextSteps += "1. Sync system time: w32tm /resync /force"
        $nextSteps += "2. Check NTP configuration: w32tm /query /configuration"
        $nextSteps += "3. Ensure w32time service is running: Get-Service w32time"
    }
    
    # Rule 4: Security Access Denied
    if ($Flags.SecurityAccessDenied) {
        $causes += @{
            Cause = "PRIVILEGE_ACCESS_ISSUE"
            Description = "Cannot read Security event log. Agent needs elevated privileges."
            Confidence = "HIGH"
        }
        $nextSteps += "1. Run agent as Administrator or SYSTEM"
        $nextSteps += "2. If running as service, ensure service account has 'Manage auditing and security log' right"
        $nextSteps += "3. Consider using Event Log Readers group membership"
    }
    
    # Rule 5: Duplicate Events
    if ($Flags.DuplicateEvents) {
        $causes += @{
            Cause = "DUPLICATE_EVENT_BUG"
            Description = "Duplicate RecordIds detected. This indicates a serious cursor/state management bug."
            Confidence = "HIGH"
        }
        $nextSteps += "1. Immediately stop agent"
        $nextSteps += "2. Delete state.json and spool"
        $nextSteps += "3. Check for multiple agent instances running"
        $nextSteps += "4. Review agent code for cursor persistence issues"
    }
    
    # Rule 6: Spool Growing but no connection issues
    if ($Flags.SpoolGrowing -and -not $Flags.ServerConnectFail -and -not $Flags.ConnectionReset) {
        $causes += @{
            Cause = "SEND_RATE_EXCEEDED"
            Description = "Events are being collected faster than they can be sent. Server accepts connections but processing is slow."
            Confidence = "MEDIUM"
        }
        $nextSteps += "1. Check server processing capacity and logs"
        $nextSteps += "2. Reduce agent poll frequency or max_events_per_poll"
        $nextSteps += "3. Consider enabling batch compression"
    }
    
    # Determine primary cause
    if ($causes.Count -gt 0) {
        $primaryCause = $causes | Sort-Object { 
            switch ($_.Confidence) { "HIGH" { 1 } "MEDIUM" { 2 } "LOW" { 3 } default { 4 } }
        } | Select-Object -First 1
        
        $rcaData.PrimaryRootCause = $primaryCause.Cause
        $rcaData.Confidence = $primaryCause.Confidence
        $rcaData.SecondaryFactors = ($causes | Select-Object -Skip 1).Cause
    } else {
        $rcaData.PrimaryRootCause = "NO_ISSUES_DETECTED"
        $rcaData.Confidence = "HIGH"
        $nextSteps += "No significant issues detected. Agent appears healthy."
        $nextSteps += "If problems persist, collect agent logs and re-run diagnostic."
    }
    
    $rcaData.NextSteps = $nextSteps
    
    # Output
    $report += "`n"
    foreach ($cause in $causes) {
        $color = switch ($cause.Confidence) { "HIGH" { "Red" } "MEDIUM" { "Yellow" } default { "White" } }
        $report += Write-Status "[$($cause.Confidence)] $($cause.Cause)" $(if ($cause.Confidence -eq "HIGH") { "ERROR" } else { "WARN" })
        $report += "    $($cause.Description)`n"
    }
    
    $report += "`n--- RECOMMENDED NEXT STEPS ---`n"
    foreach ($step in $nextSteps) {
        $report += "  $step`n"
        Write-Host "  $step" -ForegroundColor Yellow
    }
    
    $DiagData.RootCauseAnalysis = $rcaData
    return $report
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
Write-Host @"

╔══════════════════════════════════════════════════════════════════════╗
║           UEBA AGENT DIAGNOSTIC SCRIPT v1.0                          ║
║           Flood / Backlog Troubleshooter                             ║
╚══════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

$fullReport = @"
UEBA Agent Diagnostic Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Server Target: ${ServerIP}:${ServerPort}
============================================================

"@

# Run all diagnostic sections
$fullReport += Get-SystemSummary
$fullReport += Get-TimeHealth
$fullReport += Get-AgentDiscovery
$fullReport += Get-EventLogHealth
$fullReport += Get-FloodDetection
$fullReport += Get-BacklogMetrics
$fullReport += Get-NetworkTests
$fullReport += Get-RootCauseAnalysis

# Add flags summary
$fullReport += Write-Section "DIAGNOSTIC FLAGS SUMMARY"
$fullReport += ($Flags.GetEnumerator() | ForEach-Object { "  $($_.Key): $($_.Value)" }) -join "`n"
$fullReport += "`n"

# Save reports
$fullReport | Out-File -FilePath $ReportTxt -Encoding UTF8
$DiagData | ConvertTo-Json -Depth 10 | Out-File -FilePath $ReportJson -Encoding UTF8

Write-Host "`n"
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  REPORTS SAVED:" -ForegroundColor Green
Write-Host "    TXT: $((Resolve-Path $ReportTxt).Path)" -ForegroundColor White
Write-Host "    JSON: $((Resolve-Path $ReportJson).Path)" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Green

# Paste template
Write-Host @"

╔══════════════════════════════════════════════════════════════════════╗
║  PASTE RESULTS TEMPLATE - Copy and send to support:                  ║
╚══════════════════════════════════════════════════════════════════════╝

--- BEGIN PASTE ---
ServerIP/Port: ${ServerIP}:${ServerPort}
ComputerName: $env:COMPUTERNAME
Timestamp: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

PRIMARY ROOT CAUSE: $($DiagData.RootCauseAnalysis.PrimaryRootCause)
CONFIDENCE: $($DiagData.RootCauseAnalysis.Confidence)

REPORT TXT CONTENT:
<paste content of $ReportTxt here>

JSON CONTENT:
<paste content of $ReportJson here>

AGENT LOG SNIPPET (last 100 lines):
<paste last 100 lines of agent console/log output here>
--- END PASTE ---

"@ -ForegroundColor Cyan
