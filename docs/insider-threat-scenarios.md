# Insider Threat Scenarios (Demo)

## Scenario 1: After-Hours Data Exfiltration

**Story**: John Doe (finance dept) normally works 9am-6pm. One night at 3am, he logs in and uploads large files to external cloud services (Dropbox, Google Drive).

**Expected Logs**:
- Security 4624 (Logon) - 3:15am
- Sysmon Event 1 (Process Create) - chrome.exe, rclone.exe
- Sysmon Event 3 (Network) - connections to dropbox.com, drive.google.com
- Sysmon Event 11 (File Create) - temp files (zipped archives)

**Baseline Normal**:
- Login hours: 8am-7pm (weekdays)
- Common processes: outlook.exe, excel.exe, chrome.exe
- Network: internal domains only
- File ops: 10-20 files/day

**Baseline Anomaly**:
- ❌ Login hour: 3am (outlier)
- ❌ Rare process: rclone.exe
- ❌ Rare domains: dropbox.com, drive.google.com
- ❌ File volume spike: 500MB uploaded

**Expected Alert**:
```json
{
  "behavior": "ueba_anomaly",
  "risk_score": 90,
  "risk_level": "CRITICAL",
  "reasons": [
    {"type": "unusual_hour", "detail": "Login at 3:15am (baseline: 8am-7pm)"},
    {"type": "rare_process", "detail": "rclone.exe not in baseline"},
    {"type": "rare_domain", "detail": "dropbox.com accessed"}
  ],
  "mitre_tactics": ["TA0010"],
  "mitre_techniques": ["T1048.003"]
}
```

**Safe Demo Steps**:
1. Change system time to 3am (or use replay script)
2. Create dummy files: `New-Item -Path "C:\temp\sensitive.zip" -ItemType File`
3. Simulate network: `curl https://www.dropbox.com`
4. Run anomaly scan: `python scripts/run_anomaly_scan.py --hours 1`
5. Check dashboard for alert

## Scenario 2: Privilege Escalation Attempt

**Story**: Alice Smith (marketing) attempts to gain admin rights via UAC bypass, registry modification, scheduled task creation.

**Expected Logs**:
- Security 4688 (Process Create) - cmd.exe /c reg add HKLM...
- Security 4698 (Scheduled Task Create)
- Sysmon Event 1 - powershell.exe (suspicious flags)
- Sysmon Event 13 (Registry Value Set) - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

**Baseline Normal**:
- Process: outlook.exe, chrome.exe, adobe.exe
- Registry: No registry modifications
- Scheduled tasks: None
- PowerShell: Rare (1-2 events/month)

**Baseline Anomaly**:
- ❌ Rare process: cmd.exe with registry commands
- ❌ Registry modification (never in baseline)
- ❌ Scheduled task creation
- ❌ PowerShell encoded command

**Expected Alert**:
```json
{
  "behavior": "ueba_anomaly",
  "risk_score": 85,
  "risk_level": "HIGH",
  "reasons": [
    {"type": "rare_process", "detail": "cmd.exe with registry modification"},
    {"type": "registry_persistence", "detail": "HKLM Run key modified"}
  ],
  "mitre_tactics": ["TA0004", "TA0003"],
  "mitre_techniques": ["T1548", "T1053.005"]
}
```

**Safe Demo Steps**:
1. Query registry (read-only): `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
2. Query scheduled tasks: `schtasks /query /fo LIST`
3. Run harmless PowerShell: `powershell -encodedcommand "RwBlAHQALQBEAGEAdABlAA=="`
4. Run anomaly scan
5. Check dashboard

## Scenario 3: Credential Dumping (Simulated)

**Story**: Bob Williams (IT support) attempts credential dumping using tools like mimikatz.

**Expected Logs**:
- Security 4656 (Handle to Object) - lsass.exe access
- Sysmon Event 1 - mimikatz.exe, procdump.exe
- Sysmon Event 10 (Process Access) - target: lsass.exe
- Sysmon Event 7 (Image Load) - suspicious DLLs

**Baseline Normal**:
- Process: IT tools (TeamViewer, Remote Desktop)
- LSASS access: None
- DLL loads: Standard Windows DLLs

**Baseline Anomaly**:
- ❌ Rare process: mimikatz.exe (hacking tool)
- ❌ LSASS access (extremely rare)
- ❌ Suspicious DLL: sekurlsa.dll

**Expected Alert**:
```json
{
  "behavior": "ueba_anomaly",
  "risk_score": 95,
  "risk_level": "CRITICAL",
  "reasons": [
    {"type": "known_hacking_tool", "detail": "mimikatz.exe executed"},
    {"type": "lsass_access", "detail": "Process accessed lsass.exe memory"}
  ],
  "mitre_tactics": ["TA0006"],
  "mitre_techniques": ["T1003.001"]
}
```

**Safe Demo Steps**:
⚠️ **DO NOT run mimikatz on real systems!**

Instead:
1. Use replay script: `python scripts/replay_demo.py --scenario credential_dumping`
2. Or manually inject events to DB for demo
3. Check dashboard for alert

## MITRE ATT&CK Mapping

- **TA0006**: Credential Access
- **TA0010**: Exfiltration
- **TA0004**: Privilege Escalation
- **TA0003**: Persistence
- **T1003.001**: OS Credential Dumping: LSASS Memory
- **T1048.003**: Exfiltration Over Alternative Protocol
- **T1548**: Abuse Elevation Control Mechanism
- **T1053.005**: Scheduled Task/Job

