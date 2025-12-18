# Windows Audit Policy Setup Script for UEBA
# This script enables advanced Windows auditing needed for comprehensive UEBA detection
# Run as Administrator

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Windows Audit Policy Setup for UEBA" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

Write-Host "[*] Enabling Windows Audit Policies for UEBA..." -ForegroundColor Green
Write-Host ""

# ============================================
# Account Logon Events
# ============================================
Write-Host "[*] Configuring Account Logon auditing..." -ForegroundColor Yellow
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable

# ============================================
# Logon/Logoff Events (CRITICAL for Lock/Unlock)
# ============================================
Write-Host "[*] Configuring Logon/Logoff auditing (includes Lock/Unlock)..." -ForegroundColor Yellow
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"IPsec Main Mode" /success:enable /failure:enable
auditpol /set /subcategory:"IPsec Quick Mode" /success:enable /failure:enable
auditpol /set /subcategory:"IPsec Extended Mode" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable  # This enables 4800/4801

# ============================================
# Object Access (for file/registry monitoring)
# ============================================
Write-Host "[*] Configuring Object Access auditing..." -ForegroundColor Yellow
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable
auditpol /set /subcategory:"SAM" /success:enable /failure:enable
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

# ============================================
# Privilege Use
# ============================================
Write-Host "[*] Configuring Privilege Use auditing..." -ForegroundColor Yellow
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Other Privilege Use Events" /success:enable /failure:enable

# ============================================
# Detailed Tracking (Process Creation, etc.)
# ============================================
Write-Host "[*] Configuring Detailed Tracking auditing..." -ForegroundColor Yellow
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
auditpol /set /subcategory:"DPAPI Activity" /success:enable /failure:enable
auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable

# ============================================
# Policy Change
# ============================================
Write-Host "[*] Configuring Policy Change auditing..." -ForegroundColor Yellow
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable

# ============================================
# Account Management
# ============================================
Write-Host "[*] Configuring Account Management auditing..." -ForegroundColor Yellow
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable

# ============================================
# DS Access (if domain-joined)
# ============================================
Write-Host "[*] Configuring DS Access auditing..." -ForegroundColor Yellow
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed Directory Service Replication" /success:enable /failure:enable

# ============================================
# System Events
# ============================================
Write-Host "[*] Configuring System Events auditing..." -ForegroundColor Yellow
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable

# ============================================
# Enable Command Line Logging in Process Creation
# ============================================
Write-Host "[*] Enabling command line logging in Process Creation events..." -ForegroundColor Yellow
$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
Write-Host "[+] Command line logging enabled" -ForegroundColor Green

# ============================================
# Verify Configuration
# ============================================
Write-Host ""
Write-Host "[*] Verifying audit policy configuration..." -ForegroundColor Yellow
Write-Host ""
auditpol /get /category:* | Select-String -Pattern "Logon|Logoff|Process Creation|Account Lockout|Other Logon" | ForEach-Object {
    Write-Host $_ -ForegroundColor Cyan
}

Write-Host ""
Write-Host "[+] Audit policy configuration complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Key events now enabled:" -ForegroundColor Yellow
Write-Host "  - Logon/Logoff (4624, 4625, 4634, 4647)" -ForegroundColor White
Write-Host "  - Lock/Unlock (4800, 4801)" -ForegroundColor White
Write-Host "  - Process Creation (4688) with command line" -ForegroundColor White
Write-Host "  - Account Lockout (4740)" -ForegroundColor White
Write-Host "  - Special Logon (4672)" -ForegroundColor White
Write-Host ""
Write-Host "Note: Some events may require additional GPO or local policy configuration." -ForegroundColor Yellow
Write-Host "For domain environments, configure via Group Policy for consistent deployment." -ForegroundColor Yellow

