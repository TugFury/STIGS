<#
.SYNOPSIS
    Enforces STIG WN11-AU-000560 to ensure Windows audits Other Logon/Logoff Events (Success).

.DESCRIPTION
    This script configures Windows Audit Policy to enable Success auditing for Other Logon/Logoff Events
    using the auditpol command.

.NOTES
    Author          : Jason Morrissette
    LinkedIn        : https://www.linkedin.com/in/jasonmorrissette/
    GitHub          : https://github.com/TugFury
    Date Created    : 2025-12-03
    Last Modified   : 2025-12-03
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000560

.TESTED ON
    Date(s) Tested  : 2025-12-03
    Tested By       : Jason Morrissette
    Systems Tested  : 1
    PowerShell Ver. : 5.1.26100.7019

.USAGE
    Save this script as e.g. Set-DisableEncryptedIndexing.ps1.
    Run PowerShell as Administrator.
    
    Execute:
    C:\STIG-Scripts 
    .\Set-AuditOtherLogonSuccess.ps1

    
#>

# Must be run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

Write-Host "Applying STIG — enabling audit Success for Other Logon/Logoff Events..."

# Set audit policy
auditpol.exe /set /subcategory:"Other Logon/Logoff Events" /success:enable

# Validate the change
$current = auditpol.exe /get /subcategory:"Other Logon/Logoff Events"

Write-Host "Current audit setting for Other Logon/Logoff Events:"
Write-Host $current

if ($current -match "Other Logon/Logoff Events\s+Success( and Failure)?") {
    Write-Host "✔ STIG WN11-AU-000560 applied successfully — Success auditing enabled." -ForegroundColor Green
    exit 0
}
else {
    Write-Warning "❌ Validation check failed — please review auditpol output manually."
    exit 2
}
