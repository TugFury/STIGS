<#
.SYNOPSIS
   Enforces STIG WN11-SO-000025 by renaming the built-in Guest account.

.DESCRIPTION
    Renames the local built-in Guest account to a non-default name to reduce the risk of
    unauthorized access. This aligns with the Security Option:
    "Accounts: Rename guest account".

.NOTES
    Author          : Jason Morrissette
    LinkedIn        : https://www.linkedin.com/in/jasonmorrissette/
    GitHub          : https://github.com/TugFury
    Date Created    : 2025-12-03
    Last Modified   : 2025-12-03
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000025

.TESTED ON
    Date(s) Tested  : 2025-12-03
    Tested By       : Jason Morrissette
    Systems Tested  : 1
    PowerShell Ver. : 5.1.26100.7019

.USAGE
    Save this script as e.g. Set-RenameGuestAccount.ps1.
    Run PowerShell as Administrator.
    
    Execute:
    cd C:\STIG-Scripts
     .\Set-RenameGuestAccount.ps1
    
#>

# Must be run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

Write-Host "Applying STIG — enabling Failure auditing for Process Creation..." 

# Set audit policy (Failure enabled; Success left unchanged)
auditpol.exe /set /subcategory:"Process Creation" /failure:enable

# Read back the current setting
$current = auditpol.exe /get /subcategory:"Process Creation"

Write-Host "Current audit setting for Process Creation:"
Write-Host $current

# Validation: treat 'Failure' or 'Success and Failure' as compliant
if ($current -match "Process Creation\s+Failure" -or
    $current -match "Process Creation\s+Success and Failure") {

    Write-Host "✔ STIG WN11-AU-000585 applied successfully — Failure auditing enabled for Process Creation." -ForegroundColor Green
    exit 0
}
else {
    Write-Warning "❌ Validation check failed — please review auditpol output manually."
    exit 2
}