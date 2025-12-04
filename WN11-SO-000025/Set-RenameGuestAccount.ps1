<#
.SYNOPSIS
     Enforces STIG WN11-00-000175 by disabling the Secondary Logon service.

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

$oldGuestName = 'Guest'
$newGuestName = 'LocalGst_01'   # <-- change this if you want a different name

Write-Host "Checking for local account named '$oldGuestName'..."

try {
    $guest = Get-LocalUser -Name $oldGuestName -ErrorAction Stop
}
catch {
    Write-Warning "No local user named '$oldGuestName' was found. Nothing to rename."
    exit 0
}

# Check if target name already exists
if (Get-LocalUser -Name $newGuestName -ErrorAction SilentlyContinue) {
    Write-Error "A local user named '$newGuestName' already exists. Choose a different value for `\$newGuestName`."
    exit 2
}

Write-Host "Renaming '$oldGuestName' to '$newGuestName'..."
Rename-LocalUser -Name $oldGuestName -NewName $newGuestName

# Verification
$verify = Get-LocalUser -Name $newGuestName -ErrorAction SilentlyContinue

if ($null -ne $verify) {
    Write-Host "✔ STIG WN11-SO-000025 applied successfully — Guest account renamed to '$newGuestName'." -ForegroundColor Green
    exit 0
}
else {
    Write-Warning "❌ Verification failed — could not find account '$newGuestName' after rename."
    exit 3
}
