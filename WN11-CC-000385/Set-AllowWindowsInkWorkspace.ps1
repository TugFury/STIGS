<#
.SYNOPSIS
    This PowerShell script ensures that Customer Features are Disabled.
    Enforces "Allow Windows Ink Workspace" (AllowWindowsInkWorkspace = 1)

.NOTES
    Author          : Jason Morrissette
    LinkedIn        : https://www.linkedin.com/in/jasonmorrissette/
    GitHub          : https://github.com/TugFury
    Date Created    : 2025-12-03
    Last Modified   : 2025-12-03
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000197

.TESTED ON
    Date(s) Tested  : 2025-12-03
    Tested By       : Jason Morrissette
    Systems Tested  : 1
    PowerShell Ver. : 5.1.26100.7019

.USAGE
    Save as e.g. Set-DisableHTTPPrinting.ps1.
    Run PowerShell as Administrator.
    Execute:

    Set-ExecutionPolicy RemoteSigned -Scope Process
    .\Set-AllowWindowsInkWorkspace.ps1
   
    Should Return:
    AllowWindowsInkWorkspace : 1
#>

# Must be run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$regPath     = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'
$valueName   = 'AllowWindowsInkWorkspace'
$desiredValue = 1

# Ensure registry key exists
if (-not (Test-Path -Path $regPath)) {
    Write-Host "Registry path not found — creating $regPath ..."
    New-Item -Path $regPath -Force | Out-Null
}

# Create/Update DWORD value
Write-Host "Applying STIG — setting $valueName to $desiredValue ..."
New-ItemProperty -Path $regPath `
                 -Name $valueName `
                 -PropertyType DWord `
                 -Value $desiredValue `
                 -Force | Out-Null

# Verification
$current = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop).$valueName

Write-Host ("Current value of {0} = {1}" -f $valueName, $current)

if ($current -eq $desiredValue) {
    Write-Host "✔ STIG WN11-CC-000385 applied successfully — Windows Ink restricted above lock." -ForegroundColor Green
    exit 0
}
else {
    Write-Warning "❌ Value did not apply — check permissions."
    exit 2
}