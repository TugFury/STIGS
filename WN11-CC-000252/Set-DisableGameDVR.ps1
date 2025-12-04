<#
.SYNOPSIS
    Enforces STIG WN11-CC-000252 by disabling Windows Game Recording and Broadcasting.

.DESCRIPTION
    This script applies the DISA STIG requirement that prevents Windows Game DVR functionality
    from capturing screenshots or recording screen content by configuring:
    HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR\AllowGameDVR = 0
.

.NOTES
    Author          : Jason Morrissette
    LinkedIn        : https://www.linkedin.com/in/jasonmorrissette/
    GitHub          : https://github.com/TugFury
    Date Created    : 2025-12-03
    Last Modified   : 2025-12-03
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000252

.TESTED ON
    Date(s) Tested  : 2025-12-03
    Tested By       : Jason Morrissette
    Systems Tested  : 1
    PowerShell Ver. : 5.1.26100.7019

.USAGE
    Save this script as e.g. Set-DisableGameDVR.ps1.
    Run PowerShell as Administrator.
    
    Execute:
    cd C:\STIG-Scripts
     .\Set-DisableGameDVR.ps1
    
#>

# Must be run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$regPath      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'
$valueName    = 'AllowGameDVR'
$desiredValue = 0

# Ensure registry path exists
if (-not (Test-Path -Path $regPath)) {
    Write-Host "Registry path not found — creating $regPath ..."
    New-Item -Path $regPath -Force | Out-Null
}

# Apply setting
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
    Write-Host "✔ STIG WN11-CC-000252 applied successfully — Game Recording and Broadcasting disabled." -ForegroundColor Green
    exit 0
}
else {
    Write-Warning "❌ Validation failed — check registry permissions."
    exit 2
}