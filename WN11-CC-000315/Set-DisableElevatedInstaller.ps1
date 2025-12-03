<#
.SYNOPSIS
    This PowerShell script ensures that Customer Features are Disabled.
    Enforces "Turn off printing over HTTP" (DisableHTTPPrinting = 1)

.NOTES
    Author          : Jason Morrissette
    LinkedIn        : https://www.linkedin.com/in/jasonmorrissette/
    GitHub          : https://github.com/TugFury
    Date Created    : 2025-12-02
    Last Modified   : 2025-12-02
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000197

.TESTED ON
    Date(s) Tested  : 2025-12-02
    Tested By       : Jason Morrissette
    Systems Tested  : 1
    PowerShell Ver. : 5.1.26100.7019

.USAGE
    Put any usage instructions here.
    Save as e.g. Set-DisableHTTPPrinting.ps1.
    Run PowerShell as Administrator.
    Execute:

    Set-ExecutionPolicy RemoteSigned -Scope Process
    .\Set-DisableWindowsConsumerFeatures.ps1
   
    Verifying the fix
    Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures'


    Should Return:
    DisableWindowsConsumerFeatures : 1
#>

# Must be run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
$valueName = 'AlwaysInstallElevated'
$desiredValue = 0

# Ensure the registry key exists
if (-not (Test-Path -Path $regPath)) {
    Write-Host "Registry path not found. Creating $regPath ..."
    New-Item -Path $regPath -Force | Out-Null
}

# Create or update the DWORD value
Write-Host "Setting $valueName to $desiredValue under $regPath ..."
New-ItemProperty -Path $regPath `
                 -Name $valueName `
                 -PropertyType DWord `
                 -Value $desiredValue `
                 -Force | Out-Null

# Confirm the final value
$current = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop
$currentValue = $current.$valueName

Write-Host ("Current value of {0} = {1}" -f $valueName, $currentValue)

if ($currentValue -eq $desiredValue) {
    Write-Host "✅ STIG DisableElevatedInstaller applied successfully (AlwaysInstallElevated disabled)." -ForegroundColor Green
    exit 0
}
else {
    Write-Warning "⚠ Value did not apply as expected. Check permissions and retry."
    exit 2
}