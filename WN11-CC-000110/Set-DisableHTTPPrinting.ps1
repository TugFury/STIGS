<#
.SYNOPSIS
    This PowerShell script ensures that Printing over HTTP is prevented.
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
    STIG-ID         : WN11-CC-000110

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Save as e.g. Set-DisableHTTPPrinting.ps1.
    Run PowerShell as Administrator.
    Execute:

    Set-ExecutionPolicy RemoteSigned -Scope Process
    .\Set-DisableHTTPPrinting.ps1
   
    Verifying the fix
    Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name DisableHTTPPrinting

    Should Return:
    DisableHTTPPrinting : 1
#>

# Must be run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
$valueName = 'DisableHTTPPrinting'
$desiredValue = 1

# Ensure the registry key exists
if (-not (Test-Path -Path $regPath)) {
    Write-Host "Registry path not found. Creating: $regPath"
    New-Item -Path $regPath -Force | Out-Null
}

# Create or update the DWORD value
Write-Host "Setting $valueName to $desiredValue under $regPath"
New-ItemProperty -Path $regPath `
                 -Name $valueName `
                 -PropertyType DWord `
                 -Value $desiredValue `
                 -Force | Out-Null

# Confirm the final value
$current = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop
Write-Host "Current value of $valueName = $($current.$valueName)"

if ($current.$valueName -eq $desiredValue) {
    Write-Host "✅ STIG setting applied successfully (HTTP printing disabled)." -ForegroundColor Green
}
else {
    Write-Warning "⚠ Value did not apply as expected. Check permissions and retry."
}