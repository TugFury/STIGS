<#
.SYNOPSIS
    Enforces STIG WN11-CC-000305 by disabling indexing of encrypted files.
    Applies the registry value AllowIndexingEncryptedStoresOrItems = 0 to prevent exposure of sensitive encrypted data.

.NOTES
    Author          : Jason Morrissette
    LinkedIn        : https://www.linkedin.com/in/jasonmorrissette/
    GitHub          : https://github.com/TugFury
    Date Created    : 2025-12-03
    Last Modified   : 2025-12-03
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000305

.TESTED ON
    Date(s) Tested  : 2025-12-03
    Tested By       : Jason Morrissette
    Systems Tested  : 1
    PowerShell Ver. : 5.1.26100.7019

.USAGE
    Save this script as e.g. Set-DisableEncryptedIndexing.ps1.
    Run PowerShell as Administrator.
    
    Execute:
    Set-ExecutionPolicy RemoteSigned -Scope Process
    .\Set-DisableEncryptedIndexing.ps1

    Verification should return:
    AllowIndexingEncryptedStoresOrItems : 0
#>

# Must be run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$regPath      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
$valueName    = 'AllowIndexingEncryptedStoresOrItems'
$desiredValue = 0

# Ensure registry path exists
if (-not (Test-Path -Path $regPath)) {
    Write-Host "Registry path not found — creating $regPath ..."
    New-Item -Path $regPath -Force | Out-Null
}

# Apply DWORD value
Write-Host "Applying STIG — setting $valueName to $desiredValue ..."
New-ItemProperty -Path $regPath `
                 -Name $valueName `
                 -PropertyType DWord `
                 -Value $desiredValue `
                 -Force | Out-Null

# Verify result
$current = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop).$valueName

Write-Host ("Current value of {0} = {1}" -f $valueName, $current)

if ($current -eq $desiredValue) {
    Write-Host "✔ STIG WN11-CC-000305 applied successfully — encrypted file indexing disabled." -ForegroundColor Green
    exit 0
}
else {
    Write-Warning "❌ Value did not apply — check permissions."
    exit 2
}