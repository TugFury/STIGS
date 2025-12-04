<#
.SYNOPSIS
     Enforces STIG WN11-00-000175 by disabling the Secondary Logon service.

.DESCRIPTION
    Configures the Secondary Logon (seclogon) service to Disabled and stops it
    if it is currently running. This prevents users from running elevated 
    commands using alternate credentials inside normal sessions.

.NOTES
    Author          : Jason Morrissette
    LinkedIn        : https://www.linkedin.com/in/jasonmorrissette/
    GitHub          : https://github.com/TugFury
    Date Created    : 2025-12-03
    Last Modified   : 2025-12-03
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-OO-000175

.TESTED ON
    Date(s) Tested  : 2025-12-03
    Tested By       : Jason Morrissette
    Systems Tested  : 1
    PowerShell Ver. : 5.1.26100.7019

.USAGE
    Save this script as e.g. Set-DisableSecondaryLogon.ps1.
    Run PowerShell as Administrator.
    
    Execute:
    cd C:\STIG-Scripts
     .\Set-DisableSecondaryLogon.ps1
    
     to verify the change, run after reboot: 
     Get-Service seclogon
    (Get-WmiObject -Class Win32_Service -Filter "Name='seclogon'").StartMode
#>

# Must be run as Administrator
try {
    $svc = Get-Service -Name $serviceName -ErrorAction Stop

    if ($svc.Status -eq "Running") {
        Write-Host "Attempting to stop service..."
        try {
            Stop-Service -Name $serviceName -Force -ErrorAction Stop
            Write-Host "Service stopped successfully."
        }
        catch {
            Write-Warning "Could not stop service '$serviceName'. It may require a reboot to fully stop."
        }
    }

    # Set startup type to Disabled
    Write-Host "Disabling service startup..."
    Set-Service -Name $serviceName -StartupType Disabled
}
catch {
    Write-Error "The service '$serviceName' was not found or could not be accessed."
    exit 2
}

# Verification section
$verifyService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
$verifyWmi     = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'"

Write-Host ""
Write-Host "Verification:"
Write-Host "  Status      = $($verifyService.Status)"
Write-Host "  StartupType = $($verifyWmi.StartMode)"

if ($verifyWmi.StartMode -eq "Disabled") {
    if ($verifyService.Status -eq "Stopped") {
        Write-Host "✔ STIG WN11-00-000175 applied successfully — Secondary Logon disabled and stopped." -ForegroundColor Green
    }
    else {
        Write-Host "✔ Startup type is Disabled. A reboot may be required for the service to fully stop." -ForegroundColor Yellow
    }
    exit 0
}
else {
    Write-Warning "❌ Validation failed — service startup type is not Disabled."
    exit 3
}
