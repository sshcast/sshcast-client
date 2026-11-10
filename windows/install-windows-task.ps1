param(
    [string]$BinaryPath = "$env:LOCALAPPDATA\Programs\Sshcast\sshcast-tray.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $BinaryPath)) {
    $ScriptLocal = Join-Path (Split-Path -Parent $PSScriptRoot) "sshcast-tray.exe"
    if (Test-Path $ScriptLocal) {
        $BinaryPath = $ScriptLocal
    } else {
        $Resolved = Get-Command sshcast-tray.exe -ErrorAction SilentlyContinue
        if ($Resolved) {
            $BinaryPath = $Resolved.Source
        } else {
            Write-Error "sshcast-tray.exe not found at $BinaryPath or in PATH."
        }
    }
}

$TaskName = "SshcastClient"
# sshcast-tray.exe is compiled with windows_subsystem = "windows", so it runs natively in the system tray with zero console window.
$Action = New-ScheduledTaskAction -Execute $BinaryPath
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description "Sshcast Roaming SSH Agent Workstation System Tray" -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "Registered and started Windows Scheduled Task '$TaskName' using tray binary: $BinaryPath"
