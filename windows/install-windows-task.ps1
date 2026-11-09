param(
    [string]$BinaryPath = "$env:LOCALAPPDATA\Programs\Sockcast\sockcast-tray.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $BinaryPath)) {
    $ScriptLocal = Join-Path (Split-Path -Parent $PSScriptRoot) "sockcast-tray.exe"
    if (Test-Path $ScriptLocal) {
        $BinaryPath = $ScriptLocal
    } else {
        $Resolved = Get-Command sockcast-tray.exe -ErrorAction SilentlyContinue
        if ($Resolved) {
            $BinaryPath = $Resolved.Source
        } else {
            Write-Error "sockcast-tray.exe not found at $BinaryPath or in PATH."
        }
    }
}

$TaskName = "SockcastClient"
# sockcast-tray.exe is compiled with windows_subsystem = "windows", so it runs natively in the system tray with zero console window.
$Action = New-ScheduledTaskAction -Execute $BinaryPath
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description "Sockcast Roaming SSH Agent Workstation System Tray" -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "Registered and started Windows Scheduled Task '$TaskName' using tray binary: $BinaryPath"
