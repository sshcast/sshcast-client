param(
    [string]$BinaryPath = "$env:LOCALAPPDATA\Programs\Sockcast\sockcast-client.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $BinaryPath)) {
    $Resolved = Get-Command sockcast-client.exe -ErrorAction SilentlyContinue
    if ($Resolved) {
        $BinaryPath = $Resolved.Source
    } else {
        Write-Error "sockcast-client.exe not found at $BinaryPath or in PATH."
    }
}

$TaskName = "SockcastClient"
# Use WScript.Shell via VBScript or PowerShell hidden window wrapper so the background agent runs without a console window
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -Command `"& '$BinaryPath' run`""
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description "Sockcast Roaming SSH Agent Workstation Client" -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "Registered and started Windows Scheduled Task '$TaskName' using binary: $BinaryPath"
