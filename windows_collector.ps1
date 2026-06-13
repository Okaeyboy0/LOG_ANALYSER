$ComputerName = $env:COMPUTERNAME

$DefenderStatus = Get-Service -Name WinDefend -ErrorAction SilentlyContinue

$LocalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

$RunningProcesses = Get-Process | Select-Object -First 20 -ExpandProperty ProcessName

$Data = @{
    ComputerName = $ComputerName
    DefenderStatus = $DefenderStatus.Status.ToString()
    LocalAdmins = $LocalAdmins
    RunningProcesses = $RunningProcesses
}

$Data | ConvertTo-Json -Depth 3 | Out-File "windows_security_data.json" -Encoding utf8