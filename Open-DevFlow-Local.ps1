param([switch]$NoBrowser)
$ErrorActionPreference = 'Stop'
$projectFolder = $PSScriptRoot
$pythonPath = Join-Path $projectFolder '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) { throw 'Install dependencies using START_HERE.txt first.' }
if ($env:DEVFLOW_ENTERPRISE_MODE -eq '1') { throw 'Use the enterprise deployment instead of local owner mode.' }
$listeners = @(Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue)
foreach ($serverId in @($listeners | Select-Object -ExpandProperty OwningProcess -Unique)) {
    $serverInfo = Get-CimInstance Win32_Process -Filter "ProcessId=$serverId"
    $commandLine = [string]$serverInfo.CommandLine
    if ($commandLine.IndexOf($projectFolder, [StringComparison]::OrdinalIgnoreCase) -lt 0 -or $commandLine -notmatch '(run|local_owner_access)\.py') {
        throw 'Another service owns port 8000; it was not stopped.'
    }
    Stop-Process -Id $serverId
}
$env:DEVFLOW_DB = Join-Path $projectFolder 'data\devflow.sqlite3'
$env:DEVFLOW_PUBLIC_OWNER_MODE = '0'
$dataFolder = Join-Path $projectFolder 'data'
New-Item -ItemType Directory -Path $dataFolder -Force | Out-Null
$launchId = [Guid]::NewGuid().ToString('N')
$outputLog = Join-Path $dataFolder ("owner-start-$launchId.log")
$errorLog = Join-Path $dataFolder ("owner-error-$launchId.log")
Start-Process -FilePath $pythonPath -ArgumentList @('run.py') -WorkingDirectory $projectFolder -WindowStyle Hidden -RedirectStandardOutput $outputLog -RedirectStandardError $errorLog | Out-Null
$ready = $false
for ($attempt = 0; $attempt -lt 40; $attempt++) {
    try {
        $ownerStatus = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/owner/status' -TimeoutSec 1
        if ($ownerStatus.enabled -and $ownerStatus.owner_email -eq 'bhuvanjakkula@gmail.com') { $ready = $true; break }
    } catch {}
    Start-Sleep -Milliseconds 250
}
if (-not $ready) { throw "DevFlow failed to start. Check $errorLog" }
$match = [regex]::Match((Get-Content -LiteralPath $outputLog -Raw), 'http://127\.0\.0\.1:8000/owner/enter\?token=[A-Za-z0-9_-]+')
if (-not $match.Success) { throw 'A fresh owner link could not be read from the local launcher.' }
$ownerLink = $match.Value.Replace('/owner/enter?', '/owner/confirm?')
if (-not $NoBrowser) { Start-Process -FilePath $ownerLink }
Write-Output $ownerLink
