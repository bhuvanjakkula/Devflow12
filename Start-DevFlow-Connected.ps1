$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$env:GIT_TERMINAL_PROMPT = '0'
$env:GCM_INTERACTIVE = 'Never'
$credentialLines = "protocol=https`nhost=github.com`n`n" | git -c credential.interactive=never credential fill 2>$null
$credentialEntry = $credentialLines | Where-Object { $_ -match '^password=' } | Select-Object -First 1
if (-not $credentialEntry) { throw 'Sign in to GitHub through Git first, or configure a read-only CI token locally.' }
$env:DEVFLOW_CI_REPOSITORY = 'bhuvanjakkula/DevFlow'
$env:DEVFLOW_CI_WORKFLOW = '.github/workflows/tests.yml'
$env:DEVFLOW_CI_BRANCH = 'main'
$env:DEVFLOW_CI_TOKEN = $credentialEntry.Substring(9)
try { python run.py } finally { Remove-Item Env:DEVFLOW_CI_TOKEN -ErrorAction SilentlyContinue }
