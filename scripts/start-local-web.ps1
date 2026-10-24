[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int]$ApiPort = 8000,
    [ValidateRange(1, 65535)]
    [int]$FrontendPort = 4174,
    [switch]$DryRun
)

$projectRoot = Split-Path -Parent $PSScriptRoot
$frontendRoot = Join-Path $projectRoot "frontend-v2"

function Assert-PortAvailable([int]$Port) {
    $listener = Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort $Port -State Listen `
        -ErrorAction SilentlyContinue
    if ($listener) {
        throw "Port $Port is already in use. Choose a different port; this script will not stop existing services."
    }
}

Assert-PortAvailable $ApiPort
Assert-PortAvailable $FrontendPort

$python = (Get-Command python -ErrorAction Stop).Source
$npm = (Get-Command npm.cmd -ErrorAction Stop).Source
$apiArguments = @("-m", "uvicorn", "api.server:app", "--host", "127.0.0.1", "--port", "$ApiPort")
$frontendArguments = @("run", "dev", "--", "--host", "127.0.0.1", "--port", "$FrontendPort")

if ($DryRun) {
    Write-Output "API: $python $($apiArguments -join ' ')"
    Write-Output "Frontend: VITE_API_PROXY_TARGET=http://127.0.0.1:$ApiPort $npm $($frontendArguments -join ' ')"
    exit 0
}

$apiProcess = Start-Process -FilePath $python -ArgumentList $apiArguments -WorkingDirectory $projectRoot `
    -WindowStyle Hidden -PassThru

$previousProxyTarget = $env:VITE_API_PROXY_TARGET
$env:VITE_API_PROXY_TARGET = "http://127.0.0.1:$ApiPort"
try {
    $frontendProcess = Start-Process -FilePath $npm -ArgumentList $frontendArguments `
        -WorkingDirectory $frontendRoot -WindowStyle Hidden -PassThru
} finally {
    $env:VITE_API_PROXY_TARGET = $previousProxyTarget
}

Write-Output "API started: http://127.0.0.1:$ApiPort (PID $($apiProcess.Id))"
Write-Output "Frontend started: http://127.0.0.1:$FrontendPort (PID $($frontendProcess.Id))"
Write-Output "API state: $projectRoot\.vibe-sec\api-state.sqlite3"
