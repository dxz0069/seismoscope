[CmdletBinding()]
param([string]$Output = "")

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $Output) { $Output = Join-Path (Split-Path $root -Parent) "vibe-sec-platform-delivery.zip" }
$exclude = @(
    "--exclude=.git", "--exclude=.venv", "--exclude=node_modules", "--exclude=*/node_modules/*",
    "--exclude=dist", "--exclude=*/dist/*", "--exclude=.cache", "--exclude=.lab-cache",
    "--exclude=.tmp-session", "--exclude=.vibe-sec", "--exclude=__pycache__", "--exclude=*/__pycache__/*",
    "--exclude=.pytest_cache", "--exclude=pytest-cache-files-*", "--exclude=.ruff_cache", "--exclude=test-results",
    "--exclude=test-results-v3", "--exclude=test-results-vampi", "--exclude=report-assets",
    "--exclude=ppt-draft", "--exclude=frontend-v2.zip", "--exclude=vibe_sec_platform.egg-info",
    "--exclude=*.png", "--exclude=*.sqlite3", "--exclude=*.db", "--exclude=*.key", "--exclude=*.pem",
    "--exclude=key.txt", "--exclude=*.docx"
)
if (Test-Path -LiteralPath $Output) { Remove-Item -LiteralPath $Output -Force }
$tarArgs = @("-a", "-c", "-f", $Output, "-C", $root) + $exclude + @(".")
& tar @tarArgs
if ($LASTEXITCODE -ne 0) { throw "tar source packaging failed with exit code $LASTEXITCODE" }
Write-Output "Created source delivery package: $Output"
