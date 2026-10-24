param(
    [switch]$IncludeCodeQL,
    [switch]$SkipImages
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$venv = Join-Path $root ".venv"
$python = Join-Path $venv "Scripts\python.exe"
$vibeSec = Join-Path $venv "Scripts\vibe-sec.exe"

if (-not (Test-Path -LiteralPath $python)) {
    & python -m venv $venv
}
& $python -m pip install --disable-pip-version-check -e $root
if ($SkipImages) {
    & $vibeSec doctor --json
}
elseif ($IncludeCodeQL) {
    & $vibeSec setup --include-codeql --json
}
else {
    & $vibeSec setup --json
}
if ($LASTEXITCODE -ne 0) {
    throw "Vibe Sec setup did not complete"
}
