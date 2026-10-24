[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int]$Port = 8000,
    [string]$ProjectsPath = "",
    [ValidateSet("codex", "claude-code", "project")]
    [string]$Agent = "codex",
    [string]$LlmSecretFile = "",
    [switch]$NoBuild,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$deploy = Join-Path $root "scripts\deploy.ps1"
$installSkill = Join-Path $root "scripts\install-agent-skill.ps1"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker CLI is required. Install Docker Desktop or Docker Engine first."
}

$deployArgs = @("-Port", $Port, "-Detach")
if (-not $NoBuild) { $deployArgs += "-Build" }
if ($ProjectsPath) { $deployArgs += @("-ProjectsPath", $ProjectsPath) }
if ($LlmSecretFile) { $deployArgs += @("-LlmSecretFile", $LlmSecretFile) }
if ($DryRun) { $deployArgs += "-DryRun" }

& $deploy @deployArgs
if ($DryRun) {
    Write-Output "Skill install: $installSkill -Agent $Agent -Force"
    Write-Output "Web UI: http://localhost:$Port"
    exit 0
}

& $installSkill -Agent $Agent -Force
if ($LASTEXITCODE -ne 0) { throw "Skill installation failed" }

$healthUrl = "http://localhost:$Port/api/health"
for ($attempt = 1; $attempt -le 30; $attempt++) {
    try {
        $response = Invoke-WebRequest -Uri $healthUrl -TimeoutSec 3 -UseBasicParsing
        if ($response.StatusCode -eq 200) {
            $projectsDisplay = if ($ProjectsPath) { $ProjectsPath } else { Join-Path $root "projects" }
            Write-Output "Vibe Sec deployed and healthy."
            Write-Output "Web UI: http://localhost:$Port"
            Write-Output "Skill: $Agent (vibe-sec)"
            Write-Output "Projects mount: $projectsDisplay"
            exit 0
        }
    } catch { }
    Start-Sleep -Seconds 2
}
throw "Deployment started but API health check timed out: $healthUrl"
