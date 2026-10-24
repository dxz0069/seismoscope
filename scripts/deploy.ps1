[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int]$Port = 8000,
    [string]$ProjectsPath = "",
    [string]$LlmSecretFile = "",
    [switch]$Build,
    [switch]$Detach,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker CLI is required. Install Docker Desktop or Docker Engine first."
}

if (-not $ProjectsPath) {
    $ProjectsPath = Join-Path $root "projects"
}
$ProjectsPath = (Resolve-Path $ProjectsPath -ErrorAction SilentlyContinue).Path
if (-not $ProjectsPath) {
    $ProjectsPath = Join-Path $root "projects"
    if (-not $DryRun) {
        New-Item -ItemType Directory -Path $ProjectsPath -Force | Out-Null
        $ProjectsPath = (Resolve-Path $ProjectsPath).Path
    }
}

if ($LlmSecretFile) {
    $secret = (Resolve-Path $LlmSecretFile -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath $secret -PathType Leaf)) {
        throw "LLM secret path is not a file"
    }
}

$composeFiles = @("-f", (Join-Path $root "compose.yml"))
if ($LlmSecretFile) {
    $composeFiles += @("-f", (Join-Path $root "compose.llm.yml"))
}
$upArgs = @("compose", "--project-directory", $root) + $composeFiles + @("up")
if ($Build) {
    $upArgs += "--build"
}
if ($Detach) {
    $upArgs += "--detach"
}

if ($DryRun) {
    Write-Output ("docker " + ($upArgs -join " "))
    return
}

$oldPort = $env:VIBE_SEC_HTTP_PORT
$oldProjects = $env:VIBE_SEC_PROJECTS_PATH
$oldSecret = $env:VIBE_SEC_DEEPSEEK_API_KEY_FILE
try {
    $env:VIBE_SEC_HTTP_PORT = "$Port"
    $env:VIBE_SEC_PROJECTS_PATH = $ProjectsPath
    if ($LlmSecretFile) {
        $env:VIBE_SEC_DEEPSEEK_API_KEY_FILE = $secret
    }
    & docker @upArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose deployment failed with exit code $LASTEXITCODE"
    }
    Write-Output "Vibe Sec is available at http://localhost:$Port"
    Write-Output "Audited projects are mounted at /workspace inside the containers."
} finally {
    $env:VIBE_SEC_HTTP_PORT = $oldPort
    $env:VIBE_SEC_PROJECTS_PATH = $oldProjects
    $env:VIBE_SEC_DEEPSEEK_API_KEY_FILE = $oldSecret
}
