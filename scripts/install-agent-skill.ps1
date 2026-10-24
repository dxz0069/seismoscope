[CmdletBinding()]
param(
    [ValidateSet("codex", "claude-code", "project")]
    [string]$Agent = "codex",
    [string]$Destination = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$sourceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$source = Join-Path $sourceRoot "skill"
if (-not (Test-Path (Join-Path $source "SKILL.md") -PathType Leaf)) {
    throw "The repository skill entrypoint is missing: $source"
}

if (-not $Destination) {
    switch ($Agent) {
        "codex" {
            $agentHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE ".codex" }
            $Destination = Join-Path $agentHome "skills\vibe-sec"
        }
        "claude-code" {
            $agentHome = if ($env:CLAUDE_CONFIG_DIR) { $env:CLAUDE_CONFIG_DIR } else { Join-Path $env:USERPROFILE ".claude" }
            $Destination = Join-Path $agentHome "skills\vibe-sec"
        }
        "project" {
            $Destination = Join-Path (Get-Location).Path ".agents\skills\vibe-sec"
        }
    }
}

if ((Test-Path -LiteralPath $Destination) -and -not $Force) {
    throw "Skill destination already exists. Use -Force only after reviewing the existing installation: $Destination"
}
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
Copy-Item -Path (Join-Path $source "*") -Destination $Destination -Recurse -Force
Write-Output "Installed Vibe Sec Skill for $Agent at $Destination"
Write-Output "The Skill expects the vibe-sec CLI on PATH or the repository Docker Compose deployment."
