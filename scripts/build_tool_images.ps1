param(
    [switch]$SkipBase,
    [switch]$SkipTrivy,
    [switch]$SkipCodeQL,
    [switch]$SkipNuclei,
    [switch]$KeepDownloads
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Get-VerifiedArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Sha256
    )
    $directory = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    if (Test-Path -LiteralPath $Destination) {
        $existing = (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash.ToLowerInvariant()
        if ($existing -eq $Sha256.ToLowerInvariant()) {
            return
        }
    }
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        & $curl.Source --location --fail --retry 3 --retry-delay 2 --ssl-no-revoke `
            --continue-at - --output $Destination $Uri
        if ($LASTEXITCODE -ne 0) {
            throw "Download or resume failed for $Uri; partial cache was preserved"
        }
    }
    else {
        Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $Destination
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256.ToLowerInvariant()) {
        Remove-Item -LiteralPath $Destination -Force
        throw "Checksum mismatch for $Uri. Expected $Sha256, received $actual"
    }
}

function Invoke-DockerBuild {
    param([string]$Tag, [string]$Context)
    & docker build --progress=plain -t $Tag $Context
    if ($LASTEXITCODE -ne 0) {
        throw "Docker build failed for $Tag"
    }
}

$nucleiCache = Join-Path $root "container\nuclei\.build-cache\nuclei.zip"
$codeqlCache = Join-Path $root "container\codeql\.build-cache\codeql.zip"

try {
    if (-not $SkipBase) {
        Invoke-DockerBuild "vibe-sec-tools:latest" (Join-Path $root "container\security-tools")
    }
    if (-not $SkipTrivy) {
        Invoke-DockerBuild "vibe-sec-trivy:latest" (Join-Path $root "container\trivy")
    }
    if (-not $SkipNuclei) {
        Get-VerifiedArtifact `
            -Uri "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.0/nuclei_3.11.0_linux_amd64.zip" `
            -Destination $nucleiCache `
            -Sha256 "dc238d6040813e14fc30514dac5a2eb1b430c694f3ca99eee2a5097e55076283"
        Invoke-DockerBuild "vibe-sec-nuclei:latest" (Join-Path $root "container\nuclei")
    }
    if (-not $SkipCodeQL) {
        Get-VerifiedArtifact `
            -Uri "https://github.com/github/codeql-cli-binaries/releases/download/v2.26.1/codeql-linux64.zip" `
            -Destination $codeqlCache `
            -Sha256 "15480dda6e20336a9c7ddcb6171e0e9155f1fe73a1d31baeac153821cb89aeab"
        Invoke-DockerBuild "vibe-sec-codeql:latest" (Join-Path $root "container\codeql")
    }
}
finally {
    if (-not $KeepDownloads) {
        foreach ($path in @($nucleiCache, $codeqlCache)) {
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Force
            }
        }
    }
}
