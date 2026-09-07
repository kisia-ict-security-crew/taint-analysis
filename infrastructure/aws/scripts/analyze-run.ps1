param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [ValidateRange(30, 3600)][int]$WaitSeconds = 900,
    [ValidateRange(5, 300)][int]$PollSeconds = 15,
    [string]$TerraformDir = (Split-Path $PSScriptRoot -Parent)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$analysisScript = Join-Path (Join-Path $TerraformDir "analysis") "analyze_aws_run.py"
if (-not (Test-Path -LiteralPath $analysisScript)) {
    throw "Analysis script not found: $analysisScript"
}

$resolvedManifest = (Resolve-Path -LiteralPath $ManifestPath).Path
& python $analysisScript `
    --manifest $resolvedManifest `
    --terraform-dir $TerraformDir `
    --wait-seconds $WaitSeconds `
    --poll-seconds $PollSeconds

if ($LASTEXITCODE -ne 0) {
    throw "Taint analysis failed with exit code $LASTEXITCODE."
}

$runDir = Split-Path -Parent $resolvedManifest
Write-Host "CEM:       $(Join-Path $runDir 'cem.json')"
Write-Host "Analysis:  $(Join-Path $runDir 'taint-analysis.json')"
Write-Host "Trace:     $(Join-Path $runDir 'taint-trace.md')"
