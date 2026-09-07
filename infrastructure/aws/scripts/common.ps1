Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-UtcTimestamp {
    return [DateTimeOffset]::UtcNow.ToString("o")
}

function Invoke-JsonCommand {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$AllowEmpty
    )

    $output = & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code ${LASTEXITCODE}: $($Arguments -join ' ')"
    }

    $text = ($output | Out-String).Trim()
    if ($text.Length -eq 0) {
        if ($AllowEmpty) { return $null }
        throw "$FilePath returned no JSON output: $($Arguments -join ' ')"
    }

    return $text | ConvertFrom-Json
}

function Invoke-AwsJson {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $fullArguments = @($Arguments) + @("--output", "json", "--no-cli-pager")
    return Invoke-JsonCommand -FilePath "aws" -Arguments $fullArguments
}

function Get-LabConfig {
    param([Parameter(Mandatory)][string]$TerraformDir)

    Push-Location $TerraformDir
    try {
        $outputs = Invoke-JsonCommand -FilePath "terraform" -Arguments @("output", "-json")
    }
    finally {
        Pop-Location
    }

    return [pscustomobject]@{
        roles                = $outputs.research_role_arns.value
        buckets              = $outputs.experiment_buckets.value
        data_seed_uri        = $outputs.data_seed_s3_uri.value
        critical_object_uri  = $outputs.critical_object_s3_uri.value
        honeytoken_secret_arn = $outputs.honeytoken_secret_arn.value
        cloudwatch_log_group = $outputs.cloudwatch_log_group.value
        account_id           = ($outputs.research_role_arns.value.actor_a -split ":")[4]
    }
}

function Get-S3KeyFromUri {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Bucket
    )

    $prefix = "s3://$Bucket/"
    if (-not $Uri.StartsWith($prefix, [StringComparison]::Ordinal)) {
        throw "S3 URI '$Uri' does not belong to bucket '$Bucket'."
    }
    return $Uri.Substring($prefix.Length)
}

function Save-CredentialEnvironment {
    return [ordered]@{
        AWS_ACCESS_KEY_ID     = [Environment]::GetEnvironmentVariable("AWS_ACCESS_KEY_ID", "Process")
        AWS_SECRET_ACCESS_KEY = [Environment]::GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY", "Process")
        AWS_SESSION_TOKEN     = [Environment]::GetEnvironmentVariable("AWS_SESSION_TOKEN", "Process")
        AWS_PROFILE           = [Environment]::GetEnvironmentVariable("AWS_PROFILE", "Process")
    }
}

function Restore-CredentialEnvironment {
    param([Parameter(Mandatory)]$Snapshot)

    foreach ($name in $Snapshot.Keys) {
        if ($null -eq $Snapshot[$name] -or [string]$Snapshot[$name] -eq "") {
            Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
        }
        else {
            Set-Item -LiteralPath "Env:$name" -Value ([string]$Snapshot[$name])
        }
    }
}

function Use-AwsSession {
    param([Parameter(Mandatory)]$Credentials)

    # An empty AWS_PROFILE is still interpreted by AWS CLI as a profile named "".
    # Remove it from the process environment before installing session credentials.
    Remove-Item -LiteralPath "Env:AWS_PROFILE" -ErrorAction SilentlyContinue
    Set-Item -LiteralPath "Env:AWS_ACCESS_KEY_ID" -Value ([string]$Credentials.AccessKeyId)
    Set-Item -LiteralPath "Env:AWS_SECRET_ACCESS_KEY" -Value ([string]$Credentials.SecretAccessKey)
    Set-Item -LiteralPath "Env:AWS_SESSION_TOKEN" -Value ([string]$Credentials.SessionToken)
}

function Assume-LabRole {
    param(
        [Parameter(Mandatory)][string]$RoleArn,
        [Parameter(Mandatory)][string]$SessionName,
        [string]$SourceIdentity = ""
    )

    $arguments = @("sts", "assume-role", "--role-arn", $RoleArn, "--role-session-name", $SessionName)
    if ($SourceIdentity.Length -gt 0) {
        $arguments += @("--source-identity", $SourceIdentity)
    }
    return Invoke-AwsJson -Arguments $arguments
}

function New-RunManifest {
    param(
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$Scenario,
        [Parameter(Mandatory)][string]$OutputDir,
        [Parameter(Mandatory)]$BaseCaller
    )

    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    return [pscustomobject]@{
        schema_version   = "1.0"
        run_id           = $RunId
        scenario         = $Scenario
        status           = "RUNNING"
        started_at       = Get-UtcTimestamp
        ended_at         = $null
        base_caller_arn  = $BaseCaller.Arn
        account_id       = $BaseCaller.Account
        steps            = [System.Collections.Generic.List[object]]::new()
        expected_events  = [System.Collections.Generic.List[object]]::new()
        forbidden_events = [System.Collections.Generic.List[object]]::new()
        error            = $null
        manifest_path    = Join-Path $OutputDir "manifest.json"
    }
}

function Save-RunManifest {
    param([Parameter(Mandatory)]$Manifest)

    $Manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Manifest.manifest_path -Encoding UTF8
}

function Add-ExpectedEvent {
    param(
        [Parameter(Mandatory)]$Manifest,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Rule,
        [Parameter(Mandatory)][string[]]$MatchAll
    )

    $Manifest.expected_events.Add([pscustomobject]@{
        id        = $Id
        rule      = $Rule
        match_all = @($MatchAll)
    }) | Out-Null
}

function Add-ForbiddenEvent {
    param(
        [Parameter(Mandatory)]$Manifest,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string[]]$MatchAll
    )

    $Manifest.forbidden_events.Add([pscustomobject]@{
        id        = $Id
        match_all = @($MatchAll)
    }) | Out-Null
}

function Invoke-TrackedStep {
    param(
        [Parameter(Mandatory)]$Manifest,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    $startedAt = Get-UtcTimestamp
    $status = "SUCCESS"
    $errorText = $null
    try {
        return & $Action
    }
    catch {
        $status = "FAILED"
        $errorText = $_.Exception.Message
        throw
    }
    finally {
        $Manifest.steps.Add([pscustomobject]@{
            name       = $Name
            started_at = $startedAt
            ended_at   = Get-UtcTimestamp
            status     = $status
            error      = $errorText
        }) | Out-Null
        Save-RunManifest -Manifest $Manifest
    }
}

function Test-AllMarkers {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][object[]]$Markers
    )

    foreach ($marker in $Markers) {
        if ($Text.IndexOf([string]$marker, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            return $false
        }
    }
    return $true
}
