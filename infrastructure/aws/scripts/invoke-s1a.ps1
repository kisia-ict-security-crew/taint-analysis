param(
    [string]$TerraformDir = (Split-Path $PSScriptRoot -Parent),
    [string]$SourceIdentity = ""
)

. (Join-Path $PSScriptRoot "common.ps1")

$config = Get-LabConfig -TerraformDir $TerraformDir
$baseCaller = Invoke-AwsJson -Arguments @("sts", "get-caller-identity")
$runId = "s1a-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$runDir = Join-Path (Join-Path $TerraformDir "runs") $runId
$manifest = New-RunManifest -RunId $runId -Scenario "S1-a" -OutputDir $runDir -BaseCaller $baseCaller
$condition = if ($SourceIdentity) { "SOURCE_IDENTITY" } else { "DEFAULT" }
$manifest | Add-Member -NotePropertyName experimental_condition -NotePropertyValue $condition
$manifest | Add-Member -NotePropertyName source_identity_enabled -NotePropertyValue ([bool]$SourceIdentity)
$credentialSnapshot = Save-CredentialEnvironment
$tempFiles = [System.Collections.Generic.List[string]]::new()

$dataSeedKey = Get-S3KeyFromUri -Uri $config.data_seed_uri -Bucket $config.buckets.critical
$criticalKey = Get-S3KeyFromUri -Uri $config.critical_object_uri -Bucket $config.buckets.critical
$sessionA = "$runId-a"
$sessionB = "$runId-b"
$sessionC = "$runId-c"
$stagingKey = "runs/$runId/customer-copy.csv"
$egressKey = "runs/$runId/customer-export.csv"
$temporaryKey = "runs/$runId/unrelated-output.json"

Add-ExpectedEvent $manifest "assume-actor-a" "PROBE" @("AssumeRole", $config.roles.actor_a, $sessionA)
Add-ExpectedEvent $manifest "data-seed-read" "R1" @("GetObject", $config.buckets.critical, $dataSeedKey, $sessionA)
Add-ExpectedEvent $manifest "secret-seed-read" "R1" @("GetSecretValue", $config.honeytoken_secret_arn, $sessionA)
Add-ExpectedEvent $manifest "delegate-a-b" "R2" @("AssumeRole", $config.roles.pivot_b, $sessionA, $sessionB)
Add-ExpectedEvent $manifest "delegate-b-c" "R2" @("AssumeRole", $config.roles.pivot_c, $sessionB, $sessionC)
Add-ExpectedEvent $manifest "critical-read" "X1" @("GetObject", $config.buckets.critical, $criticalKey, $sessionC)
Add-ExpectedEvent $manifest "copy-critical-staging" "R7" @("CopyObject", $config.buckets.staging, $stagingKey, $sessionC)
Add-ExpectedEvent $manifest "copy-staging-egress" "R7" @("CopyObject", $config.buckets.egress, $egressKey, $sessionC)
Add-ExpectedEvent $manifest "unrelated-write" "CONTROL" @("PutObject", $config.buckets.staging, $temporaryKey, $sessionC)
Add-ExpectedEvent $manifest "unrelated-delete" "CONTROL" @("DeleteObject", $config.buckets.staging, $temporaryKey, $sessionC)
Save-RunManifest $manifest

try {
    $actorA = Invoke-TrackedStep $manifest "Assume ActorA" {
        Assume-LabRole -RoleArn $config.roles.actor_a -SessionName $sessionA -SourceIdentity $SourceIdentity
    }
    Use-AwsSession $actorA.Credentials

    $seedFile = [IO.Path]::GetTempFileName()
    $tempFiles.Add($seedFile) | Out-Null
    Invoke-TrackedStep $manifest "Read Data seed" {
        Invoke-AwsJson @("s3api", "get-object", "--bucket", $config.buckets.critical, "--key", $dataSeedKey, $seedFile) | Out-Null
    }

    Invoke-TrackedStep $manifest "Read Secret seed" {
        Invoke-AwsJson @("secretsmanager", "get-secret-value", "--secret-id", $config.honeytoken_secret_arn, "--query", "ARN") | Out-Null
    }

    $pivotB = Invoke-TrackedStep $manifest "Assume PivotB" {
        Assume-LabRole -RoleArn $config.roles.pivot_b -SessionName $sessionB
    }
    Use-AwsSession $pivotB.Credentials

    $pivotC = Invoke-TrackedStep $manifest "Assume PivotC" {
        Assume-LabRole -RoleArn $config.roles.pivot_c -SessionName $sessionC
    }
    Use-AwsSession $pivotC.Credentials

    $criticalFile = [IO.Path]::GetTempFileName()
    $tempFiles.Add($criticalFile) | Out-Null
    Invoke-TrackedStep $manifest "Read classified D-Taint source" {
        Invoke-AwsJson @("s3api", "get-object", "--bucket", $config.buckets.critical, "--key", $criticalKey, $criticalFile) | Out-Null
    }

    Invoke-TrackedStep $manifest "Copy critical to staging" {
        Invoke-AwsJson @("s3api", "copy-object", "--bucket", $config.buckets.staging, "--copy-source", "$($config.buckets.critical)/$criticalKey", "--key", $stagingKey) | Out-Null
    }

    Invoke-TrackedStep $manifest "Copy staging to simulated egress" {
        Invoke-AwsJson @("s3api", "copy-object", "--bucket", $config.buckets.egress, "--copy-source", "$($config.buckets.staging)/$stagingKey", "--key", $egressKey) | Out-Null
    }

    $unrelatedFile = [IO.Path]::GetTempFileName()
    $tempFiles.Add($unrelatedFile) | Out-Null
    [IO.File]::WriteAllText($unrelatedFile, "{`"run_id`":`"$runId`",`"derived_from_critical`":false}")
    Invoke-TrackedStep $manifest "Write unrelated control object" {
        Invoke-AwsJson @("s3api", "put-object", "--bucket", $config.buckets.staging, "--key", $temporaryKey, "--body", $unrelatedFile) | Out-Null
    }
    Invoke-TrackedStep $manifest "Delete unrelated control object" {
        Invoke-AwsJson @("s3api", "delete-object", "--bucket", $config.buckets.staging, "--key", $temporaryKey) | Out-Null
    }

    $manifest.status = "COMPLETED"
}
catch {
    $manifest.status = "FAILED"
    $manifest.error = $_.Exception.Message
    throw
}
finally {
    $manifest.ended_at = Get-UtcTimestamp
    Save-RunManifest $manifest
    Restore-CredentialEnvironment $credentialSnapshot
    foreach ($path in $tempFiles) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
    Write-Host "Manifest: $($manifest.manifest_path)"
}
