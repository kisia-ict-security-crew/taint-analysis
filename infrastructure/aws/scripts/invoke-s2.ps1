param(
    [string]$TerraformDir = (Split-Path $PSScriptRoot -Parent),
    [string]$SourceIdentity = ""
)

. (Join-Path $PSScriptRoot "common.ps1")

$config = Get-LabConfig -TerraformDir $TerraformDir
$baseCaller = Invoke-AwsJson -Arguments @("sts", "get-caller-identity")
$runId = "s2-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$runDir = Join-Path (Join-Path $TerraformDir "runs") $runId
$manifest = New-RunManifest -RunId $runId -Scenario "S2" -OutputDir $runDir -BaseCaller $baseCaller
$credentialSnapshot = Save-CredentialEnvironment
$tempFiles = [System.Collections.Generic.List[string]]::new()

$dataSeedKey = Get-S3KeyFromUri -Uri $config.data_seed_uri -Bucket $config.buckets.critical
$criticalKey = Get-S3KeyFromUri -Uri $config.critical_object_uri -Bucket $config.buckets.critical
$sessionA = "$runId-a"
$sessionB = "$runId-b"
$sessionC = "$runId-c"
$stagingKey = "runs/$runId/customer-copy.csv"
$egressKey = "runs/$runId/customer-export.csv"

Add-ExpectedEvent $manifest "assume-actor-a" "PROBE" @("AssumeRole", $config.roles.actor_a, $sessionA)
Add-ExpectedEvent $manifest "delegate-a-b" "R2-CLEAN" @("AssumeRole", $config.roles.pivot_b, $sessionA, $sessionB)
Add-ExpectedEvent $manifest "delegate-b-c" "R2-CLEAN" @("AssumeRole", $config.roles.pivot_c, $sessionB, $sessionC)
Add-ExpectedEvent $manifest "critical-read" "D-ONLY" @("GetObject", $config.buckets.critical, $criticalKey, $sessionC)
Add-ExpectedEvent $manifest "copy-critical-staging" "R7" @("CopyObject", $config.buckets.staging, $stagingKey, $sessionC)
Add-ExpectedEvent $manifest "copy-staging-egress" "R7" @("CopyObject", $config.buckets.egress, $egressKey, $sessionC)
Add-ForbiddenEvent $manifest "no-data-seed-contact" @("GetObject", $config.buckets.critical, $dataSeedKey, $sessionA)
Add-ForbiddenEvent $manifest "no-secret-seed-contact" @("GetSecretValue", $config.honeytoken_secret_arn, $sessionA)
Save-RunManifest $manifest

try {
    $actorA = Invoke-TrackedStep $manifest "Assume ActorA without seed contact" {
        Assume-LabRole -RoleArn $config.roles.actor_a -SessionName $sessionA -SourceIdentity $SourceIdentity
    }
    Use-AwsSession $actorA.Credentials

    $pivotB = Invoke-TrackedStep $manifest "Assume PivotB without C-Taint" {
        Assume-LabRole -RoleArn $config.roles.pivot_b -SessionName $sessionB
    }
    Use-AwsSession $pivotB.Credentials

    $pivotC = Invoke-TrackedStep $manifest "Assume PivotC without C-Taint" {
        Assume-LabRole -RoleArn $config.roles.pivot_c -SessionName $sessionC
    }
    Use-AwsSession $pivotC.Credentials

    $criticalFile = [IO.Path]::GetTempFileName()
    $tempFiles.Add($criticalFile) | Out-Null
    Invoke-TrackedStep $manifest "Read classified D-Taint source" {
        Invoke-AwsJson @("s3api", "get-object", "--bucket", $config.buckets.critical, "--key", $criticalKey, $criticalFile) | Out-Null
    }

    Invoke-TrackedStep $manifest "Copy D-Taint to staging" {
        Invoke-AwsJson @("s3api", "copy-object", "--bucket", $config.buckets.staging, "--copy-source", "$($config.buckets.critical)/$criticalKey", "--key", $stagingKey) | Out-Null
    }

    Invoke-TrackedStep $manifest "Copy D-Taint to simulated egress" {
        Invoke-AwsJson @("s3api", "copy-object", "--bucket", $config.buckets.egress, "--copy-source", "$($config.buckets.staging)/$stagingKey", "--key", $egressKey) | Out-Null
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
