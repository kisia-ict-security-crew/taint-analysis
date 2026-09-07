param(
    [ValidateRange(1, 1000)][int]$Iterations = 5,
    [ValidateRange(0, 3600)][int]$IntervalSeconds = 5,
    [string]$TerraformDir = (Split-Path $PSScriptRoot -Parent)
)

. (Join-Path $PSScriptRoot "common.ps1")

$config = Get-LabConfig -TerraformDir $TerraformDir
$baseCaller = Invoke-AwsJson -Arguments @("sts", "get-caller-identity")
$runId = "background-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$runDir = Join-Path (Join-Path $TerraformDir "runs") $runId
$manifest = New-RunManifest -RunId $runId -Scenario "BACKGROUND" -OutputDir $runDir -BaseCaller $baseCaller
$credentialSnapshot = Save-CredentialEnvironment
$tempFiles = [System.Collections.Generic.List[string]]::new()
$sessionName = "$runId-bot"

$dataSeedKey = Get-S3KeyFromUri -Uri $config.data_seed_uri -Bucket $config.buckets.critical
Add-ExpectedEvent $manifest "assume-background-bot" "CONTROL" @("AssumeRole", $config.roles.background_bot, $sessionName)
# Do not constrain forbidden checks to the bot session. Any principal touching a
# seed during the background window invalidates the negative control.
Add-ForbiddenEvent $manifest "no-data-seed-read" @("GetObject", $config.buckets.critical, $dataSeedKey)
Add-ForbiddenEvent $manifest "no-secret-seed-read" @("GetSecretValue", $config.honeytoken_secret_arn)
Save-RunManifest $manifest

try {
    $bot = Invoke-TrackedStep $manifest "Assume BackgroundBot" {
        Assume-LabRole -RoleArn $config.roles.background_bot -SessionName $sessionName
    }
    Use-AwsSession $bot.Credentials

    for ($i = 1; $i -le $Iterations; $i++) {
        $sequence = $i.ToString("D4")
        $incomingKey = "normal/incoming/$runId/item-$sequence.json"
        $processedKey = "normal/processed/$runId/item-$sequence.json"
        $payloadFile = [IO.Path]::GetTempFileName()
        $downloadFile = [IO.Path]::GetTempFileName()
        $tempFiles.Add($payloadFile) | Out-Null
        $tempFiles.Add($downloadFile) | Out-Null
        [IO.File]::WriteAllText($payloadFile, "{`"run_id`":`"$runId`",`"sequence`":$i,`"synthetic`":true}")

        Add-ExpectedEvent $manifest "normal-put-$sequence" "CONTROL" @("PutObject", $config.buckets.critical, $incomingKey, $sessionName)
        Add-ExpectedEvent $manifest "normal-get-$sequence" "CONTROL" @("GetObject", $config.buckets.critical, $incomingKey, $sessionName)
        Add-ExpectedEvent $manifest "normal-copy-$sequence" "CONTROL" @("CopyObject", $config.buckets.staging, $processedKey, $sessionName)
        Add-ExpectedEvent $manifest "normal-delete-source-$sequence" "CONTROL" @("DeleteObject", $config.buckets.critical, $incomingKey, $sessionName)
        Add-ExpectedEvent $manifest "normal-delete-processed-$sequence" "CONTROL" @("DeleteObject", $config.buckets.staging, $processedKey, $sessionName)
        Save-RunManifest $manifest

        Invoke-TrackedStep $manifest "Normal PutObject $sequence" {
            Invoke-AwsJson @("s3api", "put-object", "--bucket", $config.buckets.critical, "--key", $incomingKey, "--body", $payloadFile) | Out-Null
        }
        Invoke-TrackedStep $manifest "Normal GetObject $sequence" {
            Invoke-AwsJson @("s3api", "get-object", "--bucket", $config.buckets.critical, "--key", $incomingKey, $downloadFile) | Out-Null
        }
        Invoke-TrackedStep $manifest "Normal CopyObject $sequence" {
            Invoke-AwsJson @("s3api", "copy-object", "--bucket", $config.buckets.staging, "--copy-source", "$($config.buckets.critical)/$incomingKey", "--key", $processedKey) | Out-Null
        }
        Invoke-TrackedStep $manifest "Normal DeleteObject source $sequence" {
            Invoke-AwsJson @("s3api", "delete-object", "--bucket", $config.buckets.critical, "--key", $incomingKey) | Out-Null
        }
        Invoke-TrackedStep $manifest "Normal DeleteObject processed $sequence" {
            Invoke-AwsJson @("s3api", "delete-object", "--bucket", $config.buckets.staging, "--key", $processedKey) | Out-Null
        }

        if ($i -lt $Iterations -and $IntervalSeconds -gt 0) {
            Start-Sleep -Seconds $IntervalSeconds
        }
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
