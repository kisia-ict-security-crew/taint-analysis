param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [ValidateRange(30, 3600)][int]$WaitSeconds = 900,
    [ValidateRange(5, 300)][int]$PollSeconds = 30,
    [string]$TerraformDir = (Split-Path $PSScriptRoot -Parent)
)

. (Join-Path $PSScriptRoot "common.ps1")

function Convert-ToDateTimeOffsetPreservingZone {
    param([Parameter(Mandatory)]$Value)

    if ($Value -is [DateTimeOffset]) {
        return $Value
    }
    if ($Value -is [DateTime]) {
        # ConvertFrom-Json in newer PowerShell versions materializes ISO timestamps
        # as DateTime. Constructing directly preserves its Local/UTC Kind and offset.
        return [DateTimeOffset]::new([DateTime]$Value)
    }
    return [DateTimeOffset]::Parse(
        [string]$Value,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind
    )
}

$manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $manifest.ended_at) {
    throw "Manifest is still running or incomplete: $ManifestPath"
}

$config = Get-LabConfig -TerraformDir $TerraformDir
$windowStart = Convert-ToDateTimeOffsetPreservingZone $manifest.started_at
$windowEnd = Convert-ToDateTimeOffsetPreservingZone $manifest.ended_at
# CloudTrail eventTime is recorded at whole-second precision, while the local
# manifest contains fractional seconds. Compare on CloudTrail's precision so an
# event at 10:46:48Z is not rejected by a manifest start of 10:46:48.278Z.
$eventWindowStart = [DateTimeOffset]::FromUnixTimeSeconds($windowStart.ToUnixTimeSeconds())
$eventWindowEndExclusive = [DateTimeOffset]::FromUnixTimeSeconds($windowEnd.ToUnixTimeSeconds()).AddSeconds(1)
# Logs Insights needs only a small envelope around the experiment. Event matching below
# still uses CloudTrail eventTime and excludes activity outside the manifest window.
$startTime = $eventWindowStart.AddSeconds(-5).ToUnixTimeSeconds()
$deadline = [DateTimeOffset]::UtcNow.AddSeconds($WaitSeconds)
$lastEvaluation = $null
$verificationPath = Join-Path (Split-Path -Parent $ManifestPath) "verification.json"

function Invoke-LogsQuery {
    # CloudTrail can be delivered to CloudWatch after the experiment has ended.
    # Query through the present, then filter by the embedded CloudTrail eventTime.
    $queryEndTime = [DateTimeOffset]::UtcNow.AddMinutes(2).ToUnixTimeSeconds()
    $queryText = "fields @timestamp, @message | sort @timestamp asc | limit 10000"
    $started = Invoke-AwsJson @(
        "logs", "start-query",
        "--log-group-name", $config.cloudwatch_log_group,
        "--start-time", [string]$startTime,
        "--end-time", [string]$queryEndTime,
        "--query-string", $queryText
    )

    do {
        Start-Sleep -Seconds 2
        $result = Invoke-AwsJson @("logs", "get-query-results", "--query-id", $started.queryId)
    } while ($result.status -in @("Scheduled", "Running"))

    if ($result.status -ne "Complete") {
        throw "CloudWatch Logs Insights query ended with status '$($result.status)'."
    }
    return @($result.results)
}

function Get-RawMessages {
    param($Rows = @())

    $messages = [System.Collections.Generic.List[string]]::new()
    foreach ($row in $Rows) {
        $messageField = $row | Where-Object { $_.field -eq "@message" } | Select-Object -First 1
        if ($messageField -and $messageField.value) {
            $messages.Add([string]$messageField.value) | Out-Null
        }
    }
    return @($messages)
}

function Get-ManagementEventMessages {
    # STS calls made through the global endpoint are recorded in us-east-1.
    # Regional STS calls are recorded in the region that served the request.
    $regions = [System.Collections.Generic.List[string]]::new()
    foreach ($candidate in @(
        [Environment]::GetEnvironmentVariable("AWS_REGION", "Process"),
        [Environment]::GetEnvironmentVariable("AWS_DEFAULT_REGION", "Process")
    )) {
        if ($candidate -and -not $regions.Contains($candidate)) {
            $regions.Add($candidate) | Out-Null
        }
    }

    try {
        $configuredRegion = ((& aws configure get region 2>$null) | Out-String).Trim()
        if ($configuredRegion -and -not $regions.Contains($configuredRegion)) {
            $regions.Add($configuredRegion) | Out-Null
        }
    } catch { }

    if (-not $regions.Contains("us-east-1")) {
        $regions.Add("us-east-1") | Out-Null
    }

    $messages = [System.Collections.Generic.List[string]]::new()
    foreach ($region in $regions) {
        try {
            $lookup = Invoke-AwsJson @(
                "cloudtrail", "lookup-events",
                "--lookup-attributes", "AttributeKey=EventName,AttributeValue=AssumeRole",
                "--start-time", $eventWindowStart.UtcDateTime.ToString("o"),
                "--end-time", $eventWindowEndExclusive.UtcDateTime.ToString("o"),
                "--region", $region
            )
            $eventsProperty = $lookup.PSObject.Properties["Events"]
            if ($eventsProperty) {
                foreach ($entry in @($eventsProperty.Value)) {
                    $cloudTrailEvent = $entry.PSObject.Properties["CloudTrailEvent"]
                    if ($cloudTrailEvent -and $cloudTrailEvent.Value) {
                        $messages.Add([string]$cloudTrailEvent.Value) | Out-Null
                    }
                }
            }
        } catch {
            Write-Verbose "CloudTrail Event History lookup failed in ${region}: $($_.Exception.Message)"
        }
    }
    return @($messages)
}

function Evaluate-Messages {
    param([AllowNull()][AllowEmptyCollection()][string[]]$Messages = @())

    if ($null -eq $Messages) {
        $Messages = @()
    }

    $events = [System.Collections.Generic.List[object]]::new()
    foreach ($raw in $Messages) {
        try {
            $event = $raw | ConvertFrom-Json
            $eventTime = Convert-ToDateTimeOffsetPreservingZone $event.eventTime
            if ($eventTime -ge $eventWindowStart -and $eventTime -lt $eventWindowEndExclusive) {
                $events.Add([pscustomobject]@{
                    raw   = $raw
                    event = $event
                }) | Out-Null
            }
        } catch {
            # Ignore non-CloudTrail/malformed log messages.
        }
    }

    function Get-OptionalProperty {
        param(
            [AllowNull()]$Object,
            [Parameter(Mandatory)][string]$Name
        )

        if ($null -eq $Object) { return $null }
        $property = $Object.PSObject.Properties[$Name]
        if ($null -eq $property) { return $null }
        return $property.Value
    }

    function Get-EventSummary {
        param([Parameter(Mandatory)]$Record)

        $event = $Record.event
        $userIdentity = Get-OptionalProperty -Object $event -Name "userIdentity"
        $actorArn = Get-OptionalProperty -Object $userIdentity -Name "arn"
        if (-not $actorArn) {
            $sessionContext = Get-OptionalProperty -Object $userIdentity -Name "sessionContext"
            $sessionIssuer = Get-OptionalProperty -Object $sessionContext -Name "sessionIssuer"
            $actorArn = Get-OptionalProperty -Object $sessionIssuer -Name "arn"
        }
        $requestParameters = Get-OptionalProperty -Object $event -Name "requestParameters"
        return [pscustomobject]@{
            event_id   = Get-OptionalProperty -Object $event -Name "eventID"
            event_time = Get-OptionalProperty -Object $event -Name "eventTime"
            event_name = Get-OptionalProperty -Object $event -Name "eventName"
            actor_arn  = $actorArn
            source_ip  = Get-OptionalProperty -Object $event -Name "sourceIPAddress"
            bucket     = Get-OptionalProperty -Object $requestParameters -Name "bucketName"
            key        = Get-OptionalProperty -Object $requestParameters -Name "key"
            error_code = Get-OptionalProperty -Object $event -Name "errorCode"
        }
    }

    $expectedResults = [System.Collections.Generic.List[object]]::new()
    foreach ($expected in $manifest.expected_events) {
        $matches = @($events | Where-Object { Test-AllMarkers -Text $_.raw -Markers $expected.match_all })
        $expectedResults.Add([pscustomobject]@{
            id          = $expected.id
            rule        = $expected.rule
            found       = $matches.Count -gt 0
            match_count = $matches.Count
            matches     = @($matches | ForEach-Object { Get-EventSummary -Record $_ })
        }) | Out-Null
    }

    $forbiddenResults = [System.Collections.Generic.List[object]]::new()
    foreach ($forbidden in $manifest.forbidden_events) {
        $matches = @($events | Where-Object { Test-AllMarkers -Text $_.raw -Markers $forbidden.match_all })
        $forbiddenResults.Add([pscustomobject]@{
            id          = $forbidden.id
            violated    = $matches.Count -gt 0
            match_count = $matches.Count
            matches     = @($matches | ForEach-Object { Get-EventSummary -Record $_ })
        }) | Out-Null
    }

    $missing = @($expectedResults | Where-Object { -not $_.found })
    $violations = @($forbiddenResults | Where-Object { $_.violated })
    return [pscustomobject]@{
        passed            = ($missing.Count -eq 0 -and $violations.Count -eq 0)
        evaluated_at      = Get-UtcTimestamp
        manifest_started_at = $manifest.started_at
        manifest_ended_at = $manifest.ended_at
        effective_event_window_start = $eventWindowStart.ToString("o")
        effective_event_window_end_exclusive = $eventWindowEndExclusive.ToString("o")
        raw_message_count = $Messages.Count
        in_window_event_count = $events.Count
        expected          = $expectedResults
        forbidden         = $forbiddenResults
        missing_ids   = @($missing | ForEach-Object { $_.id })
        violation_ids = @($violations | ForEach-Object { $_.id })
    }
}

do {
    $rows = @(Invoke-LogsQuery)
    $messages = @(
        Get-RawMessages -Rows $rows
        Get-ManagementEventMessages
    )
    $lastEvaluation = Evaluate-Messages -Messages $messages
    $lastEvaluation | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $verificationPath -Encoding UTF8
    if ($lastEvaluation.passed) { break }

    if ($lastEvaluation.violation_ids.Count -gt 0) {
        Write-Host "Forbidden event detected inside the manifest window; waiting cannot remove it."
        foreach ($result in @($lastEvaluation.forbidden | Where-Object { $_.violated })) {
            foreach ($match in @($result.matches)) {
                Write-Host "  [$($result.id)] $($match.event_time) actor=$($match.actor_arn) event=$($match.event_name) s3://$($match.bucket)/$($match.key) eventID=$($match.event_id)"
            }
        }
        break
    }

    Write-Host "Waiting for CloudTrail delivery. Missing: $($lastEvaluation.missing_ids -join ', '); violations: $($lastEvaluation.violation_ids -join ', ')"
    if ([DateTimeOffset]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds $PollSeconds
    }
} while ([DateTimeOffset]::UtcNow -lt $deadline)

if (-not $lastEvaluation.passed) {
    Write-Host "Verification FAILED: $verificationPath"
    exit 1
}

Write-Host "Verification PASSED: $verificationPath"
