#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$RunDirectory)
$ErrorActionPreference = 'Stop'
$RunDirectory = (Resolve-Path -LiteralPath $RunDirectory).Path
$runPath = Join-Path $RunDirectory 'run.json'
if (-not (Test-Path -LiteralPath $runPath)) { throw 'run.json not found.' }
$run = Get-Content -Raw -LiteralPath $runPath | ConvertFrom-Json
$channel = 'Microsoft-Windows-Sysmon/Operational'
$start = ([DateTime]::Parse($run.window_start_utc)).ToUniversalTime()
$end = ([DateTime]::Parse($run.window_end_utc)).ToUniversalTime()
$status = [ordered]@{
    status = 'unavailable'; channel = $channel
    capture_utc = [DateTime]::UtcNow.ToString('o'); events = 0; error = ''
}
try {
    $info = Get-WinEvent -ListLog $channel
    if (-not $info.IsEnabled) { throw 'Sysmon channel is disabled.' }
    $startText = $start.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $endText = $end.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $query = "*[System[TimeCreated[@SystemTime >= '$startText' and @SystemTime <= '$endText'] and (EventID=1 or EventID=5 or EventID=7 or EventID=8 or EventID=10 or EventID=25)]]"
    $evtx = Join-Path $RunDirectory 'sysmon.evtx'
    if (Test-Path -LiteralPath $evtx) { throw 'sysmon.evtx already exists; preserve the original capture.' }
    & wevtutil epl $channel $evtx "/q:$query" '/ow:false'
    if ($LASTEXITCODE -ne 0) { throw "EVTX export failed: $LASTEXITCODE" }
    $readErrors = @()
    $events = @(Get-WinEvent -Path $evtx -Oldest -ErrorAction SilentlyContinue -ErrorVariable readErrors)
    foreach ($readError in $readErrors) {
        if ($readError.FullyQualifiedErrorId -notmatch '^NoMatchingEventsFound') { throw $readError }
    }
    $lines = @()
    foreach ($event in $events) {
        [xml]$xml = $event.ToXml()
        $data = [ordered]@{}
        foreach ($field in $xml.Event.EventData.Data) { $data[[string]$field.Name] = [string]$field.'#text' }
        $lines += ([ordered]@{
            event_id = $event.Id; record_id = $event.RecordId
            utc = $event.TimeCreated.ToUniversalTime().ToString('o')
            provider = $event.ProviderName; data = $data
        } | ConvertTo-Json -Compress -Depth 8)
    }
    if ($lines.Count) {
        $lines | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $RunDirectory 'telemetry.jsonl')
    } else {
        New-Item -ItemType File -Path (Join-Path $RunDirectory 'telemetry.jsonl') | Out-Null
    }
    $status.status = 'collected'
    $status.events = $events.Count
    $status['coverage_note'] = 'Collection does not prove all required event classes were enabled. Record sensor version and configuration.'
} catch {
    $status.error = $_.Exception.Message
}
$status | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $RunDirectory 'telemetry-status.json')
$status | Format-List
if ($status.status -ne 'collected') { exit 1 }
