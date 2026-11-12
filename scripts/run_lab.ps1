#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$SnapshotName,
    [Parameter(Mandatory=$true)][switch]$VmSnapshotConfirmed,
    [ValidateSet('crt','nt','stub','apc','section')][string]$Method = 'crt',
    [ValidateSet('B01','B02','P01','P02','P03','P04','P05')][string]$Scenario = 'P01',
    [ValidateRange(8,300)][int]$Seconds = 20,
    [ValidateRange(500,60000)][int]$ObserveMs = 4000,
    [string]$OutputRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'evidence')
)
$ErrorActionPreference = 'Stop'
if (-not $VmSnapshotConfirmed.IsPresent) { throw 'Run inside the VM after creating its snapshot.' }
if ($SnapshotName -match '[\r\n]' -or $SnapshotName.Length -gt 200) { throw 'Invalid snapshot name.' }
if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
    throw 'Use x64 Windows and x64 PowerShell.'
}
$root = Split-Path $PSScriptRoot -Parent
$bin = Join-Path $root 'dist'
foreach ($file in @('footless_loader.exe','footless_target.exe','footless_marker.dll')) {
    if (-not (Test-Path -LiteralPath (Join-Path $bin $file))) {
        throw "Missing $file; run build.ps1 or copy dist/ into the VM."
    }
}
$runId = $Scenario + '-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' +
    [Guid]::NewGuid().ToString('N').Substring(0,8)
$runDir = Join-Path (Join-Path $OutputRoot $runId) $Scenario
New-Item -ItemType Directory -Force -Path $runDir | Out-Null
$runDir = (Resolve-Path -LiteralPath $runDir).Path

$environment = [ordered]@{
    run_id = $runId
    scenario_id = $Scenario
    method = $Method
    captured_utc = [DateTime]::UtcNow.ToString('o')
    snapshot_name = $SnapshotName
    vm_snapshot_confirmed = $true
    os_caption = (Get-WmiObject Win32_OperatingSystem).Caption
    os_version = (Get-WmiObject Win32_OperatingSystem).Version
    os_build = (Get-WmiObject Win32_OperatingSystem).BuildNumber
    os_architecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
    powershell_version = $PSVersionTable.PSVersion.ToString()
    telemetry_status = 'not_collected'
    detector_status = 'not_evaluated'
    seconds = $Seconds
    observe_ms = $ObserveMs
}
$environment | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $runDir 'environment.json')
Get-ChildItem -LiteralPath $bin -File | Where-Object { $_.Extension -in @('.exe','.dll') } |
    Get-FileHash -Algorithm SHA256 | Select-Object Path,Hash |
    Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $runDir 'binary-sha256.csv')
if (Test-Path -LiteralPath (Join-Path $bin 'build.log')) {
    Copy-Item -LiteralPath (Join-Path $bin 'build.log') -Destination (Join-Path $runDir 'build.log')
}

$previousConfirm = $env:FOOTLESS_LAB_CONFIRM
$previousSnapshot = $env:FOOTLESS_VM_SNAPSHOT
$previousMarker = $env:FOOTLESS_MARKER_LOG
$previousRun = $env:FOOTLESS_RUN_ID
$env:FOOTLESS_LAB_CONFIRM = '1'
$env:FOOTLESS_VM_SNAPSHOT = $SnapshotName
$env:FOOTLESS_MARKER_LOG = Join-Path $runDir 'marker.jsonl'
$env:FOOTLESS_RUN_ID = $runId

try {
    $windowStart = [DateTime]::UtcNow.ToString('o')
    $targetOut = Join-Path $runDir 'target.stdout.txt'
    $targetErr = Join-Path $runDir 'target.stderr.txt'
    $target = Start-Process -FilePath (Join-Path $bin 'footless_target.exe') `
        -ArgumentList @($runId, "$Seconds") -WorkingDirectory $bin -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $targetOut -RedirectStandardError $targetErr

    $targetPidValue = $null; $targetTidValue = $null; $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline -and -not $target.HasExited) {
        if (Test-Path -LiteralPath $targetOut) {
            $line = Get-Content -LiteralPath $targetOut -ErrorAction SilentlyContinue |
                Where-Object { $_ -match '^READY .*pid=(\d+) tid=(\d+)' } | Select-Object -Last 1
            if ($line -and $line -match 'pid=(\d+) tid=(\d+)') {
                $targetPidValue = [int]$Matches[1]; $targetTidValue = [int]$Matches[2]; break
            }
        }
        Start-Sleep -Milliseconds 50
    }
    if (-not $targetPidValue) { throw 'Target did not print READY; inspect target.stderr.txt.' }

    $loaderOut = Join-Path $runDir 'loader.stdout.txt'
    $loaderErr = Join-Path $runDir 'loader.stderr.txt'
    $loaderArgs = @('inject', '--pid', "$targetPidValue", '--method', $Method,
        '--run', $runId, '--scenario', $Scenario, '--timeout', "$ObserveMs",
        '--log', (Join-Path $runDir 'loader.jsonl'))
    if ($Method -eq 'apc') { $loaderArgs += @('--tid', "$targetTidValue") }
    $loader = Start-Process -FilePath (Join-Path $bin 'footless_loader.exe') `
        -ArgumentList $loaderArgs -WorkingDirectory $bin -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $loaderOut -RedirectStandardError $loaderErr
    if (-not $loader.WaitForExit(($ObserveMs * 3) + 20000)) { throw 'Loader exceeded its time limit.' }
    $loader.WaitForExit(); $loaderExit = $loader.ExitCode

    if (-not $target.WaitForExit(($Seconds + 10) * 1000)) { throw 'Target exceeded its lifetime.' }
    $target.WaitForExit(); $targetExit = $target.ExitCode
    $windowEnd = [DateTime]::UtcNow.ToString('o')

    $markers = @()
    $markerFile = Join-Path $runDir 'marker.jsonl'
    if (Test-Path -LiteralPath $markerFile) {
        foreach ($line in Get-Content -LiteralPath $markerFile -Encoding UTF8) {
            if ($line.Trim()) { $markers += ($line | ConvertFrom-Json) }
        }
    }
    $valid = @($markers | Where-Object { $_.event -eq 'marker' -and $_.pid -eq $targetPidValue })
    $loaderEvents = @()
    $loaderFile = Join-Path $runDir 'loader.jsonl'
    if (Test-Path -LiteralPath $loaderFile) {
        foreach ($line in Get-Content -LiteralPath $loaderFile -Encoding UTF8) {
            if ($line.Trim()) { $loaderEvents += ($line | ConvertFrom-Json) }
        }
    }
    $threads = @($loaderEvents | Where-Object { $_.event -eq 'remote_thread' })
    $newTid = if ($threads.Count -gt 0) { $threads[-1].new_tid } else { $null }
    $queued = @($loaderEvents | Where-Object { $_.event -eq 'apc_queue' }).Count -gt 0
    $markerStatus = if ($valid.Count -gt 0) { 'yes' } else { 'no_observed' }
    $actual = if ($valid.Count -gt 0) { 'marker' } elseif ($queued) { 'queued_no_marker_in_window' } else { 'no_marker' }
    $verified = 'no'
    if ($valid.Count -gt 0) {
        if ($Method -eq 'apc') {
            $verified = if (@($valid | Where-Object { $_.tid -eq $targetTidValue }).Count -gt 0) { 'yes' } else { 'no' }
        } else {
            $verified = if ($newTid -and @($valid | Where-Object { $_.tid -eq $newTid }).Count -gt 0) { 'yes' } else { 'no' }
        }
    }
    $result = [ordered]@{
        run_id = $runId; scenario_id = $Scenario; method = $Method
        target_pid = $targetPidValue; target_tid = $targetTidValue; new_tid = $newTid
        loader_exit = $loaderExit; target_exit = $targetExit
        marker_observed = $markerStatus; actual = $actual; marker_match = $verified
        window_start_utc = $windowStart; window_end_utc = $windowEnd
        telemetry_status = 'not_collected'; detector_status = 'not_evaluated'
    }
    $result | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $runDir 'run.json')
    $result | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $OutputRoot 'results.csv') -Append
    Write-Host ("Run {0}: method={1} target_pid={2} new_tid={3} marker={4} match={5}" -f `
        $runId, $Method, $targetPidValue, $newTid, $markerStatus, $verified)
    Write-Host "Evidence: $runDir"
    if ($loaderExit -ne 0) { exit 1 }
    if ($markerStatus -eq 'no_observed' -and $Method -ne 'apc') { exit 2 }
    exit 0
}
finally {
    $env:FOOTLESS_LAB_CONFIRM = $previousConfirm
    $env:FOOTLESS_VM_SNAPSHOT = $previousSnapshot
    $env:FOOTLESS_MARKER_LOG = $previousMarker
    $env:FOOTLESS_RUN_ID = $previousRun
}
