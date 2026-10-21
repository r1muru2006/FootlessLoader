#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$SnapshotName,
    [Parameter(Mandatory=$true)][switch]$VmSnapshotConfirmed,
    [ValidateSet('All','B01','B02','B03','P01','P02','P03','P04','P05','P06')][string]$Scenario = 'All',
    [ValidateRange(1,30)][int]$Repeat = 1,
    [ValidateRange(100,10000)][int]$ObserveMs = 2500,
    [string]$OutputRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'evidence')
)
$ErrorActionPreference = 'Stop'
if (-not $VmSnapshotConfirmed.IsPresent) {throw 'Run this suite inside the VM after creating its snapshot.'}
if ($SnapshotName -match '[\r\n]' -or $SnapshotName.Length -gt 200) {throw 'Invalid snapshot name.'}
if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {throw 'Use x64 Windows and x64 PowerShell.'}
$root = Split-Path $PSScriptRoot -Parent
$bin = Join-Path $root 'bin'
foreach ($file in @('NT230_target.exe','NT230_injector.exe','NT230_marker.dll')) {
    if (-not (Test-Path -LiteralPath (Join-Path $bin $file))) {throw "Missing $file; run build.ps1 first."}
}
$suite = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$OutputRoot = (Resolve-Path -LiteralPath $OutputRoot).Path
$suiteDir = Join-Path $OutputRoot $suite
New-Item -ItemType Directory -Path $suiteDir | Out-Null
$os = Get-WmiObject Win32_OperatingSystem
$computer = Get-WmiObject Win32_ComputerSystem
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$environmentData = [ordered]@{
    suite_id=$suite; captured_utc=[DateTime]::UtcNow.ToString('o'); snapshot_name=$SnapshotName
    vm_snapshot_confirmed=$true; os_caption=$os.Caption; os_version=$os.Version; os_build=$os.BuildNumber
    os_architecture=$os.OSArchitecture; manufacturer=$computer.Manufacturer; model=$computer.Model
    powershell_version=$PSVersionTable.PSVersion.ToString(); process_architecture='x64'
    elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    observe_ms=$ObserveMs; telemetry_status='not_collected'; detector_status='not_evaluated'
}
$environmentData | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $suiteDir 'environment.json')
Get-ChildItem -LiteralPath $bin -File | Where-Object {$_.Extension -in @('.exe','.dll')} |
    Get-FileHash -Algorithm SHA256 | Select-Object Path,Hash |
    Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $suiteDir 'binary-sha256.csv')
if (Test-Path -LiteralPath (Join-Path $bin 'build.log')) {
    Copy-Item -LiteralPath (Join-Path $bin 'build.log') -Destination (Join-Path $suiteDir 'build.log')
}
$cases = @(
    @{Id='B01';Method='none';Mode='idle';Expected='no_marker';Class='benign'},
    @{Id='B02';Method='selfdll';Mode='selfdll';Expected='marker';Class='benign'},
    @{Id='B03';Method='selfapc';Mode='selfapc';Expected='marker';Class='benign'},
    @{Id='P01';Method='crt';Mode='idle';Expected='marker';Class='injection_attempt'},
    @{Id='P02';Method='dll';Mode='idle';Expected='marker';Class='injection_attempt'},
    @{Id='P03';Method='apc';Mode='alertable';Expected='marker';Class='injection_attempt'},
    @{Id='P04';Method='apc';Mode='nonalertable';Expected='queued_no_marker_in_window';Class='injection_attempt'},
    @{Id='P05';Method='nt';Mode='idle';Expected='marker';Class='injection_attempt'},
    @{Id='P06';Method='nt-image';Mode='idle';Expected='marker';Class='injection_attempt'}
)
if ($Scenario -ne 'All') {$cases = @($cases | Where-Object {$_.Id -eq $Scenario})}
$previousSnapshot = $env:NT230_VM_SNAPSHOT
$env:NT230_VM_SNAPSHOT = $SnapshotName
$results = @()
function Read-LabJsonLines([string]$Path) {
    if (Test-Path -LiteralPath $Path) {
        foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8) {
            if ($line.Trim()) {$line | ConvertFrom-Json}
        }
    }
}
function Quote-LabArg([string]$Value) {
    if ($Value.Contains('"') -or $Value.EndsWith('\')) {throw 'Output path must not contain quotes or end with a backslash.'}
    return '"' + $Value + '"'
}
try {
    for ($iteration=1; $iteration -le $Repeat; $iteration++) {
        foreach ($case in $cases) {
            $run = $case.Id + '-' + $iteration + '-' + [Guid]::NewGuid().ToString('N').Substring(0,12)
            $dir = Join-Path $suiteDir $run
            New-Item -ItemType Directory -Path $dir | Out-Null
            $seconds = [Math]::Max(8,[int][Math]::Ceiling(($ObserveMs*4+3000)/1000.0))
            $target = $null; $injector = $null; $targetPidValue=$null; $sourcePidValue=$null
            $injectExit=$null; $targetExit=$null; $errorText=''; $actual='unconfirmed'; $markerStatus='unconfirmed'
            $queued='not_applicable'; $newThreadIds=''; $starts=''; $moduleStatus='not_applicable'
            $windowStart = [DateTime]::UtcNow.ToString('o')
            try {
                $argsLine = "$run $($case.Id) $($case.Mode) $(Quote-LabArg $dir) $seconds"
                $target = Start-Process -FilePath (Join-Path $bin 'NT230_target.exe') -ArgumentList $argsLine `
                    -WorkingDirectory $bin -WindowStyle Hidden -PassThru `
                    -RedirectStandardOutput (Join-Path $dir 'target.stdout.txt') -RedirectStandardError (Join-Path $dir 'target.stderr.txt')
                $targetPidValue=$target.Id
                $ready=$null; $deadline=[DateTime]::UtcNow.AddSeconds(5)
                while ([DateTime]::UtcNow -lt $deadline -and -not $target.HasExited) {
                    $ready=@(Read-LabJsonLines (Join-Path $dir 'target.jsonl') | Where-Object {$_.event -eq 'ready'})
                    if ($ready.Count -gt 0) {break}
                    Start-Sleep -Milliseconds 50
                }
                if (-not $ready -or $ready.Count -eq 0) {throw 'Target did not become ready; inspect stderr and binary dependencies.'}
                if ($case.Class -eq 'injection_attempt') {
                    $injector=Start-Process -FilePath (Join-Path $bin 'NT230_injector.exe') `
                        -ArgumentList "$($case.Method) $run $ObserveMs" -WorkingDirectory $bin -WindowStyle Hidden -PassThru `
                        -RedirectStandardOutput (Join-Path $dir 'injector.stdout.txt') -RedirectStandardError (Join-Path $dir 'injector.stderr.txt')
                    $sourcePidValue=$injector.Id
                    if (-not $injector.WaitForExit(($ObserveMs*4)+5000)) {throw 'Injector exceeded its overall observation limit.'}
                    $injector.WaitForExit();$injectExit=$injector.ExitCode
                }
                if (-not $target.WaitForExit(($seconds+3)*1000)) {throw 'Target exceeded its configured lifetime.'}
                $target.WaitForExit();$targetExit=$target.ExitCode
                $markerFile=Join-Path $dir 'marker.jsonl'
                $markers=@(Read-LabJsonLines $markerFile)
                $valid=@($markers | Where-Object {$_.event -eq 'marker' -and $_.run_id -eq $run -and $_.scenario_id -eq $case.Id -and $_.pid -eq $targetPidValue -and $_.tid -gt 0 -and $_.utc})
                if ($markers.Count -ne $valid.Count) {throw 'Marker log contains mismatched or incomplete records.'}
                $events=@(Read-LabJsonLines (Join-Path $dir 'injector.jsonl'))
                $queue=@($events | Where-Object {$_.event -eq 'apc_queue'})
                if ($queue.Count -gt 0) {$queued=([bool]$queue[-1].queued).ToString().ToLowerInvariant()}
                $threads=@($events | Where-Object {$_.event -eq 'remote_thread'})
                $newThreadIds=($threads | ForEach-Object {$_.new_tid}) -join ';'
                $starts=($threads | ForEach-Object {$_.start_address}) -join ';'
                $module=@($events | Where-Object {$_.event -eq 'dll_module'})
                if ($module.Count) {$moduleStatus=([bool]$module[-1].loaded).ToString().ToLowerInvariant()}
                $markerStatus=if($valid.Count -gt 0){'yes'}else{'no_observed'}
                $actual=if($valid.Count -gt 0){'marker'}elseif($queued -eq 'true'){'queued_no_marker_in_window'}else{'no_marker'}
                # A marker must come from the recorded new thread or the pre-existing APC thread.
                if ($case.Method -in @('crt','nt','nt-image')) {
                    if (@($valid | Where-Object {$_.tid -notin @($threads.new_tid)}).Count) {throw 'Marker TID does not match the created remote thread.'}
                }
                if ($case.Method -eq 'dll') {
                    $markerThreads=@($threads | Where-Object {$_.phase -eq 'Nt230DllMarker'} | ForEach-Object {$_.new_tid})
                    if (@($valid | Where-Object {$_.tid -notin $markerThreads}).Count) {throw 'DLL marker TID mismatch.'}
                }
                if ($case.Method -eq 'apc' -and @($valid | Where-Object {$_.tid -ne $ready[0].tid}).Count) {throw 'APC marker did not run on the pre-existing target thread.'}
                $expectedExit=if($case.Id -eq 'P04'){20}else{0}
                if ($targetExit -ne 0 -or ($null -ne $injectExit -and $injectExit -ne $expectedExit)) {throw "Unexpected exit codes: target=$targetExit injector=$injectExit"}
                if ($actual -ne $case.Expected) {throw "Expected $($case.Expected); observed $actual"}
                $status='pass'
            } catch {$errorText=$_.Exception.Message;$status='fail'} finally {
                # Only stop Process objects created by this run, never an arbitrary PID.
                foreach ($child in @($injector,$target)) {
                    if ($null -ne $child -and -not $child.HasExited) {$child.Kill();$child.WaitForExit()}
                }
            }
            $windowEnd=[DateTime]::UtcNow.ToString('o')
            $row=[pscustomobject][ordered]@{
                run_id=$run;scenario_id=$case.Id;iteration=$iteration;method=$case.Method;ground_truth_class=$case.Class
                source_pid=$(if($sourcePidValue){$sourcePidValue}elseif($case.Method -in @('selfdll','selfapc')){$targetPidValue}else{$null})
                source_image=$(if($sourcePidValue){'NT230_injector.exe'}elseif($case.Method -in @('selfdll','selfapc')){'NT230_target.exe'}else{''})
                target_pid=$targetPidValue;target_image='NT230_target.exe';expected=$case.Expected;actual=$actual
                marker_executed=$markerStatus;apc_queued=$queued;dll_loaded=$moduleStatus
                new_thread_ids=$newThreadIds;start_addresses=$starts;status=$status
                injector_exit=$injectExit;target_exit=$targetExit;error=$errorText
                window_start_utc=$windowStart;window_end_utc=$windowEnd;evidence=$dir
                detector_result='not_evaluated';telemetry_status='not_collected'
            }
            $row | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $dir 'run.json')
            $results += $row
            $results | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $suiteDir 'results.csv')
            Write-Host "$($case.Id) $run : $status; marker=$markerStatus; queued=$queued"
        }
    }
} finally {$env:NT230_VM_SNAPSHOT=$previousSnapshot}
Write-Host "Evidence: $suiteDir"
Write-Host 'Detector has not been evaluated. Collect independent telemetry separately.'
if (@($results | Where-Object {$_.status -ne 'pass'}).Count) {exit 1}
