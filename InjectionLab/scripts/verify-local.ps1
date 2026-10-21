#requires -Version 5.1
param([string]$Compiler='gcc',[string]$Python='python')
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$dir=Join-Path $root 'verification'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$log=Join-Path $dir 'host-checks.txt'
"Host checks only; injection scenarios are NOT executed. UTC: $([DateTime]::UtcNow.ToString('o'))" | Set-Content -LiteralPath $log
foreach($script in Get-ChildItem -LiteralPath $root -Filter '*.ps1' -Recurse) {
    $tokens=$null;$parseErrors=$null
    [System.Management.Automation.Language.Parser]::ParseFile($script.FullName,[ref]$tokens,[ref]$parseErrors) | Out-Null
    if($parseErrors.Count) {throw "PowerShell syntax error in $($script.FullName): $parseErrors"}
}
'PowerShell parsing: PASS' | Add-Content -LiteralPath $log
& $Compiler '-std=c11' '-O2' '-Wall' '-Wextra' '-Werror' '-D__USE_MINGW_ANSI_STDIO=1' '-municode' '-static-libgcc' `
    (Join-Path $root 'tests\log_contract.c') '-o' (Join-Path $dir 'log_contract.exe')
if($LASTEXITCODE -ne 0) {throw 'Log contract test compilation failed.'}
$contract=Join-Path $dir 'contract.jsonl'
if(Test-Path -LiteralPath $contract) {Remove-Item -LiteralPath $contract}
& (Join-Path $dir 'log_contract.exe') $dir
if($LASTEXITCODE -ne 0) {throw 'Log serialization test failed.'}
$record=Get-Content -LiteralPath $contract -Encoding UTF8 | ConvertFrom-Json
if($record.event -ne 'serialization_test' -or $record.pointer -ne '0x123456789abcdef0' -or $record.value -ne 4294967296) {
    throw 'Log pointer or integer serialization failed.'
}
'JSON serialization and 64-bit value preservation: PASS (synthetic host test)' | Add-Content -LiteralPath $log
$savedSnapshot=$env:NT230_VM_SNAPSHOT
try {
    Remove-Item Env:\NT230_VM_SNAPSHOT -ErrorAction SilentlyContinue
    # Gate returns before process access or target creation.
    $previousPreference=$ErrorActionPreference;$ErrorActionPreference='Continue'
    & (Join-Path $root 'bin\NT230_injector.exe') crt HOST_GATE_TEST 1000 2> (Join-Path $dir 'gate.stderr.txt')
    $gateCode=$LASTEXITCODE;$ErrorActionPreference=$previousPreference
    if($gateCode -ne 2) {throw 'VM snapshot environment gate did not reject the command.'}
} finally {$env:NT230_VM_SNAPSHOT=$savedSnapshot}
'Missing snapshot declaration rejected before process access: PASS' | Add-Content -LiteralPath $log
& $Python '-m' 'unittest' 'discover' '-s' (Join-Path $root 'tests') '-p' 'test_*.py' '-v'
if($LASTEXITCODE -ne 0) {throw 'Evaluator tests failed.'}
'Evaluator synthetic edge-case tests: PASS' | Add-Content -LiteralPath $log
Get-Content -LiteralPath $log
