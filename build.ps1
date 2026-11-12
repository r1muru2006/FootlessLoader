#requires -Version 5.1
param(
    [string]$Compiler = 'gcc',
    [string]$Seed = '0x13579bdf',
    [string]$AltSeed = '0xdeadbeef'
)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$out = Join-Path $root 'dist'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$buildLog = Join-Path $out 'build.log'
@("UTC: $([DateTime]::UtcNow.ToString('o'))", "Compiler: $Compiler",
  "Seed: $Seed", "AltSeed: $AltSeed") | Set-Content -LiteralPath $buildLog
& $Compiler --version | Add-Content -LiteralPath $buildLog
$machine = (& $Compiler -dumpmachine | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $machine -notmatch '^x86_64-w64-mingw32$') {
    throw 'Use MinGW-w64 x64 GCC. The lab is x64-only.'
}

$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) { $python = (Get-Command py -ErrorAction SilentlyContinue).Source }
if (-not $python) { throw 'Python 3 is required for build-time hash generation.' }
& $python (Join-Path $root 'tools\gen_api_hashes.py') --seed $Seed `
    --out (Join-Path $root 'src\api_hashes.h') | Add-Content -LiteralPath $buildLog
& $python (Join-Path $root 'tools\gen_api_hashes.py') --seed $AltSeed `
    --out (Join-Path $out 'api_hashes_alt.h') | Add-Content -LiteralPath $buildLog

$flags = @('-std=c11','-O2','-g','-Wall','-Wextra','-Werror',
    '-D_WIN32_WINNT=0x0601','-D__USE_MINGW_ANSI_STDIO=1','-static-libgcc')
$common = @(
    (Join-Path $root 'src\hash.c'),
    (Join-Path $root 'src\resolver.c'),
    (Join-Path $root 'src\ntapi.c'),
    (Join-Path $root 'src\log.c')
)
$loader = $common + @((Join-Path $root 'src\inject.c'), (Join-Path $root 'src\main.c'))

function Build-One {
    param([string]$Output, [string[]]$Extra, [string[]]$Sources)
    $arguments = $flags + $Extra + $Sources + @('-o', $Output)
    $compilerOutput = & $Compiler @arguments 2>&1
    $compilerOutput | Add-Content -LiteralPath $buildLog
    if ($LASTEXITCODE -ne 0) { throw "Build failed: $Output" }
    "Built $Output" | Add-Content -LiteralPath $buildLog
}

Build-One (Join-Path $out 'footless_loader.exe') @("-DFOOTLESS_DEFAULT_SEED_VALUE=$Seed") $loader
Build-One (Join-Path $out 'footless_loader_seeded.exe') @('-DFOOTLESS_DEFAULT_VARIANT=1', "-DFOOTLESS_DEFAULT_SEED_VALUE=$Seed") $loader
Build-One (Join-Path $out 'footless_loader_module_api.exe') @('-DFOOTLESS_DEFAULT_VARIANT=2', "-DFOOTLESS_DEFAULT_SEED_VALUE=$Seed") $loader
Build-One (Join-Path $out 'footless_loader_quiet.exe') @('-DFOOTLESS_QUIET', "-DFOOTLESS_DEFAULT_SEED_VALUE=$Seed") $loader
Build-One (Join-Path $out 'footless_loader_seed_alt.exe') @(
    '-include', (Join-Path $out 'api_hashes_alt.h'),
    "-DFOOTLESS_DEFAULT_SEED_VALUE=$AltSeed") $loader
Build-One (Join-Path $out 'footless_target.exe') @() @(
    (Join-Path $root 'src\target.c'), (Join-Path $root 'src\log.c'))
Build-One (Join-Path $out 'benign_app.exe') @() @((Join-Path $root 'src\benign.c'))
Build-One (Join-Path $out 'footless_marker.dll') @('-shared') @(
    (Join-Path $root 'src\marker.c'), (Join-Path $root 'src\log.c'))

Get-ChildItem -LiteralPath $out -File | Where-Object {
    $_.Extension -in @('.exe','.dll')
} | Get-FileHash -Algorithm SHA256 | Select-Object Path,Hash |
    Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $out 'sha256.csv')

Write-Host 'Build completed. No binary was executed.'
Write-Host 'Injection additionally requires FOOTLESS_LAB_CONFIRM=1 and FOOTLESS_VM_SNAPSHOT.'
