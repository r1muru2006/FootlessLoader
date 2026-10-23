param([string]$Compiler = 'gcc')

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$outputDir = Join-Path $root 'resolve-build'
$output = Join-Path $outputDir 'footless-resolver.exe'

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
$machine = (& $Compiler -dumpmachine | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $machine -notmatch '^x86_64-w64-mingw32$') {
    throw 'Use an x86_64 MinGW-w64 compiler. This lab is x64-only.'
}

$flags = @(
    '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
    '-D_WIN32_WINNT=0x0601', '-D__USE_MINGW_ANSI_STDIO=1',
    '-static-libgcc'
)
$sources = @(
    (Join-Path $root 'hash.c'),
    (Join-Path $root 'resolver.c'),
    (Join-Path $root 'ntapi.c'),
    (Join-Path $root 'main.c')
)

& $Compiler @flags @sources '-o' $output
if ($LASTEXITCODE -ne 0) {
    throw 'Resolver build failed.'
}

$hash = Get-FileHash -Algorithm SHA256 -LiteralPath $output
[pscustomobject]@{Path='footless-resolver.exe';Hash=$hash.Hash} |
    Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $outputDir 'sha256.csv')

Write-Host 'Built resolve-build\footless-resolver.exe'
Write-Host 'This demo only resolves and calls benign APIs in the current process.'
