param([string]$Compiler = 'gcc')
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$bin = Join-Path $root 'bin'
New-Item -ItemType Directory -Force -Path $bin | Out-Null
$machine = (& $Compiler -dumpmachine | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $machine -notmatch '^x86_64-w64-mingw32$') {
    throw 'Use MinGW-w64 x64 GCC. x86 is not supported by the fixed x64 marker stub.'
}
$buildLog = Join-Path $bin 'build.log'
@("UTC: $([DateTime]::UtcNow.ToString('o'))", "Compiler: $Compiler", "Target: $machine") | Set-Content -LiteralPath $buildLog
& $Compiler --version | Add-Content -LiteralPath $buildLog
$flags = @('-std=c11','-O2','-g','-Wall','-Wextra','-Werror','-D_WIN32_WINNT=0x0601','-D__USE_MINGW_ANSI_STDIO=1','-municode','-static-libgcc')
foreach ($unit in @('target','injector','marker')) {
    $source = Join-Path $root "src\$unit.c"
    $output = Join-Path $bin $(if ($unit -eq 'marker') {'NT230_marker.dll'} else {"NT230_$unit.exe"})
    $extra = @()
    if ($unit -eq 'marker') {$extra = @('-shared')}
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $compilerOutput = & $Compiler @flags @extra $source '-o' $output 2>&1
    $compilerExit = $LASTEXITCODE
    $ErrorActionPreference = $previousPreference
    $compilerOutput | ForEach-Object {"$_"} | Tee-Object -FilePath $buildLog -Append
    if ($compilerExit -ne 0) {throw "Build failed: $unit"}
    "Built $output" | Tee-Object -FilePath $buildLog -Append
}
Get-ChildItem -LiteralPath $bin -File | Where-Object {$_.Extension -in @('.exe','.dll')} |
    Get-FileHash -Algorithm SHA256 | Select-Object Path,Hash |
    Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $bin 'sha256.csv')
Write-Host 'Build completed. No demo was executed.'
