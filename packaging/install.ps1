<#
.SYNOPSIS
  Install Aivory Warden on Windows without a package manager.
.DESCRIPTION
  Downloads the release zip for this CPU, checks its SHA-256 against SHA256SUMS, and installs
  aivory-warden.exe and awd.exe into $env:WARDEN_PREFIX\bin (default %LOCALAPPDATA%\Aivory\Warden\bin).
  The folder goes on the user PATH. -Service and -Extension are off by default.
  Environment: WARDEN_VERSION (fixed version, default latest), WARDEN_PREFIX (install prefix).
.EXAMPLE
  irm https://github.com/aivorynet/warden/releases/latest/download/install.ps1 | iex
.EXAMPLE
  & ([scriptblock]::Create((irm https://github.com/aivorynet/warden/releases/latest/download/install.ps1))) -Service -Extension
#>
param(
  [switch]$Service,
  [switch]$Extension
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repo = 'aivorynet/warden'
$prefix = if ($env:WARDEN_PREFIX) { $env:WARDEN_PREFIX } else { Join-Path $env:LOCALAPPDATA 'Aivory\Warden' }
$bin = Join-Path $prefix 'bin'

$arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
switch ($arch) {
  'AMD64' { $target = 'x86_64-pc-windows-msvc' }
  'ARM64' { $target = 'aarch64-pc-windows-msvc' }
  default { throw "warden: no build for CPU $arch" }
}
$name = "aivory-warden-$target"
if ($env:WARDEN_VERSION) {
  $v = $env:WARDEN_VERSION.TrimStart('v')
  $base = "https://github.com/$repo/releases/download/v$v"
} else {
  $base = "https://github.com/$repo/releases/latest/download"
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("warden-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Write-Host "warden: downloading $base/$name.zip"
  Invoke-WebRequest "$base/$name.zip" -OutFile (Join-Path $tmp "$name.zip")
  Invoke-WebRequest "$base/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS')

  $line = Get-Content (Join-Path $tmp 'SHA256SUMS') |
    Where-Object { $_.Trim() -and (($_ -split '\s+', 2)[1].TrimStart('*') -eq "$name.zip") } |
    Select-Object -First 1
  if (-not $line) { throw "warden: $name.zip is not listed in SHA256SUMS" }
  $expected = ($line -split '\s+')[0].ToLowerInvariant()
  $actual = (Get-FileHash (Join-Path $tmp "$name.zip") -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($expected -ne $actual) { throw "warden: SHA-256 mismatch for $name.zip (expected $expected, got $actual)" }
  Write-Host 'warden: SHA-256 ok'

  Expand-Archive (Join-Path $tmp "$name.zip") -DestinationPath $tmp -Force
  New-Item -ItemType Directory -Path $bin -Force | Out-Null
  foreach ($f in 'aivory-warden.exe', 'awd.exe') {
    Copy-Item (Join-Path $tmp "$name\$f") (Join-Path $bin $f) -Force
  }
  Write-Host "warden: installed aivory-warden and awd in $bin"
} finally {
  Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $bin) {
  [Environment]::SetEnvironmentVariable('Path', "$userPath;$bin".TrimStart(';'), 'User')
  Write-Host 'warden: added the folder to the user PATH. Open a new terminal.'
}

if ($Service) { & (Join-Path $bin 'aivory-warden.exe') service install }
if ($Extension) { & (Join-Path $bin 'aivory-warden.exe') extension install }
Write-Host 'warden: next step: awd init'
