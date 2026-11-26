# Build an unsigned MSIX for the Microsoft Store. Partner Center signs it on upload.
# Usage: packaging\msix\build-msix.ps1 -Version 2026.11.0
# Build first: cargo build --profile store -p aivory-warden -p aivory-warden-desktop
#              (cd apps\desktop && npm run build) for the UI.
param(
  [Parameter(Mandatory)] [string] $Version,
  # Values from Partner Center > AIVory Warden (9MZ0VQZ1V112) > Product identity.
  [string] $IdentityName = "AIVoryInc.AIVoryWarden",
  [string] $Publisher = "CN=1E786547-45C5-4CB8-8218-99D720EF3558",
  [string] $PublisherDisplay = "AIVory",
  [string] $BinDir = "target\store",
  [string] $OutDir = "dist"
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\..\.."
Set-Location $root

# MSIX versions have four parts; the last part must be 0 for the Store.
$msixVersion = "$Version.0"

$sdk = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\makeappx.exe" |
  Sort-Object FullName | Select-Object -Last 1
if (-not $sdk) { throw "makeappx.exe not found. Install the Windows SDK." }

$stage = Join-Path $OutDir "msix-stage"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force "$stage\Assets" | Out-Null

foreach ($exe in "aivory-warden-desktop.exe", "aivory-warden.exe") {
  $src = Join-Path $BinDir $exe
  if (-not (Test-Path $src)) { throw "$src missing. Run: cargo build --profile store -p aivory-warden -p aivory-warden-desktop" }
  Copy-Item $src $stage
}

python "$PSScriptRoot\make-logos.py" "apps\desktop\src-tauri\icons\icon.png" "$stage\Assets"
if ($LASTEXITCODE) { throw "logo step failed" }

(Get-Content "$PSScriptRoot\AppxManifest.xml" -Raw).
  Replace("{{IDENTITY_NAME}}", $IdentityName).
  Replace("{{PUBLISHER}}", [Security.SecurityElement]::Escape($Publisher)).
  Replace("{{PUBLISHER_DISPLAY}}", [Security.SecurityElement]::Escape($PublisherDisplay)).
  Replace("{{VERSION}}", $msixVersion) |
  Set-Content -Encoding utf8 "$stage\AppxManifest.xml"

$out = Join-Path $OutDir "aivory-warden-$Version-x64.msix"
& $sdk.FullName pack /o /d $stage /p $out
if ($LASTEXITCODE) { throw "makeappx failed" }
Write-Host "MSIX: $out"
