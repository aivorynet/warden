#requires -Version 7
<#
.SYNOPSIS
  Smoke test: MCP server over stdio against a real daemon, in an isolated WARDEN_HOME.
.DESCRIPTION
  Starts a daemon, creates a vault, adds a Command-provider secret with an MCP policy
  (host example.com), pairs a client, runs `aivory-warden mcp` and speaks JSON-RPC to it.
  Asserts that the secret never appears in any output. Writes the transcript, with the
  secret replaced by <redacted>, to docs/verification/mcp-stdio.txt. Needs network access
  to https://example.com/. Exit code 0 means pass.
#>
param(
  [string]$Exe = (Join-Path $PSScriptRoot '..\target\debug\aivory-warden.exe'),
  [string]$Transcript = (Join-Path $PSScriptRoot '..\docs\verification\mcp-stdio.txt')
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Exe)) {
  cargo build -q -p aivory-warden --manifest-path (Join-Path $PSScriptRoot '..\Cargo.toml')
}
$Exe = (Resolve-Path $Exe).Path

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('warden-mcp-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory $tmp | Out-Null
$env:WARDEN_HOME = $tmp
$env:WARDEN_NO_KEYCHAIN = '1'
$env:WARDEN_NO_NOTIFY = '1'

$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$b = New-Object byte[] 18; $rng.GetBytes($b)
$secret = 'smk-' + [BitConverter]::ToString($b).Replace('-', '').ToLower()
$password = 'pw-' + [guid]::NewGuid().ToString('N')

$allOutput = New-Object System.Text.StringBuilder
$log = New-Object System.Text.StringBuilder
function Note($t) { [void]$log.AppendLine($t) }
function Fail($m) { Write-Error "FAIL: $m"; throw $m }

function Run-Cli([string[]]$CliArgs, [string]$StdinText) {
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = $Exe
  foreach ($a in $CliArgs) { [void]$psi.ArgumentList.Add($a) }
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $p = [Diagnostics.Process]::Start($psi)
  $outT = $p.StandardOutput.ReadToEndAsync(); $errT = $p.StandardError.ReadToEndAsync()
  if ($StdinText) { $p.StandardInput.Write($StdinText) }
  $p.StandardInput.Close()
  if (-not $p.WaitForExit(60000)) { $p.Kill(); Fail "timeout: $($CliArgs -join ' ')" }
  $o = $outT.Result + $errT.Result
  [void]$allOutput.Append($o)
  if ($p.ExitCode -ne 0) { Fail "exit $($p.ExitCode): $($CliArgs[0]) $o" }
  return $o
}

$daemon = $null; $mcp = $null
try {
  # daemon (own process, output to files so no pipe is held open)
  $dout = Join-Path $tmp 'daemon.out'; $derr = Join-Path $tmp 'daemon.err'
  $daemon = Start-Process -FilePath $Exe -ArgumentList 'daemon' -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $dout -RedirectStandardError $derr
  Start-Sleep -Seconds 2
  Note '# steps: daemon, init --pledge, add (command provider, mcp host example.com), pair --cap mcp --save'
  [void](Run-Cli @('init', '--pledge', '--password-stdin', '--json') ($password + "`n"))
  $cfg = '{}'
  [void](Run-Cli @('add', '--name', 'smoke', '--provider', 'command', '--config', $cfg, '--mcp-host', 'example.com', '--secret-stdin') ($secret + "`n"))
  [void](Run-Cli @('pair', 'smoke-mcp', '--cap', 'mcp', '--save') $null)
  $list = Run-Cli @('list') $null
  Note "list: $($list.Trim())"

  # MCP child
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = $Exe; [void]$psi.ArgumentList.Add('mcp')
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
  $mcp = [Diagnostics.Process]::Start($psi)
  $errTask = $mcp.StandardError.ReadToEndAsync()

  function Send($obj) {
    $line = ($obj | ConvertTo-Json -Compress -Depth 10)
    Note ">> $line"
    $mcp.StandardInput.WriteLine($line); $mcp.StandardInput.Flush()
  }
  function Recv([int]$id) {
    while ($true) {
      $t = $mcp.StandardOutput.ReadLineAsync()
      if (-not $t.Wait(60000)) { Fail "no MCP answer for id $id" }
      $l = $t.Result
      if ($null -eq $l) { Fail "MCP closed before answer $id" }
      [void]$allOutput.AppendLine($l)
      Note "<< $l"
      $o = $l | ConvertFrom-Json
      if ($o.id -eq $id) { return $o }
    }
  }
  Send @{ jsonrpc = '2.0'; id = 1; method = 'initialize'; params = @{ protocolVersion = '2025-03-26'; capabilities = @{}; clientInfo = @{ name = 'smoke'; version = '1' } } }
  $r = Recv 1; if (-not $r.result.serverInfo) { Fail 'initialize: no serverInfo' }
  Send @{ jsonrpc = '2.0'; method = 'notifications/initialized' }
  Send @{ jsonrpc = '2.0'; id = 2; method = 'tools/list' }
  $r = Recv 2; $names = @($r.result.tools | ForEach-Object name)
  foreach ($n in 'list_secrets', 'http_request') { if ($names -notcontains $n) { Fail "tools/list lacks $n" } }
  Send @{ jsonrpc = '2.0'; id = 3; method = 'tools/call'; params = @{ name = 'list_secrets'; arguments = @{} } }
  $r = Recv 3; if ($r.error -or $r.result.isError) { Fail 'list_secrets failed' }
  if ($r.result.content[0].text -notmatch 'smoke') { Fail 'list_secrets lacks the secret name' }
  Send @{ jsonrpc = '2.0'; id = 4; method = 'tools/call'; params = @{ name = 'http_request'; arguments = @{ secret = 'smoke'; method = 'GET'; url = 'https://example.com/' } } }
  $r = Recv 4; if ($r.error -or $r.result.isError) { Fail "http_request failed: $($r.result.content[0].text)" }
  $body = $r.result.content[0].text | ConvertFrom-Json
  if ($body.status -ne 200) { Fail "http_request status $($body.status)" }
  Note "http_request status: $($body.status)"
  # negative check: a host outside the policy must be refused
  Send @{ jsonrpc = '2.0'; id = 5; method = 'tools/call'; params = @{ name = 'http_request'; arguments = @{ secret = 'smoke'; method = 'GET'; url = 'https://example.org/' } } }
  $r = Recv 5; if (-not ($r.error -or $r.result.isError)) { Fail 'host outside the policy was not refused' }
  Note 'host example.org refused: yes'
  $mcp.StandardInput.Close()
  if (-not $mcp.WaitForExit(10000)) { $mcp.Kill() }
  [void]$allOutput.Append($errTask.Result)
  if ($errTask.Result) { Note "mcp stderr: $($errTask.Result.Trim())" }

  # the secret must not appear in any output
  foreach ($f in $dout, $derr) { if (Test-Path $f) { [void]$allOutput.Append((Get-Content -Raw $f)) } }
  if ($allOutput.ToString().Contains($secret)) { Fail 'the secret appears in an output' }
  if ($log.ToString().Contains($secret)) { Fail 'the secret appears in the transcript' }
  Note 'ASSERT: the secret string does not appear in any output: pass'
  $dir = Split-Path $Transcript -Parent
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory $dir | Out-Null }
  $log.ToString().Replace($secret, '<redacted>') | Set-Content -Encoding utf8 $Transcript
  Write-Host "PASS. Transcript: $Transcript"
}
finally {
  if ($mcp -and -not $mcp.HasExited) { $mcp.Kill() }
  if ($daemon -and -not $daemon.HasExited) { Stop-Process -Id $daemon.Id -Force }
  Start-Sleep -Milliseconds 500
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
