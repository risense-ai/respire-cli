# Source-only regression: execute the actual helper with synthetic results, never products.
param([string]$Sweep = (Join-Path $PSScriptRoot 'dev-release-sweep.ps1'))
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Sweep, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Sweep parse failed' }
$helpers = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Complete-SmokeKeygen' }, $true))
if ($helpers.Count -ne 1) { throw 'Missing unique keygen helper' }
. ([scriptblock]::Create($helpers[0].Extent.Text))
function Assert-Smoke([string]$Name, [bool]$Condition) { if (-not $Condition) { throw $Name } }
$device = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) 'synthetic-keygen-device'))
$profile = Join-Path $device 'profiles/offline'
function New-Keygen {
    return [pscustomobject]@{ Ok=$true; Exit=0; Envelope=[pscustomobject]@{
        command='keygen'; status='ok'; summary=[pscustomobject]@{super='synthetic-secret';path=(Join-Path $profile 'session.json')}; actions=@('runtime start')
    } }
}
function Invoke-Om {
    param($Name, $ArgList, $DataDir, $AllowStatus, [switch]$NoReadyRetry, [switch]$HostProfile)
    $script:starts++
    if (($ArgList -join ' ') -cne '--json runtime start' -or $DataDir -cne $device -or
        ($AllowStatus -join ' ') -cne 'ok' -or -not $NoReadyRetry -or $HostProfile) { throw 'Unsafe Start invocation' }
    return $script:startResult
}
function Get-OwnedRuntimeHealth($DataDir) {
    $script:healthReads++
    if ($DataDir -cne $device -or $script:healthFailure) { throw 'Owned health rejected' }
    return $script:health
}
function Reset-Fixture {
    $script:starts=0; $script:healthReads=0; $script:healthFailure=$false
    $script:startResult=[pscustomobject]@{Ok=$true;Exit=0;Envelope=[pscustomobject]@{command='runtime.start';status='ok'}}
    $script:health=[pscustomobject]@{data_dir=$profile;store_ready=$true}
}
function Check-Run($Keygen, [bool]$ShouldPass, [int]$Starts, [int]$Reads) {
    $failed=$false
    try { Complete-SmokeKeygen 'synthetic' $Keygen $device } catch { $failed=$true }
    if ($failed -eq $ShouldPass -or $script:starts -ne $Starts -or $script:healthReads -ne $Reads) {
        throw 'Keygen Start fail-closed regression'
    }
}
Reset-Fixture; Check-Run (New-Keygen) $true 1 1
foreach ($case in @('not-ok','exit','warn','pending','fail','wrong-command','no-secret','no-path','no-action','foreign-profile','prefix-collision')) {
    Reset-Fixture; $key=New-Keygen
    switch ($case) {
        'not-ok' { $key.Ok=$false }
        'exit' { $key.Exit=1 }
        'warn' { $key.Envelope.status='warn' }
        'pending' { $key.Envelope.status='pending' }
        'fail' { $key.Envelope.status='fail' }
        'wrong-command' { $key.Envelope.command='login' }
        'no-secret' { $key.Envelope.summary.super='' }
        'no-path' { $key.Envelope.summary.path='' }
        'no-action' { $key.Envelope.actions=@() }
        'foreign-profile' { $key.Envelope.summary.path=Join-Path ([IO.Path]::GetTempPath()) 'foreign/session.json' }
        'prefix-collision' { $key.Envelope.summary.path=Join-Path ($device+'-other') 'session.json' }
    }
    Check-Run $key $false 0 0
}
foreach ($case in @('not-ok','exit','wrong-command','pending')) {
    Reset-Fixture
    switch ($case) {
        'not-ok' { $script:startResult.Ok=$false }
        'exit' { $script:startResult.Exit=1 }
        'wrong-command' { $script:startResult.Envelope.command='status' }
        'pending' { $script:startResult.Envelope.status='pending' }
    }
    Check-Run (New-Keygen) $false 1 0
}
foreach ($case in @('unready','wrong-profile','identity-rejected')) {
    Reset-Fixture
    switch ($case) {
        'unready' { $script:health.store_ready=$false }
        'wrong-profile' { $script:health.data_dir=Join-Path $device 'profiles/other' }
        'identity-rejected' { $script:healthFailure=$true }
    }
    Check-Run (New-Keygen) $false 1 1
}
# Inspect real callsites, not a duplicate model. Refusal cases must never acquire Start.
$commands=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst]},$true))
$calls=@($commands | Where-Object { $_.GetCommandName() -ceq 'Complete-SmokeKeygen' })
$expected=@("Complete-SmokeKeygen 'keygen-local' `$offlineKeys `$offlineDir", "Complete-SmokeKeygen 'keygen-force' `$forcedKeys `$offlineDir", "Complete-SmokeKeygen 'reset-vault-keygen' `$resetKeys `$resetDir")
if ($calls.Count -ne 3) { throw 'Unexpected keygen completion callsite' }
$source=Get-Content -LiteralPath $Sweep -Raw
$before=@('keygen-local-v4-material','keygen-force-rotates-material','reset-vault-local-keygen')
$after=@('keygen-local-write','offline-full-logout','reset-vault-old-local-write')
for ($i=0; $i -lt 3; $i++) {
    if ($calls[$i].Extent.Text -cne $expected[$i] -or
        $source.IndexOf("'"+$before[$i]+"'") -ge $calls[$i].Extent.StartOffset -or
        $source.IndexOf("'"+$after[$i]+"'") -le $calls[$i].Extent.EndOffset) { throw 'Keygen completion sequence changed' }
}
$invoke=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Invoke-Om'},$true))
if ($invoke.Count -ne 1 -or -not $invoke[0].Extent.Text.Contains('$readyFail = -not $NoReadyRetry -and')) { throw 'Explicit Start may be retried' }
foreach ($guard in @('keygen-local-overwrite-guard','keygen-local-memory-readable','full-logout-session-file-removed','reset-vault-mismatched-fixture-written','login-key-mismatch-original-data-readable')) {
    if (-not $source.Contains("Assert-Smoke '$guard'")) { throw 'Business assertion removed' }
}
Write-Host 'PASS: keygen fixture explicit handoff, rejection paths, exact profile, no replay, and business ordering'
