# Synthetic process identities only. Never open, stop, or kill a process.
$ErrorActionPreference = 'Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Cleanup helper parse failed' }
foreach ($name in @('Read-CheckpointCreationDate','Test-TrackedCreationIdentity')) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'Missing unique cleanup identity function' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Expect-CheckpointFailure($Record,[string]$Expected) {
    $failed=$false; $message=$null
    try { $null=Read-CheckpointCreationDate $Record } catch { $failed=$true; $message=$_.Exception.Message }
    if (-not $failed -or $message -cne $Expected) { throw 'Checkpoint rejection did not use expected guard' }
}
$exact=[datetime]::new(2026,11,9,16,57,38,[DateTimeKind]::Utc).AddTicks(9641230)
$record=[pscustomobject]@{CreationDate=$exact;creation_utc_ticks=$exact.Ticks.ToString([Globalization.CultureInfo]::InvariantCulture)}
# Exercise this interpreter's real JSON serializer, including Windows PowerShell 5.
$decoded=$record | ConvertTo-Json | ConvertFrom-Json
$decoded.CreationDate=Read-CheckpointCreationDate $decoded
if (-not (Test-TrackedCreationIdentity $record $decoded)) { throw 'Exact birth did not survive JSON roundtrip' }
foreach ($delta in @(1,10,10000)) {
    $reused=[pscustomobject]@{CreationDate=$exact.AddTicks($delta)}
    if (Test-TrackedCreationIdentity $reused $decoded) { throw 'Different process birth was accepted' }
}
$rounded=[pscustomobject]@{CreationDate=[datetime]::new($exact.Ticks-($exact.Ticks%10000),[DateTimeKind]::Utc)}
if (Test-TrackedCreationIdentity $rounded $decoded) { throw 'Millisecond birth substituted for exact evidence' }
foreach ($bad in @($null,123,$exact.Ticks,1.5,'','+123','01','1e15','synthetic-private-secret',' 123','123 ',"123`n")) {
    Expect-CheckpointFailure ([pscustomobject]@{creation_utc_ticks=$bad}) 'Detached cleanup requires exact creation ticks'
}
Expect-CheckpointFailure ([pscustomobject]@{CreationDate=$exact}) 'Detached cleanup requires exact creation ticks'
foreach ($bad in @('9223372036854775808','3155378976000000000')) {
    Expect-CheckpointFailure ([pscustomobject]@{creation_utc_ticks=$bad}) 'Detached cleanup creation ticks out of range'
}
$failed=$false
try { $null=Test-TrackedCreationIdentity ([pscustomobject]@{CreationDate='synthetic-private-secret'}) $decoded } catch {
    $failed=$_.Exception.Message -ceq 'Cleanup process birth evidence is not typed'
}
if (-not $failed) { throw 'Untyped process birth was accepted' }
Write-Output 'Synthetic cleanup identity checks passed (not native cleanup acceptance)'

# Exercise the actual binding function with synthetic health/process records only.
$nativeAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Native binding helper parse failed' }
foreach ($name in @('Test-OfflineProfilePath','Bind-OfflineRuntime','Assert-OfflineRuntime')) {
    $nodes=@($nativeAst.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'Unique native binding function required' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$binding=@{runtime_exe='C:\fixture\rsrs-runtime.exe';data_directory='C:\fixture';session_id=2;runtime_sha256=('a'*64)}
$nativeHealth=[pscustomobject]@{server='respire';v=1;pid=42;exe=$binding.runtime_exe;data_dir=$binding.data_directory}
$nativeProcess=[pscustomobject]@{Id=42;Path=$binding.runtime_exe;SessionId=2;StartTime=$exact}
$nativeRecord=[pscustomobject]@{ProcessId=42;ParentProcessId=41;ExecutablePath=$binding.runtime_exe;CreationDate=$exact;SessionId=2}
$nativeHash='a'*64
function Read-OfflineHttp([string]$Path) { return $nativeHealth }
function Get-Process { param($Id,$ErrorAction) return $nativeProcess }
function Get-CimInstance { param($ClassName,$Filter) return $nativeRecord }
function Get-FileHash { param($LiteralPath,$Algorithm) return [pscustomobject]@{Hash=$nativeHash} }
$OutputDirectory=Join-Path (Split-Path -Parent $PSScriptRoot) ('.verification/native-binding-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $OutputDirectory
try {
    foreach ($image in @('C:\fixture\rsrs-runtime.exe','\\?\C:\fixture\rsrs-runtime.exe')) {
        $nativeHealth.exe=$image; $report=@{offline=@{}}
        Bind-OfflineRuntime
        if ($report.offline.runtime_binding_stage -cne 'bound' -or $offlineRuntime.pid -ne 42) { throw 'Matching Runtime image did not bind' }
        if ($report.offline.runtime_binding_checks.Count -ne 8 -or @($report.offline.runtime_binding_checks.Values | Where-Object { $_ -isnot [bool] -or -not $_ }).Count) { throw 'Successful binding diagnostic was not eight true booleans' }
    }
    $nativeHealth.data_dir='\\?\C:\fixture'
    Bind-OfflineRuntime
    $null=Assert-OfflineRuntime
    $nativeHealth.data_dir='\\?\C:\foreign'
    $rejected=$false
    try { $null=Assert-OfflineRuntime } catch { $rejected=$_.Exception.Message -ceq 'Offline Runtime actor changed during business acceptance' }
    if (-not $rejected) { throw 'Repeated identity check accepted a foreign extended profile' }
    foreach ($case in @('foreign_image','empty_image','foreign_process','foreign_session','foreign_data','wrong_digest')) {
        $nativeHealth.exe=$binding.runtime_exe; $nativeHealth.data_dir=$binding.data_directory
        $nativeProcess.Path=$binding.runtime_exe; $nativeProcess.SessionId=2; $nativeHash='a'*64
        switch ($case) {
            foreign_image { $nativeHealth.exe='\\?\C:\foreign\rsrs-runtime.exe' }
            empty_image { $nativeHealth.exe=$null }
            foreign_process { $nativeProcess.Path='C:\foreign\rsrs-runtime.exe' }
            foreign_session { $nativeProcess.SessionId=3 }
            foreign_data { $nativeHealth.data_dir='\\?\C:\foreign' }
            wrong_digest { $nativeHash='b'*64 }
        }
        $report=@{offline=@{}}; $rejected=$false
        try { Bind-OfflineRuntime } catch { $rejected=$_.Exception.Message -ceq 'Offline Runtime health/process/profile/hash binding failed' }
        if (-not $rejected) { throw "Native binding did not reject synthetic case: $case" }
        $failedField=@{foreign_image='health_image';empty_image='health_image';foreign_process='process_image';foreign_session='session';foreign_data='data_directory';wrong_digest='image_digest'}[$case]
        $identity=$report.offline.runtime_binding_checks
        if ($identity[$failedField] -isnot [bool] -or $identity[$failedField] -or @($identity.Values | Where-Object { $_ -isnot [bool] }).Count -or @($identity.Values | Where-Object { -not $_ }).Count -ne 1) { throw 'Binding diagnostics changed the rejection or exported a nonboolean' }
    }
} finally {
    Remove-Item -LiteralPath (Join-Path $OutputDirectory 'native-gui.json') -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $OutputDirectory
}
Write-Output 'Synthetic Runtime image binding checks passed (not native acceptance)'
