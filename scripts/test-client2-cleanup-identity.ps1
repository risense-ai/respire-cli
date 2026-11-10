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
