# Synthetic contract only; real GUI and Runtime readback remain separate gates.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'GUI helper parse failed' }
foreach ($name in @('Assert-OfflineDiaryReader','Close-OfflineDiaryReader')) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'Missing unique diary policy function' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$script:title='synthetic.[diary]+title'; $script:body='synthetic diary body'
function Assert-Target { param($Foreground) if ($script:foreign) { throw 'Foreign target' }; $script:guards++ }
function Wait-OfflineRecoveryDismissed { if ($script:recovery) { throw 'Recovery dialog remains' }; $script:dismissals++ }
function Find-OfflineControl {
    param($Type,$Name,$Seconds,[switch]$AllowAbsent)
    if ($Type -cne 'ControlType.Edit' -or $Name -cne ('^'+[regex]::Escape($script:title)+'$')) { throw 'Unbound diary selector' }
    $script:lookups++
    if ($script:ambiguous) { throw 'Ambiguous target' }
    if ($AllowAbsent -and $script:closed) { return $null }
    return $script:element
}
function Press-OfflineButton {
    param($Name)
    if ($Name -cne [regex]::Unescape('\u005e\u5173\u95ed\u0024')) { throw 'Unexpected dialog action' }
    $script:closed=$true; $script:closes++
}
function Pause-Probe {}
function Reset-Diary {
    $script:guards=0; $script:dismissals=0; $script:lookups=0; $script:reads=0; $script:closes=0
    $script:foreign=$false; $script:recovery=$false; $script:ambiguous=$false; $script:closed=$false
    $script:readonly=$true; $script:supported=$true; $script:value=$script:body
    $script:element=[pscustomobject]@{Current=[pscustomobject]@{IsOffscreen=$false}}
    $script:element | Add-Member ScriptMethod TryGetCurrentPattern {
        param($Pattern,$Result)
        $script:reads++
        if ($Pattern -ne [Windows.Automation.ValuePattern]::Pattern) { throw 'Unexpected pattern' }
        if (-not $script:supported) { return $false }
        $Result.Value=[pscustomobject]@{Current=[pscustomobject]@{IsReadOnly=$script:readonly;Value=$script:value}}
        return $true
    }
}
Reset-Diary
Assert-OfflineDiaryReader $script:title $script:body
if ($script:dismissals -ne 1 -or $script:reads -ne 1 -or $script:guards -ne 2) { throw 'Diary read bypassed exact guarded path' }
Close-OfflineDiaryReader $script:title
if (-not $script:closed -or $script:closes -ne 1 -or $script:lookups -ne 3 -or $script:guards -ne 3) { throw 'Diary dialog closure did not verify exact Edit disappearance' }
foreach ($case in @('recovery','ambiguous','hidden','unsupported','editable','wrong-body','foreign')) {
    Reset-Diary
    switch ($case) {
        recovery {$script:recovery=$true}
        ambiguous {$script:ambiguous=$true}
        hidden {$script:element.Current.IsOffscreen=$true}
        unsupported {$script:supported=$false}
        editable {$script:readonly=$false}
        wrong-body {$script:value='synthetic-private-marker'}
        foreign {$script:foreign=$true}
    }
    $expected=@{
        recovery='Recovery dialog remains'; ambiguous='Ambiguous target'; hidden='Synthetic diary reader is not visible'
        unsupported='Synthetic diary reader has no value pattern'; editable='Synthetic diary reader is not read-only'
        'wrong-body'='Synthetic diary reader does not contain the saved body'; foreign='Foreign target'
    }[$case]
    $expectedReads=$(if ($case -in @('unsupported','editable','wrong-body')) { 1 } else { 0 })
    $failed=$false
    try { Assert-OfflineDiaryReader $script:title $script:body } catch {
        $failed=$true
        if ($_.Exception.Message -cne $expected) { throw 'Diary rejection came from an unexpected source' }
    }
    if (-not $failed) { throw 'Invalid diary read accepted' }
    if ($script:reads -ne $expectedReads) { throw 'Diary rejection bypassed its expected guard' }
}
$source=$ast.Extent.Text
$acceptance=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Invoke-OfflineGuiAcceptance'},$true))
if ($acceptance.Count -ne 1) { throw 'Missing offline acceptance' }
$part=$acceptance[0].Extent.Text
$read=$part.IndexOf('Assert-OfflineDiaryReader')
$close=$part.IndexOf('Close-OfflineDiaryReader')
$capture=$part.IndexOf('$report.screenshot = Capture-Target')
if ($read -lt 0 -or $capture -le $read -or $close -le $capture) { throw 'Diary read/capture/close order changed' }
$persist=$part.IndexOf("Read-OfflineRpc @('--json','diary')")
$unique=$part.IndexOf('Trivial UI write did not appear exactly once')
$titleGate=$part.IndexOf('Diary title differs from the explicit synthetic UI write')
if ($persist -lt 0 -or $unique -lt 0 -or $titleGate -lt 0 -or $persist -ge $read -or $unique -ge $read -or $titleGate -ge $read) { throw 'Persisted diary identity gate missing or moved after UI read' }
$settings=$part.IndexOf("Press-OfflineButton ([regex]::Unescape('\u005e\u8bbe\u7f6e\u0024'))")
if ($settings -le $close) { throw 'Settings navigation precedes closing diary dialog' }
Write-Host 'PASS: exact readonly diary value and normal dialog closure policy'
