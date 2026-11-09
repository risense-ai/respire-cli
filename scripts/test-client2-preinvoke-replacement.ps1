# Actual caller, five-attempt loop and preparation, with synthetic observations.
# Complete proof traversal and identity failures remain covered by focus-replacement.
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Pre-invoke source parse failed' }
foreach ($name in @('Find-FocusedOfflineButton','Prepare-OfflineButtonInvoke','Press-OfflineButton')) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'Pre-invoke function missing' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Assert-Target { param($Foreground) $script:guards++; if ($script:case -eq 'post_guard' -and $script:invokes -eq 1) { throw 'Synthetic postguard failure' } }
function Find-OfflineControl { param($Type,$Name,$Seconds) $script:selects++; if ($Seconds -le 0 -or $Seconds -gt 10) { throw 'Selector budget expanded' }; return $script:element }
function Focus-OfflineControl { param($Element,$Evidence) $script:focuses++ }
function Test-OfflineFocusRetryable { param($Exception) throw 'Preparation entered generic retry handler' }
function Pause-Probe { throw 'Preparation added a pause' }
function Assert-AccountFocusStable { param($Element,$Name) $script:stability++ }
function Read-TargetFocus {
    $script:reads++
    if ($script:useFocusOverride) { return $script:focusOverride }
    if ($script:case -eq 'read_error') { throw 'Synthetic focus read failure' }
    $different=($script:case -in @('replacement','old_present','ambiguous','unknown_proof','nonboolean_proof','all_replaced','foreign','outside','hidden','candidate_mismatch'))
    if ($script:case -eq 'replacement' -and $script:selects -gt 1) { $different=$false }
    $id='7'; if ($different) { $id='9' }
    return @{runtime_id=$id;belongs_to_target=($script:case -ne 'foreign');in_document=($script:case -ne 'outside');offscreen=($script:case -eq 'hidden')}
}
function Test-OfflineButtonReplacement {
    param($Name,$OriginalId,$Clock,$Seconds)
    $script:proofs++
    if ($OriginalId -cne '7' -or $Seconds -ne 10 -or $Clock.Elapsed.TotalSeconds -ge 10 -or $script:invokes -ne 0) { throw 'Proof lost original identity, budget or no-effect boundary' }
    if ($script:case -eq 'unknown_proof') { throw 'Synthetic proof failure' }
    if ($script:case -eq 'nonboolean_proof') { return 'true' }
    return ($script:case -in @('replacement','all_replaced'))
}
$script:useFocusOverride=$false
$script:element=[pscustomobject]@{Current=[pscustomobject]@{IsEnabled=$true;IsKeyboardFocusable=$true;IsOffscreen=$false}}
$element | Add-Member ScriptMethod GetRuntimeId { $script:ids++; return @(7) }
$element | Add-Member ScriptMethod TryGetCurrentPattern {
    param($Type,$Result)
    $script:patterns++
    if ($script:case -eq 'pattern_missing') { return $false }
    $Result.Value=$script:pattern; return $true
}
$script:pattern=[pscustomobject]@{}
$pattern | Add-Member ScriptMethod Invoke { $script:invokes++; if ($script:case -eq 'invoke_error') { throw 'Synthetic invoke failure' } }
foreach ($script:case in @('success','replacement','old_present','ambiguous','unknown_proof','nonboolean_proof','all_replaced','foreign','outside','hidden','read_error','pattern_missing','invoke_error','post_guard','candidate_success','candidate_mismatch')) {
    $script:selects=0; $script:focuses=0; $script:reads=0; $script:ids=0; $script:patterns=0; $script:proofs=0; $script:invokes=0; $script:guards=0; $script:stability=0
    $script:report=@{offline=@{}}
    $caught=$null
    try {
        if ($case -like 'candidate_*') { Press-OfflineButton '^synthetic$' -VerifySourceStability } else { Press-OfflineButton '^synthetic$' }
    } catch { $caught=$_.Exception.Message }
    $n=1; $p=0; $v=0; $readCount=1; $guardCount=2; $shouldPass=$false
    switch ($case) {
        'success' { $v=1; $guardCount=3; $shouldPass=$true }
        'replacement' { $n=2; $p=1; $v=1; $readCount=2; $guardCount=5; $shouldPass=$true }
        'old_present' { $p=1 }
        'ambiguous' { $p=1 }
        'unknown_proof' { $p=1 }
        'nonboolean_proof' { $p=1 }
        'all_replaced' { $n=5; $p=4; $readCount=5; $guardCount=10 }
        'pattern_missing' { $readCount=0; $guardCount=1 }
        'invoke_error' { $v=1 }
        'post_guard' { $v=1; $guardCount=3 }
        'candidate_success' { $v=1; $guardCount=3; $shouldPass=$true }
    }
    $stable=0; if ($case -like 'candidate_*') { $stable=1 }
    if ($selects -ne $n -or $focuses -ne $n -or $ids -ne $n -or $patterns -ne $n -or $reads -ne $readCount -or $proofs -ne $p -or $invokes -ne $v -or $guards -ne $guardCount -or $stability -ne $stable -or ($null -eq $caught) -ne $shouldPass) { throw ('Pre-invoke operation boundary failed: '+$case) }
    if ($case -in @('old_present','ambiguous','unknown_proof','nonboolean_proof','all_replaced','foreign','outside','hidden','candidate_mismatch') -and $caught -cne 'Offline button focus changed before UIA Invoke') { throw 'Original final mismatch was not preserved' }
}
Write-Host 'PASS: actual pre-invoke loop preserves five attempts, bounded proof and zero-or-one effect'

# Exercise real preparation through the real caller/loop with hostile properties.
foreach ($field in @('belongs_to_target','in_document','offscreen','runtime_id')) {
    foreach ($fault in @('missing','null','number','wrong_type','empty','throw')) {
        $script:case='invalid_focus'; $script:useFocusOverride=$true
        $script:focusOverride=[pscustomobject]@{belongs_to_target=$true;in_document=$true;offscreen=$false;runtime_id='7'}
        $focusOverride.PSObject.Properties.Remove($field)
        $counter=@{reads=0}
        if ($fault -ne 'missing') {
            $getter={
                $counter.reads++
                switch ($fault) {
                    'null' { return $null }
                    'number' { return 0 }
                    'wrong_type' { if ($field -eq 'runtime_id') { return $true }; return 'true' }
                    'empty' { return '' }
                    'throw' { throw 'Synthetic property failure' }
                }
            }.GetNewClosure()
            $focusOverride | Add-Member ScriptProperty $field $getter
        }
        $script:selects=0; $script:focuses=0; $script:reads=0; $script:ids=0; $script:patterns=0; $script:proofs=0; $script:invokes=0; $script:guards=0; $script:stability=0
        $script:report=@{offline=@{}}
        $caught=$null; try { Press-OfflineButton '^synthetic$' } catch { $caught=$_.Exception.Message }
        $expectedReads=1; if ($fault -eq 'missing') { $expectedReads=0 }
        if ($null -eq $caught -or ($fault -ne 'throw' -and $caught -cne 'Offline button focus changed before UIA Invoke') -or $selects -ne 1 -or $focuses -ne 1 -or $reads -ne 1 -or $ids -ne 1 -or $patterns -ne 1 -or $proofs -ne 0 -or $invokes -ne 0 -or $guards -ne 2 -or $counter.reads -ne $expectedReads) { throw 'Unknown focus property escaped fail-closed preparation' }
    }
}
# Valid first reads with a later throwing getter must not be read twice.
$script:case='single_read'; $script:focusOverride=[pscustomobject]@{}; $counts=@{}
foreach ($field in @('belongs_to_target','in_document','offscreen','runtime_id')) {
    $counts[$field]=0
    $getter={
        $counts[$field]++
        if ($counts[$field] -gt 1) { throw 'Focus property reread' }
        if ($field -eq 'runtime_id') { return '7' }
        return ($field -ne 'offscreen')
    }.GetNewClosure()
    $focusOverride | Add-Member ScriptProperty $field $getter
}
$script:selects=0; $script:focuses=0; $script:reads=0; $script:ids=0; $script:patterns=0; $script:proofs=0; $script:invokes=0; $script:guards=0
$script:report=@{offline=@{}}
Press-OfflineButton '^synthetic$'
if ($invokes -ne 1 -or $selects -ne 1 -or $focuses -ne 1 -or $proofs -ne 0 -or @($counts.Values | Where-Object { $_ -ne 1 }).Count -ne 0) { throw 'Final focus fields were not single-read validated' }
$script:useFocusOverride=$false
Write-Host 'PASS: final focus property types and single-read lifetime fail closed'
