# Synthetic policy tests only; this does not establish real GUI acceptance.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'GUI helper parse failed' }
foreach ($name in @('Focus-OfflineControl','Test-OfflineFocusRetryable','Find-FocusedOfflineButton','Wait-OfflineRecoveryDismissed','Assert-OfflineLocalKeys')) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'Missing unique policy function' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Assert-Target { param($Foreground) $script:guardCalls++; if ($script:foreign -or $script:guardCalls -eq $script:failGuard) { throw 'synthetic foreign target' } }
function Pause-Probe {}
# Replacement traversal is exercised separately; these existing cases retain their original failure boundaries.
function Test-OfflineButtonReplacement { return $false }
function Read-TargetFocus { $script:focusReads++; if ($script:failRead) { throw 'synthetic-private-secret' }; return $script:focus }
function Find-OfflineControl {
    param($Type,$Name,$Seconds)
    $script:lookups++
    if ($script:ambiguous) { throw 'synthetic ambiguous selector' }
    return $script:elements[[Math]::Min($script:lookups-1,$script:elements.Count-1)]
}
function New-SyntheticElement([bool]$Visible=$true,[bool]$Focusable=$true,[string]$Failure='', [string]$ScrollMode='unsupported') {
    $element=[pscustomobject]@{Current=[pscustomobject]@{IsEnabled=$true;IsKeyboardFocusable=$Focusable;IsOffscreen=(-not $Visible)};Failure=$Failure;ScrollMode=$ScrollMode}
    $element | Add-Member ScriptMethod TryGetCurrentPattern {
        param($Pattern, $Result)
        if ($Pattern -ne [Windows.Automation.ScrollItemPattern]::Pattern) { throw 'Unexpected synthetic pattern' }
        if ($this.ScrollMode -eq 'unsupported') { return $false }
        $scroll=[pscustomobject]@{Mode=$this.ScrollMode}
        $scroll | Add-Member ScriptMethod ScrollIntoView {
            $script:scrollCalls++
            if ($this.Mode -eq 'throws') { throw 'synthetic-private-secret' }
            if ($this.Mode -eq 'foreign') { $script:foreign=$true }
        }
        $Result.Value=$scroll
        return $true
    }
    $element | Add-Member ScriptMethod GetRuntimeId { if ($this.Failure -eq 'runtimeid') { throw 'synthetic-private-secret' }; return @(7,11) }
    $element | Add-Member ScriptMethod SetFocus {
        $script:focusCalls++
        if ($this.Failure -eq 'stale') { throw [Windows.Automation.ElementNotAvailableException]::new() }
        if ($this.Failure -eq 'disabled') { throw [Windows.Automation.ElementNotEnabledException]::new() }
        if ($this.Failure -eq 'unknown') { throw 'synthetic-private-secret' }
    }
    return $element
}
function Reset-Synthetic {
    $script:guardCalls=0; $script:focusReads=0; $script:lookups=0; $script:focusCalls=0; $script:scrollCalls=0; $script:foreign=$false; $script:ambiguous=$false
    $script:failGuard=0; $script:failRead=$false
    $script:report=@{offline=@{}}
    $script:focus=@{belongs_to_target=$true;in_document=$true;runtime_id='7.11';offscreen=$false}
}
function Expect-Failure([string]$ExpectedMessage, [int]$Guards, [int]$Lookups, [int]$FocusCalls, [int]$FocusReads) {
    $failed=$false; $message=$null
    try { $null=Find-FocusedOfflineButton '^synthetic$' } catch { $failed=$true; $message=$_.Exception.Message }
    if (-not $failed) { throw 'Invalid synthetic focus was accepted' }
    # Do not print unexpected messages: they may contain the synthetic private marker.
    if ($message -cne $ExpectedMessage) { throw 'Synthetic failure came from an unexpected source' }
    if ($script:guardCalls -ne $Guards -or $script:lookups -ne $Lookups -or
        $script:focusCalls -ne $FocusCalls -or $script:focusReads -ne $FocusReads) {
        throw 'Synthetic failure did not traverse the expected identity and focus guards'
    }
    if (($script:report | ConvertTo-Json -Depth 8) -match 'synthetic-private-secret') { throw 'Private diagnostic escaped' }
}
$boundedFailure='Offline button did not become focus-ready within the bounded attempts'
$unretryableFailure='Offline button focus failed without a retryable UIA readiness condition'
foreach ($failure in @('stale','disabled')) {
    Reset-Synthetic
    $script:elements=@((New-SyntheticElement -Failure $failure),(New-SyntheticElement))
    $result=Find-FocusedOfflineButton '^synthetic$'
    if ($guardCalls -ne 5 -or $focusReads -ne 1 -or $lookups -ne 2 -or $focusCalls -ne 2 -or $result -ne $elements[1]) { throw 'Fresh focus element was not reacquired' }
}
Reset-Synthetic
$script:elements=@((New-SyntheticElement -Failure 'stale'))
Expect-Failure $boundedFailure 10 5 5 0
if ($lookups -ne 5) { throw 'Stale retry bound failed' }
foreach ($kind in @('notfocusable')) {
    Reset-Synthetic
    $script:elements=@((New-SyntheticElement -Visible ($kind -ne 'hidden') -Focusable ($kind -ne 'notfocusable')))
    Expect-Failure $boundedFailure 5 5 0 0
    if ($lookups -ne 5 -or $focusCalls -ne 0) { throw 'Readiness bound or focus guard failed' }
}
# Real scrolling is modeled only here; the production helper uses UIA itself.
Reset-Synthetic
$script:elements=@((New-SyntheticElement -Visible $false -ScrollMode 'normal'),(New-SyntheticElement))
$result=Find-FocusedOfflineButton '^synthetic$'
if ($guardCalls -ne 6 -or $focusReads -ne 1 -or $lookups -ne 2 -or $scrollCalls -ne 1 -or $focusCalls -ne 1 -or $result -ne $elements[1]) {
    throw 'Scrolled button was not freshly reacquired and focused'
}
foreach ($mode in @('unsupported','normal','throws','foreign')) {
    Reset-Synthetic
    $script:elements=@((New-SyntheticElement -Visible $false -ScrollMode $mode))
    $expectedGuards = switch ($mode) { 'unsupported' {1} 'normal' {7} 'throws' {2} 'foreign' {3} }
    $expectedLookups = if ($mode -eq 'normal') {3} else {1}
    Expect-Failure $unretryableFailure $expectedGuards $expectedLookups 0 0
    if ($focusCalls -ne 0) { throw 'Offscreen button received focus without visibility proof' }
    if ($mode -eq 'normal') {
        if ($scrollCalls -ne 2 -or $lookups -ne 3) { throw 'Ineffective scroll exceeded bounds' }
    } elseif ($lookups -ne 1) { throw 'Unsupported/failed/foreign scroll was retried' }
}
foreach ($kind in @('unknown','wrongid','foreignfocus','offscreen','foreigntarget','ambiguous')) {
    Reset-Synthetic
    $script:elements=@((New-SyntheticElement -Failure $kind))
    if ($kind -eq 'wrongid') { $script:focus.runtime_id='99' }
    if ($kind -eq 'foreignfocus') { $script:focus.belongs_to_target=$false }
    if ($kind -eq 'offscreen') { $script:focus.offscreen=$true }
    if ($kind -eq 'foreigntarget') { $script:foreign=$true }
    if ($kind -eq 'ambiguous') { $script:ambiguous=$true }
    switch ($kind) {
        'foreigntarget' { Expect-Failure 'synthetic foreign target' 1 0 0 0 }
        'ambiguous' { Expect-Failure 'synthetic ambiguous selector' 1 1 0 0 }
        'unknown' { Expect-Failure $unretryableFailure 2 1 1 0 }
        default { Expect-Failure $unretryableFailure 3 1 1 1 }
    }
    if ($lookups -gt 1) { throw 'Non-readiness failure was retried' }
}
# Exercise every failing focus phase without retrying or exposing exception text.
foreach ($phase in @('target_before','expected_id','set_focus','target_after','read_focus','match_focus')) {
    Reset-Synthetic
    $failure = switch ($phase) { 'set_focus' {'unknown'} 'expected_id' {'runtimeid'} default {''} }
    $script:elements=@((New-SyntheticElement -Failure $failure))
    switch ($phase) {
        'target_before' { $script:failGuard=2; $guards=2; $calls=0; $reads=0 }
        'expected_id' { $guards=2; $calls=0; $reads=0 }
        'set_focus' { $guards=2; $calls=1; $reads=0 }
        'target_after' { $script:failGuard=3; $guards=3; $calls=1; $reads=0 }
        'read_focus' { $script:failRead=$true; $guards=3; $calls=1; $reads=1 }
        'match_focus' { $script:focus.runtime_id='wrong'; $guards=3; $calls=1; $reads=1 }
    }
    Expect-Failure $unretryableFailure $guards 1 $calls $reads
    $d=$report.offline.focus_diagnostic
    $kind=if ($phase -eq 'match_focus') {'focus_mismatch'} else {'other_exception'}
    if ($d.phase -cne $phase -or $d.kind -cne $kind) { throw 'Focus diagnostic phase/class mismatch' }
    if ($phase -eq 'match_focus') {
        if (-not $d.observed.belongs_to_target -or -not $d.observed.in_document -or
            $d.observed.expected_id_match -or $d.observed.offscreen -or $d.observed.Count -ne 4) { throw 'Focus diagnostic predicates mismatch' }
    } elseif ($d.ContainsKey('observed')) { throw 'Focus evidence recorded before it was observed' }
}
foreach ($failure in @('stale','disabled')) {
    Reset-Synthetic
    $script:elements=@((New-SyntheticElement -Failure $failure))
    Expect-Failure $boundedFailure 10 5 5 0
    if ($report.offline.focus_diagnostic.phase -cne 'set_focus' -or
        $report.offline.focus_diagnostic.kind -cne $failure) { throw 'Known readiness classification changed' }
}
# Mismatch observations must remain independent, boolean-only, and non-retryable.
foreach ($case in @('unchanged','idchanged','idthrows','focusmissing','focusnonboolean','focusthrows','focusedother')) {
    Reset-Synthetic
    $script:focus.runtime_id='wrong'; $script:focus.control_type='ControlType.Button'
    $element=New-SyntheticElement
    $element.Current | Add-Member NoteProperty HasKeyboardFocus $true
    $script:idReads=0
    $element | Add-Member -Force ScriptMethod GetRuntimeId {
        $script:idReads++
        if ($script:idReads -gt 1 -and $script:observationCase -eq 'idchanged') { return @(7,12) }
        if ($script:idReads -gt 1 -and $script:observationCase -eq 'idthrows') { throw [Windows.Automation.ElementNotAvailableException]::new('synthetic-private-secret') }
        return @(7,11)
    }
    $script:observationCase=$case
    switch ($case) {
        'focusmissing' { $element.Current.PSObject.Properties.Remove('HasKeyboardFocus') }
        'focusnonboolean' { $element.Current.HasKeyboardFocus='synthetic-private-secret' }
        'focusthrows' {
            $element.Current.PSObject.Properties.Remove('HasKeyboardFocus')
            $element.Current | Add-Member ScriptProperty HasKeyboardFocus { throw [Windows.Automation.ElementNotEnabledException]::new('synthetic-private-secret') }
        }
        'focusedother' { $script:focus.control_type='synthetic-private-secret' }
    }
    $script:elements=@($element)
    Expect-Failure $unretryableFailure 3 1 1 1
    $d=$report.offline.focus_diagnostic
    if ($d.phase -cne 'match_focus' -or $d.kind -cne 'focus_mismatch' -or $d.observed.Count -ne 4) { throw 'Observation changed primary focus failure' }
    $detail=$d.mismatch_detail
    $keys=@('requested_id_available','requested_id_matches_original','requested_focus_available','requested_has_keyboard_focus','focused_type_available','focused_is_button')
    if ($detail.Count -ne $keys.Count) { throw 'Mismatch observation schema changed' }
    foreach ($key in $keys) { if (-not $detail.ContainsKey($key) -or $detail[$key] -isnot [bool]) { throw 'Mismatch observation is not a fixed boolean' } }
    $focusAvailable=$case -notin @('focusmissing','focusnonboolean','focusthrows')
    if ($detail.requested_id_available -ne ($case -ne 'idthrows') -or
        $detail.requested_id_matches_original -ne ($case -notin @('idchanged','idthrows')) -or
        $detail.requested_focus_available -ne $focusAvailable -or $detail.requested_has_keyboard_focus -ne $focusAvailable -or
        -not $detail.focused_type_available -or $detail.focused_is_button -ne ($case -ne 'focusedother') -or $idReads -ne 2) { throw 'Mismatch observations did not distinguish the fixed cases' }
}
# The direct helper also retains the exact original mismatch exception.
Reset-Synthetic
$script:focus.runtime_id='wrong'
$caught=$null
try { Focus-OfflineControl (New-SyntheticElement) } catch { $caught=$_.Exception.Message }
if ($caught -cne 'Offline control did not receive real target-document keyboard focus' -or
    $guardCalls -ne 2 -or $focusCalls -ne 1 -or $focusReads -ne 1 -or $lookups -ne 0) { throw 'Mismatch observation masked the primary failure' }
Reset-Synthetic
Focus-OfflineControl (New-SyntheticElement)
if ($report.offline.focus_diagnostic.ContainsKey('mismatch_detail')) { throw 'Mismatch observations ran on successful focus' }
# No raw exception, selector, UI value or identity is stored by readiness diagnostics.
if (($report | ConvertTo-Json -Depth 8) -match 'synthetic-private-secret') { throw 'Private diagnostic escaped' }
Write-Host 'PASS: synthetic focus readiness policy; real GUI acceptance remains required'

# Recovery dismissal/status diagnostics use only fixed-selector existence and a
# strict boolean. Mock objects deliberately have no Value property to read.
function Find-OfflineControl {
    param($Type,$Name,$Seconds,[switch]$AllowAbsent)
    if (-not $AllowAbsent -or $Type -notin @('ControlType.Edit','ControlType.Text')) {
        throw 'Unexpected recovery selector query'
    }
    $expected='^' + [regex]::Escape([regex]::Unescape('\u8bf7\u4fdd\u5b58\u672c\u673a\u6062\u590d\u6750\u6599')) + '$'
    if ($Name -cne $expected) { throw 'Recovery probe inspected an unexpected selector' }
    $script:recoveryQueries++
    if ($script:recoveryMode -eq 'ambiguous') { throw 'synthetic ambiguous recovery selector' }
    if ($script:recoveryMode -eq 'edit' -and $Type -eq 'ControlType.Edit') { return [pscustomobject]@{} }
    if ($script:recoveryMode -eq 'title' -and $Type -eq 'ControlType.Text') { return [pscustomobject]@{} }
    return $null
}
foreach ($mode in @('absent','edit','title','ambiguous')) {
    $script:failGuard=0; $script:failRead=$false
    $script:report=@{offline=@{}}; $script:recoveryMode=$mode; $script:recoveryQueries=0
    $failure=$null
    try { Wait-OfflineRecoveryDismissed } catch { $failure=$_.Exception.Message }
    if ($mode -eq 'absent') {
        if ($failure -or $report.offline.recovery_controls_absent -ne $true -or $recoveryQueries -ne 2) { throw 'Recovery absence was not verified' }
    } else {
        $expected=if ($mode -eq 'ambiguous') {'synthetic ambiguous recovery selector'} else {'Original recovery dialog controls did not disappear within the bounded checks'}
        if ($failure -cne $expected -or $report.offline.recovery_controls_absent) { throw 'Recovery presence guard failed' }
        if ($mode -ne 'ambiguous' -and $recoveryQueries -ne 20) { throw 'Recovery presence bound changed' }
    }
}
foreach ($inputCase in @(
    @{value=$true; expected=$null},
    @{value=$false; expected='Offline status does not confirm local keys'},
    @{value='true'; expected='Offline status local-key flag is missing or not boolean'},
    @{value=1; expected='Offline status local-key flag is missing or not boolean'},
    @{value=$null; expected='Offline status local-key flag is missing or not boolean'},
    @{value=@($true); expected='Offline status local-key flag is missing or not boolean'},
    @{value=@{secret='synthetic-private-secret'}; expected='Offline status local-key flag is missing or not boolean'}
)) {
    $script:failGuard=0; $script:failRead=$false
    $script:report=@{offline=@{}}; $failure=$null
    $envelope=[pscustomobject]@{summary=[pscustomobject]@{session=[pscustomobject]@{has_local_keys=$inputCase.value; secret='synthetic-private-secret'}}}
    try { Assert-OfflineLocalKeys $envelope } catch { $failure=$_.Exception.Message }
    if ($failure -cne $inputCase.expected) { throw 'Status boolean contract failed' }
    if (($report | ConvertTo-Json -Depth 8) -match 'synthetic-private-secret') { throw 'Status copied private material' }
}
Write-Host 'PASS: recovery dismissal and strict status boolean diagnostics'

# Guard the real acceptance setup order, not a duplicate model of the sequence.
# A completed host keygen drains any old owner and does not auto-start a new one.
$acceptance=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Invoke-OfflineGuiAcceptance'},$true))
if ($acceptance.Count -ne 1) { throw 'Missing unique offline acceptance function' }
$source=$acceptance[0].Extent.Text
$stages=@('key_generation','recovery_dismiss','runtime_start','account_verification','credential_persistence')
$previous=-1
foreach ($stage in $stages) {
    $marker="`$report.offline.action_stage = '$stage'"
    $position=$source.IndexOf($marker,[StringComparison]::Ordinal)
    if ($position -le $previous -or $source.IndexOf($marker,$position+1,[StringComparison]::Ordinal) -ge 0) { throw 'Offline setup stage order changed' }
    $previous=$position
}
$commands=@($acceptance[0].FindAll({param($n) $n -is [Management.Automation.Language.CommandAst]},$true))
$bindings=@($commands | Where-Object { $_.GetCommandName() -ceq 'Bind-OfflineRuntime' })
$dismissals=@($commands | Where-Object { $_.GetCommandName() -ceq 'Wait-OfflineRecoveryDismissed' })
$persist=@($commands | Where-Object { $_.GetCommandName() -ceq 'Assert-OfflineLocalKeys' })
$writes=@($commands | Where-Object { $_.GetCommandName() -ceq 'Create-OfflineMemory' })
if ($bindings.Count -ne 1 -or $dismissals.Count -ne 1 -or $persist.Count -ne 1 -or $writes.Count -ne 2 -or
    $dismissals[0].Extent.StartOffset -ge $bindings[0].Extent.StartOffset -or
    $bindings[0].Extent.StartOffset -ge $persist[0].Extent.StartOffset -or
    $persist[0].Extent.StartOffset -ge $writes[0].Extent.StartOffset) { throw 'Offline acceptance must bind once after keygen and verify persistence before business writes' }
Write-Host 'PASS: explicit post-keygen start and single-actor acceptance order'

& (Join-Path $PSScriptRoot 'test-client2-diary-readback.ps1')
& (Join-Path $PSScriptRoot 'test-client2-cleanup-identity.ps1')
& (Join-Path $PSScriptRoot 'test-client2-gui-exit-code.ps1')
& (Join-Path $PSScriptRoot 'test-client2-document-readiness.ps1')
& (Join-Path $PSScriptRoot 'test-client2-document-descendants.ps1')

& (Join-Path $PSScriptRoot 'test-client2-focus-replacement.ps1')
& (Join-Path $PSScriptRoot 'test-client2-source-candidate-binding.ps1')
& (Join-Path $PSScriptRoot 'test-client2-account-focus-stability.ps1')

& (Join-Path $PSScriptRoot 'test-client2-diary-navigation.ps1')

& (Join-Path $PSScriptRoot 'test-client2-stop-diagnostics.ps1')

& (Join-Path $PSScriptRoot 'test-client2-preinvoke-replacement.ps1')

& (Join-Path $PSScriptRoot 'test-client2-document-pid-diagnostics.ps1')

& (Join-Path $PSScriptRoot 'test-client2-document-sampling.ps1')

& (Join-Path $PSScriptRoot 'test-client2-field-postcondition.ps1')

& (Join-Path $PSScriptRoot 'test-client2-document-node-info.ps1')

& (Join-Path $PSScriptRoot 'test-client2-start-stop-selector.ps1')
