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
function Assert-Target { param($Foreground) $script:guardCalls++; if ($script:foreign) { throw 'synthetic foreign target' } }
function Pause-Probe {}
function Read-TargetFocus { $script:focusReads++; return $script:focus }
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
    $element | Add-Member ScriptMethod GetRuntimeId { return @(7,11) }
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
    $script:report=@{offline=@{}}; $failure=$null
    $envelope=[pscustomobject]@{summary=[pscustomobject]@{session=[pscustomobject]@{has_local_keys=$inputCase.value; secret='synthetic-private-secret'}}}
    try { Assert-OfflineLocalKeys $envelope } catch { $failure=$_.Exception.Message }
    if ($failure -cne $inputCase.expected) { throw 'Status boolean contract failed' }
    if (($report | ConvertTo-Json -Depth 8) -match 'synthetic-private-secret') { throw 'Status copied private material' }
}
Write-Host 'PASS: recovery dismissal and strict status boolean diagnostics'
