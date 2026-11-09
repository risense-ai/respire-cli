# Synthetic policy tests only; this does not establish real GUI acceptance.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'GUI helper parse failed' }
foreach ($name in @('Focus-OfflineControl','Test-OfflineFocusRetryable','Find-FocusedOfflineButton')) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'Missing unique policy function' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Assert-Target { param($Foreground) if ($script:foreign) { throw 'synthetic foreign target' } }
function Pause-Probe {}
function Read-TargetFocus { return $script:focus }
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
    $script:lookups=0; $script:focusCalls=0; $script:scrollCalls=0; $script:foreign=$false; $script:ambiguous=$false
    $script:report=@{offline=@{}}
    $script:focus=@{belongs_to_target=$true;in_document=$true;runtime_id='7.11';offscreen=$false}
}
function Expect-Failure {
    $failed=$false
    try { $null=Find-FocusedOfflineButton '^synthetic$' } catch { $failed=$true }
    if (-not $failed) { throw 'Invalid synthetic focus was accepted' }
    if (($script:report | ConvertTo-Json -Depth 8) -match 'synthetic-private-secret') { throw 'Private diagnostic escaped' }
}
foreach ($failure in @('stale','disabled')) {
    Reset-Synthetic
    $script:elements=@((New-SyntheticElement -Failure $failure),(New-SyntheticElement))
    $result=Find-FocusedOfflineButton '^synthetic$'
    if ($lookups -ne 2 -or $focusCalls -ne 2 -or $result -ne $elements[1]) { throw 'Fresh focus element was not reacquired' }
}
Reset-Synthetic
$script:elements=@((New-SyntheticElement -Failure 'stale'))
Expect-Failure
if ($lookups -ne 5) { throw 'Stale retry bound failed' }
foreach ($kind in @('notfocusable')) {
    Reset-Synthetic
    $script:elements=@((New-SyntheticElement -Visible ($kind -ne 'hidden') -Focusable ($kind -ne 'notfocusable')))
    Expect-Failure
    if ($lookups -ne 5 -or $focusCalls -ne 0) { throw 'Readiness bound or focus guard failed' }
}
# Real scrolling is modeled only here; the production helper uses UIA itself.
Reset-Synthetic
$script:elements=@((New-SyntheticElement -Visible $false -ScrollMode 'normal'),(New-SyntheticElement))
$result=Find-FocusedOfflineButton '^synthetic$'
if ($lookups -ne 2 -or $scrollCalls -ne 1 -or $focusCalls -ne 1 -or $result -ne $elements[1]) {
    throw 'Scrolled button was not freshly reacquired and focused'
}
foreach ($mode in @('unsupported','normal','throws','foreign')) {
    Reset-Synthetic
    $script:elements=@((New-SyntheticElement -Visible $false -ScrollMode $mode))
    Expect-Failure
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
    Expect-Failure
    if ($lookups -gt 1) { throw 'Non-readiness failure was retried' }
}
# No raw exception, selector, UI value or identity is stored by readiness diagnostics.
if (($report | ConvertTo-Json -Depth 8) -match 'synthetic-private-secret') { throw 'Private diagnostic escaped' }
Write-Host 'PASS: synthetic focus readiness policy; real GUI acceptance remains required'
