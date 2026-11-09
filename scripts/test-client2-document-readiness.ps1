# Synthetic execution of actual metadata/readiness functions; no GUI acceptance claim.
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Document readiness source parse failed' }
foreach ($name in @('Element-Info','Assert-DocumentNodeIdentity','Wait-TargetDocument')) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'Document readiness function missing' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$element=[pscustomobject]@{Current=[pscustomobject]@{Name=$null;IsPassword=$false;ProcessId=17;ControlType=[pscustomobject]@{ProgrammaticName='ControlType.Pane'};AutomationId='';ClassName='';IsKeyboardFocusable=$false;IsOffscreen=$false}}
$element | Add-Member ScriptMethod GetRuntimeId { return @(1,2) }
$info=Element-Info $element
if ($info.name -cne '' -or $info.runtime_id -cne '1.2' -or $info.process_id -ne 17) { throw 'Unnamed UIA diagnostic lost identity' }
$element.Current.Name='x'*140
if ((Element-Info $element).name.Length -ne 128) { throw 'Name diagnostic bound changed' }
$element.Current.IsPassword=$true; $element.Current.Name='synthetic-private-secret'
if ((Element-Info $element).name -cne '') { throw 'Password diagnostic escaped' }
function Assert-Target { param($Foreground) $script:guards++; if ($script:foreign) { throw 'fixed foreign target' } }
function Pause-Probe { $script:pauses++ }
function Read-TargetTree {
    $script:reads++
    if ($script:treeFailure) { throw 'fixed tree failure' }
    return @{document_count=$(if ($script:reads -eq 1) {0} else {1});focusable_count=1;traversal_complete=$true;truncation_reasons=@();elapsed_ms=1}
}
$script:ownedIds=[Collections.Generic.HashSet[int]]::new()
$script:report=@{}; $script:guards=0; $script:reads=0; $script:pauses=0; $script:foreign=$false; $script:treeFailure=$false
Wait-TargetDocument
if ($guards -ne 3 -or $reads -ne 2 -or $pauses -ne 1 -or $report.document_readiness.attempts.Count -ne 2 -or
    -not $report.document_readiness.ready -or $report.document_readiness.budget_seconds -ne 15 -or $report.document_readiness_phase -cne 'ready') { throw 'Empty document did not wait under original guards and budget' }
foreach ($kind in @('guard','tree','budget')) {
    $script:report=@{}; $script:guards=0; $script:reads=0; $script:pauses=0
    $script:foreign=$kind -eq 'guard'; $script:treeFailure=$kind -eq 'tree'
    $expected= switch ($kind) { 'guard' {'fixed foreign target'} 'tree' {'fixed tree failure'} 'budget' {'Original WebView UIA Document/focusable controls not observed within readiness budget; inspect traversal truncation reasons'} }
    $caught=$null
    try { if ($kind -eq 'budget') { Wait-TargetDocument 0 } else { Wait-TargetDocument } } catch { $caught=$_.Exception.Message }
    if ($caught -cne $expected -or $pauses -ne 0) { throw 'Readiness failure was swallowed or retried' }
    $phase=switch ($kind) { 'guard' {'target_guard'} 'tree' {'read_tree'} 'budget' {'budget_exhausted'} }
    if ($report.document_readiness_phase -cne $phase -or $report.document_readiness.ready) { throw 'Failed readiness reported success' }
}
Write-Host 'PASS: unnamed metadata and guarded empty-document readiness'
