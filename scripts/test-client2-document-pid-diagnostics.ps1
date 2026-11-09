# Actual tree AST: rejected PID observations never reach node diagnostics or input.
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Document PID source parse failed' }
foreach ($name in @('Read-TargetTree','Element-Info')) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'Document PID function missing' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
# Verify these seams retain the exact original HWND and ControlViewWalker sources.
foreach ($spec in @(@('Get-OfflineReplacementRoot','[Windows.Automation.AutomationElement]::FromHandle([IntPtr][long]$binding.hwnd)'),@('Get-OfflineReplacementWalker','[Windows.Automation.TreeWalker]::ControlViewWalker'))) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $spec[0]},$true))
    if ($nodes.Count -ne 1 -or -not $nodes[0].Extent.Text.Contains($spec[1])) { throw 'Tree source seam changed bound HWND or walker' }
}
function Get-OfflineReplacementRoot { return $script:root }
function Get-OfflineReplacementWalker { return $script:walker }
function Assert-DocumentNodeIdentity { param($Id,$Identities) $script:identityReads++; if ($Id -ne 20) { throw 'Unknown identity inspected' } }
function Send-TargetTab { $script:inputs++; throw 'Forbidden input' }
function Send-OfflineKey { $script:inputs++; throw 'Forbidden input' }
function Press-OfflineButton { $script:inputs++; throw 'Forbidden Invoke' }
$script:walker=[pscustomobject]@{}
$walker | Add-Member ScriptMethod GetFirstChild { param($Element) $script:walkerReads++; return $null }
$walker | Add-Member ScriptMethod GetNextSibling { param($Element) throw 'Unexpected sibling read' }
$script:ownedIds=[Collections.Generic.HashSet[int]]::new(); [void]$ownedIds.Add(20)
foreach ($mode in @('missing','null','wrong_type','throw','zero','negative','positive_unbound','positive_return','known')) {
    $script:report=@{}; $counts=@{pid=0;metadata=0}; $script:identityReads=0; $script:inputs=0; $script:walkerReads=0
    $current=[pscustomobject]@{}
    if ($mode -ne 'missing') {
        $getter={
            $counts.pid++
            switch ($mode) {
                'null' { return $null }
                'wrong_type' { return '20' }
                'throw' { throw 'Synthetic PID getter fault' }
                'zero' { return 0 }
                'negative' { return -1 }
                'positive_unbound' { return 99 }
                'positive_return' { return 99 }
                'known' { return 20 }
            }
        }.GetNewClosure()
        $current | Add-Member ScriptProperty ProcessId $getter
    }
    foreach ($field in @('Name','AutomationId','ClassName','IsPassword','ControlType','IsKeyboardFocusable','IsOffscreen')) {
        $getter={
            $counts.metadata++
            if ($mode -ne 'known') { throw 'Unproven node metadata read' }
            switch ($field) {
                'ControlType' { return [pscustomobject]@{ProgrammaticName='ControlType.Document'} }
                'IsPassword' { return $false }
                'IsKeyboardFocusable' { return $true }
                'IsOffscreen' { return $false }
                default { return '' }
            }
        }.GetNewClosure()
        $current | Add-Member ScriptProperty $field $getter
    }
    $script:root=[pscustomobject]@{Current=$current}
    $root | Add-Member ScriptMethod GetRuntimeId { return @(1,2) }
    $caught=$null; $result=$null
    try { $result=Read-TargetTree -ReportUnknownProcess:($mode -ne 'positive_unbound') -AdmittedIds $ownedIds -LiveIdentities @{20=@{}} } catch { $caught=$_.Exception.Message }
    if ($mode -eq 'known') {
        if ($null -ne $caught -or $result.document_count -ne 1 -or -not $result.traversal_complete -or $identityReads -ne 1 -or $walkerReads -ne 1 -or $report.ContainsKey('document_pid_diagnostic')) { throw 'Known live tree path changed' }
        continue
    }
    $expected='unavailable'; if ($mode -eq 'wrong_type') { $expected='invalid_type' }; if ($mode -in @('zero','negative')) { $expected='nonpositive' }; if ($mode -like 'positive_*') { $expected='unbound_positive' }
    $pidReads=1; if ($mode -eq 'missing') { $pidReads=0 }
    if ($counts.pid -ne $pidReads -or $counts.metadata -ne 0 -or $identityReads -ne 0 -or $walkerReads -ne 0 -or $inputs -ne 0 -or $report.Count -ne 1 -or $report.document_pid_diagnostic -cne $expected) { throw 'PID rejection read metadata, repeated getter, or escaped closed diagnostics' }
    if ($mode -eq 'positive_return') {
        if ($null -ne $caught -or $result -isnot [int] -or $result -ne 99) { throw 'Private unknown-positive proof protocol changed' }
    } elseif ($null -eq $caught -or ($mode -ne 'throw' -and $caught -cne 'UIA node belongs to an unbound process')) { throw 'PID rejection no longer fails closed with original error' }
}
Write-Host 'PASS: actual tree PID observations fail closed before metadata with fixed diagnostics'
