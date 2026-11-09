# Execute the real bounded traversal/caller with synthetic UIA nodes, never real input.
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Replacement source parse failed' }
foreach ($name in @('Assert-DocumentProcessHandle','Assert-DocumentNodeIdentity','Focus-OfflineControl','Test-OfflineFocusRetryable','Test-OfflineButtonReplacement','Find-FocusedOfflineButton')) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'Replacement function missing' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Send-OfflineKey { throw 'Input forbidden during replacement proof' }
function Press-OfflineButton { throw 'Invoke forbidden during replacement proof' }
function Pause-Probe { $script:pauses++ }
function Assert-Target {
    param($Foreground)
    $script:guards++
    if ($script:failGuard -eq $script:guards) { throw 'synthetic-private-secret' }
    $script:ownedIds=[Collections.Generic.HashSet[int]]::new(); [void]$script:ownedIds.Add(20)
}
function New-ProofNode([int]$Id,$Type,[string]$Name='') {
    $node=[pscustomobject]@{Id=$Id;Reads=0;Children=@();Sibling=$null
        Current=[pscustomobject]@{ProcessId=20;ControlType=$Type;Name=$Name;IsEnabled=$true;IsKeyboardFocusable=$true;IsOffscreen=$false}}
    $node | Add-Member ScriptMethod GetRuntimeId {
        $this.Reads++
        if ($script:changeCandidate -and $this.Id -eq 3 -and $this.Reads -gt 1) { return @(8) }
        return @([int]$this.Id)
    }
    $node | Add-Member ScriptMethod SetFocus {
        $script:focusCalls++
        if ($script:focusThrows) { throw 'synthetic-private-secret' }
    }
    return $node
}
function Get-Process { param($Id,$ErrorAction) if ($Id -ne 20) { throw 'Unexpected proof process' }; $script:acquired++; return $script:live }
function Get-OfflineReplacementRoot { $script:proofs++; return $script:root }
function Get-OfflineReplacementWalker { return $script:walker }
function Reset-Proof {
    $script:guards=0; $script:failGuard=0; $script:proofs=0; $script:pauses=0; $script:lookups=0
    $script:focusCalls=0; $script:focusReads=0; $script:foreignNameReads=0; $script:changeCandidate=$false
    $script:focusThrows=$false; $script:focusOutside=$false; $script:alwaysMismatch=$false; $script:walkerThrows=$false
    $script:acquired=0; $script:disposed=0; $script:exitDuring=$false; $script:reuseDuring=$false; $script:spendBudget=$false; $script:proofClock=$null
    $script:live=[pscustomobject]@{StartTime=[datetime]::new(638000000000000000,[DateTimeKind]::Utc);SessionId=2;Path='C:\fixture\webview.exe';HasExited=$false;SafeHandle=[pscustomobject]@{IsInvalid=$false;IsClosed=$false}}
    $script:live | Add-Member ScriptMethod Dispose { $script:disposed++ }
    $script:report=@{offline=@{}}
    $script:root=New-ProofNode 1 ([Windows.Automation.ControlType]::Window)
    $script:document=New-ProofNode 2 ([Windows.Automation.ControlType]::Document)
    $script:button=New-ProofNode 3 ([Windows.Automation.ControlType]::Button) 'synthetic'
    $script:oldButton=New-ProofNode 9 ([Windows.Automation.ControlType]::Button) 'synthetic'
    $script:root.Children=@($script:document); $script:document.Children=@($script:button)
    $script:walker=[pscustomobject]@{}
    $script:walker | Add-Member ScriptMethod GetFirstChild {
        param($Element)
        if ($script:walkerThrows) { throw 'synthetic-private-secret' }
        if ($script:spendBudget) { $script:proofClock.Elapsed.TotalSeconds=10 }
        if ($script:exitDuring) { $script:live.HasExited=$true }
        if ($script:reuseDuring) { $script:live.StartTime=$script:live.StartTime.AddTicks(1) }
        if ($Element.Children.Count -gt 0) { return $Element.Children[0] }
        return $null
    }
    $script:walker | Add-Member ScriptMethod GetNextSibling { param($Element) return $Element.Sibling }
}
function Find-OfflineControl {
    param($Type,$Name,$Seconds)
    $script:lookups++
    if ($Type -cne 'ControlType.Button' -or $Name -cne '^synthetic$' -or $Seconds -le 0 -or $Seconds -gt 10) { throw 'Selector contract changed' }
    if ($script:lookups -eq 1) { return $script:oldButton }
    return $script:button
}
function Read-TargetFocus {
    $script:focusReads++
    return @{belongs_to_target=(-not $script:focusOutside);in_document=$true;offscreen=$false
        runtime_id=$(if ($script:alwaysMismatch -or $script:focusCalls -eq 1) {'2'} else {'3'})
        control_type='ControlType.Document'}
}
Reset-Proof
if (-not (Test-OfflineButtonReplacement '^synthetic$' '9' ([Diagnostics.Stopwatch]::StartNew()))) { throw 'Complete unique replacement was refused' }
if ($guards -ne 3 -or $proofs -ne 1 -or $acquired -ne 1 -or $disposed -ne 1 -or $focusCalls -ne 0 -or $pauses -ne 0) { throw 'Proof performed effects or omitted binding guards' }
foreach ($case in @('oldpresent','oldoutsidedocument','duplicate_disabled','disabled','hidden','notfocusable','missing','outside_document','foreign','depth','nodes','budget','midbudget','changedcandidate','guard','finalguard','walker','exitduring','reuseduring','invalidhandle')) {
    Reset-Proof
    $seconds=10
    $clock=[Diagnostics.Stopwatch]::StartNew()
    switch ($case) {
        'oldpresent' { $document.Children=@($oldButton); $oldButton.Sibling=$button }
        'oldoutsidedocument' { $root.Children=@($oldButton); $oldButton.Sibling=$document }
        'duplicate_disabled' {
            $other=New-ProofNode 4 ([Windows.Automation.ControlType]::Button) 'synthetic'; $other.Current.IsEnabled=$false; $button.Sibling=$other
        }
        'disabled' { $button.Current.IsEnabled=$false }
        'hidden' { $button.Current.IsOffscreen=$true }
        'notfocusable' { $button.Current.IsKeyboardFocusable=$false }
        'missing' { $document.Children=@() }
        'outside_document' { $root.Children=@($button) }
        'foreign' {
            $button.Current.ProcessId=99; $button.Current.PSObject.Properties.Remove('Name')
            $button.Current | Add-Member ScriptProperty Name { $script:foreignNameReads++; throw 'synthetic-private-secret' }
        }
        'depth' {
            $cursor=$document
            foreach ($id in 10..41) { $next=New-ProofNode $id ([Windows.Automation.ControlType]::Pane); $cursor.Children=@($next); $cursor=$next }
            $cursor.Children=@($button)
        }
        'nodes' {
            $cursor=$button
            foreach ($id in 10..520) { $next=New-ProofNode $id ([Windows.Automation.ControlType]::Pane); $cursor.Sibling=$next; $cursor=$next }
        }
        'budget' { $seconds=0 }
        'midbudget' { $script:spendBudget=$true; $script:proofClock=[pscustomobject]@{Elapsed=[pscustomobject]@{TotalSeconds=0.0}}; $clock=$script:proofClock }
        'changedcandidate' { $script:changeCandidate=$true }
        'guard' { $script:failGuard=2 }
        'finalguard' { $script:failGuard=3 }
        'walker' { $script:walkerThrows=$true }
        'exitduring' { $script:exitDuring=$true }
        'reuseduring' { $script:reuseDuring=$true }
        'invalidhandle' { $script:live.SafeHandle.IsInvalid=$true }
    }
    $accepted=$false
    try { $accepted=Test-OfflineButtonReplacement '^synthetic$' '9' $clock $seconds } catch {}
    if ($disposed -ne $acquired) { throw 'Proof failure leaked process handles' }
    if ($accepted -or $focusCalls -ne 0 -or $pauses -ne 0 -or $foreignNameReads -ne 0) { throw 'Invalid replacement proof crossed a boundary' }
}
# A second unreadable possible match must never disappear from uniqueness proof.
foreach ($field in @('ControlType','Name')) {
    foreach ($fault in @('throwing','missing','null','invalid')) {
        Reset-Proof
        $second=New-ProofNode 4 ([Windows.Automation.ControlType]::Button) 'synthetic'
        $button.Sibling=$second
        $second.Current.PSObject.Properties.Remove($field)
        switch ($fault) {
            'throwing' { $second.Current | Add-Member ScriptProperty $field { throw 'synthetic-private-secret' } }
            'null' { $second.Current | Add-Member NoteProperty $field $null }
            'invalid' { $second.Current | Add-Member NoteProperty $field 123 }
        }
        $accepted=$false
        try { $accepted=Test-OfflineButtonReplacement '^synthetic$' '9' ([Diagnostics.Stopwatch]::StartNew()) } catch {}
        if ($accepted -or $disposed -ne $acquired -or $focusCalls -ne 0 -or $pauses -ne 0) { throw 'Unreadable possible match escaped complete traversal proof' }
        # Exercise the actual caller with the same malformed second node.
        $script:guards=0; $script:proofs=0; $script:acquired=0; $script:disposed=0
        $caught=$null
        try { $null=Find-FocusedOfflineButton '^synthetic$' } catch { $caught=$_.Exception.Message }
        if ($caught -cne 'Offline button focus failed without a retryable UIA readiness condition' -or
            $report.offline.focus_diagnostic.kind -cne 'focus_mismatch' -or
            $lookups -ne 1 -or $focusCalls -ne 1 -or $focusReads -ne 1 -or $proofs -ne 1 -or
            $disposed -ne $acquired -or $pauses -ne 0) { throw 'Unreadable possible match changed the original mismatch or retried' }
        if (($report | ConvertTo-Json -Depth 8) -match 'synthetic-private-secret') { throw 'Unreadable node detail escaped' }
    }
}
# The real caller can reacquire only after the complete proof, before any effect.
Reset-Proof
$result=Find-FocusedOfflineButton '^synthetic$'
if ($disposed -ne $acquired) { throw 'Successful caller leaked process handles' }
if ($result -ne $button -or $lookups -ne 2 -or $focusCalls -ne 2 -or $focusReads -ne 2 -or $proofs -ne 1 -or $pauses -ne 0) { throw 'Verified replacement did not consume exactly one existing attempt' }
foreach ($case in @('oldpresent','duplicate','foreignfocus','providererror','prooferror','changedcandidate')) {
    Reset-Proof
    switch ($case) {
        'oldpresent' { $document.Children=@($oldButton) }
        'duplicate' { $button.Sibling=New-ProofNode 4 ([Windows.Automation.ControlType]::Button) 'synthetic' }
        'foreignfocus' { $script:focusOutside=$true }
        'providererror' { $script:focusThrows=$true }
        'prooferror' { $script:walkerThrows=$true }
        'changedcandidate' { $script:changeCandidate=$true }
    }
    $caught=$null
    try { $null=Find-FocusedOfflineButton '^synthetic$' } catch { $caught=$_.Exception.Message }
    if ($disposed -ne $acquired) { throw 'Failed caller leaked process handles' }
    if ($caught -cne 'Offline button focus failed without a retryable UIA readiness condition' -or
        $lookups -ne 1 -or $focusCalls -ne 1 -or $pauses -ne 0) { throw 'Failed replacement proof changed the primary failure or retried' }
    if ($case -in @('foreignfocus','providererror') -and $proofs -ne 0) { throw 'Unknown or foreign focus reached replacement proof' }
    if (($report | ConvertTo-Json -Depth 8) -match 'synthetic-private-secret') { throw 'Private proof detail escaped' }
}
# A proven replacement that is replaced again cannot expand the five-attempt limit.
Reset-Proof
$script:alwaysMismatch=$true
function Find-OfflineControl {
    param($Type,$Name,$Seconds)
    $script:lookups++
    $old=New-ProofNode (100+$script:lookups) ([Windows.Automation.ControlType]::Button) 'synthetic'
    return $old
}
$caught=$null
try { $null=Find-FocusedOfflineButton '^synthetic$' } catch { $caught=$_.Exception.Message }
if ($caught -cne 'Offline button focus failed without a retryable UIA readiness condition' -or
    $lookups -ne 5 -or $focusCalls -ne 5 -or $focusReads -ne 5 -or $proofs -ne 4 -or $pauses -ne 0) { throw 'Replacement recognition expanded attempt or effect bounds' }
if ($disposed -ne $acquired) { throw 'Bounded caller leaked process handles' }
Write-Host 'PASS: complete replacement proof and pre-effect bounded reacquisition'
