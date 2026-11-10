# Real AST functions over synthetic nodes. No desktop, native input, process, or timer is used.
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Candidate stability source parse failed' }
foreach ($name in @('Assert-DocumentProcessHandle','Assert-DocumentNodeIdentity','Read-AccountStabilityButton','Read-AccountStabilityFocus','Assert-AccountFocusStable','Prepare-OfflineButtonInvoke','Press-OfflineButton')) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'Candidate stability function missing' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$modeGate=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text.StartsWith('if ($SourceCandidateStability)')},$true))
if ($modeGate.Count -ne 1) { throw 'Native candidate mode binding gate missing' }
foreach ($case in @('candidate','official','missing_switch','missing_offline','wrong_mode','bad_commit')) {
    $SourceCandidateStability=$case -notin @('official','missing_switch')
    $OfflineAcceptance=$case -ne 'missing_offline'
    $binding=[pscustomobject]@{fixture_mode='source-client2-ui-candidate';source_commit='e50f877c92ea4ddcbbbc25a657aa046442b9ed90'}
    if ($case -eq 'official') { $binding=[pscustomobject]@{} }
    if ($case -eq 'wrong_mode') { $binding.fixture_mode='official' }
    if ($case -eq 'bad_commit') { $binding.source_commit='bad' }
    $report=@{}; $accepted=$true
    try { & ([scriptblock]::Create($modeGate[0].Extent.Text)) } catch { $accepted=$false }
    if ($accepted -ne ($case -in @('candidate','official'))) { throw 'Native source stability mode binding was bypassed' }
    if ($case -eq 'candidate' -and $report.fixture_mode -cne 'source-client2-ui-candidate') { throw 'Native candidate report lacks source scope' }
}
function New-StabilityNode([int]$Id,$Type,[string]$Name='') {
    $node=[pscustomobject]@{Id=$Id;Children=@();Sibling=$null;Parent=$null
        Current=[pscustomobject]@{ProcessId=20;ControlType=$Type;Name=$Name;IsEnabled=$true;IsKeyboardFocusable=$true;IsOffscreen=$false}}
    $node | Add-Member ScriptMethod GetRuntimeId { return @([int]$this.Id) }
    $node | Add-Member ScriptMethod SetFocus { throw 'Stability observation must not restore focus' }
    $node | Add-Member ScriptMethod TryGetCurrentPattern {
        param($Pattern,$Result)
        if ($Pattern -ne [Windows.Automation.InvokePattern]::Pattern) { throw 'Unexpected pattern requested' }
        $invoke=[pscustomobject]@{}
        $invoke | Add-Member ScriptMethod Invoke { $script:invokes++ }
        $Result.Value=$invoke
        return $true
    }
    return $node
}
function Reset-Stability {
    $script:mode='valid'; $script:guards=0; $script:pauses=0; $script:acquired=0; $script:disposed=0
    $script:invokes=0; $script:focusCalls=0; $script:lookups=0; $script:focusReads=0; $script:nameReads=0
    $script:report=@{offline=@{}}
    $script:clock=[pscustomobject]@{Elapsed=[pscustomobject]@{TotalSeconds=0.0;TotalMilliseconds=0.0}}
    $script:root=New-StabilityNode 1 ([Windows.Automation.ControlType]::Window)
    $script:document=New-StabilityNode 2 ([Windows.Automation.ControlType]::Document)
    $script:button=New-StabilityNode 3 ([Windows.Automation.ControlType]::Button) 'synthetic'
    $script:root.Children=@($script:document); $script:document.Children=@($script:button)
    $script:button.Parent=$script:document; $script:document.Parent=$script:root
    $script:live=[pscustomobject]@{StartTime=[datetime]::new(638000000000000000,[DateTimeKind]::Utc);SessionId=2;Path='C:\fixture\webview.exe';HasExited=$false;SafeHandle=[pscustomobject]@{IsInvalid=$false;IsClosed=$false}}
    $script:live | Add-Member ScriptMethod Dispose { $script:disposed++ }
    $script:walker=[pscustomobject]@{}
    $script:walker | Add-Member ScriptMethod GetFirstChild {
        param($Element)
        if ($script:mode -eq 'walker') { throw 'synthetic-private-secret' }
        if ($Element.Children.Count -gt 0) { return $Element.Children[0] }
        return $null
    }
    $script:walker | Add-Member ScriptMethod GetNextSibling { param($Element) return $Element.Sibling }
    $script:walker | Add-Member ScriptMethod GetParent { param($Element) return $Element.Parent }
}
function Assert-Target {
    param($Foreground)
    $script:guards++
    if ($script:mode -eq 'guard' -and $script:guards -eq 2) { throw 'synthetic-private-secret' }
    $script:ownedIds=[Collections.Generic.HashSet[int]]::new(); [void]$script:ownedIds.Add(20)
}
function Get-Process { param($Id,$ErrorAction) if ($Id -ne 20) { throw 'Unknown process requested' }; $script:acquired++; return $script:live }
function Get-OfflineReplacementRoot {
    if ($script:mode -eq 'latefirst' -and $script:clock.Elapsed.TotalSeconds -eq 0) { $script:clock.Elapsed.TotalSeconds=6 }
    return $script:root
}
function Get-OfflineReplacementWalker { return $script:walker }
function Get-AccountStabilityFocusedElement {
    if ($script:mode -eq 'focus' -and $script:pauses -gt 0) {
        $other=New-StabilityNode 4 ([Windows.Automation.ControlType]::Button); $other.Parent=$script:document; return $other
    }
    return $script:button
}
function Get-AccountStabilityRawWalker { return $script:walker }
function New-AccountStabilityClock { return $script:clock }
function Pause-AccountStability {
    $script:pauses++
    $script:clock.Elapsed.TotalSeconds++; $script:clock.Elapsed.TotalMilliseconds=$script:clock.Elapsed.TotalSeconds*1000
    switch ($script:mode) {
        'replacement' { $script:button.Id=4 }
        'exit' { $script:live.HasExited=$true }
        'reuse' { $script:live.StartTime=$script:live.StartTime.AddTicks(1) }
        'closed' { $script:live.SafeHandle.IsClosed=$true }
        'budget' { $script:clock.Elapsed.TotalSeconds=15 }
    }
}
function Read-TargetFocus {
    $script:focusReads++
    return @{belongs_to_target=$true;in_document=$true;offscreen=$false;runtime_id=$(if ($script:mode -eq 'focus' -and $script:pauses -gt 0) {'4'} else {'3'})}
}
function Find-FocusedOfflineButton {
    param($Name,[switch]$PrepareInvoke,$DiagnosticStage)
    $script:lookups++; $script:focusCalls++
    if ($PrepareInvoke) {
        $evidence=$null; $diag=@{}
        if ($DiagnosticStage) { $diag.DiagnosticStage=$DiagnosticStage }
        return (Prepare-OfflineButtonInvoke $script:button ([ref]$evidence) @diag)
    }
    return $script:button
}
function Send-OfflineKey { throw 'No input permitted in stability observation' }
# Execute the actual minimal reader, including ancestry walking, without mocking it.
foreach ($case in @('valid','foreign','exited','reused','foreignparent','outside','hidden','untyped_visibility')) {
    Reset-Stability
    $identities=@{20=@{process=$live;birth=$live.StartTime.ToUniversalTime().Ticks;session=$live.SessionId;image=$live.Path}}
    $script:metadataReads=0
    foreach ($node in @($root,$document,$button)) {
        foreach ($property in @('Name','Value','AutomationId','ClassName')) {
            $node.Current.PSObject.Properties.Remove($property)
            $node.Current | Add-Member ScriptProperty $property { $script:metadataReads++; throw 'synthetic-private-secret' }
        }
    }
    switch ($case) {
        'foreign' { $button.Current.ProcessId=99 }
        'exited' { $live.HasExited=$true }
        'reused' { $live.StartTime=$live.StartTime.AddTicks(1) }
        'foreignparent' { $document.Current.ProcessId=99 }
        'outside' { $button.Parent=$root }
        'hidden' { $button.Current.IsOffscreen=$true }
        'untyped_visibility' { $button.Current.IsOffscreen='false' }
    }
    $accepted=$false; $focus=$null
    try { $focus=Read-AccountStabilityFocus $identities $clock; $accepted=$true } catch {}
    if ($metadataReads -ne 0 -or $accepted -ne ($case -in @('valid','hidden'))) { throw 'Minimal focus reader read metadata or accepted foreign identity' }
    if ($case -eq 'valid' -and ($focus.runtime_id -cne '3' -or -not $focus.belongs_to_target -or -not $focus.in_document -or $focus.offscreen)) { throw 'Minimal focus reader lost original ancestry' }
    if ($case -eq 'hidden' -and $focus.offscreen -ne $true) { throw 'Minimal focus reader lost visibility evidence' }
}
# Exercise the real selector with changing ScriptProperty state getters.
foreach ($field in @('IsEnabled','IsKeyboardFocusable','IsOffscreen')) {
    foreach ($fault in @('second_throw','first_throw','null','wrong_type')) {
        Reset-Stability
        $identities=@{20=@{process=$live;birth=$live.StartTime.ToUniversalTime().Ticks;session=$live.SessionId;image=$live.Path}}
        $script:stateReads=0; $script:stateField=$field; $script:stateFault=$fault
        $button.Current.PSObject.Properties.Remove($field)
        $button.Current | Add-Member ScriptProperty $field {
            $script:stateReads++
            if ($script:stateFault -eq 'first_throw' -or ($script:stateFault -eq 'second_throw' -and $script:stateReads -gt 1)) { throw 'synthetic-private-secret' }
            if ($script:stateFault -eq 'null') { return $null }
            if ($script:stateFault -eq 'wrong_type') { return 'false' }
            return ($script:stateField -ne 'IsOffscreen')
        }
        $accepted=$false
        try { $null=Read-AccountStabilityButton '^synthetic$' $identities $clock; $accepted=$true } catch {}
        if ($accepted -ne ($fault -eq 'second_throw') -or $stateReads -ne 1 -or $focusCalls -ne 0 -or $invokes -ne 0) { throw 'Stability state getter was reread or unknown state accepted' }
        if ($fault -eq 'second_throw') {
            $accepted=$false
            try { $null=Read-AccountStabilityButton '^synthetic$' $identities $clock; $accepted=$true } catch {}
            if ($accepted -or $stateReads -ne 2) { throw 'Next stability sample accepted an unreadable state' }
        }
    }
}
Reset-Stability
Assert-AccountFocusStable $button '^synthetic$'
$evidence=$report.offline.account_focus_stability
if ($evidence.status -cne 'timed-window-passed' -or $evidence.completed_poll_count -cne 'not-observed' -or
    $evidence.observed_window_ms -lt 10000 -or $evidence.observations -ne 11 -or $pauses -ne 10 -or
    $acquired -ne 1 -or $disposed -ne 1 -or $focusCalls -ne 0 -or $invokes -ne 0) { throw 'Timed stability observation changed focus, effects, or evidence' }
foreach ($case in @('replacement','focus','exit','reuse','closed','budget','latefirst','guard','foreign','duplicate','disabled','hidden','notfocusable','type','name','depth','nodes','walker')) {
    Reset-Stability; $script:mode=$case
    switch ($case) {
        'foreign' {
            $button.Current.ProcessId=99; $button.Current.PSObject.Properties.Remove('Name')
            $button.Current | Add-Member ScriptProperty Name { $script:nameReads++; throw 'synthetic-private-secret' }
        }
        'duplicate' { $other=New-StabilityNode 4 ([Windows.Automation.ControlType]::Button) 'synthetic'; $other.Current.IsEnabled=$false; $button.Sibling=$other }
        'disabled' { $button.Current.IsEnabled=$false }
        'hidden' { $button.Current.IsOffscreen=$true }
        'notfocusable' { $button.Current.IsKeyboardFocusable=$false }
        'type' { $button.Current.ControlType=$null }
        'name' { $button.Current.PSObject.Properties.Remove('Name'); $button.Current | Add-Member ScriptProperty Name { throw 'synthetic-private-secret' } }
        'depth' { $cursor=$document; foreach ($id in 10..41) { $next=New-StabilityNode $id ([Windows.Automation.ControlType]::Pane); $cursor.Children=@($next); $cursor=$next }; $cursor.Children=@($button) }
        'nodes' { $cursor=$button; foreach ($id in 10..520) { $next=New-StabilityNode $id ([Windows.Automation.ControlType]::Pane); $cursor.Sibling=$next; $cursor=$next } }
    }
    $failed=$false
    try { Press-OfflineButton '^synthetic$' -VerifySourceStability } catch { $failed=$true }
    if (-not $failed -or $report.offline.account_focus_stability.status -eq 'timed-window-passed' -or
        $disposed -ne $acquired -or $lookups -ne 1 -or $focusCalls -ne 1 -or $invokes -ne 0 -or $nameReads -ne 0) { throw 'Invalid stability observation was repaired, invoked, or leaked handles' }
    if (($report | ConvertTo-Json -Depth 8) -match 'synthetic-private-secret') { throw 'Private observation escaped' }
}
# Both paths still invoke exactly once, after one normal focus; only candidate observes.
foreach ($candidate in @($false,$true)) {
    Reset-Stability
    Press-OfflineButton '^synthetic$' -VerifySourceStability:$candidate
    if ($lookups -ne 1 -or $focusCalls -ne 1 -or $invokes -ne 1 -or $disposed -ne $acquired) { throw 'Candidate observation changed normal focus/invoke counts' }
    if (-not $candidate -and ($pauses -ne 0 -or $report.offline.ContainsKey('account_focus_stability'))) { throw 'Official mode unexpectedly observed candidate stability' }
}
Write-Host 'PASS: read-only source candidate stability window and unchanged official action counts'
