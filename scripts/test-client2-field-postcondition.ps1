# Synthetic actual AST execution only: no OS input, processes, or recovery values.
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
if ('RespireNativeInput' -as [type]) { throw 'Refuse field tests with an existing native input type' }
Add-Type -TypeDefinition @'
using System;
public static class RespireNativeInput {
    public static int TextCalls, KeyCalls;
    public static bool Incomplete;
    public static int Text(IntPtr hwnd, string text) { TextCalls++; return Incomplete ? 1 : text.Length*2; }
    public static int Key(IntPtr hwnd, uint key) { KeyCalls++; return Incomplete ? 1 : 2; }
}
'@
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Field source parse failed' }
foreach ($name in @('Assert-DocumentProcessHandle','Assert-DocumentNodeIdentity','Read-AccountStabilityFocus','Assert-OfflineFieldIdentity','Read-OfflineFieldValue','Fill-OfflineField','Send-OfflineKey','Wait-OfflineRecoveryDismissed')) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'Field source function missing' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Assert-Target {
    param($Foreground)
    $script:guards++
    if ([RespireNativeInput]::TextCalls -gt 0) {
        if ($script:mode -eq 'exit') { $script:live.HasExited=$true }
        if ($script:mode -eq 'reuse') { $script:live.StartTime=[datetime]::new(101,[DateTimeKind]::Utc) }
        if ($script:mode -eq 'foreground') { throw 'Synthetic foreground changed' }
    }
    $script:ownedIds=[Collections.Generic.HashSet[int]]::new(); [void]$script:ownedIds.Add(20)
}
function Get-Process { param($Id,$ErrorAction) $script:acquired++; if ($Id -ne 20) { throw 'New process admitted' }; return $script:live }
function Find-OfflineControl { param($Type,$Name) $script:lookups++; return $script:field }
function Focus-OfflineControl { param($Element) $script:focuses++; if ($Element -ne $script:field) { throw 'Replacement focused' } }
function New-OfflineFieldClock { return $script:clock }
function Pause-Probe { $script:pauses++; $script:clock.Elapsed.TotalSeconds+=0.5 }
function Get-OfflineReplacementRoot { return $script:root }
function Get-AccountStabilityFocusedElement {
    if ([RespireNativeInput]::TextCalls -gt 0 -and $script:mode -eq 'deadline_before_value') { $script:clock.Elapsed.TotalSeconds=3 }
    if ([RespireNativeInput]::TextCalls -gt 0 -and $script:mode -eq 'focus_lost') { return $script:root }
    if ([RespireNativeInput]::TextCalls -gt 0 -and $script:mode -eq 'focus_unknown') { $script:field.Current.IsOffscreen=$null }
    return $script:field
}
function Get-AccountStabilityRawWalker { return $script:walker }
function New-FieldNode([int]$Id,$Type) {
    $node=[pscustomobject]@{Id=$Id;Current=[pscustomobject]@{ProcessId=20;ControlType=$Type;IsOffscreen=$false};Parent=$null}
    $node | Add-Member ScriptMethod GetRuntimeId { if ($this.Id -eq 7 -and [RespireNativeInput]::TextCalls -gt 0 -and $script:mode -eq 'id_change') { return @(8) }; return @([int]$this.Id) }
    return $node
}
function Reset-Field {
    [RespireNativeInput]::TextCalls=0; [RespireNativeInput]::KeyCalls=0; [RespireNativeInput]::Incomplete=($script:mode -eq 'incomplete')
    $script:report=@{offline=@{}}; $script:binding=@{hwnd=1}; $script:lookups=0; $script:focuses=0; $script:guards=0; $script:pauses=0; $script:acquired=0; $script:disposed=0; $script:patternCalls=0; $script:postValues=0
    $script:clock=[pscustomobject]@{Elapsed=[pscustomobject]@{TotalSeconds=0}}
    $clock | Add-Member ScriptMethod Restart { $this.Elapsed.TotalSeconds=0 }
    $script:live=[pscustomobject]@{HasExited=$false;StartTime=[datetime]::new(100,[DateTimeKind]::Utc);SessionId=1;Path='synthetic';SafeHandle=[pscustomobject]@{IsInvalid=$false;IsClosed=$false}}
    $live | Add-Member ScriptMethod Dispose { $script:disposed++ }
    $script:root=New-FieldNode 1 ([Windows.Automation.ControlType]::Window)
    $script:document=New-FieldNode 2 ([Windows.Automation.ControlType]::Document); $document.Parent=$root
    $script:field=New-FieldNode 7 ([Windows.Automation.ControlType]::Edit); $field.Parent=$document
    $script:walker=[pscustomobject]@{}
    $walker | Add-Member ScriptMethod GetParent { param($Element) return $Element.Parent }
    $script:pattern=[pscustomobject]@{Current=[pscustomobject]@{}}
    $pattern.Current | Add-Member ScriptProperty Value {
        if ([RespireNativeInput]::TextCalls -eq 0) { if ($script:mode -eq 'initial_nonempty') { return 'not empty' }; return '' }
        $script:postValues++
        switch ($script:mode) {
            'delayed' { if ($script:postValues -eq 1) { return '' }; if ($script:postValues -eq 2) { return 'Case' }; return 'Case-Sensitive' }
            'never' { return 'Case' }
            'wrong_case' { return 'case-sensitive' }
            'late_full' { $script:clock.Elapsed.TotalSeconds=3; return 'Case-Sensitive' }
            'value_unknown' { return $null }
            'pattern_lost' { throw 'Synthetic original pattern lost' }
            'exit_during_value' { $script:live.HasExited=$true; return 'Case-Sensitive' }
            default { return 'Case-Sensitive' }
        }
    }
    $field | Add-Member ScriptMethod GetCurrentPattern { param($Type) $script:patternCalls++; if ($Type -ne [Windows.Automation.ValuePattern]::Pattern) { throw 'Wrong original pattern' }; return $script:pattern }
    $field | Add-Member ScriptMethod GetCurrentPropertyValue {
        param($Property,$IgnoreDefault)
        if ($IgnoreDefault -ne $true) { throw 'Property defaults were allowed' }
        $post=[RespireNativeInput]::TextCalls -gt 0
        if ($Property -eq [Windows.Automation.AutomationElement]::ProcessIdProperty) {
            if ($post -and $script:mode -eq 'pid_unknown') { return $null }
            if ($post -and $script:mode -eq 'foreign') { return 99 }
            return 20
        }
        if ($Property -eq [Windows.Automation.AutomationElement]::IsPasswordProperty) {
            if ($post -and $script:mode -eq 'password') { return $true }
            if ($post -and $script:mode -eq 'password_unknown') { return $null }
            if ($post -and $script:mode -eq 'property_error') { throw 'Synthetic property failure' }
            return $false
        }
        if ($Property -eq [Windows.Automation.AutomationElement]::IsOffscreenProperty) {
            if ($post -and $script:mode -eq 'offscreen') { return $true }
            if ($post -and $script:mode -eq 'offscreen_unknown') { return 0 }
            return $false
        }
        if ($Property -eq [Windows.Automation.AutomationElement]::IsEnabledProperty) { return $true }
        throw 'Unexpected field property read'
    }
}
foreach ($script:mode in @('success','delayed','never','wrong_case','late_full','deadline_before_value','value_unknown','pattern_lost','exit_during_value','exit','reuse','foreground','id_change','pid_unknown','foreign','password','password_unknown','property_error','offscreen','offscreen_unknown','focus_lost','focus_unknown','incomplete','initial_nonempty')) {
    Reset-Field
    $caught=$null; try { Fill-OfflineField 'synthetic' 'Case-Sensitive' } catch { $caught=$_.Exception.Message }
    $success=$mode -in @('success','delayed'); $inputCount=1; $focusCount=1
    if ($mode -eq 'initial_nonempty') { $inputCount=0; $focusCount=0 }
    if (($null -eq $caught) -ne $success -or [RespireNativeInput]::TextCalls -ne $inputCount -or [RespireNativeInput]::KeyCalls -ne 0 -or $lookups -ne 1 -or $focuses -ne $focusCount -or $patternCalls -ne 1 -or $acquired -ne 1 -or $disposed -ne 1) { throw ('Field effect or lifetime boundary failed: '+$mode) }
    if ($mode -in @('never','wrong_case','late_full','deadline_before_value') -and $caught -cne 'Synthetic text was not observed in the original visible control') { throw 'Field deadline changed original failure' }
    if ($mode -eq 'delayed' -and ($postValues -ne 3 -or $pauses -ne 2)) { throw 'Delayed full value did not use read-only postcondition' }
    if ($mode -in @('exit','reuse','foreground','id_change','pid_unknown','foreign','password','password_unknown','property_error','offscreen','offscreen_unknown','focus_lost','focus_unknown','deadline_before_value','incomplete') -and $postValues -ne 0) { throw 'Unsafe field state reached value read' }
    if ($mode -notin @('delayed','never','wrong_case') -and $pauses -ne 0) { throw 'Unknown state was retried' }
    if ($report.offline.Count -ne 0) { throw 'Field contents or identities escaped to report' }
}
# Actual Escape sender: same guard/focus/send/postguard sequence and one key only.
function Assert-Target { param($Foreground) $script:steps.Add('guard'); if ($script:recoveryFail -eq 'guard' -or ($script:recoveryFail -eq 'post' -and [RespireNativeInput]::KeyCalls -gt 0)) { throw 'Synthetic recovery guard' } }
function Read-TargetFocus { $script:steps.Add('focus'); if ($script:recoveryFail -eq 'focus') { throw 'Synthetic recovery focus' }; return @{belongs_to_target=$true;in_document=$true;offscreen=$false;runtime_id='7'} }
foreach ($script:recoveryFail in @('none','guard','focus','send','post')) {
    $script:report=@{offline=@{}}; $script:steps=[Collections.Generic.List[string]]::new(); [RespireNativeInput]::KeyCalls=0; [RespireNativeInput]::Incomplete=($recoveryFail -eq 'send')
    $caught=$false; try { Send-OfflineKey 27 -RecoveryDismiss } catch { $caught=$true }
    $stage='after_guard'; $keys=1; $sequence='guard,focus,guard'
    switch ($recoveryFail) {
        'guard' { $stage='before_guard'; $keys=0; $sequence='guard' }
        'focus' { $stage='before_focus'; $keys=0; $sequence='guard,focus' }
        'send' { $stage='escape_send'; $sequence='guard,focus' }
    }
    if ($caught -ne ($recoveryFail -ne 'none') -or $report.offline.recovery_dismiss_detail -cne $stage -or [RespireNativeInput]::KeyCalls -ne $keys -or ($steps -join ',') -cne $sequence) { throw 'Recovery diagnostic changed action order' }
}
function Find-OfflineControl { param($Type,$Name,$Seconds,[switch]$AllowAbsent) $script:queries++; if (-not $AllowAbsent -or $Seconds -ne 1) { throw 'Recovery observation changed' }; if ($script:present) { return [pscustomobject]@{} }; return $null }
function Pause-Probe { $script:pauses++ }
foreach ($script:present in @($false,$true)) {
    $script:queries=0; $script:pauses=0; $script:report=@{offline=@{}}; $caught=$null
    try { Wait-OfflineRecoveryDismissed } catch { $caught=$_.Exception.Message }
    if ($present) {
        if ($queries -ne 20 -or $pauses -ne 10 -or $caught -cne 'Original recovery dialog controls did not disappear within the bounded checks' -or $report.offline.recovery_dismiss_detail -cne 'observe_absence') { throw 'Recovery presence protocol changed' }
    } elseif ($queries -ne 2 -or $pauses -ne 0 -or $null -ne $caught -or $report.offline.recovery_dismiss_detail -cne 'complete') { throw 'Recovery completion protocol changed' }
}
Write-Host 'PASS: one text input with a strict three-second read-only postcondition and recovery-only breadcrumbs'
