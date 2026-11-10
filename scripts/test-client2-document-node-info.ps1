# Actual startup reader/tree with explicit synthetic .NET provider methods.
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -ReferencedAssemblies @([Windows.Automation.AutomationElement].Assembly.Location,[Windows.Automation.ElementNotAvailableException].Assembly.Location) -TypeDefinition @'
using System;
using System.Windows.Automation;
public sealed class RespireStrictNodeProvider {
    public string Point = "", Fault = "";
    public bool Password;
    public bool UnknownReadiness;
    public object ControlValue = ControlType.Document, FocusableValue = true, OffscreenValue = false;
    public int NodeId = 1;
    public int PidCalls, NameCalls, GetterCalls;
    public string[] Calls = new string[0];
    public Action<string> Observe;
    public object Current { get { GetterCalls++; throw new Exception("Legacy getter forbidden"); } }
    private object Read(string point, object normal) {
        Array.Resize(ref Calls, Calls.Length + 1);
        Calls[Calls.Length - 1] = point;
        if (Observe != null) Observe(point);
        if (UnknownReadiness && (point == "control_type" || point == "focusable" || point == "offscreen")) return AutomationElement.NotSupported;
        if (Point != point) return normal;
        if (Fault == "stale") throw new ElementNotAvailableException();
        if (Fault == "wrapped") throw new System.Reflection.TargetInvocationException(new ElementNotAvailableException());
        if (Fault == "unknown_wrapper") throw new Exception("Unknown wrapper", new ElementNotAvailableException());
        if (Fault == "com") throw new System.Runtime.InteropServices.COMException("Unknown provider");
        if (Fault == "null") return null;
        if (Fault == "unsupported") return AutomationElement.NotSupported;
        if (Fault == "nonint") return "20";
        if (Fault == "different") return 21;
        if (Fault == "wrongbool") return 0;
        if (Fault == "wrongstring") return "synthetic-private-value";
        if (Fault == "empty") return new object[0];
        if (Fault == "boolarray") return new object[] {false};
        if (Fault == "typearray") return new object[] {ControlType.Document};
        return normal;
    }
    public object GetRuntimeId() { return Read("runtime_id", new int[] {1,NodeId}); }
    public object GetCurrentPropertyValue(object property, bool ignoreDefault) {
        if (!ignoreDefault) throw new Exception("Default substitution forbidden");
        if (property == AutomationElement.ProcessIdProperty) {
            PidCalls++;
            return Read(PidCalls == 1 ? "first_pid" : PidCalls == 2 ? "second_pid" : "final_pid", 20);
        }
        if (property == AutomationElement.IsPasswordProperty) throw new Exception("Startup password query forbidden");
        if (property == AutomationElement.NameProperty) { NameCalls++; throw new Exception("Startup Name query forbidden"); }
        if (property == AutomationElement.ControlTypeProperty) return Read("control_type", ControlValue);
        if (property == AutomationElement.AutomationIdProperty) throw new Exception("Startup AutomationId query forbidden");
        if (property == AutomationElement.ClassNameProperty) throw new Exception("Startup ClassName query forbidden");
        if (property == AutomationElement.IsKeyboardFocusableProperty) return Read("focusable", FocusableValue);
        if (property == AutomationElement.IsOffscreenProperty) return Read("offscreen", OffscreenValue);
        throw new Exception("Unexpected property");
    }
}
'@
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Strict node source parse failed' }
foreach ($name in @('Get-DocumentUnavailableException','Read-DocumentProperty','Read-DocumentRuntimeId','Assert-DocumentInspectionPid','Read-DocumentNodeInfo','Read-TargetTree','Assert-DocumentProcessHandle','Assert-DocumentNodeIdentity','New-DocumentReadinessClock','Wait-TargetDocument')) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'Strict node function missing' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Get-OfflineReplacementRoot { return $script:node }
function Get-OfflineReplacementWalker { return $script:walker }
function Reset-Node {
    $script:node=[RespireStrictNodeProvider]::new(); $script:report=@{}; $script:walks=0
    $script:ids=[Collections.Generic.HashSet[int]]::new(); [void]$ids.Add(20)
    $script:live=[pscustomobject]@{HasExited=$false;StartTime=[datetime]::new(100,[DateTimeKind]::Utc);SessionId=1;Path='synthetic';SafeHandle=[pscustomobject]@{IsInvalid=$false;IsClosed=$false}}
    $script:identities=@{20=@{process=$live;birth=100;session=1;image='synthetic'}}
    $script:walker=[pscustomobject]@{}
    $walker | Add-Member ScriptMethod GetFirstChild { param($Element) $script:walks++; return $null }
    $walker | Add-Member ScriptMethod GetNextSibling { param($Element) throw 'Unexpected sibling' }
}
foreach ($password in @($false,$true)) {
    Reset-Node; $node.Password=$password
    $tree=Read-TargetTree -ReportUnknownProcess -AdmittedIds $ids -LiveIdentities $identities
    if ($tree.document_count -ne 1 -or -not $tree.traversal_complete -or $tree.nodes.Count -ne 1 -or $node.PidCalls -ne 3 -or $node.NameCalls -ne 0 -or $node.GetterCalls -ne 0 -or $walks -ne 1) { throw 'Three-PID strict success path changed' }
    foreach ($point in @('runtime_id','control_type','focusable','offscreen')) {
        if (@($node.Calls | Where-Object { $_ -ceq $point }).Count -ne 1) { throw 'Diagnostic method was read more than once' }
    }
    foreach ($removed in @('name','automation_id','class_name')) {
        if ($tree.nodes[0].ContainsKey($removed)) { throw 'Startup metadata was emitted' }
    }
}
foreach ($point in @('second_pid','final_pid')) {
    foreach ($fault in @('different','null','nonint','unsupported')) {
        Reset-Node; $node.Point=$point; $node.Fault=$fault
        $caught=$null; try { $null=Read-TargetTree -ReportUnknownProcess -AdmittedIds $ids -LiveIdentities $identities } catch { $caught=$_.Exception.Message }
        if ($caught -cne 'UIA node process changed during inspection' -or $walks -ne 0 -or $node.GetterCalls -ne 0 -or $report.document_pid_diagnostic -eq 'element_unavailable') { throw 'PID disagreement became a resample' }
        if ($point -eq 'second_pid' -and ($node.NameCalls -ne 0 -or $node.Calls.Count -ne 2)) { throw 'Second PID failure reached diagnostics' }
    }
}
Reset-Node; $node.Point='runtime_id'; $node.Fault='unsupported'
$caught=$false; try { $null=Read-TargetTree -ReportUnknownProcess -AdmittedIds $ids -LiveIdentities $identities } catch { $caught=$true }
if (-not $caught -or $walks -ne 0 -or $report.document_pid_diagnostic -eq 'element_unavailable' -or $node.NameCalls -ne 0) { throw 'Unknown runtime identity was accepted or retried' }
# A malformed readiness observation never becomes a false/default value. It
# excludes only the witness requiring that field; identity is still completed.
$fields=@{control_type='control_type';focusable='keyboard_focusable';offscreen='offscreen'}
foreach ($point in @('control_type','focusable','offscreen')) {
    foreach ($fault in @('null','unsupported','wrongbool','wrongstring','empty','boolarray','typearray')) {
        Reset-Node; $node.Point=$point; $node.Fault=$fault
        $tree=Read-TargetTree -ReportUnknownProcess -AdmittedIds $ids -LiveIdentities $identities
        $documents=if ($point -eq 'focusable') {1} else {0}
        $focusable=if ($point -eq 'control_type') {1} else {0}
        if ($tree.document_count -ne $documents -or $tree.focusable_count -ne $focusable -or -not $tree.traversal_complete -or
            $node.PidCalls -ne 3 -or $walks -ne 1 -or $node.NameCalls -ne 0 -or $node.GetterCalls -ne 0 -or
            $null -ne $tree.nodes[0][$fields[$point]] -or $report.ContainsKey('document_pid_diagnostic')) { throw 'Unknown readiness observation supplied a witness or skipped identity' }
        foreach ($field in $fields.Values) {
            $expected=if ($field -eq $fields[$point]) {1} else {0}
            if ($tree['unknown_'+$field+'_count'] -ne $expected) { throw 'Unknown readiness count was not field-specific' }
        }
        if (($tree | ConvertTo-Json -Depth 10) -match 'synthetic-private-value') { throw 'Raw unknown provider value escaped' }
        Reset-Node; $node.Point=$point; $node.Fault=$fault
        $caught=$null; try { $null=Read-TargetTree -AdmittedIds $ids -LiveIdentities $identities } catch { $caught=$_.Exception.Message }
        if ($caught -cne 'UIA node diagnostic property type is unknown' -or $walks -ne 0) { throw 'Unknown observations were admitted outside startup readiness' }
    }
}
# All 27 known/unknown combinations execute the production reader and counter.
foreach ($control in @([Windows.Automation.ControlType]::Document,[Windows.Automation.ControlType]::Pane,$null)) {
    foreach ($focusable in @($true,$false,$null)) {
        foreach ($offscreen in @($true,$false,$null)) {
            Reset-Node; $node.ControlValue=$control; $node.FocusableValue=$focusable; $node.OffscreenValue=$offscreen
            $tree=Read-TargetTree -ReportUnknownProcess -AdmittedIds $ids -LiveIdentities $identities
            $visible=$offscreen -is [bool] -and $offscreen -eq $false
            $documents=if ($control -eq [Windows.Automation.ControlType]::Document -and $visible) {1} else {0}
            $focusableCount=if ($focusable -is [bool] -and $focusable -eq $true -and $visible) {1} else {0}
            if ($tree.document_count -ne $documents -or $tree.focusable_count -ne $focusableCount -or $node.PidCalls -ne 3 -or -not $tree.traversal_complete) { throw 'Readiness witness truth table failed' }
        }
    }
}
# Valid evidence survives an unsupported node before or after it, never instead
# of inspecting that node. Each witness needs its required fields on one row;
# Document and focusable witnesses may be different rows.
foreach ($unknownFirst in @($true,$false)) {
    Reset-Node
    $script:child=[RespireStrictNodeProvider]::new(); $child.NodeId=2
    if ($unknownFirst) { $node.UnknownReadiness=$true } else { $child.UnknownReadiness=$true }
    $walker | Add-Member -Force ScriptMethod GetFirstChild { param($Element) $script:walks++; if ($Element -eq $script:node) { return $script:child }; return $null }
    $walker | Add-Member -Force ScriptMethod GetNextSibling { param($Element) return $null }
    $tree=Read-TargetTree -ReportUnknownProcess -AdmittedIds $ids -LiveIdentities $identities
    if ($tree.document_count -ne 1 -or $tree.focusable_count -ne 1 -or -not $tree.traversal_complete -or $walks -ne 2 -or
        $node.PidCalls -ne 3 -or $child.PidCalls -ne 3 -or $tree.nodes.Count -ne 2) { throw 'Mixed tree lost positive evidence or skipped unknown-node identity' }
    foreach ($field in $fields.Values) { if ($tree['unknown_'+$field+'_count'] -ne 1) { throw 'Mixed tree unknown count changed' } }
}
Reset-Node
$node.ControlValue=[Windows.Automation.ControlType]::Document; $node.FocusableValue=$true; $node.OffscreenValue=$null
$script:child=[RespireStrictNodeProvider]::new(); $child.NodeId=2; $child.ControlValue=$null; $child.FocusableValue=$null; $child.OffscreenValue=$false
$walker | Add-Member -Force ScriptMethod GetFirstChild { param($Element) if ($Element -eq $script:node) { return $script:child }; return $null }
$walker | Add-Member -Force ScriptMethod GetNextSibling { param($Element) return $null }
$tree=Read-TargetTree -ReportUnknownProcess -AdmittedIds $ids -LiveIdentities $identities
if ($tree.document_count -ne 0 -or $tree.focusable_count -ne 0 -or -not $tree.traversal_complete) { throw 'Readiness combined unrelated nodes into a witness' }
# Unknown observations cannot short-circuit the third PID/lifetime check.
foreach ($fault in @('different','null','nonint','unsupported')) {
    Reset-Node; $node.UnknownReadiness=$true; $node.Point='final_pid'; $node.Fault=$fault
    $caught=$null; try { $null=Read-TargetTree -ReportUnknownProcess -AdmittedIds $ids -LiveIdentities $identities } catch { $caught=$_.Exception.Message }
    if ($caught -cne 'UIA node process changed during inspection' -or $walks -ne 0 -or $node.PidCalls -ne 3) { throw 'Unknown observations hid a final PID failure' }
}
foreach ($change in @('exit','reuse')) {
    Reset-Node; $node.UnknownReadiness=$true
    $node.Observe=[Action[string]]({param($point)
        if ($point -ceq 'final_pid') {
            if ($change -eq 'exit') { $script:live.HasExited=$true }
            else { $script:live.StartTime=[datetime]::new(101,[DateTimeKind]::Utc) }
        }
    })
    $caught=$null; try { $null=Read-TargetTree -ReportUnknownProcess -AdmittedIds $ids -LiveIdentities $identities } catch { $caught=$_.Exception.Message }
    if ($caught -cne 'Document node process identity changed after admission' -or $walks -ne 0 -or $node.PidCalls -ne 3) { throw 'Unknown observations hid a final lifetime failure' }
}
foreach ($point in @('second_pid','runtime_id','control_type','focusable','offscreen','final_pid')) {
    foreach ($fault in @('stale','wrapped','unknown_wrapper','com')) {
        Reset-Node; $node.Point=$point; $node.Fault=$fault
        $result=$null; $caught=$false; $message=$null
        try { $result=Read-TargetTree -ReportUnknownProcess -AdmittedIds $ids -LiveIdentities $identities } catch { $caught=$true; $message=$_.Exception.Message }
        $typed=$fault -in @('stale','wrapped')
        if ($caught -eq $typed -or $walks -ne 0 -or $node.GetterCalls -ne 0) { throw 'Provider exception boundary widened' }
        if (-not $typed -and $message -notin @('UIA document property method failed','UIA document runtime identity method failed')) { throw 'Unknown provider message escaped fixed failure' }
        if ($typed -and ($result.GetType() -ne [Windows.Automation.ElementNotAvailableException] -or $result.PSObject.Properties.Name -contains 'nodes' -or $report.document_pid_diagnostic -cne 'element_unavailable')) { throw 'Typed node failure retained partial tree evidence' }
        if ($node.NameCalls -ne 0) { throw 'Unproven identity or password reached Name' }
        Reset-Node; $node.Point=$point; $node.Fault=$fault; $caught=$false
        try { $null=Read-TargetTree -AdmittedIds $ids -LiveIdentities $identities } catch { $caught=$true }
        if (-not $caught) { throw 'Ordinary traversal returned a readiness signal' }
    }
}
foreach ($change in @('exit','reuse')) {
    foreach ($at in @('second_pid','control_type','final_pid')) {
        Reset-Node
        $node.Observe=[Action[string]]({param($point)
            if ($point -ceq $at) {
                if ($change -eq 'exit') { $script:live.HasExited=$true }
                else { $script:live.StartTime=[datetime]::new(101,[DateTimeKind]::Utc) }
            }
        })
        $caught=$false; try { $null=Read-TargetTree -ReportUnknownProcess -AdmittedIds $ids -LiveIdentities $identities } catch { $caught=$true }
        if (-not $caught -or $walks -ne 0 -or $report.document_pid_diagnostic -eq 'element_unavailable' -or ($at -eq 'second_pid' -and $node.NameCalls -ne 0)) { throw 'Read-time identity change was accepted or retried' }
    }
}
# An earlier complete Document row cannot survive a later typed node failure.
Reset-Node
$script:child=[RespireStrictNodeProvider]::new(); $child.Point='final_pid'; $child.Fault='stale'
$walker | Add-Member -Force ScriptMethod GetFirstChild { param($Element) if ($Element -eq $script:node) { return $script:child }; return $null }
$walker | Add-Member -Force ScriptMethod GetNextSibling { param($Element) return $null }
$result=Read-TargetTree -ReportUnknownProcess -AdmittedIds $ids -LiveIdentities $identities
if ($result.GetType() -ne [Windows.Automation.ElementNotAvailableException] -or $result.PSObject.Properties.Name -contains 'nodes' -or $node.PidCalls -ne 3 -or $child.PidCalls -ne 3) { throw 'Earlier Document evidence survived whole-tree invalidation' }
# Actual readiness loop must reject all-unknown and known-negative trees under
# the original budget; mixed positive evidence may pass only after full traversal.
function Get-Process { param($Id,$ErrorAction) return $script:live }
function Assert-Target { param($Foreground) $script:ownedIds=$script:ids }
function New-DocumentReadinessClock { return $script:budgetClock }
function Pause-Probe { $script:pauses++; $script:budgetClock.Elapsed.TotalSeconds+=5 }
function Send-TargetTab { throw 'Input forbidden in startup readiness test' }
function Send-OfflineKey { throw 'Input forbidden in startup readiness test' }
foreach ($mode in @('all_unknown','no_document','no_focusable','offscreen','mixed','independent_witnesses')) {
    Reset-Node; $script:budgetClock=[pscustomobject]@{Elapsed=[pscustomobject]@{TotalSeconds=0};ElapsedMilliseconds=0}; $script:pauses=0; $script:disposed=0
    $live | Add-Member ScriptMethod Dispose { $script:disposed++ }
    switch ($mode) {
        'all_unknown' { $node.UnknownReadiness=$true }
        'no_document' { $node.ControlValue=$null }
        'no_focusable' { $node.FocusableValue=$null }
        'offscreen' { $node.OffscreenValue=$true }
        { $_ -in @('mixed','independent_witnesses') } {
            $script:child=[RespireStrictNodeProvider]::new(); $child.NodeId=2
            if ($mode -eq 'mixed') { $child.UnknownReadiness=$true }
            else { $node.FocusableValue=$null; $child.ControlValue=$null }
            $walker | Add-Member -Force ScriptMethod GetFirstChild { param($Element) $script:walks++; if ($Element -eq $script:node) { return $script:child }; return $null }
            $walker | Add-Member -Force ScriptMethod GetNextSibling { param($Element) return $null }
        }
    }
    $caught=$null; try { Wait-TargetDocument } catch { $caught=$_.Exception.Message }
    if ($mode -in @('mixed','independent_witnesses')) {
        if ($null -ne $caught -or -not $report.document_readiness.ready -or $pauses -ne 0 -or $walks -ne 2 -or $child.PidCalls -ne 3) { throw 'Complete mixed positive tree failed readiness' }
        $last=$report.document_readiness.attempts[-1]
        if ($last.document_count -ne 1 -or $last.focusable_count -ne 1 -or $last.unknown_control_type_count -ne 1 -or
            $last.unknown_keyboard_focusable_count -ne 1 -or $last.unknown_offscreen_count -ne $(if ($mode -eq 'mixed') {1} else {0})) { throw 'Independent positive witnesses or unknown counts changed' }
    } else {
        if ($caught -cne 'Original WebView UIA Document/focusable controls not observed within readiness budget; inspect traversal truncation reasons' -or
            $report.document_readiness.ready -or $report.document_readiness_phase -cne 'budget_exhausted' -or $pauses -ne 3 -or $walks -ne 3 -or $node.PidCalls -ne 9) { throw 'Unproven readiness exceeded its original budget or was accepted' }
    }
    if ($disposed -ne 1 -or $report.document_discarded_samples -ne 0) { throw 'Unknown observations leaked a handle or used exception retries' }
}
# Even an exact UIA exception raised by an identity assertion is outside catches.
function Assert-DocumentNodeIdentity { param($NodePid,$LiveIdentities) throw [Windows.Automation.ElementNotAvailableException]::new() }
Reset-Node; $caught=$false
try { $null=Read-TargetTree -ReportUnknownProcess -AdmittedIds $ids -LiveIdentities $identities } catch { $caught=$true }
if (-not $caught -or $node.NameCalls -ne 0 -or $node.PidCalls -ne 1 -or $report.document_pid_diagnostic -eq 'element_unavailable') { throw 'Identity assertion entered provider retry scope' }
Write-Host 'PASS: positive startup witnesses preserve complete identity, unknown observations, strict provider failures and original readiness budget'
