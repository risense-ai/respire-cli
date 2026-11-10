# Actual startup reader/tree with explicit synthetic .NET provider methods.
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -ReferencedAssemblies @([Windows.Automation.AutomationElement].Assembly.Location,[Windows.Automation.ElementNotAvailableException].Assembly.Location) -TypeDefinition @'
using System;
using System.Windows.Automation;
public sealed class RespireStrictNodeProvider {
    public string Point = "", Fault = "";
    public bool Password;
    public int PidCalls, NameCalls, GetterCalls;
    public string[] Calls = new string[0];
    public Action<string> Observe;
    public object Current { get { GetterCalls++; throw new Exception("Legacy getter forbidden"); } }
    private object Read(string point, object normal) {
        Array.Resize(ref Calls, Calls.Length + 1);
        Calls[Calls.Length - 1] = point;
        if (Observe != null) Observe(point);
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
        return normal;
    }
    public object GetRuntimeId() { return Read("runtime_id", new int[] {1,2}); }
    public object GetCurrentPropertyValue(object property, bool ignoreDefault) {
        if (!ignoreDefault) throw new Exception("Default substitution forbidden");
        if (property == AutomationElement.ProcessIdProperty) {
            PidCalls++;
            return Read(PidCalls == 1 ? "first_pid" : PidCalls == 2 ? "second_pid" : "final_pid", 20);
        }
        if (property == AutomationElement.IsPasswordProperty) throw new Exception("Startup password query forbidden");
        if (property == AutomationElement.NameProperty) { NameCalls++; throw new Exception("Startup Name query forbidden"); }
        if (property == AutomationElement.ControlTypeProperty) return Read("control_type", ControlType.Document);
        if (property == AutomationElement.AutomationIdProperty) throw new Exception("Startup AutomationId query forbidden");
        if (property == AutomationElement.ClassNameProperty) throw new Exception("Startup ClassName query forbidden");
        if (property == AutomationElement.IsKeyboardFocusableProperty) return Read("focusable", true);
        if (property == AutomationElement.IsOffscreenProperty) return Read("offscreen", false);
        throw new Exception("Unexpected property");
    }
}
'@
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Strict node source parse failed' }
foreach ($name in @('Get-DocumentUnavailableException','Read-DocumentProperty','Read-DocumentRuntimeId','Assert-DocumentInspectionPid','Read-DocumentNodeInfo','Read-TargetTree','Assert-DocumentProcessHandle','Assert-DocumentNodeIdentity')) {
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
foreach ($point in @('runtime_id','control_type','focusable','offscreen')) {
    Reset-Node; $node.Point=$point; $node.Fault='unsupported'
    $caught=$false; try { $null=Read-TargetTree -ReportUnknownProcess -AdmittedIds $ids -LiveIdentities $identities } catch { $caught=$true }
    if (-not $caught -or $walks -ne 0 -or $report.document_pid_diagnostic -eq 'element_unavailable' -or $node.NameCalls -ne 0) { throw 'Unknown diagnostic type was accepted or retried' }
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
# Even an exact UIA exception raised by an identity assertion is outside catches.
function Assert-DocumentNodeIdentity { param($NodePid,$LiveIdentities) throw [Windows.Automation.ElementNotAvailableException]::new() }
Reset-Node; $caught=$false
try { $null=Read-TargetTree -ReportUnknownProcess -AdmittedIds $ids -LiveIdentities $identities } catch { $caught=$true }
if (-not $caught -or $node.NameCalls -ne 0 -or $node.PidCalls -ne 1 -or $report.document_pid_diagnostic -eq 'element_unavailable') { throw 'Identity assertion entered provider retry scope' }
Write-Host 'PASS: explicit startup node methods enforce three PID checks, zero startup metadata reads and narrow typed invalidation'
