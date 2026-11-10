# Real .NET method exceptions plus actual tree/readiness AST. No desktop or input.
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -ReferencedAssemblies @([Windows.Automation.AutomationElement].Assembly.Location,[Windows.Automation.ElementNotAvailableException].Assembly.Location) -TypeDefinition @'
public sealed class RespireSyntheticPidProvider {
    public string Mode;
    public int Calls;
    public int Metadata;
    public object Current { get { Metadata++; throw new System.Exception("Metadata forbidden"); } }
    public object GetCurrentPropertyValue(object property, bool ignoreDefault) {
        Calls++;
        if (!ignoreDefault || property != System.Windows.Automation.AutomationElement.ProcessIdProperty) throw new System.Exception("Wrong query");
        if (Mode == "stale") throw new System.Windows.Automation.ElementNotAvailableException();
        if (Mode == "wrapped") throw new System.Reflection.TargetInvocationException(new System.Windows.Automation.ElementNotAvailableException());
        if (Mode == "unknown_inner") throw new System.Exception("Unknown wrapper", new System.Windows.Automation.ElementNotAvailableException());
        if (Mode == "com") throw new System.Runtime.InteropServices.COMException("Unknown provider");
        if (Mode == "null") return null;
        if (Mode == "unsupported") return System.Windows.Automation.AutomationElement.NotSupported;
        if (Mode == "nonint") return "20";
        if (Mode == "nonpositive") return 0;
        throw new System.Exception("Unknown provider");
    }
}
'@
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Sampling source parse failed' }
foreach ($name in @('Get-DocumentUnavailableException','Read-DocumentProperty','Read-DocumentRuntimeId','Assert-DocumentInspectionPid','Read-DocumentNodeInfo','Read-TargetTree','Assert-DocumentProcessHandle','Assert-DocumentNodeIdentity','Wait-TargetDocument')) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'Sampling function missing' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Get-OfflineReplacementRoot { return $script:root }
function Get-OfflineReplacementWalker { return $script:walker }
$script:root=[pscustomobject]@{}
$root | Add-Member ScriptMethod GetCurrentPropertyValue {
    param($Property,$IgnoreDefault)
    if ($IgnoreDefault -ne $true) { throw 'Default property value allowed' }
    if ($Property -eq [Windows.Automation.AutomationElement]::ProcessIdProperty) { return 20 }
    if ($Property -eq [Windows.Automation.AutomationElement]::IsPasswordProperty -or $Property -eq [Windows.Automation.AutomationElement]::IsOffscreenProperty) { return $false }
    if ($Property -eq [Windows.Automation.AutomationElement]::IsKeyboardFocusableProperty) { return $true }
    if ($Property -eq [Windows.Automation.AutomationElement]::ControlTypeProperty) { return [Windows.Automation.ControlType]::Document }
    if ($Property -eq [Windows.Automation.AutomationElement]::NameProperty -or $Property -eq [Windows.Automation.AutomationElement]::AutomationIdProperty -or $Property -eq [Windows.Automation.AutomationElement]::ClassNameProperty) { return '' }
    throw 'Unexpected root property'
}
$root | Add-Member ScriptMethod GetRuntimeId { return @(1,2) }
$script:walker=[pscustomobject]@{}
$walker | Add-Member ScriptMethod GetFirstChild { param($Element) if ($Element -eq $script:root) { return $script:bad }; return $null }
$walker | Add-Member ScriptMethod GetNextSibling { param($Element) return $null }
$script:ownedIds=[Collections.Generic.HashSet[int]]::new(); [void]$ownedIds.Add(20)
foreach ($mode in @('stale','wrapped','unknown_inner','com','null','unsupported','nonint','nonpositive','unknown')) {
    $script:report=@{}; $script:bad=[RespireSyntheticPidProvider]::new(); $bad.Mode=$mode
    $result=$null; $caught=$false
    try { $result=Read-TargetTree -ReportUnknownProcess -AdmittedIds $ownedIds } catch { $caught=$true }
    $retry=($mode -in @('stale','wrapped'))
    if ($bad.Calls -ne 1 -or $bad.Metadata -ne 0 -or $caught -eq $retry) { throw 'PID method exception boundary failed' }
    if ($retry -and ($result.GetType() -ne [Windows.Automation.ElementNotAvailableException] -or $result.PSObject.Properties.Name -contains 'nodes' -or $report.document_pid_diagnostic -cne 'element_unavailable')) { throw 'Partial Document tree survived typed sampling failure' }
}
# Even a recognized method exception is not a signal outside readiness mode.
$script:bad=[RespireSyntheticPidProvider]::new(); $bad.Mode='stale'; $caught=$false
try { $null=Read-TargetTree -AdmittedIds $ownedIds } catch { $caught=$true }
if (-not $caught -or $bad.Metadata -ne 0) { throw 'Non-readiness traversal retried a sampling failure' }
$deep=[Exception][Windows.Automation.ElementNotAvailableException]::new()
for ($i=0;$i -lt 6;$i++) { $deep=[Reflection.TargetInvocationException]::new($deep) }
if ($null -ne (Get-DocumentUnavailableException $deep)) { throw 'Unbounded exception unwrapping' }
function Send-TargetTab { throw 'Forbidden input in sampling' }
function Send-OfflineKey { throw 'Forbidden input in sampling' }
function Press-OfflineButton { throw 'Forbidden Invoke in sampling' }
function New-DocumentReadinessClock { return $script:clock }
function Get-Process { param($Id,$ErrorAction) return $script:live }
function Assert-Target {
    param($Foreground)
    $script:guards++
    if ($script:mode -eq 'foreground' -and $script:pauses -gt 0) { throw 'Foreground changed' }
    $script:ownedIds=[Collections.Generic.HashSet[int]]::new(); [void]$script:ownedIds.Add(20)
    if ($script:mode -eq 'unproven_sibling' -and $script:pauses -gt 0) { [void]$script:ownedIds.Add(99) }
}
function Pause-Probe {
    $script:pauses++; $script:clock.Elapsed.TotalSeconds+=5
    if ($script:mode -eq 'exit') { $script:live.HasExited=$true }
    if ($script:mode -eq 'reuse') { $script:live.StartTime=$script:live.StartTime.AddTicks(1) }
}
function Confirm-NewWebViewDescendant { param($NodePid,$Clock,$Seconds,$Held) $script:proofs++; return @{pid=20;process=$script:live;birth=100;session=1;image='synthetic'} }
function Read-TargetTree {
    param([switch]$ReportUnknownProcess,$AdmittedIds,$LiveIdentities)
    $script:scans++
    if ($AdmittedIds.Contains(99)) { throw 'New sibling auto-admitted' }
    if ($script:mode -eq 'provider') { throw 'Unknown provider error' }
    if ($script:mode -eq 'unproven_sibling' -and $script:scans -eq 2) { throw 'Unproven sibling rejected' }
    if ($script:mode -eq 'proof_budget') {
        if ($script:scans -eq 1 -or $script:scans -eq 3) { return [int]30 }
        return [Windows.Automation.ElementNotAvailableException]::new()
    }
    if ($script:mode -eq 'repeat' -or $script:scans -eq 1) { return [Windows.Automation.ElementNotAvailableException]::new() }
    if ($script:mode -eq 'late_complete') { $script:clock.Elapsed.TotalSeconds=15 }
    return @{document_count=1;focusable_count=1;traversal_complete=$true;truncation_reasons=@();elapsed_ms=1}
}
foreach ($script:mode in @('success','repeat','exit','reuse','foreground','provider','proof_budget','late_complete','unproven_sibling')) {
    $script:clock=[pscustomobject]@{Elapsed=[pscustomobject]@{TotalSeconds=0};ElapsedMilliseconds=0}
    $script:scans=0; $script:guards=0; $script:pauses=0; $script:proofs=0; $script:disposed=0; $script:report=@{}
    $script:live=[pscustomobject]@{HasExited=$false;StartTime=[datetime]::new(100,[DateTimeKind]::Utc);SessionId=1;Path='synthetic';SafeHandle=[pscustomobject]@{IsInvalid=$false;IsClosed=$false}}
    $live | Add-Member ScriptMethod Dispose { $script:disposed++ }
    $caught=$false; try { Wait-TargetDocument } catch { $caught=$true }
    $expectedScans=2; $expectedPauses=1; $expectedProofs=0
    switch ($mode) {
        'repeat' { $expectedScans=3; $expectedPauses=3 }
        'exit' { $expectedScans=1 }
        'reuse' { $expectedScans=1 }
        'foreground' { $expectedScans=1 }
        'provider' { $expectedScans=1; $expectedPauses=0 }
        'proof_budget' { $expectedScans=3; $expectedProofs=1 }
    }
    $expectedDiscards=$expectedPauses
    if ($report.document_discarded_samples -ne $expectedDiscards) { throw 'Typed sample discard count changed' }
    if ($caught -ne ($mode -ne 'success') -or $scans -ne $expectedScans -or $pauses -ne $expectedPauses -or $proofs -ne $expectedProofs -or $disposed -ne 1) { throw ('Readiness sampling boundary failed: '+$mode) }
    if ($mode -eq 'success') {
        if (-not $report.document_readiness.ready -or $report.document_readiness.attempts.Count -ne 1) { throw 'Discarded sample contributed readiness evidence' }
    } elseif ($report.document_readiness.ready) { throw 'Failed sampling marked ready' }
}
Write-Host 'PASS: narrow typed sampling invalidation shares original lifetime and readiness budget'
