# Synthetic execution only. No process is spawned, signalled, or added to an allowlist.
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Descendant policy source parse failed' }
foreach ($name in @('Assert-DocumentNodeIdentity','Read-ProvenWebViewChain','Confirm-NewWebViewDescendant','Wait-TargetDocument')) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'Descendant policy function missing' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
# Bind the synthetic guard test to the real traversal's pre-diagnostic ordering.
$treeNode=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Read-TargetTree'},$true))
$treeText=$treeNode[0].Extent.Text
if ($treeNode.Count -ne 1 -or $treeText.IndexOf('Assert-DocumentNodeIdentity $nodePid $LiveIdentities') -lt 0 -or
    $treeText.IndexOf('Assert-DocumentNodeIdentity $nodePid $LiveIdentities') -gt $treeText.IndexOf('Element-Info $next.element')) { throw 'Traversal diagnostic ran before live identity guard' }
function Send-TargetTab { throw 'Input is forbidden in descendant proof' }
function Send-OfflineKey { throw 'Input is forbidden in descendant proof' }
function Assert-Target {
    param($Foreground)
    $script:guards++
    $script:ownedIds=[Collections.Generic.HashSet[int]]::new()
    [void]$script:ownedIds.Add(20)
    if ($script:guards -gt 1) { [void]$script:ownedIds.Add(99) }
    if ($script:mode -eq 'changedroot' -or ($script:mode -eq 'changedbinding' -and $script:guards -gt 1)) { throw 'fixed binding changed' }
}
function Get-CimInstance {
    param($Class,$Filter)
    $script:snapshots++
    if ($script:mode -eq 'changedchain' -and $script:snapshots -eq 3) {
        $script:child.CreationDate=$script:child.CreationDate.AddTicks(1)
        $script:lives[30].StartTime=$script:child.CreationDate
    }
    if ($script:mode -eq 'exitduring') { $script:lives[30].HasExited=$true }
    $wanted=[int]($Filter -replace '^ProcessId=','')
    return @(@($script:child,$script:browser) | Where-Object { $_.ProcessId -eq $wanted })
}
function Get-Process { param($Id,$ErrorAction) if (-not $script:lives.ContainsKey([int]$Id)) { throw 'WebView process chain is missing or ambiguous' }; $script:acquired++; return $script:lives[[int]$Id] }
function Pause-Probe { $script:pauses++ }
function Read-TargetTree {
    param([switch]$ReportUnknownProcess,$AdmittedIds,$LiveIdentities)
    $script:scans++
    if (-not $ReportUnknownProcess) { throw 'Missing explicit startup-only unknown mode' }
    if ($script:scans -gt 1 -and $AdmittedIds.Contains(99)) { throw 'Unproven sibling was admitted' }
    if ($script:scans -gt 1 -and -not $AdmittedIds.Contains(30)) { throw 'Proven descendant was not admitted' }
    if ($script:scans -gt 1) {
        if ($script:disposed -ne 3 -or $script:acquired -ne 7) { throw 'Process handles were not retained across the rescan' }
        if ($script:mode -eq 'postproofexit') { $script:lives[30].HasExited=$true }
        if ($script:mode -eq 'postproofreuse') { $script:lives[30].StartTime=$script:lives[30].StartTime.AddTicks(1) }
        if ($script:mode -eq 'initialexit') { $script:lives[20].HasExited=$true }
        if ($script:mode -eq 'initialreuse') { $script:lives[20].StartTime=$script:lives[20].StartTime.AddTicks(1) }
        foreach ($nodePid in @(20,30)) { Assert-DocumentNodeIdentity $nodePid $LiveIdentities }
        $script:diagnostics++
    }
    if ($script:scans -gt 1 -and $script:mode -eq 'newsibling') { return [int]99 }
    if ($script:scans -eq 1 -or $script:mode -eq 'secondunknown') { return [int]30 }
    return @{document_count=1;focusable_count=1;traversal_complete=$true;truncation_reasons=@();elapsed_ms=1}
}
function Reset-Descendant {
    $script:diagnostics=0; $script:mode='valid'; $script:guards=0; $script:snapshots=0; $script:scans=0; $script:pauses=0; $script:report=@{}
    $birth=[datetime]::new(638000000000000000,[DateTimeKind]::Utc)
    $image='C:\fixture\msedgewebview2.exe'
    $script:binding=@{browser_pid=20;browser_started_ticks=$birth.Ticks;session_id=2}
    $script:browser=[pscustomobject]@{ProcessId=20;ParentProcessId=10;CreationDate=$birth;SessionId=2;ExecutablePath=$image}
    $script:child=[pscustomobject]@{ProcessId=30;ParentProcessId=20;CreationDate=$birth.AddSeconds(1);SessionId=2;ExecutablePath=$image}
    $script:lives=@{
        20=[pscustomobject]@{StartTime=$birth;SessionId=2;Path=$image;SafeHandle=1;HasExited=$false}
        30=[pscustomobject]@{StartTime=$birth.AddSeconds(1).AddTicks(7);SessionId=2;Path=$image;SafeHandle=1;HasExited=$false}
    }
    $script:disposed=0; $script:acquired=0
    foreach ($live in $script:lives.Values) { $live | Add-Member ScriptMethod Dispose { $script:disposed++ } }
}
Reset-Descendant
Wait-TargetDocument
if ($acquired -ne 7 -or $disposed -ne $acquired) { throw 'Successful proof leaked process handles' }
if ($scans -ne 2 -or $snapshots -ne 4 -or $guards -ne 6 -or -not $report.document_readiness.ready -or
    $report.document_descendant_refresh -cne 'verified_discard_and_rescan' -or $report.document_readiness.budget_seconds -ne 15) { throw 'Proven descendant did not force one complete rescan' }
foreach ($kind in @('foreignparent','reusedpid','handlefailure','exitduring','youngerparent','session','image','changedbrowser','changedroot','changedbinding','changedchain','secondunknown','newsibling','postproofexit','postproofreuse','initialexit','initialreuse')) {
    Reset-Descendant; $script:mode=$kind
    $expected=switch ($kind) {
        { $_ -in @('postproofexit','postproofreuse','initialexit','initialreuse') } { 'Document node process identity changed after admission' }
        'foreignparent' { $child.ParentProcessId=99; 'WebView process chain is missing or ambiguous' }
        'reusedpid' { $script:mode='changedchain'; 'WebView process chain changed during verification' }
        'handlefailure' {
            $lives[30].PSObject.Properties.Remove('SafeHandle')
            $lives[30] | Add-Member ScriptProperty SafeHandle { throw 'fixed safe handle failure' }
            'fixed safe handle failure'
        }
        'exitduring' { 'WebView chain process exited during verification' }
        'youngerparent' { $child.CreationDate=$browser.CreationDate.AddTicks(-1);$lives[30].StartTime=$child.CreationDate; 'WebView process parent is younger than its child' }
        'session' { $child.SessionId=3; 'WebView process chain identity is unproven' }
        'image' { $child.ExecutablePath='C:\other\msedgewebview2.exe'; 'WebView process chain identity is unproven' }
        'changedbrowser' { $lives[20].StartTime=$browser.CreationDate.AddTicks(1); 'WebView chain browser identity changed' }
        'changedroot' { 'fixed binding changed' }
        'changedbinding' { 'fixed binding changed' }
        'changedchain' { 'WebView process chain changed during verification' }
        'newsibling' { 'UIA node belongs to an unbound process after one verified refresh' }
        'secondunknown' { 'UIA node belongs to an unbound process after one verified refresh' }
    }
    $caught=$null
    try { Wait-TargetDocument } catch {
        $caught=$_.Exception.Message
        if ($kind -eq 'handlefailure') {
            $cause=$_.Exception
            for ($depth=0; $cause -and $depth -lt 8; $depth++) {
                if ($cause.Message -ceq 'fixed safe handle failure') { $caught='fixed safe handle failure'; break }
                $cause=$cause.InnerException
            }
        }
    }
    if ($disposed -ne $acquired) { throw 'Held process handles were not all disposed' }
    if ($caught -cne $expected -or $report.document_readiness.ready -or $pauses -ne 0) { throw 'Unproven descendant did not fail closed at expected boundary' }
    if ($kind -in @('postproofexit','postproofreuse','initialexit','initialreuse') -and $diagnostics -ne 0) { throw 'Changed identity reached node diagnostics' }
    if ($kind -in @('secondunknown','newsibling','postproofexit','postproofreuse','initialexit','initialreuse')) { if ($scans -ne 2 -or $snapshots -ne 4) { throw 'Second unknown was refreshed again' } }
    elseif ($scans -gt 1) { throw 'Unproven tree was rescanned' }
}
# A document in a truncated traversal is not readiness evidence.
function Read-TargetTree {
    param([switch]$ReportUnknownProcess,$AdmittedIds,$LiveIdentities)
    $script:scans++
    return @{document_count=1;focusable_count=1;traversal_complete=$script:complete;truncation_reasons=$script:reasons;elapsed_ms=1}
}
function Pause-Probe { throw 'fixed incomplete tree waited' }
foreach ($case in @(@{complete=$false;reasons=@('node-limit')},@{complete=$true;reasons=@('depth-limit')},@{complete=$false;reasons=@()})) {
    Reset-Descendant; $script:complete=$case.complete; $script:reasons=$case.reasons
    $caught=$null
    try { Wait-TargetDocument } catch { $caught=$_.Exception.Message }
    if ($disposed -ne $acquired) { throw 'Incomplete traversal leaked process handles' }
    if ($caught -cne 'fixed incomplete tree waited' -or $report.document_readiness.ready -or $scans -ne 1) { throw 'Truncated document was accepted as ready' }
}
function Read-TargetTree { param([switch]$ReportUnknownProcess,$AdmittedIds,$LiveIdentities) $script:scans++; return [int]30 }
# Spend the original budget in verification: no second scan or new budget is allowed.
function Confirm-NewWebViewDescendant { param($NodePid) Start-Sleep -Milliseconds 1100 }
Reset-Descendant
$caught=$null
try { Wait-TargetDocument 1 } catch { $caught=$_.Exception.Message }
if ($disposed -ne $acquired) { throw 'Budget exhaustion leaked process handles' }
if ($caught -cne 'Original WebView UIA Document/focusable controls not observed within readiness budget; inspect traversal truncation reasons' -or
    $scans -ne 1 -or $report.document_readiness_phase -cne 'budget_exhausted') { throw 'Descendant refresh reset or exceeded scan admission budget' }
Write-Host 'PASS: proven live descendant rescan and fail-closed negative cases'
