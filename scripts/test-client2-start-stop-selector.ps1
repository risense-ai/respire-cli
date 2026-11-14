# Differential execution of actual AST functions over deterministic synthetic UIA.
# No real input/process/desktop. Run under Windows PowerShell 5 and PowerShell 7.
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
function Read-SelectorAst([string]$Path) {
    $tokens=$null; $errors=$null
    $tree=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw 'Selector source parse failed' }
    return $tree
}
$fixturePath=Join-Path $PSScriptRoot 'fixtures/client2-start-stop-selector-acd4.ps1'
# Checkout CRLF conversion must not change the frozen logical source check.
$sha=[Security.Cryptography.SHA256]::Create()
try {
    $bytes=[Text.Encoding]::UTF8.GetBytes([IO.File]::ReadAllText($fixturePath).Replace("`r`n","`n"))
    $digest=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()
} finally { $sha.Dispose() }
if ($digest -cne '1983fa815f409c66901d9166a87ee3ce8af2ddeab948c515b33a7443e3786aaf') { throw 'Frozen acd4 baseline selector source changed' }
$source=Read-SelectorAst (Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1')
$baseline=Read-SelectorAst (Join-Path $PSScriptRoot 'fixtures/client2-start-stop-selector-acd4.ps1')
function Selector-Body($Tree) {
    $nodes=@($Tree.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Find-OfflineControl'},$true))
    if ($nodes.Count -ne 1) { throw 'Unique actual selector function required' }
    $body=$nodes[0].Extent.Text
    # Replace only AST-identified clock construction, equally in both versions.
    $clocks=@($nodes[0].FindAll({param($n) $n -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Extent.Text -ceq '[Diagnostics.Stopwatch]::StartNew()'},$true))
    if ($clocks.Count -ne 2) { throw 'Selector clock contract changed' }
    foreach ($clock in ($clocks | Sort-Object { $_.Extent.StartOffset } -Descending)) {
        $offset=$clock.Extent.StartOffset-$nodes[0].Extent.StartOffset
        $body=$body.Remove($offset,$clock.Extent.Text.Length).Insert($offset,'(New-SelectorClock)')
    }
    return [scriptblock]::Create($body)
}
$original=Selector-Body $baseline; $candidate=Selector-Body $source
$callsites=@($source.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Find-OfflineControl' -and @($n.CommandElements | Where-Object { $_ -is [Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -ceq 'ObserveStartStopSelector' }).Count -gt 0},$true))
if ($callsites.Count -ne 1 -or $callsites[0].Extent.Text -notmatch "\) 60 -ObserveStartStopSelector$") { throw 'Observation must be confined to original 60-second caller' }
$accept=@($source.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Invoke-OfflineGuiAcceptance'},$true))
if ($accept.Count -ne 1 -or $callsites[0].Extent.StartOffset -lt $accept[0].Extent.StartOffset -or $callsites[0].Extent.EndOffset -gt $accept[0].Extent.EndOffset) { throw 'Observation caller escaped acceptance function' }
# These statements must remain adjacent: Start, original Stop wait, Bind.
$statements=@($accept[0].Body.EndBlock.Statements)
$wait=-1
for ($i=0;$i -lt $statements.Count;$i++) { if ($statements[$i].Extent.Text.Contains('-ObserveStartStopSelector')) { $wait=$i } }
if ($wait -lt 2 -or $statements[$wait+1].Extent.Text -cne 'Bind-OfflineRuntime' -or $statements[$wait-2].Extent.Text -cne "`$report.offline.action_stage = 'runtime_start'" -or $statements[$wait-1].Extent.Text -notmatch '^Press-OfflineButton ') { throw 'Start/wait/Bind ordering changed' }
function Trace([string]$Value) { $script:trace.Add($Value) }
function New-SelectorClock {
    Trace 'clock'
    $c=[pscustomobject]@{Elapsed=[pscustomobject]@{TotalSeconds=0.0}}
    $script:clocks.Add($c);return $c
}
function Assert-Target { param($Foreground) Trace 'guard';if ($script:case -ceq 'guard') { throw 'fixture-private-canary' } }
function Get-OfflineReplacementRoot { Trace 'root';return $script:root }
function Get-OfflineReplacementWalker { Trace 'walker';return $script:walker }
function Pause-Probe {
    Trace 'pause';$script:pauses++
    if ($script:case -cne 'saturation' -or $script:pauses -ge 260) { $script:clocks[0].Elapsed.TotalSeconds=61 }
}
function New-Node([int]$Id,$Type,[string]$Name='other',$Enabled=$true) {
    $cur=[pscustomobject]@{Id=$Id;Pid=20;Type=$Type;Label=$Name;Enabled=$Enabled;TypeReads=0}
    $cur | Add-Member ScriptProperty ProcessId { Trace ('pid:'+ $this.Id);if ($this.Id -eq 3 -and $script:case -in @('pid_throw_miss','pid_throw_match')) { throw 'fixture-private-canary' };return $this.Pid }
    $cur | Add-Member ScriptProperty ControlType { Trace ('type:'+ $this.Id);$this.TypeReads++;if (($this.Id -eq 3 -and $script:case -ceq 'type_throw') -or ($this.Id -eq 2 -and $this.TypeReads -eq 2 -and $script:case -ceq 'second_type_throw')) { throw 'fixture-private-canary' };return $this.Type }
    $cur | Add-Member ScriptProperty Name { Trace ('name:'+ $this.Id);if ($this.Id -eq 3 -and $script:case -ceq 'name_throw') { throw 'fixture-private-canary' };return $this.Label }
    $cur | Add-Member ScriptProperty IsEnabled { Trace ('enabled:'+ $this.Id);if ($script:case -ceq 'enabled_throw') { throw 'fixture-private-canary' };return $this.Enabled }
    $node=[pscustomobject]@{Id=$Id;Info=$cur;Children=@();Sibling=$null}
    $node | Add-Member ScriptProperty Current { Trace ('current:'+ $this.Id);if ($script:case -ceq 'current_throw' -and $this.Id -eq 3) { throw 'fixture-private-canary' };return $this.Info }
    return $node
}
function Reset-Case([string]$Case) {
    $script:case=$Case;$script:trace=[Collections.Generic.List[string]]::new();$script:clocks=[Collections.Generic.List[object]]::new();$script:pauses=0
    $script:report=@{offline=@{}};$script:ownedIds=[Collections.Generic.HashSet[int]]::new();[void]$ownedIds.Add(20)
    $script:root=New-Node 1 ([Windows.Automation.ControlType]::Window)
    $script:document=New-Node 2 ([Windows.Automation.ControlType]::Document)
    $script:button=New-Node 3 ([Windows.Automation.ControlType]::Button) 'synthetic-stop'
    $root.Children=@($document);$document.Children=@($button)
    switch ($Case) {
        'current_null' { $button.Info=$null }
        'pid_null_miss' { $button.Info.Pid=$null;$button.Info.Label='other' }
        'pid_throw_miss' { $button.Info.Label='other' }
        'pid_string' { $button.Info.Pid='20' }
        'type_null' { $button.Info.Type=$null }
        'type_wrong' { $button.Info.Type=123 }
        'typename_throw' {
            $type=[pscustomobject]@{}
            $type | Add-Member ScriptProperty ProgrammaticName { Trace 'typename:3';throw 'fixture-private-canary' }
            $button.Info.Type=$type
        }
        'typename_null' { $button.Info.Type=[pscustomobject]@{ProgrammaticName=$null} }
        'typename_wrong' { $button.Info.Type=[pscustomobject]@{ProgrammaticName=123} }
        'type_object_match' { $button.Info.Type=[pscustomobject]@{ProgrammaticName='ControlType.Button'} }
        'name_null' { $button.Info.Label=$null }
        'name_wrong' { $button.Info.Label=123 }
        'disabled' { $button.Info.Enabled=$false }
        'saturation' { $button.Info.Enabled=$false }
        'absent' { $document.Children=@() }
        'outside_document' { $root.Children=@($button) }
        'foreign' { $button.Info.Pid=99 }
        'truthy_nonbool' { $button.Info.Enabled='truthy' }
        'falsey_nonbool' { $button.Info.Enabled=$null }
        'allow_absent' { $button.Info.Enabled=$false }
        'mixed_duplicate' { $other=New-Node 4 ([Windows.Automation.ControlType]::Button) 'synthetic-stop' $false;$button.Sibling=$other }
        'enabled_duplicate' { $other=New-Node 4 ([Windows.Automation.ControlType]::Button) 'synthetic-stop';$button.Sibling=$other }
        'depth' { $cursor=$document;foreach ($id in 10..42) { $next=New-Node $id ([Windows.Automation.ControlType]::Pane);$cursor.Children=@($next);$cursor=$next };$cursor.Children=@($button) }
        'nodes' { $cursor=$button;foreach ($id in 10..530) { $next=New-Node $id ([Windows.Automation.ControlType]::Pane);$cursor.Sibling=$next;$cursor=$next } }
    }
    $script:walker=[pscustomobject]@{}
    $walker | Add-Member ScriptMethod GetFirstChild {
        param($Node) Trace ('first:'+ $Node.Id)
        if ($script:case -ceq 'walker_throw') { throw 'fixture-private-canary' }
        if ($script:case -ceq 'walk_budget') { $script:clocks[$script:clocks.Count-1].Elapsed.TotalSeconds=6 }
        if ($Node.Children.Count) { return $Node.Children[0] };return $null
    }
    $walker | Add-Member ScriptMethod GetNextSibling { param($Node) Trace ('next:'+ $Node.Id);return $Node.Sibling }
}
function Run-Case($Definition,[string]$Case,[bool]$Observe) {
    Reset-Case $Case
    . $Definition
    $failure=$null;$id=$null
    try {
        $params=@{Type='ControlType.Button';Name='^synthetic-stop$';Seconds=60}
        if ($Case -ceq 'allow_absent') { $params.AllowAbsent=$true }
        if ($Observe) { $params.ObserveStartStopSelector=$true }
        $result=Find-OfflineControl @params
        if ($null -ne $result) { $id=$result.Id }
    } catch { $failure=$_.Exception.Message }
    return @{failure=$failure;id=$id;trace=($script:trace -join ',');diagnostic=$report.offline.runtime_start_stop_selector;pauses=$script:pauses}
}
$expected=@{enabled='enabled';disabled='disabled';absent='absent';outside_document='absent';foreign='unobservable';truthy_nonbool='unobservable';falsey_nonbool='unobservable';allow_absent='unobservable';mixed_duplicate='ambiguous';enabled_duplicate='ambiguous';depth='unobservable';nodes='unobservable';guard='unobservable';current_throw='unobservable';enabled_throw='unobservable';walker_throw='unobservable';walk_budget='unobservable';saturation='disabled'}
foreach ($name in @('current_null','pid_null_miss','pid_throw_miss','pid_throw_match','pid_string','type_null','type_wrong','type_throw','second_type_throw','typename_throw','typename_null','typename_wrong','type_object_match','name_null','name_wrong','name_throw')) { $expected[$name]='unobservable' }
foreach ($case in $expected.Keys) {
    $before=Run-Case $original $case $false
    $off=Run-Case $candidate $case $false
    $after=Run-Case $candidate $case $true
    foreach ($actual in @($off,$after)) {
        if ($actual.failure -cne $before.failure -or $actual.id -cne $before.id -or $actual.trace -cne $before.trace) { throw "Selector behavior/read order changed: $case" }
    }
    if ($null -ne $off.diagnostic) { throw 'Default selector unexpectedly emits diagnostics' }
    if ($after.diagnostic.state -cne $expected[$case]) { throw "Wrong closed state: $case" }
    $count=$after.diagnostic.complete_samples
    # Derive completed traversals from the real baseline on THIS engine.
    # A return or the baseline ambiguity throw completes its final walk;
    # each pause follows one completed zero-enabled walk. Other failures do not.
    # Thus suppressed getter errors can complete, while propagated errors do not.
    $want=$before.pauses
    if ($null -ne $before.id -or $case -ceq 'allow_absent' -and $null -eq $before.failure -or $before.failure -ceq 'Offline selector is ambiguous') { $want++ }
    $want=[Math]::Min(256,$want)
    if ($count -isnot [int] -or $count -ne $want) { throw "Wrong bounded complete count: $case" }
    if (($after.diagnostic | ConvertTo-Json -Compress) -match 'fixture-private-canary|synthetic-stop|ControlType') { throw 'Diagnostic leaked private input' }
}
Write-Output "$($expected.Count) differential selector cases: identical getters, walker/guard/clock/pause order, result and exception, with diagnostics on and off."
