# Execute real AST functions and the unchanged acceptance stop tail over synthetic providers.
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Stop diagnostic source parse failed' }
$press=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Press-OfflineButton'},$true))
$accept=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Invoke-OfflineGuiAcceptance'},$true))
if ($press.Count -ne 1 -or $accept.Count -ne 1) { throw 'Stop diagnostic source functions missing' }
. ([scriptblock]::Create($press[0].Extent.Text))
$getInvoke=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Get-OfflineButtonInvoke'},$true))
if ($getInvoke.Count -ne 1) { throw 'Stop pattern acquisition function missing' }
. ([scriptblock]::Create($getInvoke[0].Extent.Text))
$prepare=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Prepare-OfflineButtonInvoke'},$true))
if ($prepare.Count -ne 1) { throw 'Stop preparation function missing' }
. ([scriptblock]::Create($prepare[0].Extent.Text))
function Record-Step([string]$Name) {
    $script:calls.Add($Name)
    if ($script:fail -ceq $Name -or ($script:fail -ceq 'post_guard' -and $Name -ceq 'guard' -and @($script:calls | Where-Object { $_ -ceq 'guard' }).Count -eq 2)) { throw 'Synthetic observation failure' }
}
function Find-FocusedOfflineButton { param($Name,[switch]$PrepareInvoke,$DiagnosticStage) Record-Step 'select'; if ($PrepareInvoke) { $evidence=$null; $diag=@{}; if ($DiagnosticStage) { $diag.DiagnosticStage=$DiagnosticStage }; return (Prepare-OfflineButtonInvoke $script:element ([ref]$evidence) @diag) }; return $script:element }
function Assert-Target { param($Foreground) Record-Step 'guard' }
function Read-TargetFocus { Record-Step 'focus'; return @{belongs_to_target=$true;in_document=$true;offscreen=$false;runtime_id='7'} }
function Assert-AccountFocusStable { throw 'Stop diagnostics unexpectedly requested stability' }
$script:element=[pscustomobject]@{}
$element | Add-Member ScriptMethod GetRuntimeId { Record-Step 'id'; return @(7) }
$element | Add-Member ScriptMethod TryGetCurrentPattern { param($Type,$Result) Record-Step 'pattern'; $Result.Value=$script:pattern; return $true }
$script:pattern=[pscustomobject]@{}
$pattern | Add-Member ScriptMethod Invoke { Record-Step 'invoke' }
foreach ($mode in @('default','normal_stop')) {
    $script:fail=''; $script:calls=[Collections.Generic.List[string]]::new()
    $script:report=@{offline=@{action_stage='sentinel';failure_kind='unknown'}}
    if ($mode -eq 'default') { Press-OfflineButton 'synthetic' } else { Press-OfflineButton 'synthetic' -DiagnosticStage normal_stop }
    if (($calls -join ',') -cne 'select,id,pattern,guard,focus,invoke,guard') { throw 'Diagnostic option changed button operations' }
    $expected='sentinel'; if ($mode -eq 'normal_stop') { $expected='normal_stop_post_invoke_guard' }
    if ($report.offline.action_stage -cne $expected) { throw 'Button diagnostic default or terminal stage changed' }
}
foreach ($case in @(@('select','normal_stop_select','select'),@('pattern','normal_stop_pattern','select,id,pattern'),@('guard','normal_stop_focus_guard','select,id,pattern,guard'),@('post_guard','normal_stop_post_invoke_guard','select,id,pattern,guard,focus,invoke,guard'),@('focus','normal_stop_focus_guard','select,id,pattern,guard,focus'),@('invoke','normal_stop_invoke','select,id,pattern,guard,focus,invoke'))) {
    $script:fail=$case[0]; $script:calls=[Collections.Generic.List[string]]::new(); $script:report=@{offline=@{failure_kind='unknown'}}
    $caught=$false; try { Press-OfflineButton 'synthetic' -DiagnosticStage normal_stop } catch { $caught=$true }
    if (-not $caught -or $report.offline.action_stage -cne $case[1] -or ($calls -join ',') -cne $case[2] -or $report.offline.failure_kind -cne 'unknown') { throw 'Button diagnostic failure replayed or misclassified' }
}
# Extract actual top-level acceptance statements starting at the process lookup breadcrumb.
$statements=@($accept[0].Body.EndBlock.Statements)
$start=-1
for ($i=0;$i -lt $statements.Count;$i++) {
    if ($statements[$i].Extent.Text -ceq "`$report.offline.action_stage = 'normal_stop_process_lookup'") { $start=$i; break }
}
if ($start -lt 0) { throw 'Missing acceptance stop tail' }
$tail=[scriptblock]::Create((($statements[$start..($statements.Count-1)] | ForEach-Object { $_.Extent.Text }) -join "`n"))
function Get-Process { param($Id,$ErrorAction) Record-Step 'lookup'; if ($script:case -eq 'absent') { return $null }; return $script:process }
function Get-CimInstance { param($Class,$Filter) Record-Step 'cim'; if ($script:case -eq 'present' -or ($script:case -eq 'present_second' -and @($script:calls | Where-Object { $_ -ceq 'cim' }).Count -eq 2)) { return [pscustomobject]@{} }; return $null }
function Pause-Probe { Record-Step 'pause' }
foreach ($script:case in @('success','absent','reused','timeout','present','present_second','lookup_error')) {
    $script:calls=[Collections.Generic.List[string]]::new(); $script:fail=''; if ($case -eq 'lookup_error') { $script:fail='lookup' }
    $script:report=@{offline=@{failure_kind='unknown';runtime_normal_stop_confirmed=$false}}
    $script:offlineRuntime=@{pid=123;started_ticks=100}
    $script:process=[pscustomobject]@{StartTime=[datetime]::new(100,[DateTimeKind]::Utc)}
    if ($case -eq 'reused') { $process.StartTime=[datetime]::new(101,[DateTimeKind]::Utc) }
    $process | Add-Member ScriptMethod WaitForExit { param($Milliseconds) if ($Milliseconds -ne 30000) { throw 'Stop wait changed' }; Record-Step 'wait'; return ($script:case -ne 'timeout') }
    $caught=$null; try { . $tail } catch { $caught=$_.Exception.Message }
    $expectedCalls='lookup,wait,cim,pause,cim,pause'; $kind='unknown'; $stage='normal_stop_confirmed'; $message=$null
    switch ($case) {
        'absent' { $expectedCalls='lookup,cim,pause,cim,pause' }
        'reused' { $expectedCalls='lookup'; $kind='pid_reused'; $stage='normal_stop_birth_check'; $message='Runtime PID reused before normal-stop observation' }
        'timeout' { $expectedCalls='lookup,wait'; $kind='exit_timeout'; $stage='normal_stop_wait_exit'; $message='Runtime did not exit after visible normal Stop' }
        'present' { $expectedCalls='lookup,wait,cim'; $kind='pid_present_after_stop'; $stage='normal_stop_cim_first'; $message='Runtime PID still exists or was reused after normal Stop' }
        'present_second' { $expectedCalls='lookup,wait,cim,pause,cim'; $kind='pid_present_after_stop'; $stage='normal_stop_cim_second'; $message='Runtime PID still exists or was reused after normal Stop' }
        'lookup_error' { $expectedCalls='lookup'; $stage='normal_stop_process_lookup'; $message='Synthetic observation failure' }
    }
    if (($calls -join ',') -cne $expectedCalls -or $report.offline.failure_kind -cne $kind -or $report.offline.action_stage -cne $stage -or $caught -cne $message -or $report.offline.runtime_normal_stop_confirmed -ne ($null -eq $message)) { throw 'Actual stop tail changed operations, exception, or closed diagnostics' }
}
Write-Host 'PASS: actual stop AST preserves operations and exceptions with closed diagnostics'
