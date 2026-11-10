# Execute the actual rejection assertion and helpers against disposable synthetic fixtures.
param([string]$Sweep = (Join-Path $PSScriptRoot 'dev-release-sweep.ps1'))
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Sweep, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Sweep parse failed' }
foreach ($name in @('Test-RuntimeUnchanged', 'Get-AccountRejectionSnapshot')) {
    $functions = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name }, $true))
    if ($functions.Count -ne 1) { throw "Missing unique helper: $name" }
    . ([scriptblock]::Create($functions[0].Extent.Text))
}
$checks = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Assert-Smoke' -and $n.Extent.Text.StartsWith("Assert-Smoke 'account-live-rejected-restores-service'") }, $true))
if ($checks.Count -ne 1) { throw 'Missing unique rejection assertion' }
$check = [scriptblock]::Create($checks[0].Extent.Text)
function Assert-Smoke([string]$Name, [bool]$Condition) { if (-not $Condition) { throw $Name } }
function Get-Process { param($Id, $ErrorAction) if ($script:alive) { return [pscustomobject]@{Id=$Id} } }
$DirA = Join-Path ([IO.Path]::GetTempPath()) ('rejection-contract-' + [Guid]::NewGuid().ToString('N'))
$otherUser = 'synthetic'
$profile = Join-Path $DirA "accounts/$otherUser"
New-Item -ItemType Directory -Path $profile, (Join-Path $DirA 'runtime') -Force | Out-Null
function Reset-Fixture {
    $script:alive = $true
    foreach ($file in @('client.json', 'runtime/endpoint.json', "accounts/$otherUser/session.json")) {
        [IO.File]::WriteAllText((Join-Path $DirA $file), '{}')
    }
    foreach ($path in @('invalid', 'accounts/unexpected')) {
        if (Test-Path (Join-Path $DirA $path)) { Remove-Item (Join-Path $DirA $path) -Recurse -Force }
    }
    $script:profileConfig = [IO.File]::ReadAllBytes((Join-Path $DirA 'client.json'))
    $script:rejectionSnapshot = Get-AccountRejectionSnapshot $DirA $profile
    $script:switchedHealth = [pscustomobject]@{pid=101;data_dir=$profile;account_id='account';instance_id='actor';generation=5;exe='owned';bin='dev';runtime_version='dev';store_ready=$true}
    $script:rejectedHealth = $switchedHealth.PSObject.Copy()
    $script:invalidAccount = [pscustomobject]@{Ok=$true;Exit=1;Envelope=[pscustomobject]@{errors=@('account profile name allows only letters/digits/-/_')}}
    $script:rejectedStatus = [pscustomobject]@{Ok=$true;Envelope=[pscustomobject]@{summary=[pscustomobject]@{session=[pscustomobject]@{user=$otherUser};unlocked=$true}}}
}
# The diagnostic label must not alias the script-scope foreach $case iterator.
function Check-Run([bool]$Expected) {
    $passed = $true
    try { & $check } catch { $passed = $false }
    if ($passed -ne $Expected) { throw "Rejection contract mutation failed: $script:caseLabel" }
}
try {
    Reset-Fixture; $script:caseLabel='same actor'; Check-Run $true
    foreach ($field in @('pid','data_dir','account_id','instance_id','generation','exe','bin','runtime_version','store_ready')) {
        Reset-Fixture; $script:caseLabel=$field
        switch ($field) {
            'pid' { $rejectedHealth.pid=102 }
            'generation' { $rejectedHealth.generation=6 }
            'store_ready' { $rejectedHealth.store_ready=$false }
            default { $rejectedHealth.$field='changed' }
        }
        Check-Run $false
    }
    foreach ($case in @('dead','empty-account','empty-instance','zero-generation','before-not-ready','wrong-profile','wrong-user','locked','status-fail','command-fail','wrong-exit','wrong-error','config-write','endpoint-write','session-write','new-profile','traversal-path')) {
        Reset-Fixture; $script:caseLabel=$case
        switch ($case) {
            'dead' { $script:alive=$false }
            'empty-account' { $switchedHealth.account_id='';$rejectedHealth.account_id='' }
            'empty-instance' { $switchedHealth.instance_id='';$rejectedHealth.instance_id='' }
            'zero-generation' { $switchedHealth.generation=0;$rejectedHealth.generation=0 }
            'before-not-ready' { $switchedHealth.store_ready=$false }
            'wrong-profile' { $switchedHealth.data_dir=$DirA;$rejectedHealth.data_dir=$DirA }
            'wrong-user' { $rejectedStatus.Envelope.summary.session.user='other' }
            'locked' { $rejectedStatus.Envelope.summary.unlocked=$false }
            'status-fail' { $rejectedStatus.Ok=$false }
            'command-fail' { $invalidAccount.Ok=$false }
            'wrong-exit' { $invalidAccount.Exit=0 }
            'wrong-error' { $invalidAccount.Envelope.errors=@('unrelated') }
            'config-write' { [IO.File]::WriteAllText((Join-Path $DirA 'client.json'), 'changed') }
            'endpoint-write' { [IO.File]::WriteAllText((Join-Path $DirA 'runtime/endpoint.json'), 'changed') }
            'session-write' { [IO.File]::WriteAllText((Join-Path $profile 'session.json'), 'changed') }
            'new-profile' { New-Item -ItemType Directory (Join-Path $DirA 'accounts/unexpected') | Out-Null }
            'traversal-path' { New-Item -ItemType Directory (Join-Path $DirA 'invalid') | Out-Null }
        }
        Check-Run $false
    }
    Write-Output 'PASS: same actor accepted; 26 identity/readiness/status/result/side-effect mutations rejected.'
    $spaceChecks = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Assert-Smoke' -and $n.Extent.Text.StartsWith("Assert-Smoke 'space-live-rejected-restores-service'") }, $true))
    if ($spaceChecks.Count -ne 1) { throw 'Missing unique space rejection assertion' }
    $check = [scriptblock]::Create($spaceChecks[0].Extent.Text)
    $otherUser = 'sweepspace'; $profile = Join-Path $DirA 'accounts/sweepspace'
    New-Item -ItemType Directory $profile -Force | Out-Null
    foreach ($case in @('same-actor','pid','instance','generation','account','not-ready','dead','wrong-profile','read-fail','wrong-id','wrong-content','config-write','endpoint-write','session-write','created-space','new-profile','wrong-exit','wrong-reason','wrong-type','wrong-error','command-fail')) {
        Reset-Fixture; $script:caseLabel='space-' + $case
        $spaceProfileConfig=$profileConfig; $spaceRejectionSnapshot=$rejectionSnapshot
        $spaceReturnHealth=$switchedHealth; $spaceRejectedHealth=$rejectedHealth
        $missingSpace='missing'; $spaceEntryId='synthetic-id'; $spaceMarker='synthetic-content'
        $spaceRejected=[pscustomobject]@{Ok=$true;Exit=2;Envelope=[pscustomobject]@{summary=[pscustomobject]@{reason='invalid_input'};details=[pscustomobject]@{error_type='user'};errors=@('space "missing" does not exist')}}
        $spaceRejectedReadback=[pscustomobject]@{Ok=$true;Envelope=[pscustomobject]@{details=[pscustomobject]@{entry=[pscustomobject]@{id=$spaceEntryId;content=$spaceMarker}}}}
        switch ($case) {
            'pid' { $spaceRejectedHealth.pid=102 }
            'instance' { $spaceRejectedHealth.instance_id='new' }
            'generation' { $spaceRejectedHealth.generation=6 }
            'account' { $spaceRejectedHealth.account_id='new' }
            'not-ready' { $spaceRejectedHealth.store_ready=$false }
            'dead' { $script:alive=$false }
            'wrong-profile' { $spaceRejectedHealth.data_dir=$DirA }
            'read-fail' { $spaceRejectedReadback.Ok=$false }
            'wrong-id' { $spaceRejectedReadback.Envelope.details.entry.id='wrong' }
            'wrong-content' { $spaceRejectedReadback.Envelope.details.entry.content='wrong' }
            'config-write' { [IO.File]::WriteAllText((Join-Path $DirA 'client.json'), 'changed') }
            'endpoint-write' { [IO.File]::WriteAllText((Join-Path $DirA 'runtime/endpoint.json'), 'changed') }
            'session-write' { [IO.File]::WriteAllText((Join-Path $profile 'session.json'), 'changed') }
            'created-space' { New-Item -ItemType Directory (Join-Path $DirA 'accounts/missing') | Out-Null }
            'new-profile' { New-Item -ItemType Directory (Join-Path $DirA 'accounts/unexpected') | Out-Null }
            'wrong-exit' { $spaceRejected.Exit=1 }
            'wrong-reason' { $spaceRejected.Envelope.summary.reason='wrong' }
            'wrong-type' { $spaceRejected.Envelope.details.error_type='wrong' }
            'wrong-error' { $spaceRejected.Envelope.errors=@('wrong') }
            'command-fail' { $spaceRejected.Ok=$false }
        }
        Check-Run ($case -ceq 'same-actor')
        if (Test-Path (Join-Path $DirA 'accounts/missing')) { Remove-Item (Join-Path $DirA 'accounts/missing') -Recurse -Force }
    }
    Write-Output 'PASS: missing-space same actor accepted; 20 mutations rejected.'
} finally { Remove-Item -LiteralPath $DirA -Recurse -Force }
