# Exercise the actual diagnostic function without running the account/network sweep.
param([string]$Sweep = (Join-Path $PSScriptRoot 'dev-release-sweep.ps1'))
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Sweep, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Sweep parse failed' }
$functions = @($ast.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-SafeFailureReason'
}, $true))
if ($functions.Count -ne 1) { throw 'Sweep diagnostic function changed' }
. ([scriptblock]::Create($functions[0].Extent.Text))

function Assert-Diagnostic($Envelope, [string]$Expected) {
    $actual = @(Get-SafeFailureReason $Envelope)
    if ($actual.Count -ne 1 -or $actual[0] -isnot [string] -or $actual[0] -cne $Expected) {
        # Never include the supplied envelope or actual output in assertion diagnostics.
        throw 'Account failure diagnostic whitelist mismatch'
    }
}

foreach ($reason in @('account_outcome_unknown', 'account_handoff_pending')) {
    # Parse like the real CLI envelope. Adversarial private fields must not escape,
    # and old text heuristics must not obscure the structured transaction state.
    $envelope = @{
        command = 'register'; summary = @{ reason = $reason; token = 'synthetic-private-token' }
        details = @{ operation_id = 'synthetic-private-operation'; source_profile = 'synthetic-private-path' }
        actions = @('synthetic-private-action'); errors = @('HTTP 401 synthetic-private-secret')
    } | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    Assert-Diagnostic $envelope $reason
}

foreach ($reason in @(
    'account_outcome_unknown synthetic-private-secret',
    'account_handoff_pending/synthetic-private-secret',
    'ACCOUNT_OUTCOME_UNKNOWN', ' account_handoff_pending', '',
    $true, 1, $null,
    @('account_outcome_unknown'),
    @{ value = 'account_handoff_pending'; secret = 'synthetic-private-secret' }
)) {
    $envelope = @{
        summary = @{ reason = $reason }
        errors = @('synthetic-private-secret')
        details = @{ reason = 'account_handoff_pending' }
        actions = @('account_outcome_unknown synthetic-private-secret')
    } | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    Assert-Diagnostic $envelope 'unclassified'
}
# Explicit collection case prevents PowerShell pipeline enumeration from hiding a type bug.
Assert-Diagnostic ([pscustomobject]@{
    summary = [pscustomobject]@{ reason = @('account_outcome_unknown') }
    errors = @('synthetic-private-secret')
}) 'unclassified'
foreach ($envelope in @($null, [pscustomobject]@{}, [pscustomobject]@{ summary = $null })) {
    Assert-Diagnostic $envelope 'unclassified'
}
# Existing non-account classification remains intact.
Assert-Diagnostic ([pscustomobject]@{ errors = @('already registered') }) 'account_exists'
Assert-Diagnostic ([pscustomobject]@{ summary = @{ reason = 'synthetic-private-secret' }; errors = @('HTTP 503') }) 'http_503'
foreach ($case in @(
    @('host control response channel failure', 'account_helper_channel_failed', 'auth_helper_channel_failed'),
    @('host control deadline exceeded', 'account_helper_launch_deadline', 'auth_helper_launch_deadline'),
    @('cannot wait for host control Runtime exit', 'account_helper_exit_wait_failed', 'auth_helper_exit_wait_failed'),
    @('host control response deadline or channel failure', 'account_helper_deadline_or_channel', 'auth_helper_deadline_or_channel'),
    @('host control response deadline exceeded', 'account_helper_deadline_or_channel', 'auth_helper_deadline_or_channel'),
    @('host control exit deadline exceeded', 'account_helper_deadline_or_channel', 'auth_helper_deadline_or_channel')
)) {
    Assert-Diagnostic ([pscustomobject]@{ summary = @{ reason = 'account_outcome_unknown' }
        errors = @("$($case[0]): synthetic-private-secret") }) "account_outcome_unknown/$($case[1])"
    Assert-Diagnostic ([pscustomobject]@{ errors = @("$($case[0]): synthetic-private-secret") }) $case[2]
}
foreach ($case in @(
    @('parent authorization ended or control channel was interrupted', 'account_parent_revoked_or_channel_interrupted'),
    @('account deadline or parent authorization ended', 'account_runtime_deadline_or_parent_revoked'),
    @('control deadline or parent revocation; query the same operation ID before retrying', 'account_runtime_deadline_or_parent_revoked')
)) {
    Assert-Diagnostic ([pscustomobject]@{ summary = @{ reason = 'account_outcome_unknown' }
        errors = @("Runtime rejected account control (control_outcome_unknown): $($case[0]); synthetic-private-secret") }) "account_outcome_unknown/$($case[1])"
}
foreach ($class in @('auth_parent_revoked_or_channel_interrupted', 'auth_runtime_deadline_or_parent_revoked')) {
    Assert-Diagnostic ([pscustomobject]@{ errors = @("auth control completion is unknown; auth_diagnostic=$class; synthetic-private-secret") }) $class
}
Write-Host 'PASS: account diagnostic whitelist preserves outcomes without private fields'
