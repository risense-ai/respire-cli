<# Manually invoke a Windows Task Scheduler sign-in action against a disposable off-mode profile.
   Never installs startup on a user's computer. Intended for the manual hosted CI job.
   No account, keyring, model download, password, elevation or persistent credential.
   Does not exercise an actual logon or establish G1 acceptance.
#>
param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [string]$RuntimeExecutable = $env:RSRS_RUNTIME_BIN,
    [string]$RuntimeArchive = $env:RSRS_RUNTIME_ARCHIVE,
    [string]$RuntimeVersion = $env:RSRS_RUNTIME_VERSION
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:STARTUP_TEST_HOSTED -ne 'true') {
    throw 'This fixture runs only in the explicitly selected GitHub-hosted Windows CI job'
}
if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
    throw 'Windows Task Scheduler validation requires Windows'
}
$nativeExecutable = (Get-Item -LiteralPath $Executable -ErrorAction Stop).FullName
if ([IO.Path]::GetExtension($nativeExecutable) -ne '.exe') { throw 'Expected a native CLI executable' }
if ($RuntimeArchive -and ($RuntimeExecutable -or -not $RuntimeVersion)) {
    throw 'Runtime archive requires a version and cannot be combined with a Runtime executable'
}
if ($RuntimeVersion -and -not $RuntimeArchive) { throw 'Runtime version requires a Runtime archive' }
if (-not $RuntimeArchive -and [string]::IsNullOrWhiteSpace($RuntimeExecutable)) {
    $RuntimeExecutable = Join-Path ([IO.Path]::GetDirectoryName($nativeExecutable)) 'rsrs-runtime.exe'
}
$runtimeCandidate = if ($RuntimeArchive) { $null } else { (Get-Item -LiteralPath $RuntimeExecutable -ErrorAction Stop).FullName }
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('respire-startup-ci-' + [guid]::NewGuid().ToString('N'))
$fixtureHome = Join-Path $fixtureRoot 'home'
$profileRoot = Join-Path $fixtureHome '.rsrs'
$selectedProfile = Join-Path $profileRoot 'accounts/startup-fixture'
$nativeDirectory = Join-Path $profileRoot 'bin'
$statusFile = Join-Path $fixtureRoot 'startup-status.json'
$taskName = 'RespireStartupCI-' + [guid]::NewGuid().ToString('N')
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$registered = $false
$runtimeOwned = $false
$startupAttempted = $false
$runtimeStopped = $false
$startupAction = $null
$primaryFailure = $null
$validationPassed = $false
$utf8 = [Text.UTF8Encoding]::new($false)
function Literal([string]$Value) { return "'" + $Value.Replace("'", "''") + "'" }
function NormalizeFixturePath([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { throw 'Fixture path is missing' }
    # Match the drive/UNC namespace handling in autostart::manager::windows_task_path.
    if ($Value.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
        $Value = '\\' + $Value.Substring(8)
    } elseif ($Value.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) {
        $Value = $Value.Substring(4)
        if ($Value -notmatch '^[A-Za-z]:\\') { throw 'Unsupported Windows fixture path namespace' }
    }
    return [IO.Path]::GetFullPath($Value)
}
function FixturePathEquals([string]$Actual, [string]$Expected) {
    return [StringComparer]::OrdinalIgnoreCase.Equals((NormalizeFixturePath $Actual), (NormalizeFixturePath $Expected))
}
function EnvironmentPrefix {
    return @"
Get-ChildItem Env: | Where-Object { `$_.Name -match '^(RSRS_|RESPIRE_|ONEMEMORY_)' } | Remove-Item
`$env:HOME = $(Literal $fixtureHome)
`$env:USERPROFILE = $(Literal $fixtureHome)
`$env:RSRS_DATA_DIR = $(Literal $profileRoot)
`$env:RSRS_BIN_DIR = $(Literal $nativeDirectory)
`$env:RSRS_RUNTIME_BIN = $(Literal $fixtureRuntime)
`$env:RSRS_CORE_TEST_MODE = '1'
`$env:RSRS_RPC_PORT = '$runtimePort'
`$env:RSRS_NO_AUTOSYNC = '1'
`$env:RSRS_UPDATE_CHECK = '0'
`$env:RUST_MIN_STACK = '16777216'
"@
}
$powershell = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
function InvokeFixture([string]$Arguments) {
    $code = (EnvironmentPrefix) + "`n& " + (Literal $nativeExecutable) + ' ' + $Arguments + "`nexit `$LASTEXITCODE"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $result = & $powershell -NoProfile -NonInteractive -EncodedCommand $encoded
    $fixtureExit = $LASTEXITCODE
    return @{exit = $fixtureExit; output = ($result -join "`n")}
}
function FindFixtureTask {
    try { return Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop }
    catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) { return $null }
        throw
    }
}
function ResolveTaskSid([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 512) { throw 'Task identity is missing or invalid' }
    try {
        if ($Value -match '^S-\d-') { return [Security.Principal.SecurityIdentifier]::new($Value).Value }
        return [Security.Principal.NTAccount]::new($Value).Translate([Security.Principal.SecurityIdentifier]).Value
    } catch { throw 'Task identity could not be resolved to a verified Windows SID' }
}
function TaskOwnershipChecks($TaskObject) {
    $actions = @($TaskObject.Actions)
    $triggers = @($TaskObject.Triggers)
    $principalSid = ResolveTaskSid $TaskObject.Principal.UserId
    $triggerSid = if ($triggers.Count -eq 1) { ResolveTaskSid $triggers[0].UserId } else { '' }
    $actionPathMatches = $false
    if ($actions.Count -eq 1 -and -not [string]::IsNullOrWhiteSpace($actions[0].Execute)) {
        $actionPathMatches = FixturePathEquals $actions[0].Execute $powershell
    }
    return [ordered]@{
        principal_sid = $principalSid -eq $identity.User.Value
        interactive = $TaskObject.Principal.LogonType -eq 'Interactive'
        limited = $TaskObject.Principal.RunLevel -eq 'Limited'
        one_action = $actions.Count -eq 1
        executable = $actionPathMatches
        arguments = $actions.Count -eq 1 -and $actions[0].Arguments -ceq $startupAction.Arguments
        one_trigger = $triggers.Count -eq 1
        logon_trigger = $triggers.Count -eq 1 -and $triggers[0].CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger'
        trigger_sid = $triggerSid -eq $identity.User.Value
    }
}
function RemoveFixtureTask {
    $currentTask = FindFixtureTask
    if ($null -eq $currentTask) { return }
    $checks = TaskOwnershipChecks $currentTask
    if ($checks.Values -contains $false) { throw 'Task ownership/action/trigger changed; refusing removal' }
    if ($currentTask.State -eq 'Running') {
        Stop-ScheduledTask -TaskName $taskName -TaskPath '\'
        $stopDeadline = [DateTime]::UtcNow.AddSeconds(10)
        while ((FindFixtureTask).State -eq 'Running' -and [DateTime]::UtcNow -lt $stopDeadline) {
            Start-Sleep -Milliseconds 100
        }
        if ((FindFixtureTask).State -eq 'Running') { throw 'Owned scheduled task did not stop; preserving fixture' }
    }
    Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false
    if ($null -ne (FindFixtureTask)) { throw 'Fixture task remained after removal' }
}
try {
    New-Item -ItemType Directory -Path $selectedProfile -Force | Out-Null
    $bundlePreparation = Join-Path $PSScriptRoot 'runtime-acceptance-bundle.py'
    $candidateArguments = if ($RuntimeArchive) { @('--archive', $RuntimeArchive, '--version', $RuntimeVersion) } else { @('--runtime-binary', $runtimeCandidate) }
    & python -I -B $bundlePreparation --binary $nativeExecutable --destination $nativeDirectory @candidateArguments
    if ($LASTEXITCODE -ne 0) { throw 'Independent Runtime bundle preparation failed; no startup task registered' }
    $fixtureRuntime = Join-Path $nativeDirectory 'rsrs-runtime.exe'
    [IO.File]::WriteAllText((Join-Path $profileRoot 'client.json'),
        (@{data_dir = $selectedProfile; service_mode = 'off'} | ConvertTo-Json -Compress), $utf8)
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $runtimePort = $listener.LocalEndpoint.Port
    $listener.Stop()
    $healthUrl = "http://127.0.0.1:$runtimePort/api/health"
    if ($null -ne (FindFixtureTask)) { throw 'Refusing to replace an existing task' }
    $startupCode = (EnvironmentPrefix) + "`n& " + (Literal $nativeExecutable) +
        ' runtime start --json | Out-File -Encoding utf8 -LiteralPath ' + (Literal $statusFile) + "`nexit `$LASTEXITCODE"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($startupCode))
    $startupAction = New-ScheduledTaskAction -Execute $powershell -Argument "-NoProfile -NonInteractive -EncodedCommand $encoded"
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.User.Value
    $principal = New-ScheduledTaskPrincipal -UserId $identity.User.Value -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $startupAction -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
    $registered = $true
    $task = FindFixtureTask
    $checks = TaskOwnershipChecks $task
    Write-Output (@{principal_form = $(if ($task.Principal.UserId -match '^S-\d-') {'sid'} else {'account-name'});
        trigger_form = $(if ($task.Triggers.UserId -match '^S-\d-') {'sid'} else {'account-name'});
        ownership_checks = $checks} | ConvertTo-Json -Depth 4 -Compress)
    if ($checks.Values -contains $false) { throw 'Scheduled task identity/action/trigger drifted' }
    # A case change in Base64 is a different command, even though Windows paths
    # and account names can be compared through their canonical identities.
    $base64Offset = $startupAction.Arguments.LastIndexOf(' ') + 1
    $changedArguments = $null
    for ($offset = $base64Offset; $offset -lt $startupAction.Arguments.Length; $offset++) {
        $letter = $startupAction.Arguments[$offset]
        if ([char]::IsLetter($letter)) {
            $replacement = if ([char]::IsUpper($letter)) { [char]::ToLowerInvariant($letter) } else { [char]::ToUpperInvariant($letter) }
            $changedArguments = $startupAction.Arguments.Substring(0, $offset) + $replacement + $startupAction.Arguments.Substring($offset + 1)
            break
        }
    }
    if ($null -eq $changedArguments) { throw 'Encoded command has no case-sensitive test character' }
    $changedTask = [pscustomobject]@{Principal = $task.Principal; Triggers = $task.Triggers;
        Actions = @([pscustomobject]@{Execute = $task.Actions.Execute; Arguments = $changedArguments})}
    if ((TaskOwnershipChecks $changedTask).arguments) { throw 'Case-changed encoded command was accepted' }
    $startupAttempted = $true
    Start-ScheduledTask -TaskName $taskName -TaskPath '\'
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    $health = $null
    $status = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        try { $health = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2 } catch { Start-Sleep -Milliseconds 100; continue }
        if ($health.server -ne 'respire' -or -not (FixturePathEquals $health.data_dir $selectedProfile)) {
            throw 'Fixture port belongs to another runtime/profile; no lifecycle request sent'
        }
        if (-not (FixturePathEquals $health.exe $fixtureRuntime)) {
            throw 'Fixture health does not identify the selected independent Runtime'
        }
        $runtimeOwned = $true
        if (Test-Path -LiteralPath $statusFile) {
            try { $status = Get-Content -Raw -LiteralPath $statusFile | ConvertFrom-Json } catch { $status = $null }
            if ($null -ne $status) { break }
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not $runtimeOwned -or $null -eq $status) {
        try {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\' -ErrorAction Stop
            Write-Output (@{stage = 'startup-timeout'; runtime_identity_verified = $runtimeOwned;
                result_file_exists = (Test-Path -LiteralPath $statusFile); result_parsed = ($null -ne $status);
                task_state = [string](FindFixtureTask).State; last_task_result = [long]$taskInfo.LastTaskResult} | ConvertTo-Json -Compress)
        } catch { Write-Warning 'Startup task diagnostics unavailable; original timeout retained' }
        throw 'Scheduled host startup did not become ready'
    }
    if ($status.command -ne 'runtime.start' -or $status.status -ne 'ok' -or
        $status.summary.runtime.running -ne $true -or $status.summary.runtime.pid -ne $health.pid) {
        throw 'Scheduled host start did not verify the observed runtime owner'
    }
    $runtimePid = $health.pid
    $denied = InvokeFixture '--client-only --runtime-internal --stop --json'
    if ($denied.exit -eq 0 -or ($denied.output | ConvertFrom-Json).status -ne 'fail') { throw 'Client-only lifecycle command was accepted' }
    if ((Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2).pid -ne $runtimePid) { throw 'Client-only command changed runtime ownership' }
    $stop = InvokeFixture '--runtime-internal --stop --json'
    if ($stop.exit -ne 0) { throw 'Owned host runtime could not be stopped' }
    $runtimeOwned = $false
    $runtimeStopped = $true
    RemoveFixtureTask
    $registered = $false
    $validationPassed = $true
} catch {
    $primaryFailure = $_
    throw
} finally {
  try {
    if ($runtimeOwned) {
        try {
            $current = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2
            if ($current.server -eq 'respire' -and (FixturePathEquals $current.data_dir $selectedProfile) -and
                (FixturePathEquals $current.exe $fixtureRuntime)) {
                $cleanupStop = InvokeFixture '--runtime-internal --stop --json'
                if ($cleanupStop.exit -eq 0) { $runtimeOwned = $false; $runtimeStopped = $true }
            }
        } catch { Write-Warning 'Fixture runtime cleanup needs inspection; no unrelated process was killed' }
    }
    if ($registered -or $null -ne $startupAction) { RemoveFixtureTask }
    if (-not $startupAttempted -or $runtimeStopped) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
    else { Write-Warning 'Startup outcome uncertain; fixture files retained for inspection' }
  } catch {
    if ($null -eq $primaryFailure) { throw }
    Write-Warning ('Fixture cleanup also failed; preserving the original exception: ' + $_.Exception.Message)
  }
}
if ($validationPassed) {
    Write-Output (@{result = 'PASS'; profile = 'isolated synthetic off-mode'; sign_in_trigger = $true;
        limited_interactive_principal = $true; host_startup = $true; client_only_stop_denied = $true;
        task_removed = $true; runtime_stopped = $true; encoded_command_case_guard = $true;
        task_action_invocation = 'manual'; real_logon_tested = $false; g1_acceptance = $false;
        physical_reboot_tested = $false} | ConvertTo-Json -Compress)
}
