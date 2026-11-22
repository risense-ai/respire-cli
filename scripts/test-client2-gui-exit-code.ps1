# Execute the actual terminal gates in child PS5/pwsh processes, never the GUI body.
$ErrorActionPreference='Stop'
$root=Join-Path ([IO.Path]::GetTempPath()) ('respire-exit-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
try {
    $hostExe=(Get-Process -Id $PID).Path
    foreach ($name in @('probe-client2-gui.ps1','probe-client2-gui-native.ps1')) {
        $tokens=$null; $errors=$null
        $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name),[ref]$tokens,[ref]$errors)
        if ($errors.Count) { throw 'Exit contract source parse failed' }
        $statements=@($ast.EndBlock.Statements)
        $gate=$statements[-2]; $success=$statements[-1]
        if ($gate -isnot [Management.Automation.Language.IfStatementAst] -or
            $success -isnot [Management.Automation.Language.ExitStatementAst] -or $success.Extent.Text -cne 'exit 0') { throw 'Explicit terminal exit contract missing' }
        $terminal=Join-Path $root 'terminal.ps1'
        [IO.File]::WriteAllText($terminal,($gate.Extent.Text+"`n"+$success.Extent.Text+"`n"))
        $cases=if ($name -eq 'probe-client2-gui.ps1') {
            @(
                @{report=@{status='connectivity-passed';cleanup_exit_confirmed=$true};expected=0},
                @{report=@{status='failed';cleanup_exit_confirmed=$true};expected=1},
                @{report=@{status='connectivity-passed';cleanup_exit_confirmed=$false};expected=1},
                @{report=@{status='connectivity-passed';cleanup_exit_confirmed=$true;cleanup_error='fixed-test-failure'};expected=1}
            )
        } else {
            @(
                @{report=@{status='native-connectivity-passed';offline=@{status='offline-subset-passed'}};expected=0;offline=$true},
                @{report=@{status='native-connectivity-passed'};expected=0;offline=$false},
                @{report=@{status='failed';offline=@{status='offline-subset-passed'}};expected=1;offline=$true},
                @{report=@{status='native-connectivity-passed';offline=@{status='failed'}};expected=1;offline=$true},
                @{report=@{status='native-connectivity-passed';recovery=@{status='recovery-subset-passed'}};expected=0;offline=$true;recovery='issue'},
                @{report=@{status='native-connectivity-passed';recovery=@{status='failed'}};expected=1;offline=$true;recovery='resume'},
                @{report=@{status='failed';recovery=@{status='recovery-subset-passed'}};expected=1;offline=$true;recovery='resume'}
            )
        }
        foreach ($case in $cases) {
          foreach ($seed in @('unset','nonzero')) {
            $case.seed=$seed
            $casePath=Join-Path $root 'case.json'
            [IO.File]::WriteAllText($casePath,($case|ConvertTo-Json -Depth 8))
            $harness=Join-Path $root 'harness.ps1'
            [IO.File]::WriteAllText($harness,@'
$ErrorActionPreference='Stop'
$case=Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'case.json') | ConvertFrom-Json
$report=$case.report
$OfflineAcceptance=[bool]$case.offline
$RecoveryPhase=$case.recovery
if ($case.seed -eq 'nonzero') {
    & $env:ComSpec /d /c 'exit 7'
    if ($LASTEXITCODE -ne 7) { throw 'Native exit seed failed' }
} else {
    Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
    if ($null -ne $LASTEXITCODE) { throw 'Unset native exit seed failed' }
}
& (Join-Path $PSScriptRoot 'terminal.ps1')
# Model the caller workflow: script invocation must replace stale native exit 7.
if ($LASTEXITCODE -ne [int]$case.expected) { throw 'Terminal gate returned an incorrect exit code' }
exit 0
'@)
            & $hostExe -NoLogo -NoProfile -NonInteractive -File $harness
            if ($LASTEXITCODE -ne 0) { throw 'Child exit-code contract failed' }
          }
        }
    }
    # Execute the real public-journal validator; these are synthetic records, not GUI evidence.
    $nativePath=Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1'
    $tokens=$null; $errors=$null
    $nativeAst=[Management.Automation.Language.Parser]::ParseFile($nativePath,[ref]$tokens,[ref]$errors)
    $reader=@($nativeAst.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Read-RecoveryRecord'},$true))
    if ($errors.Count -or $reader.Count -ne 1) { throw 'Recovery journal validator missing' }
    . ([scriptblock]::Create($reader[0].Extent.Text))
    $binding=@{data_directory=$root}
    $null=New-Item -ItemType Directory -Path (Join-Path $root 'client2')
    $journal=Join-Path $root 'client2/requests.json'
    $publicCases = @('public','saved','public-runtime-key')
    foreach ($case in $publicCases + @('envelope','private-transaction','pending','duplicate','invalid-id','invalid-runtime-key','missing-candidate-runtime-key')) {
        $report=@{recovery=@{}}
        $binding.final_public_assets = $case -in @('public','saved','public-runtime-key','invalid-runtime-key','private-transaction')
        $binding.verified_candidate_assets = $case -ceq 'missing-candidate-runtime-key'
        $record=[pscustomobject]@{id=('desktop-'+[guid]::NewGuid());name='auth_reset';started='2026-11-16T00:00:00Z';state='done';host=$true;
            transaction=[pscustomobject]@{operation_id=[guid]::NewGuid().ToString();source_profile=$root;kind='key'}}
        switch ($case) {
            'saved' { $record | Add-Member NoteProperty materialSaved $true }
            'public-runtime-key' { $record.transaction | Add-Member NoteProperty runtime_key $true }
            'invalid-runtime-key' { $record.transaction | Add-Member NoteProperty runtime_key 'true' }
            'envelope' { $record | Add-Member NoteProperty envelope @{} }
            'private-transaction' { $record.transaction | Add-Member NoteProperty super 'synthetic-forbidden-field' }
            'pending' { $record.state='unconfirmed' }
            'invalid-id' { $record.transaction.operation_id='not-an-original-operation' }
        }
        $records=if ($case -ceq 'duplicate') { @($record,$record) } else { @($record) }
        [IO.File]::WriteAllText($journal,(ConvertTo-Json -InputObject @($records) -Depth 6))
        $failed=$false
        try { $null=Read-RecoveryRecord } catch { $failed=$true }
        if ($failed -eq ($case -in $publicCases)) { throw 'Recovery journal accepted private data or rejected public identity' }
        if ($case -in @('envelope','private-transaction','pending','invalid-id','invalid-runtime-key','missing-candidate-runtime-key')) {
            $diagnostic=$report.recovery.journal_validation
            $field=@{envelope='record_fields_public'; 'private-transaction'='transaction_fields_public'; pending='state_done'; 'invalid-id'='operation_id_valid';
                'invalid-runtime-key'='transaction_fields_public'; 'missing-candidate-runtime-key'='transaction_fields_public'}[$case]
            if ($diagnostic.Count -ne 9 -or @($diagnostic.Values | Where-Object { $_ -isnot [bool] }).Count -or $diagnostic[$field] -ne $false -or
                (ConvertTo-Json $diagnostic -Compress).Contains('synthetic-forbidden-field')) { throw 'Journal diagnostic must identify the failed predicate using fixed booleans only' }
        }
    }
    $source=[IO.File]::ReadAllText($nativePath)
    $resume=$source.Substring($source.LastIndexOf("if (`$RecoveryPhase -ceq 'resume')"))
    if ($resume.IndexOf('Invoke-NativeGuiProbe') -lt 0 -or
        -not $source.Contains("if (`$script:recoveryMaterialVisible) { throw") -or
        -not $source.Contains('Confirm-RecoveryMaterial') -or
        -not $source.Contains("Send-OfflineKey 32 -ExpectedRuntimeId `$id")) { throw 'Recovery input/capture contract missing' }
} finally { Remove-Item -LiteralPath $root -Recurse -Force }
Write-Host 'PASS: actual terminal gates and public-only original reset journal validation'
