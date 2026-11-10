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
                @{report=@{status='native-connectivity-passed';offline=@{status='failed'}};expected=1;offline=$true}
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
} finally { Remove-Item -LiteralPath $root -Recurse -Force }
Write-Host 'PASS: actual terminal gates replace stale native exit and preserve failures'
