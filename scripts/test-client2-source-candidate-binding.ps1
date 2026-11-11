# AST-extracted contract tests. No executable is launched and no network is used.
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Candidate launcher parse failed' }
foreach ($name in @('Assert-SourceClient2Manifest','Assert-CandidateRegularPath','Copy-SourceClient2Candidate')) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'Candidate contract function missing' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$source=$ast.Extent.Text
foreach ($anchor in @("DefaultParameterSetName=`"Official`"", "release = 'v2.0.0-dev.4'; asset_id = 735260343", "source_sha = '62eebaf43333978afd5b6b7a6fc7a45665189c6c'", "expected_exe_sha256 = 'd0f65ebfdb49404301f4af4468357ac3859e877fcff485d0125904a190307d62'", "https://github.com/risense-ai/respire-client2/releases/download/v2.0.0-dev.4/respire-windows-amd64.exe")) {
    if (-not $source.Contains($anchor)) { throw 'Official fixture default changed' }
}
$paramText=$ast.ParamBlock.Extent.Text
$paramText=$paramText.Substring($paramText.IndexOf('param('))
$bind=[scriptblock]::Create('[CmdletBinding(DefaultParameterSetName="Official")]'+"`n"+$paramText+"`n"+'return $PSCmdlet.ParameterSetName')
$common=@{Cli='x';RuntimeArchive='x';RuntimeVersion='1.0.0';OutputDirectory='x'}
if ((& $bind @common) -cne 'Official' -or (& $bind @common -OfflineAcceptance) -cne 'Official') { throw 'Original parameter binding changed' }
if ((& $bind @common -SourceCandidate -SourceClient2Exe x -SourceClient2Manifest x -SourceClient2Commit x) -cne 'SourceCandidate') { throw 'Candidate parameter set is not distinct' }
$guard=@($ast.EndBlock.Statements | Where-Object { $_.Extent.Text.StartsWith("if (`$PSCmdlet.ParameterSetName") })
if ($guard.Count -ne 1) { throw 'Explicit candidate mode guard missing' }
$guardHarness=[scriptblock]::Create('[CmdletBinding(DefaultParameterSetName="Official")]'+"`n"+$paramText+"`n"+$guard[0].Extent.Text)
$caught=$false
try { & $guardHarness @common -SourceCandidate:$false -SourceClient2Exe x -SourceClient2Manifest x -SourceClient2Commit x } catch { $caught=$true }
if (-not $caught) { throw 'False candidate switch bypassed explicit mode' }
$root=Join-Path ([IO.Path]::GetTempPath()) ('candidate-contract-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
$saved=@{}; foreach ($name in @('GITHUB_WORKSPACE','RUNNER_TEMP','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_JOB')) { $saved[$name]=[Environment]::GetEnvironmentVariable($name) }
function Get-Item {
    param($LiteralPath,[switch]$Force,$ErrorAction)
    $item=Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
    if ($script:reparsePath -and $item.FullName -eq $script:reparsePath) {
        return [pscustomobject]@{FullName=$item.FullName;PSIsContainer=$item.PSIsContainer;Length=1;Attributes=([IO.FileAttributes]::ReparsePoint)}
    }
    return $item
}
function Copy-Item {
    param($LiteralPath,$Destination)
    Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LiteralPath -Destination $Destination
    if ($script:mutateCopy) { [IO.File]::WriteAllText($Destination,'changed-copy') }
}
try {
    $env:GITHUB_WORKSPACE=$root; $env:RUNNER_TEMP=$root; $env:GITHUB_RUN_ID='123'; $env:GITHUB_RUN_ATTEMPT='1'; $env:GITHUB_JOB='candidate_ui'
    $inputRoot=Join-Path $root 'input'; $outputRoot=Join-Path $root 'output'
    $null=New-Item -ItemType Directory -Path $inputRoot,$outputRoot
    $exe=Join-Path $inputRoot 'respire-windows-amd64.exe'; [IO.File]::WriteAllText($exe,'synthetic-not-executable')
    $manifestPath=Join-Path $inputRoot 'source.json'
    $commit='e50f877c92ea4ddcbbbc25a657aa046442b9ed90'
    $valid=[ordered]@{schema_version=1;mode='source-client2-ui-candidate';repository='risense-ai/respire-client2';source_commit=$commit
        platform='windows-amd64';exe_file='respire-windows-amd64.exe';exe_sha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
        build_version='0.2.56-dev.123';build_command='./scripts/build.ps1 -Version 0.2.56-dev.123 -Arch amd64';run_id='123';run_attempt='1';job='candidate_ui'}
    foreach ($case in @('valid','sha','command','version','run','job','attempt','platform','official','missing','null','numeric','schema','bytes','copy','reparse_file','reparse_parent','directory','destination')) {
        $m=$valid | ConvertTo-Json | ConvertFrom-Json
        $script:reparsePath=$null; $script:mutateCopy=$false; $sourceExe=$exe
        $dest=Join-Path $outputRoot ($case+'.exe')
        switch ($case) {
            'sha' { $m.source_commit='0'*40 }
            'command' { $m.build_command='synthetic-private-secret' }
            'version' { $m.build_version='1; invalid' }
            'run' { $m.run_id='124' }
            'job' { $m.job='other' }
            'attempt' { $m.run_attempt='2' }
            'platform' { $m.platform='windows-arm64' }
            'official' { $m | Add-Member NoteProperty official_client2_asset $true }
            'missing' { $m.PSObject.Properties.Remove('exe_sha256') }
            'null' { $m.exe_sha256=$null }
            'numeric' { $m.run_id=123 }
            'schema' { $m.schema_version='1' }
            'bytes' { $m.exe_sha256='0'*64 }
            'copy' { $script:mutateCopy=$true }
            'reparse_file' { $script:reparsePath=$exe }
            'reparse_parent' { $script:reparsePath=$inputRoot }
            'directory' { $sourceExe=$inputRoot }
            'destination' { [IO.File]::WriteAllText($dest,'existing') }
        }
        [IO.File]::WriteAllText($manifestPath,($m | ConvertTo-Json))
        $accepted=$false
        try { $result=Copy-SourceClient2Candidate $sourceExe $manifestPath $commit $dest; $accepted=$true } catch {}
        if ($accepted -ne ($case -eq 'valid')) { throw 'Candidate binding accepted invalid provenance or bytes' }
        if ($case -eq 'valid' -and ($result.mode -cne 'source-client2-ui-candidate' -or (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash.ToLowerInvariant() -cne $valid.exe_sha256)) { throw 'Candidate copy did not bind actual bytes' }
    }
    foreach ($badPath in @('\\server\share\candidate.exe','C:\outside-candidate\candidate.exe',($exe+':stream'))) {
        $accepted=$false
        try { $null=Assert-CandidateRegularPath $badPath -File; $accepted=$true } catch {}
        if ($accepted) { throw 'Candidate path escaped local isolated regular-file boundary' }
    }
} finally {
    foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name,$saved[$name]) }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force
}
Write-Host 'PASS: explicit source candidate binding and unchanged official defaults'
