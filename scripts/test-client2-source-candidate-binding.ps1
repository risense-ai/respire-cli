# AST-extracted contract tests. No executable is launched and no network is used.
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Candidate launcher parse failed' }
foreach ($name in @('Assert-SourceClient2Manifest','Assert-CandidateRegularPath','Copy-SourceClient2Candidate','Assert-DesktopClient2Candidate','Save-DownloadedClient2')) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'Candidate contract function missing' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$source=$ast.Extent.Text
foreach ($old in @("release = 'v2.0.0-dev.5'", "source_sha = 'be682108", '/releases/download/v2.0.0-dev.5/')) {
    if ($source.Contains($old)) { throw 'Old Client2 defaults remain' }
}
$paramText=$ast.ParamBlock.Extent.Text
$paramText=$paramText.Substring($paramText.IndexOf('param('))
$bind=[scriptblock]::Create('[CmdletBinding(DefaultParameterSetName="Official")]'+"`n"+$paramText+"`n"+'return $PSCmdlet.ParameterSetName')
$common=@{Cli='x';RuntimeArchive='x';RuntimeVersion='1.0.0';OutputDirectory='x'}
$official=@{Client2Release='v2.0.0-dev.6';Client2Commit=('a'*40)}
if ((& $bind @common @official) -cne 'Official' -or (& $bind @common @official -OfflineAcceptance) -cne 'Official') { throw 'Explicit release binding changed' }
if ((& $bind @common -Client2CandidateRunId 123 -Client2Commit ('a'*40)) -cne 'DesktopCandidate') { throw 'Desktop candidate binding is not distinct' }
foreach ($name in @('Client2Release','Client2CandidateRunId','Client2Commit')) {
    $parameter=@($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -ceq $name })
    if ($parameter.Count -ne 1 -or $parameter[0].DefaultValue -or $parameter[0].Extent.Text -notmatch 'Mandatory') { throw 'Client2 identity input is not explicit and mandatory' }
}
if ((& $bind @common -SourceCandidate -SourceClient2Exe x -SourceClient2Manifest x -SourceClient2Commit x) -cne 'SourceCandidate') { throw 'Candidate parameter set is not distinct' }
$identityGuards=@($ast.EndBlock.Statements | Where-Object { $_.Extent.Text.StartsWith("if (`$PSCmdlet.ParameterSetName -ne 'SourceCandidate'") -or $_.Extent.Text.StartsWith("if (`$PSCmdlet.ParameterSetName -eq 'Official'") })
if ($identityGuards.Count -ne 2) { throw 'Explicit release identity guards missing' }
$identityHarness=[scriptblock]::Create('[CmdletBinding(DefaultParameterSetName="Official")]'+"`n"+$paramText+"`n"+($identityGuards.Extent.Text -join "`n"))
foreach ($case in @('valid','old','invalid_tag','invalid_commit')) {
    $values=@{Client2Release='v2.0.0-dev.6';Client2Commit=('a'*40)}
    switch ($case) {
        'old' { $values.Client2Release='v2.0.0-dev.5' }
        'invalid_tag' { $values.Client2Release='latest' }
        'invalid_commit' { $values.Client2Commit='main' }
    }
    $accepted=$false
    try { & $identityHarness @common @values; $accepted=$true } catch {}
    if ($accepted -ne ($case -in @('valid','old'))) { throw 'Explicit release syntax guard failed; compatibility must be checked by the real probe' }
}
$guard=@($ast.EndBlock.Statements | Where-Object { $_.Extent.Text.StartsWith("if (`$PSCmdlet.ParameterSetName -ceq 'SourceCandidate'") })
if ($guard.Count -ne 1) { throw 'Explicit candidate mode guard missing' }
$guardHarness=[scriptblock]::Create('[CmdletBinding(DefaultParameterSetName="Official")]'+"`n"+$paramText+"`n"+$guard[0].Extent.Text)
$caught=$false
try { & $guardHarness @common -SourceCandidate:$false -SourceClient2Exe x -SourceClient2Manifest x -SourceClient2Commit x } catch { $caught=$true }
if (-not $caught) { throw 'False candidate switch bypassed explicit mode' }
$runJson='{"id":123,"head_sha":"COMMIT","repository":{"full_name":"risense-ai/respire-client2"},"head_repository":{"full_name":"risense-ai/respire-client2"},"path":".github/workflows/desktop.yml","event":"pull_request","status":"completed","conclusion":"success"}'
$artifactJson='{"id":456,"name":"respire-windows-amd64","expired":false,"size_in_bytes":100,"digest":"sha256:DIGEST","workflow_run":{"id":123,"head_sha":"COMMIT"}}'
foreach ($case in @('valid','run','sha','repository','fork','workflow','event','status','conclusion','artifact_run','artifact_sha','name','expired','digest','size','id')) {
    $run=$runJson.Replace('COMMIT',('a'*40)) | ConvertFrom-Json
    $artifact=$artifactJson.Replace('COMMIT',('a'*40)).Replace('DIGEST',('b'*64)) | ConvertFrom-Json
    switch ($case) {
        'run' { $run.id=124 }
        'sha' { $run.head_sha='c'*40 }
        'repository' { $run.repository.full_name='other/repository' }
        'fork' { $run.head_repository.full_name='other/repository' }
        'workflow' { $run.path='.github/workflows/other.yml' }
        'event' { $run.event='workflow_dispatch' }
        'status' { $run.status='in_progress' }
        'conclusion' { $run.conclusion='failure' }
        'artifact_run' { $artifact.workflow_run.id=124 }
        'artifact_sha' { $artifact.workflow_run.head_sha='c'*40 }
        'name' { $artifact.name='respire-windows-arm64' }
        'expired' { $artifact.expired=$true }
        'digest' { $artifact.digest='unverified' }
        'size' { $artifact.size_in_bytes=0 }
        'id' { $artifact.id=0 }
    }
    $accepted=$false
    try { Assert-DesktopClient2Candidate $run $artifact ('a'*40) '123'; $accepted=$true } catch {}
    if ($accepted -ne ($case -eq 'valid')) { throw "Desktop candidate provenance guard failed: $case" }
}
$root=Join-Path ([IO.Path]::GetTempPath()) ('candidate-contract-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
$saved=@{}; foreach ($name in @('GITHUB_WORKSPACE','RUNNER_TEMP','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_JOB','GH_TOKEN')) { $saved[$name]=[Environment]::GetEnvironmentVariable($name) }
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
    & {
        $Client2Release='v2.0.0-dev.6'; $Client2Commit='a'*40; $Client2CandidateRunId=$null; $env:GH_TOKEN='synthetic-read-token'
        function Invoke-RestMethod { param($Headers,$Uri,$TimeoutSec)
            if ($Uri -like '*/commits/*') { return @{sha=$tagCommit} }; return $release
        }
        function Invoke-WebRequest { param($Uri,$OutFile,$TimeoutSec) [IO.File]::WriteAllText($OutFile,'synthetic-not-executable') }
        $digest='sha256:'+(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
        foreach ($case in @('valid','draft','tag','commit','missing','duplicate','digestless','digest','size')) {
            $report=[ordered]@{}; $tagCommit=$Client2Commit
            $asset=@{id=1;name='respire-windows-amd64.exe';size=(Get-Item -LiteralPath $exe).Length;digest=$digest;browser_download_url='https://example.invalid/test'}
            $release=@{draft=$false;tag_name=$Client2Release;assets=@($asset)}
            switch ($case) {
                'draft' { $release.draft=$true }
                'tag' { $release.tag_name='v2.0.0-dev.5' }
                'commit' { $tagCommit='b'*40 }
                'missing' { $release.assets=@() }
                'duplicate' { $release.assets=@($asset,$asset) }
                'digestless' { $asset.digest=$null }
                'digest' { $asset.digest='sha256:'+('0'*64) }
                'size' { $asset.size=1 }
            }
            $accepted=$false
            try { Save-DownloadedClient2 (Join-Path $outputRoot ('release-'+$case+'.exe')); $accepted=$true } catch {}
            if ($accepted -ne ($case -eq 'valid')) { throw "Published Client2 asset guard failed: $case" }
        }
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
Write-Host 'PASS: explicit release/source/Desktop candidate inputs and authenticated candidate provenance'
