# AST-extracted contract tests. No executable is launched and no network is used.
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'probe-client2-gui.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Candidate launcher parse failed' }
foreach ($name in @('Assert-SourceClient2Manifest','Assert-CandidateRegularPath','Copy-SourceClient2Candidate','Assert-DesktopClient2Candidate','Save-DownloadedClient2','Assert-GuiCliAbsent','Assert-GuiProcessTrace')) {
    $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($nodes.Count -ne 1) { throw 'Candidate contract function missing' }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$source=$ast.Extent.Text
$payloadLoops=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.ForEachStatementAst] -and $n.Condition.Extent.Text.Contains('$runtimeMetadata.files')},$true))
if ($payloadLoops.Count -ne 2) { throw 'Online and candidate Runtime payload checks must both remain' }
$runtimeMetadata=@{files=@(
    @{path='rsrs-runtime.exe'}, @{path='core-runtime.json'}, @{path='core-notices/consumer/.coderabbit.yaml'},
    @{path='core-notices-extra/library.dll'}, @{path='lib/provider.dll'}
)}
foreach ($loop in $payloadLoops) {
    $selected=@(Invoke-Expression $loop.Condition.Extent.Text)
    if (($selected.path -join ',') -cne 'rsrs-runtime.exe,core-runtime.json,core-notices-extra/library.dll,lib/provider.dll') { throw 'Managed payload inventory omitted loader files or retained compacted notices' }
    foreach ($check in @('$file.size','$file.sha256','Get-FileHash')) {
        if (-not $loop.Body.Extent.Text.Contains($check)) { throw 'Runtime payload integrity check missing' }
    }
}
foreach ($old in @("release = 'v2.0.0-dev.5'", "source_sha = 'be682108", '/releases/download/v2.0.0-dev.5/')) {
    if ($source.Contains($old)) { throw 'Old Client2 defaults remain' }
}
$paramText=$ast.ParamBlock.Extent.Text
$paramText=$paramText.Substring($paramText.IndexOf('param('))
$bind=[scriptblock]::Create('[CmdletBinding(DefaultParameterSetName="Official")]'+"`n"+$paramText+"`n"+'return $PSCmdlet.ParameterSetName')
$common=@{Cli='x';RuntimeArchive='x';RuntimeVersion='1.0.0';OutputDirectory='x'}
$official=@{Client2Release='v2.0.0-dev.6';Client2Commit=('a'*40)}
if ((& $bind @common @official) -cne 'Official' -or (& $bind @common @official -OfflineAcceptance) -cne 'Official') { throw 'Explicit release binding changed' }
if ((& $bind @common -Client2CandidateRunId 123 -Client2Commit ('a'*40)) -cne 'DesktopCandidate' -or
    (& $bind @common -Client2CandidateRunId 123 -Client2Commit ('a'*40) -LegacyGuiCli) -cne 'DesktopCandidate') { throw 'Desktop candidate binding is not distinct' }
$legacyRejected = $false
try { $null = & $bind @common @official -LegacyGuiCli } catch { $legacyRejected = $true }
if (-not $legacyRejected -or $source.Contains("'prepare-cli'") -or $source.Contains('respire-cli/releases?')) {
    throw 'Current GUI acceptance still permits CLI installation or CLI channel discovery'
}
& {
    $root = 'C:/fixture/gui'
    $taskProfile = 'C:/fixture/profile'
    $taskHome = 'C:/fixture/home'
    $childEnv = @{PATH='C:/fixture/system'}
    $report = @{environment=@{session_id=7}}
    function Test-Path([string]$LiteralPath) { $LiteralPath.Replace('\','/') -ceq $installedCli }
    function Get-CimInstance([string]$ClassName, [string]$Filter) {
        if ($ClassName -cne 'Win32_Process' -or $Filter -cne "Name = 'rsrs.exe' AND SessionId = 7") {
            throw 'CLI check queried the wrong process scope'
        }
        if ($liveCli) { @{ProcessId=123} }
    }
    $installedCli='C:/external/rsrs.exe'; $liveCli=$false
    Assert-GuiCliAbsent
    foreach ($installedCli in @('C:/fixture/gui/rsrs.exe','C:/fixture/profile/bin/rsrs.exe',
        'C:/fixture/home/.rsrs/bin/rsrs.exe','C:/fixture/system/rsrs.exe','')) {
        $liveCli = -not $installedCli
        $rejected=$false
        try { Assert-GuiCliAbsent } catch { $rejected=$true }
        if (-not $rejected) { throw 'Client2 accepted a discoverable or running CLI' }
    }
}
$fixture = @{ProcessName='rsrs.exe';ProcessID=21;ParentProcessID=20}
$desktop = @{ProcessName='respire-windows-amd64.exe';ProcessID=22;ParentProcessID=20}
Assert-GuiProcessTrace @($fixture,$desktop) @(22) @(21) 20
foreach ($events in @(
    @{events=@($fixture)}, @{events=@($desktop,@{ProcessName='rsrs.exe';ProcessID=21;ParentProcessID=22})},
    @{events=@($desktop,@{ProcessName='rsrs.exe';ProcessID=23;ParentProcessID=20})}
)) {
    $rejected=$false
    try { Assert-GuiProcessTrace $events.events @(22) @(21) 20 } catch { $rejected=$true }
    if (-not $rejected) { throw 'GUI process trace missed an incomplete launch or a CLI outside explicit seeding' }
}
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

# Exercise the actual public/private binding split without launching a product.
$report = @{native_binding=@{core_query=@{phase='core-issue';address='http://127.0.0.1:1'}}}
$CoreConfigQuery = $true; $phase='core-issue'; $queryProxy=@{address='http://127.0.0.1:1';nonce='private-control-canary'}
$readyPath='private-control-file-not-uploaded'
$publicBinding = @($ast.FindAll({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and
    $node.Left.Extent.Text -ceq '$report.native_binding.core_query'},$true))
if ($publicBinding.Count -ne 1) { throw 'Public query binding is not explicit' }
. ([scriptblock]::Create($publicBinding[0].Extent.Text))
$bindingStatements = @($ast.FindAll({param($node)
    ($node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq '$driverBinding') -or
    ($node -is [Management.Automation.Language.ForEachStatementAst] -and $node.Extent.Text.StartsWith('foreach ($key in $report.native_binding.Keys)')) -or
    ($node -is [Management.Automation.Language.IfStatementAst] -and $node.Extent.Text.Contains('$driverBinding.core_query ='))
},$true))
if ($bindingStatements.Count -ne 3) { throw 'Private binding split is not explicit' }
. ([scriptblock]::Create(($bindingStatements.Extent.Text -join "`n")))
$public = $report | ConvertTo-Json -Depth 8
if ($public.Contains('nonce') -or $public.Contains('private-control-canary') -or $public.Contains($readyPath) -or
    $driverBinding.core_query.control_file -cne $readyPath -or $driverBinding.core_query.ContainsKey('nonce')) { throw 'Private control escaped into public binding' }

$forwarder = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'dev-core-config-query-fixture.py')
$handler = $forwarder.Substring($forwarder.IndexOf('        def handle_request(self):'))
$ordering = @('connection.request(self.command', 'state["result_forwarded"] += 1', 'response = connection.getresponse()',
    'data, status = response.read(), response.status', 'if result and drop_result_reply:', "state['result_response_lost'] += 1")
$last=-1
foreach ($step in $ordering) {
    $index=$handler.IndexOf($step)
    if ($index -le $last) { throw 'Result fault must forward/read the real response before reporting loss' }
    $last=$index
}
if ($handler.Substring(0,$handler.IndexOf('connection.request(self.command')).Contains('self.close_reply()')) { throw 'Result is cut off before real forwarding' }
$snapshot = [regex]::Match($forwarder,'(?s)    def snapshot\(\):.*?(?=    class Handler)').Value
foreach ($field in @('result_issued','result_forwarded','result_response_lost','operation_id','scope','apply_fusion','effective_fusion')) {
    if (-not $snapshot.Contains("'$field'")) { throw 'Public result proof counter/identity is missing' }
}
if ($snapshot.Contains('nonce') -or $snapshot.Contains('owner') -or $snapshot.Contains('json.dumps(state)')) { throw 'Proxy proof serializes private state wholesale' }
$nativeSource = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1')
$coreIssue = [regex]::Match($nativeSource,"(?s)if \(\`$binding.core_query.phase -ceq 'core-issue'\) \{.*?(?=\} elseif)").Value
if (-not $coreIssue -or $coreIssue.Contains('GetCurrentPattern(') -or $coreIssue.Contains('0x0D')) {
    throw 'Core select must use one explicit keyboard route without pattern fallback or Enter submit'
}
$last=-1
foreach ($step in @('Focus-OfflineControl $combo', 'Send-OfflineKey 0x24 $comboId', 'Send-OfflineKey 0x28 $comboId',
    'Send-OfflineKey 0x09 $comboId', "Read-CoreQueryControl 'lose_reply'", '$save = Find-CoreQuerySave',
    'Focus-OfflineControl $save ([ref]$mismatch)', 'Prepare-OfflineButtonInvoke $save ([ref]$mismatch)', '$prepared.pattern.Invoke()')) {
    $index=$coreIssue.IndexOf($step)
    if ($index -le $last) { throw 'Core select keyboard/one-save order or original-focus guard changed' }
    $last=$index
}
foreach ($step in @('candidate["recall_fusion"]["fusion"] == "attention"', 'summary["candidate"] == candidate',
    'summary["effective"]["recall_fusion"]["fusion"] == "attention"')) {
    if (-not $handler.Contains($step) -or $handler.IndexOf($step) -ge $handler.LastIndexOf('self.close_reply()')) {
        throw 'Real candidate/effective fusion must be checked before losing the apply response'
    }
}
foreach ($step in @('supported_patterns', 'call_site', 'failure_script_line', 'Read-CoreQueryControl -FailureEvidence')) {
    if (-not $nativeSource.Contains($step)) { throw 'Core issue failure diagnostics are missing' }
}
if ($nativeSource.Contains('$binding.core_query.nonce') -or -not $nativeSource.Contains('$script:coreQueryControl.nonce') -or
    -not $nativeSource.Contains("throw 'Forwarding proof has non-public fields'")) { throw 'Native control/private-proof separation changed' }
$workflow = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '../.github/workflows/client2-core-query-diagnostic.yml')
foreach ($image in @('workspace.png','core-selection.png')) {
    if (-not $workflow.Contains('/core-query-gui/' + $image)) { throw 'Exact safe core query screenshot upload is missing' }
}
foreach ($private in @('native-binding.json','core-query-proxy-ready.json','core-query-gui/**','core-query-gui/*')) {
    if ($workflow.Contains($private)) { throw 'Diagnostic upload includes private fixture control files' }
}
@'
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const workflow=fs.readFileSync(process.argv[2],'utf8');
const guard=workflow.slice(workflow.indexOf('const run=api('),workflow.indexOf("for(const path of ['.github/runtime-test-fixture.json'"))+
  workflow.slice(workflow.indexOf('assert.match(e.CLI_ARTIFACT_ID'),workflow.indexOf("const root=join(e.RUNNER_TEMP,'core-query-assets')"));
assert.ok(guard.includes('const job=jobs[0]')&&guard.includes('Date.parse(artifact.created_at)'));
const source={run_id:1,run_attempt:2,sha:'a'.repeat(40)},repo={full_name:'risense-ai/respire-cli'};
const e={CLI_ARTIFACT_ID:'3',CLI_ARTIFACT_DIGEST:'sha256:'+'b'.repeat(64)};
const base={run:{repository:repo,head_repository:repo,workflow_id:4,path:'.github/workflows/release.yml',event:'workflow_dispatch',head_branch:'main',head_sha:source.sha,run_attempt:2,status:'in_progress',conclusion:null},
  job:{id:5,name:'validate / Release (x86_64-pc-windows-msvc)',run_id:1,run_attempt:2,head_sha:source.sha,status:'completed',conclusion:'success',started_at:'2026-11-18T01:00:00Z',completed_at:'2026-11-18T01:10:00Z'},
  artifact:{name:'cli-release-x86_64-pc-windows-msvc',expired:false,workflow_run:{id:1,head_sha:source.sha},digest:e.CLI_ARTIFACT_DIGEST,created_at:'2026-11-18T01:09:00Z'}};
function check(change=()=>{},jobCount=1){
  const state=structuredClone(base);change(state);
  vm.runInNewContext(guard,{assert,source,e,api(path){
    if(path==='repos/risense-ai/respire-cli/actions/runs/1')return state.run;
    if(path==='repos/risense-ai/respire-cli/actions/workflows/release.yml')return {id:4};
    assert.equal(path,'repos/risense-ai/respire-cli/actions/artifacts/3');return state.artifact;
  },execFileSync(command,args){
    assert.equal(command,'gh');assert.deepEqual(Array.from(args),['api','--paginate','--slurp','repos/risense-ai/respire-cli/actions/runs/1/attempts/2/jobs?per_page=100']);
    return JSON.stringify([{jobs:[{name:'unrelated'}]},{jobs:Array(jobCount).fill(state.job)}]);
  }});
}
check();check(s=>{s.run.status='completed';s.run.conclusion='success'});
for(const change of [
  s=>s.run.head_repository={full_name:'fork/repo'},s=>s.run.repository={full_name:'fork/repo'},
  s=>s.run.workflow_id=9,s=>s.run.path='other.yml',s=>s.run.event='pull_request',s=>s.run.head_branch='feature',s=>s.run.head_sha='c'.repeat(40),s=>s.run.run_attempt=1,
  s=>s.job.run_id=9,s=>s.job.run_attempt=1,s=>s.job.head_sha='c'.repeat(40),s=>s.job.name='other',
  s=>s.job.status='in_progress',s=>s.job.conclusion='failure',s=>s.job.conclusion='skipped',
  s=>s.artifact.name='other',s=>s.artifact.expired=true,s=>s.artifact.workflow_run.id=9,
  s=>s.artifact.workflow_run.head_sha='c'.repeat(40),s=>s.artifact.digest='sha256:'+'c'.repeat(64),
  s=>s.artifact.created_at='2026-11-18T00:59:59Z',s=>s.artifact.created_at='2026-11-18T01:10:01Z',s=>s.artifact.created_at='invalid'
])assert.throws(()=>check(change));
assert.throws(()=>check(()=>{},0));assert.throws(()=>check(()=>{},2));
console.log('PASS: diagnostic accepts a successful exact-attempt Windows build while full runs; rejects untrusted producers, jobs and artifacts');
'@ | node - (Join-Path $PSScriptRoot '../.github/workflows/client2-core-query-diagnostic.yml')
if ($LASTEXITCODE -ne 0) { throw 'Diagnostic platform build producer checks failed' }
Write-Host 'PASS: real result forward/read/loss ordering and private control/public proof separation (static fixture checks only)'
