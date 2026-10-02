#Requires -Version 7
<#
.SYNOPSIS
  Sweep the npm dev CLI against the development server using isolated data.
  Run only in GitHub Actions; the default port would disrupt a developer runtime.
  Authenticate shutdown of the previous test runtime before switching libraries.
.DESCRIPTION
  Use disposable accounts. Keep keys in the isolated secrets directory, never reports.
  Usage: pwsh -NoProfile -File scripts/dev-release-sweep.ps1
#>
[CmdletBinding()]
param(
    [string]$Server = $env:RESPIRE_DEV_SERVER_ADDR,
    [string]$Package = '@rsrsai/cli@dev',
    [string]$Root = '',
    [string]$Exe = '',
    [string]$ExpectVersion = ''
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($env:RESPIRE_DEV_SERVER_ADDR) -or $Server -ne $env:RESPIRE_DEV_SERVER_ADDR) {
    throw 'Configure RESPIRE_DEV_SERVER_ADDR with the approved development server before running this sweep.'
}
$pkgMatch = [regex]::Match($Package, '^@rsrsai/cli@(dev|\d+\.\d+\.\d+(-dev\.\d+)?)$')
if (-not $pkgMatch.Success) {
    throw "拒绝：包必须是 @rsrsai/cli@dev 或 @rsrsai/cli@x.y.z[-dev.n]，收到 $Package"
}
$requested = $pkgMatch.Groups[1].Value

$stamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
if (-not $Root) {
    if ($env:RUNNER_TEMP) {
        $Root = Join-Path $env:RUNNER_TEMP "om-dev-sweep-$stamp"
    } elseif (Test-Path 'E:\tmp_rust_target') {
        $Root = "E:\tmp_rust_target\om-dev-sweep-$stamp"
    } else {
        $Root = Join-Path ([System.IO.Path]::GetTempPath()) "om-dev-sweep-$stamp"
    }
}
$resolvedRoot = [System.IO.Path]::GetFullPath($Root)
if ($resolvedRoot -match '(?i)[/\\]\.(onememory|respire)([/\\]|$)') {
    throw "拒绝：根目录落在用户库 .onememory/.respire 内：$resolvedRoot"
}
$Root = $resolvedRoot
New-Item -ItemType Directory -Force -Path $Root, (Join-Path $Root 'logs'), (Join-Path $Root 'secrets'), (Join-Path $Root 'work') | Out-Null
$Prefix = Join-Path $Root 'npm'
$DirA = Join-Path $Root 'a'
$DirB = Join-Path $Root 'b'
$DirD = Join-Path $Root 'd'
$Work = Join-Path $Root 'work'
$Secrets = Join-Path $Root 'secrets'
$ReportPath = Join-Path $Root 'report.md'
function Stop-OurRuntimes {
    # Runtime command lines contain web --internal; the data directory is in the environment.
    # With -Exe, the binary is outside the npm prefix; locate the isolated runtime correctly.
    $self = $PID
    $targets = New-Object System.Collections.Generic.List[int]
    if (Test-Path -LiteralPath $resolvedRoot) {
        Get-ChildItem -LiteralPath $resolvedRoot -Filter endpoint.json -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '[\\/]runtime[\\/]endpoint\.json$' } |
            ForEach-Object {
                try {
                    $ep = Get-Content -LiteralPath $_.FullName -Raw -Encoding utf8 | ConvertFrom-Json
                    $procId = 0
                    if ($null -ne $ep.pid) { $procId = [int]$ep.pid }
                    if ($procId -gt 0 -and $procId -ne $self) { [void]$targets.Add($procId) }
                } catch { }
            }
    }
    foreach ($procId in ($targets | Select-Object -Unique)) {
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
    }
    foreach ($procId in ($targets | Select-Object -Unique)) {
        for ($i = 0; $i -lt 25; $i++) {
            if (-not (Get-Process -Id $procId -ErrorAction SilentlyContinue)) { break }
            Start-Sleep -Milliseconds 200
        }
    }
}
trap { Write-SweepReport; Stop-OurRuntimes; throw $_ }
$Rows = New-Object System.Collections.Generic.List[object]
$script:Step = 0

function Write-SweepReport {
    $lines = @('# CLI development sweep', '', "- Server: $Server", "- Version: $ExpectVersion", '', '| Step | Command | Exit | Status | Result | Note |', '| --- | --- | --- | --- | --- | --- |')
    foreach ($row in $Rows) {
        $mark = if ($row.Ok) { 'PASS' } else { 'FAIL' }
        $note = (($row.Note + ' ' + $row.Leak).Trim()) -replace '\|', '/'
        $lines += "| $($row.Step) | $($row.Name) | $($row.Exit) | $($row.Status) | $mark | $note |"
    }
    [IO.File]::WriteAllText($ReportPath, ($lines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
}

function Get-SafeFailureReason($Envelope) {
    # Report fixed classifications only, never raw authentication responses.
    $message = @($Envelope.errors) -join ' '
    if ($message -match '\b([45]\d\d)\b') { return "http_$($Matches[1])" }
    foreach ($entry in @(
        @('already registered', 'account_exists'),
        @('none in the local keyring|super password required', 'recovery_key_missing'),
        @('keyring|keychain', 'keyring'),
        @('session not unlocked|vault.*locked', 'vault_locked'),
        @('TLS|certificate', 'tls'),
        @('DNS|resolve', 'dns'),
        @('connect|timeout|transport', 'transport'),
        @('runtime.*token|runtime.*auth', 'runtime_auth')
    )) {
        if ($message -match $entry[0]) { return $entry[1] }
    }
    return 'unclassified'
}

function Assert-DevEnvelope($Envelope, [string]$Where) {
    if (-not $Envelope -or -not $Envelope.summary) { return }
    foreach ($key in @('addr', 'server_addr')) {
        $prop = $Envelope.summary.PSObject.Properties[$key]
        if ($prop -and [string]$prop.Value -and [string]$prop.Value -ne $Server) {
            throw "$Where has a $key outside the approved development server. Sweep stopped."
        }
    }
}

function Get-JsonRpc([string]$Text, $Id) {
    foreach ($line in ($Text -split "`n")) {
        $t = $line.Trim()
        if (-not $t.StartsWith('{')) { continue }
        try {
            $obj = $t | ConvertFrom-Json
            if ($null -ne $obj.id -and [string]$obj.id -eq [string]$Id) { return $obj }
        } catch { }
    }
    return $null
}

function Get-McpToolEnvelope($Rpc) {
    if (-not $Rpc -or -not $Rpc.result) { return $null }
    if ($Rpc.result.isError -eq $true) { return $null }
    $content = $Rpc.result.content
    if (-not $content -or $content.Count -lt 1) { return $null }
    $text = [string]$content[0].text
    try { return $text | ConvertFrom-Json } catch { return $null }
}

function Add-SweepRow([string]$Name, [bool]$Ok, [string]$Note) {
    $script:Step++
    $Rows.Add([pscustomobject]@{
        Step = $script:Step; Name = $Name; Exit = $(if ($Ok) { 0 } else { 1 }); Status = $(if ($Ok) { 'ok' } else { 'fail' }); Ok = $Ok; Leak = ''; Note = $Note
    }) | Out-Null
    Write-Host "$(if ($Ok) {'PASS'} else {'FAIL'}) $Name $Note"
}

function Invoke-McpStdioTool {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Tool,
        [hashtable]$Arguments = @{},
        [Parameter(Mandatory)][string]$DataDir,
        [int]$TimeoutSec = 90
    )
    $argJson = if ($Arguments.Count -eq 0) { '{}' } else { $Arguments | ConvertTo-Json -Compress -Depth 8 }
    $stdin = (@(
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"sweep","version":"0"}}}'
        '{"jsonrpc":"2.0","method":"notifications/initialized"}'
        "{`"jsonrpc`":`"2.0`",`"id`":2,`"method`":`"tools/call`",`"params`":{`"name`":`"$Tool`",`"arguments`":$argJson}}"
    ) -join "`n") + "`n"
    $run = Invoke-Om -Name $Name -ArgList @('mcp') -DataDir $DataDir -Raw -TimeoutSec $TimeoutSec -StdinText $stdin -Note $Tool
    $rpc = Get-JsonRpc $run.Stdout 2
    $envlp = Get-McpToolEnvelope $rpc
    return [pscustomobject]@{ Run = $run; Rpc = $rpc; Envelope = $envlp }
}

function Get-Envelope([string]$Text) {
    $t = $Text.Trim()
    if (-not $t) { return $null }
    $start = $t.IndexOf("{")
    if ($start -lt 0) { return $null }
    $slice = $t.Substring($start)
    try { return $slice | ConvertFrom-Json } catch { return $null }
}

function Get-Leak([string]$Text, [bool]$Secret) {
    $hits = @()
    if ($Text -cmatch 'DETAILS') { $hits += 'DETAILS' }
    if (-not $Secret) {
        foreach ($w in @('"ciphertext"', '"embedding_enc"', '"wrapped_urk"', '"kdf_salt"', '"embedding"', '"nonce"')) {
            if ($Text.Contains($w)) { $hits += $w }
        }
    }
    return $hits
}

function Invoke-Om {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$ArgList = @(),
        [Parameter(Mandatory)][string]$DataDir,
        [int[]]$ExpectExit = @(0),
        [string[]]$AllowStatus = @('ok', 'warn', 'skip'),
        [switch]$Secret,
        [switch]$Raw,
        [int]$TimeoutSec = 180,
        [string]$StdinText = '',
        [string]$Note = '',
        [int]$MinStdout = 0,
        [string]$RequireCommand = ''
    )
    # These are separate simulated devices sharing one CI host/port. The host
    # must stop the old device with its own credentials before switching roots.
    if ($script:ActiveDataDir -and $script:ActiveDataDir -ne $DataDir) {
        Invoke-Om -Name 'host-stop-before-device-switch' -ArgList @('web', '--stop') `
            -DataDir $script:ActiveDataDir -Raw | Out-Null
    }
    $script:ActiveDataDir = $DataDir
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    $script:Step++
    $safe = ($Name -replace '[^\w\-]+', '_')
    $outFile = Join-Path $Root "logs\$($script:Step)-$safe.out.txt"
    $errFile = Join-Path $Root "logs\$($script:Step)-$safe.err.txt"
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    if ($script:UseExe) {
        $psi.FileName = $script:ExePath
    } else {
        $psi.FileName = 'node'
        $psi.ArgumentList.Add($script:CliJs)
    }
    $psi.WorkingDirectory = $Work
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    $psi.StandardOutputEncoding = $utf8
    $psi.StandardErrorEncoding = $utf8
    $psi.StandardInputEncoding = $utf8
    foreach ($a in $ArgList) { $psi.ArgumentList.Add([string]$a) }
    $psi.Environment['ONEMEMORY_DATA_DIR'] = $DataDir
    $psi.Environment['ONEMEMORY_LANG'] = 'en'
    $psi.Environment.Remove('ONEMEMORY_SERVER')
    Write-Host "STEP $script:Step $Name"
    $readyTries = 0
    do {
        $readyTries++
        if ($readyTries -gt 1) { Write-Host "RETRY $Name" }
    $proc = [System.Diagnostics.Process]::Start($psi)
    if ($StdinText) { $proc.StandardInput.Write($StdinText) }
    $proc.StandardInput.Close()
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    $timedOut = $false
    if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
        $timedOut = $true
        try { $proc.Kill($true) } catch { try { $proc.Kill() } catch { } }
        Stop-OurRuntimes
        $proc.WaitForExit(5000) | Out-Null
    }
    $stdout = ''
    $stderr = ''
    if ($outTask.Wait(10000)) { try { $stdout = $outTask.Result } catch { $stdout = '' } }
    if ($errTask.Wait(10000)) { try { $stderr = $errTask.Result } catch { $stderr = '' } }
    $exit = if ($timedOut) { 124 } else { $proc.ExitCode }
    $blob = $stdout + "`n" + $stderr
    if ($Secret) {
        [System.IO.File]::WriteAllText((Join-Path $Secrets "$script:Step-$safe.txt"), $blob, [Text.UTF8Encoding]::new($false))
        $stdoutForScan = $stdout
    } else {
        [System.IO.File]::WriteAllText($outFile, $stdout, [Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText($errFile, $stderr, [Text.UTF8Encoding]::new($false))
        $stdoutForScan = $stdout
    }
    $leaks = @(Get-Leak $stdoutForScan $Secret.IsPresent)
    $envlp = Get-Envelope $stdout
    Assert-DevEnvelope $envlp $Name
    $status = ''
    if ($envlp -and $envlp.PSObject.Properties['status']) { $status = [string]$envlp.status }
    if ($envlp -and [string]$envlp.command -eq 'cli') {
        $keys = @($envlp.summary.PSObject.Properties.Name)
        if ($keys.Count -eq 0) { $Note = ("RPC 带回空 cli 信封 " + $Note).Trim() }
    }
    if ($Raw -or -not $status) {
        $exitOk = $ExpectExit -contains [int]$exit
        $statusOk = $true
    } else {
        $want = switch ($status) { 'ok' { 0 } 'skip' { 0 } 'warn' { 2 } 'pending' { 2 } 'fail' { 1 } default { -1 } }
        $exitOk = ($exit -eq $want)
        $statusOk = $AllowStatus -contains $status
    }
    if ($stdout.Length -lt $MinStdout) { $statusOk = $false; $Note = ("stdout 过短 " + $Note).Trim() }
    if ($RequireCommand) {
        $got = [string]$envlp.command
        $total = $null
        if ($envlp -and $envlp.summary) { $total = $envlp.summary.total }
        if ($got -ne $RequireCommand -or $null -eq $total) {
            $statusOk = $false
            $Note = ("command=$got total=$total want $RequireCommand " + $Note).Trim()
        }
    }
    $readyFail = ($stdout + $stderr) -match 'did not become ready'
        if ($readyFail -and $readyTries -lt 2) { Stop-OurRuntimes; Start-Sleep -Seconds 1 }
    } while ($readyFail -and $readyTries -lt 2)
    if ($readyTries -gt 1) { $Note = ("runtime 重试 $readyTries 次 " + $Note).Trim() }
    $ok = $exitOk -and $statusOk -and ($leaks.Count -eq 0) -and (-not $timedOut)
    if (-not $ok -and $Secret) { $Note = ("failure_reason=$(Get-SafeFailureReason $envlp) $Note").Trim() }
    $row = [pscustomobject]@{
        Step   = $script:Step
        Name   = $Name
        Exit   = $exit
        Status = $status
        Ok     = $ok
        Leak   = ($leaks -join ',')
        Note   = $(if ($timedOut) { "timeout ${TimeoutSec}s; $Note" } else { $Note })
    }
    $Rows.Add($row) | Out-Null
    Write-SweepReport
    $flag = if ($ok) { 'PASS' } else { 'FAIL' }
    Write-Host "$flag $Name exit=$exit status=$status leak=$($row.Leak)"
    if (-not $ok) {
        $detail = ($stderr + " " + $(if ($Secret) { '' } else { $stdout }))
        $detail = [regex]::Replace($detail, '(?i)(super|secret|token|password|nonce|wrapped_urk|kdf_salt)[^,\s"]{0,120}', '${1}=[redacted]')
        $detail = ($detail -replace '\s+', ' ').Trim()
        if ($detail.Length -gt 240) { $detail = $detail.Substring($detail.Length - 240) }
        if ($detail) { Write-Host "DETAIL $detail" }
    }
    return [pscustomobject]@{ Ok = $ok; Exit = $exit; Envelope = $envlp; Stdout = $(if ($Secret) { '' } else { $stdout }); Row = $row }
}

function Assert-Count([string]$Name, $Envelope, [string]$Field, [int]$Min) {
    $n = 0
    if ($Envelope -and $Envelope.summary -and $null -ne $Envelope.summary.$Field) {
        $n = [int]$Envelope.summary.$Field
    }
    if ($n -lt $Min) { throw "$Name ${Field}=$n，需要至少 $Min" }
}

function New-Pass {
    -join ((48..57 + 65..90 + 97..122 | Get-Random -Count 24 | ForEach-Object { [char]$_ }))
}

$script:UseExe = [bool]$Exe
$script:ExePath = $Exe
if ($script:UseExe) {
    if (-not (Test-Path $script:ExePath)) { throw "找不到二进制 $($script:ExePath)" }
    Write-Host "ROOT $resolvedRoot"
    Write-Host "EXE $($script:ExePath)"
    $script:CliJs = ''
    $cliVersion = ''
} else {
Write-Host "ROOT $resolvedRoot"
Write-Host "WAIT $Package"
$seen = ''
for ($try = 0; $try -lt 24; $try++) {
    $seen = (npm view $Package version --registry https://registry.npmjs.org 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -eq 0 -and $seen) { break }
    Start-Sleep -Seconds 10
}
if (-not $seen) { throw "npm 上还看不到 $Package" }
Write-Host "INSTALL $Package ($seen)"
npm install --prefix $Prefix $Package --include=optional --no-fund --no-audit --registry https://registry.npmjs.org
if ($LASTEXITCODE -ne 0) { throw "npm install 失败：$LASTEXITCODE" }
$script:CliJs = Join-Path $Prefix 'node_modules\@rsrsai\cli\bin\cli.js'
if (-not (Test-Path $script:CliJs)) { throw "找不到 $script:CliJs" }
$pkgJson = Get-Content (Join-Path $Prefix 'node_modules\@rsrsai\cli\package.json') -Raw | ConvertFrom-Json
$cliVersion = [string]$pkgJson.version
$tags = npm view @rsrsai/cli dist-tags --json --registry https://registry.npmjs.org | ConvertFrom-Json
$specIsDev = $requested -eq 'dev' -or $requested -match '-dev\.'
if ($specIsDev -and $cliVersion -notmatch '-dev') { throw "拒绝：装到的版本不是 dev：$cliVersion" }
if ($requested -ne 'dev' -and $cliVersion -ne $requested) { throw "装到 $cliVersion，要的是 $requested" }
if ($specIsDev -and [string]$tags.latest -eq $cliVersion) { throw "拒绝：dev 版本 $cliVersion 已等于 latest" }
Write-Host "CLI $cliVersion latest=$($tags.latest) dev=$($tags.dev)"
$rid = [System.Runtime.InteropServices.RuntimeInformation]::RuntimeIdentifier
$plat = switch ($rid) {
    'win-x64' { '@rsrsai/win-x64' }
    'win-arm64' { '@rsrsai/win-arm64' }
    'osx-arm64' { '@rsrsai/macos-arm64' }
    'linux-x64' { '@rsrsai/linux-x64' }
    'linux-arm64' { '@rsrsai/linux-arm64' }
    default { '' }
}
if ($env:RSRS_LIBC -and $rid -like 'linux-*') {
    if ($env:RSRS_LIBC -notin @('glibc', 'musl')) { throw 'RSRS_LIBC must be musl or glibc' }
    if ($plat -and $env:RSRS_LIBC -eq 'glibc') { $plat += '-gnu' }
}
if ($plat) {
    npm install --prefix $Prefix "$plat@$cliVersion" --no-fund --no-audit --registry https://registry.npmjs.org
    if ($LASTEXITCODE -ne 0) { throw "平台包 $plat 安装失败：$LASTEXITCODE" }
}
}

$ver = Invoke-Om -Name 'version' -ArgList @('--version') -DataDir $DirA -Raw -Note $(if ($cliVersion) { $cliVersion } else { $ExpectVersion })
$wantVersion = if ($ExpectVersion) { $ExpectVersion.Trim().TrimStart('v') } else { $cliVersion }
Invoke-Om -Name 'version-short' -ArgList @('-v') -DataDir $DirA -Raw -Note $wantVersion | Out-Null
Invoke-Om -Name 'version-v' -ArgList @('v') -DataDir $DirA -Raw -Note $wantVersion | Out-Null
$verJson = Invoke-Om -Name 'version-json' -ArgList @('--json', 'v') -DataDir $DirA -Note 'command=version'
if (-not ($verJson.Stdout -like '*"command":"version"*')) {
    Add-SweepRow 'version-json-command' $false $verJson.Stdout
}
if ($wantVersion -and $ver.Stdout -notmatch [regex]::Escape($wantVersion)) { throw "version 输出与 $wantVersion 不符" }

Invoke-Om -Name 'help' -ArgList @('--help') -DataDir $DirA -Raw | Out-Null
Invoke-Om -Name 'no-args-no-tty' -ArgList @() -DataDir $DirA -ExpectExit @(2) -Raw -Note '无 TTY 应退出 2' | Out-Null
Invoke-Om -Name 'parse-error' -ArgList @('not-a-command') -DataDir $DirA -ExpectExit @(2) -Raw | Out-Null

$splitHelp = Invoke-Om -Name 'split-help-contract' -ArgList @('split', '--help') -DataDir $DirA -Raw
if ($splitHelp.Stdout -notmatch 'Split a mixed node' -or $splitHelp.Stdout -match 'Tree hygiene|--parent') {
    throw 'split help contains another command description'
}
$cureHelp = Invoke-Om -Name 'tree-cure-help-contract' -ArgList @('tree-cure', '--help') -DataDir $DirA -Raw
if ($cureHelp.Stdout -notmatch 'Tree hygiene') { throw 'tree-cure help has no description' }
$pluginHelp = Invoke-Om -Name 'plugin-help-contract' -ArgList @('plugin', '--help') -DataDir $DirA -Raw
if ($pluginHelp.Stdout -match '--list' -or $pluginHelp.Stdout -notmatch 'list shows config') {
    throw 'plugin help does not match its subcommands'
}
Invoke-Om -Name 'plugin-reject-list-flag' -ArgList @('plugin', '--list') -DataDir $DirA -ExpectExit @(2) -Raw | Out-Null
Invoke-Om -Name 'plugin-test-requires-event' -ArgList @('plugin', 'test') -DataDir $DirA -ExpectExit @(2) -Raw | Out-Null
Invoke-Om -Name 'chain-reject-from-flag' -ArgList @('chain', '--from', 'missing') -DataDir $DirA -ExpectExit @(2) -Raw | Out-Null

Invoke-Om -Name 'config-addr' -ArgList @('--json', 'config', '--addr', $Server) -DataDir $DirA | Out-Null
$cfg = Invoke-Om -Name 'config-read' -ArgList @('--json', 'config') -DataDir $DirA
$cfgAddr = [string]$cfg.Envelope.summary.addr
if ($cfgAddr -ne $Server) { throw "config 地址不是测试服：$cfgAddr" }

$user = "sweep$stamp"
$pass = New-Pass
[System.IO.File]::WriteAllText((Join-Path $Secrets 'account.txt'), "user=$user`n", [Text.UTF8Encoding]::new($false))
$reg = Invoke-Om -Name 'register' -ArgList @('--json', 'register', '--addr', $Server, '--user', $user, '--pass', $pass) -DataDir $DirA -Secret -TimeoutSec 120
if (-not $reg.Ok) { throw 'register 失败，中止。密钥见 secrets，勿外传。' }
$super = ''
if ($reg.Envelope.summary.super) { $super = [string]$reg.Envelope.summary.super }
if (-not $super) { throw 'register 响应没有 summary.super' }
$regAddr = [string]$reg.Envelope.summary.addr
if ($regAddr -ne $Server) { throw "register 地址不是测试服：$regAddr" }

$st = Invoke-Om -Name 'status-json' -ArgList @('--json', 'status') -DataDir $DirA
$serverAddr = ''
if ($st.Envelope.summary.server_addr) { $serverAddr = [string]$st.Envelope.summary.server_addr }
if ($serverAddr -ne $Server) { throw "status.server_addr=$serverAddr，不是测试服。中止。" }
Invoke-Om -Name 'status-human' -ArgList @('status') -DataDir $DirA -Raw | Out-Null

Invoke-Om -Name 'doctor-human' -ArgList @('doctor') -DataDir $DirA -Raw -ExpectExit @(0, 1, 2) -MinStdout 40 -TimeoutSec 180 -Note '退出 1 表示有检查项失败，干净 runner 上允许' | Out-Null
$docj = Invoke-Om -Name 'doctor-json' -ArgList @('--json', 'doctor') -DataDir $DirA -TimeoutSec 180 -AllowStatus @('ok', 'warn', 'fail', 'skip') -RequireCommand 'doctor' -Note '信封必须是 doctor 且 summary.total 存在'
$mcpBinItem = @($docj.Envelope.items) | Where-Object { [string]$_.name -eq 'mcp bin' } | Select-Object -First 1
$mcpHttpItem = @($docj.Envelope.items) | Where-Object { [string]$_.name -eq 'mcp http' } | Select-Object -First 1
$binName = if ($IsWindows) { 'rsrs.exe' } else { 'rsrs' }
$mcpBinPath = Join-Path $DirA "bin\$binName"
Add-SweepRow 'doctor-mcp-bin-item' ($null -ne $mcpBinItem -and [string]$mcpBinItem.status -eq 'ok') ([string]$mcpBinItem.value)
Add-SweepRow 'doctor-mcp-http-item' ($null -ne $mcpHttpItem -and ([string]$mcpHttpItem.value -like '*/mcp*')) ([string]$mcpHttpItem.value)
Add-SweepRow 'mcp-bin-file' (Test-Path -LiteralPath $mcpBinPath) $mcpBinPath
$embedder = @($docj.Envelope.items) | Where-Object { [string]$_.name -eq 'embedder' } | Select-Object -First 1
if ($embedder -and [string]$embedder.status -eq 'fail') {
    Invoke-Om -Name 'doctor-fix' -ArgList @('--json', 'doctor', '--fix') -DataDir $DirA -TimeoutSec 900 -AllowStatus @('ok', 'warn', 'fail') -RequireCommand 'doctor' -Note '干净环境安装 BGE' | Out-Null
}
Invoke-Om -Name 'doctor-remote' -ArgList @('--json', 'doctor', '--remote') -DataDir $DirA -TimeoutSec 180 -AllowStatus @('ok', 'warn', 'fail', 'skip') -RequireCommand 'doctor' | Out-Null

Invoke-Om -Name 'taxonomy' -ArgList @('--json', 'taxonomy') -DataDir $DirA | Out-Null
Invoke-Om -Name 'taxonomy-list' -ArgList @('--json', 'taxonomy', '--list') -DataDir $DirA | Out-Null
Invoke-Om -Name 'taxonomy-ensure' -ArgList @('--json', 'taxonomy', '--ensure', '编程开发') -DataDir $DirA | Out-Null
Invoke-Om -Name 'agent-config' -ArgList @('--json', 'agent-config') -DataDir $DirA | Out-Null
Invoke-Om -Name 'agent-config-set' -ArgList @('--json', 'agent-config', '--set', 'diary_mode=concise') -DataDir $DirA | Out-Null
Invoke-Om -Name 'update-check' -ArgList @('--json', 'update-check') -DataDir $DirA -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'update-check-clear' -ArgList @('--json', 'update-check', '--clear') -DataDir $DirA | Out-Null
$pluginList = Invoke-Om -Name 'plugin-list' -ArgList @('--json', 'plugin', 'list') -DataDir $DirA
if (($pluginList.Envelope.actions -join ' ') -match '--event') { throw 'plugin action suggests unsupported --event' }
Invoke-Om -Name 'plugin-test' -ArgList @('--json', 'plugin', 'test', 'post-recall', '--payload', '{}') -DataDir $DirA | Out-Null
$vetoCommand = if ($IsWindows) { 'echo {"verdict":"block","reason":"sweep veto"}' } else { 'echo ''{"verdict":"block","reason":"sweep veto"}''' }
$pluginConfig = @{ hooks = @{ 'pre-remember' = @(@{ cmd = $vetoCommand; on_error = 'skip'; timeout_ms = 2000 }) } } | ConvertTo-Json -Depth 5
$pluginPath = Join-Path $DirA 'plugins.json'
[IO.File]::WriteAllText($pluginPath, $pluginConfig, [Text.UTF8Encoding]::new($false))
try {
    $veto = Invoke-Om -Name 'plugin-explicit-veto' -ArgList @('--json', 'plugin', 'test', 'pre-remember', '--payload', '{}') -DataDir $DirA -AllowStatus @('warn')
    if (-not $veto.Envelope.summary.blocked -or $veto.Envelope.details.reason -notmatch 'sweep veto') {
        throw 'configured plugin did not execute and return its veto'
    }
} finally {
    Remove-Item -LiteralPath $pluginPath
}
Invoke-Om -Name 'inject-targets' -ArgList @('--json', 'inject', '--targets') -DataDir $DirA | Out-Null
Invoke-Om -Name 'inject-preview-codex' -ArgList @('--json', 'inject', '--preview', '--id', 'codex') -DataDir $DirA -ExpectExit @(0, 1, 2) -Raw -Note '只预览，不写本机 Agent 配置' | Out-Null
Invoke-Om -Name 'inject-tui-no-tty' -ArgList @('inject', '--tui') -DataDir $DirA -ExpectExit @(1, 2) -Raw -Note '无 TTY' | Out-Null

# Disable autosync so the later explicit sync owns the push step.
Invoke-Om -Name 'config-autosync-off-before-write' -ArgList @('--json', 'config', '--autosync', 'false') -DataDir $DirA | Out-Null
$marker = "sweep-marker-$stamp"
$title = "sweep标记$stamp"
$rem = Invoke-Om -Name 'remember-force' -ArgList @(
    '--json', 'remember', "dev sweep marker $marker on TB16P",
    '--title', $title, '--type', 'decision', '--importance', 'important', '--force', '--project', 'respire-cli'
) -DataDir $DirA -TimeoutSec 300
$id = ''
if ($rem.Envelope.summary.id) { $id = [string]$rem.Envelope.summary.id }
if (-not $id) { throw 'remember 没有 summary.id，后面的提取链无法继续。' }
$short = $id.Substring(0, [Math]::Min(8, $id.Length))
Invoke-Om -Name 'remember-human' -ArgList @('remember', "human path $marker", '--title', "人类$stamp", '--force', '--importance', 'trivial') -DataDir $DirA -Raw -TimeoutSec 300 | Out-Null
$child = Invoke-Om -Name 'remember-parent' -ArgList @(
    '--json', 'remember', "child of $marker", '--title', "子条$stamp", '--parent', $short, '--force', '--importance', 'important', '--type', 'context'
) -DataDir $DirA -TimeoutSec 300
$childId = [string]$child.Envelope.summary.id
$disp = Invoke-Om -Name 'remember-disposable' -ArgList @(
    '--json', 'remember', "disposable $marker", '--title', "丢弃$stamp", '--force', '--importance', 'trivial'
) -DataDir $DirA -TimeoutSec 300
$dispId = [string]$disp.Envelope.summary.id

$mergeA = Invoke-Om -Name 'merge-src-a' -ArgList @(
    '--json', 'remember', "merge source A $marker",
    '--title', "合并甲$stamp", '--type', 'decision', '--importance', 'important', '--force', '--project', 'respire-cli'
) -DataDir $DirA -TimeoutSec 180
$mergeAId = [string]$mergeA.Envelope.summary.id
if (-not $mergeAId) { throw 'merge-src-a 没有 id' }
$mergeShort = $mergeAId.Substring(0, [Math]::Min(8, $mergeAId.Length))
Invoke-Om -Name 'merge-src-b' -ArgList @(
    '--json', 'remember', "merge source B $marker",
    '--title', "合并乙$stamp", '--type', 'decision', '--importance', 'important', '--force', '--project', 'respire-cli'
) -DataDir $DirA -TimeoutSec 180 | Out-Null
$merged = Invoke-Om -Name 'merge-ids-short-and-title' -ArgList @(
    '--json', 'remember', "merged $marker",
    '--title', "合并结果$stamp", '--merge-ids', "$mergeShort,合并乙$stamp",
    '--type', 'decision', '--importance', 'important', '--force', '--project', 'respire-cli'
) -DataDir $DirA -TimeoutSec 180
if (-not $merged.Ok) { throw 'merge-ids 失败' }
if ([int]$merged.Envelope.summary.dropped -lt 2) {
    throw "merge-ids dropped=$($merged.Envelope.summary.dropped)，短 id 或纲名没有删掉"
}
$gone = Invoke-Om -Name 'merge-old-gone' -ArgList @('--json', 'show', $mergeShort) -DataDir $DirA -ExpectExit @(1, 2) -AllowStatus @('fail')
if ($gone.Exit -eq 0) { throw "合并后旧短 id $mergeShort 仍能 show，旧条还在" }

# Full merge regressions: both input orders, a root and an external parent,
# surviving descendants, and rejection before deleting any source.
foreach ($rootCase in @($true, $false)) {
    foreach ($reverseCase in @($false, $true)) {
        $case = "merge-tree-$rootCase-$reverseCase"
        $expectedParent = if ($rootCase) { '' } else { $id }
        $argsA = @('--json', 'remember', "$case ancestor $marker", '--title', "$case-a-$stamp", '--importance', 'important', '--force')
        if ($expectedParent) { $argsA += @('--parent', $expectedParent) }
        $aResult = Invoke-Om -Name "$case-create-a" -ArgList $argsA -DataDir $DirA
        $aId = [string]$aResult.Envelope.summary.id
        $bResult = Invoke-Om -Name "$case-create-b" -ArgList @('--json', 'remember', "$case child $marker", '--title', "$case-b-$stamp", '--importance', 'important', '--parent', $aId) -DataDir $DirA
        $bId = [string]$bResult.Envelope.summary.id
        $leafResult = Invoke-Om -Name "$case-create-leaf" -ArgList @('--json', 'remember', "$case leaf $marker", '--title', "$case-leaf-$stamp", '--importance', 'important', '--parent', $bId) -DataDir $DirA
        $leafId = [string]$leafResult.Envelope.summary.id
        $mergeIds = if ($reverseCase) { "$bId,$aId" } else { "$aId,$bId" }
        $rejected = Invoke-Om -Name "$case-reject-deleted-parent" -ArgList @('--json', 'remember', "$case rejected", '--title', "$case-rejected", '--importance', 'important', '--merge-ids', $mergeIds, '--parent', $aId) -DataDir $DirA -ExpectExit @(1) -AllowStatus @('fail')
        if (-not $rejected.Ok) { throw "$case did not reject a merged parent" }
        Invoke-Om -Name "$case-source-survives" -ArgList @('--json', 'show', $aId) -DataDir $DirA | Out-Null
        $result = Invoke-Om -Name "$case-apply" -ArgList @('--json', 'remember', "$case combined $marker", '--title', "$case-result-$stamp", '--importance', 'important', '--merge-ids', $mergeIds) -DataDir $DirA
        if (-not $result.Ok -or [string]$result.Envelope.summary.parent -ne $expectedParent -or [int]$result.Envelope.summary.dropped -ne 2) { throw "$case wrong merge result" }
        $leafResult = Invoke-Om -Name "$case-leaf-parent" -ArgList @('--json', 'show', $leafId) -DataDir $DirA
        if ([string]$leafResult.Envelope.details.entry.parent_id -ne $expectedParent) { throw "$case lost descendant ancestry" }
        $treeAudit = Invoke-Om -Name "$case-audit" -ArgList @('--json', 'audit') -DataDir $DirA
        if ([int]$treeAudit.Envelope.summary.orphans -ne 0) { throw "$case left orphans" }
    }
}

$recA = Invoke-Om -Name 'recall' -ArgList @('--json', 'recall', $marker, '--limit', '3', '--project', 'respire-cli') -DataDir $DirA -TimeoutSec 180
if ($recA.Stdout -notlike "*$marker*") { throw "A recall 没有召回标记 $marker" }
Invoke-Om -Name 'recall-human' -ArgList @('recall', $marker, '--limit', '3') -DataDir $DirA -Raw -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'recall-trace' -ArgList @('--json', 'recall', $marker, '--trace', '--limit', '3') -DataDir $DirA -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'list' -ArgList @('--json', 'list', '--limit', '10') -DataDir $DirA | Out-Null
Invoke-Om -Name 'list-human' -ArgList @('list', '--limit', '5') -DataDir $DirA -Raw | Out-Null
Invoke-Om -Name 'show' -ArgList @('--json', 'show', $short) -DataDir $DirA | Out-Null
Invoke-Om -Name 'show-human' -ArgList @('show', $short) -DataDir $DirA -Raw | Out-Null
Invoke-Om -Name 'chain' -ArgList @('--json', 'chain', $short, '--depth', '2') -DataDir $DirA | Out-Null
Invoke-Om -Name 'candidates' -ArgList @('--json', 'candidates', "dev sweep marker $marker") -DataDir $DirA -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'update' -ArgList @('--json', 'update', $short, '--title', "sweep已改$stamp", '--content', "updated $marker") -DataDir $DirA -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'retitle' -ArgList @('--json', 'retitle', $short, '--title', $title) -DataDir $DirA -TimeoutSec 180 | Out-Null
$retitleFile = Join-Path $Work 'retitle.json'
[System.IO.File]::WriteAllText($retitleFile, "[{`"id`":`"$id`",`"title`":`"$title`"}]", [Text.UTF8Encoding]::new($false))
Invoke-Om -Name 'retitle-many' -ArgList @('--json', 'retitle-many', $retitleFile) -DataDir $DirA -TimeoutSec 180 | Out-Null
if ($childId) {
    Invoke-Om -Name 'attach' -ArgList @('--json', 'attach', $childId, '--parent', $short) -DataDir $DirA | Out-Null
    Invoke-Om -Name 'demote' -ArgList @('--json', 'demote', $childId, '--parent', $short) -DataDir $DirA | Out-Null
    Invoke-Om -Name 'promote' -ArgList @('--json', 'promote', $childId) -DataDir $DirA | Out-Null
}
Invoke-Om -Name 'tree' -ArgList @('--json', 'tree', '--depth', '3') -DataDir $DirA | Out-Null
Invoke-Om -Name 'tree-outline' -ArgList @('--json', 'tree', '--outline') -DataDir $DirA | Out-Null
Invoke-Om -Name 'tree-from' -ArgList @('--json', 'tree', '--from', $short, '--depth', '2') -DataDir $DirA | Out-Null
Invoke-Om -Name 'tree-material' -ArgList @('--json', 'tree', '--material', $short) -DataDir $DirA | Out-Null
Invoke-Om -Name 'diary' -ArgList @('--json', 'diary', '--limit', '5') -DataDir $DirA | Out-Null
Invoke-Om -Name 'diary-today' -ArgList @('--json', 'diary', '--date', 'today') -DataDir $DirA | Out-Null
Invoke-Om -Name 'history' -ArgList @('--json', 'history', $short, '--limit', '10') -DataDir $DirA | Out-Null
Invoke-Om -Name 'query-log' -ArgList @('--json', 'query-log', '--limit', '10') -DataDir $DirA | Out-Null
Invoke-Om -Name 'query-log-stats' -ArgList @('--json', 'query-log', '--stats') -DataDir $DirA | Out-Null
Invoke-Om -Name 'query-log-mark' -ArgList @('--json', 'query-log', 'mark', $short, '--good') -DataDir $DirA -ExpectExit @(0, 1) -Note '无近窗候选时允许失败' | Out-Null
Invoke-Om -Name 'audit' -ArgList @('--json', 'audit') -DataDir $DirA | Out-Null
Invoke-Om -Name 'resort-status' -ArgList @('--json', 'resort', '--status') -DataDir $DirA | Out-Null
Invoke-Om -Name 'resort-threshold' -ArgList @('--json', 'resort', '--threshold', '50') -DataDir $DirA | Out-Null
if ($childId) {
    $spec = (@{ ops = @(@{ id = $childId; parent = $id }) } | ConvertTo-Json -Compress)
    Invoke-Om -Name 'resort-dry' -ArgList @('--json', 'resort', '--spec', $spec) -DataDir $DirA -AllowStatus @('ok', 'pending', 'warn') -Note '无 --go 时应为 pending' | Out-Null
}
Invoke-Om -Name 'defrag' -ArgList @('--json', 'defrag', '--top', '5') -DataDir $DirA -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'tree-cure' -ArgList @('--json', 'tree-cure', '--top', '5') -DataDir $DirA -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'tree-float' -ArgList @('--json', 'tree-float') -DataDir $DirA | Out-Null
Invoke-Om -Name 'split-material' -ArgList @('--json', 'split', $short) -DataDir $DirA | Out-Null
Invoke-Om -Name 'tree-deepen' -ArgList @('--json', 'tree-deepen', '--root', $short) -DataDir $DirA -AllowStatus @('ok', 'fail') -Note '小树应拒绝加深' | Out-Null
Invoke-Om -Name 'classify-plan' -ArgList @('--json', 'classify', '--plan', '--limit', '5') -DataDir $DirA | Out-Null
Invoke-Om -Name 'classify-dry-run' -ArgList @('--json', 'classify', '--dry-run', '--limit', '1') -DataDir $DirA | Out-Null
Invoke-Om -Name 'repack' -ArgList @('--json', 'repack') -DataDir $DirA -TimeoutSec 300 | Out-Null
Invoke-Om -Name 'reembed' -ArgList @('--json', 'reembed') -DataDir $DirA -TimeoutSec 300 | Out-Null
Invoke-Om -Name 'book-material' -ArgList @('--json', 'book-material', $short) -DataDir $DirA | Out-Null
Invoke-Om -Name 'portrait-material' -ArgList @('--json', 'portrait-material', '--limit', '10') -DataDir $DirA | Out-Null
Invoke-Om -Name 'passport' -ArgList @('--json', 'passport') -DataDir $DirA | Out-Null
$shareFile = Join-Path $Work 'share.txt'
Invoke-Om -Name 'share' -ArgList @('--json', 'share', '--root', $short, '--out', $shareFile) -DataDir $DirA | Out-Null
if (Test-Path $shareFile) {
    Invoke-Om -Name 'share-import-preview' -ArgList @('--json', 'share-import', $shareFile) -DataDir $DirA -AllowStatus @('ok', 'pending', 'warn') -Note '预览待决时 status=pending、退出 2' | Out-Null
    Invoke-Om -Name 'share-import-go' -ArgList @('--json', 'share-import', $shareFile, '--go', '--force', '--title', "导入$stamp") -DataDir $DirA | Out-Null
}
$exportFile = Join-Path $Work 'export.json'
$backupFile = Join-Path $Work 'backup.sqlite'
Invoke-Om -Name 'export' -ArgList @('--json', 'export', $exportFile) -DataDir $DirA | Out-Null
if (-not (Test-Path $exportFile) -or (Get-Item $exportFile).Length -lt 10) { throw 'export 没有写出非空文件' }
Invoke-Om -Name 'backup' -ArgList @('--json', 'backup', $backupFile) -DataDir $DirA | Out-Null
if (-not (Test-Path $exportFile)) { throw 'export 未写出文件' }
$imported = Invoke-Om -Name 'import' -ArgList @('--json', 'import', $exportFile) -DataDir $DirA -TimeoutSec 300
if (-not $imported.Ok) { throw 'import 失败' }
$evalFile = Join-Path $Work 'eval.jsonl'
[System.IO.File]::WriteAllText($evalFile, "{`"query`":`"$marker`",`"expect`":[`"$short`"]}`n", [Text.UTF8Encoding]::new($false))
$benchOut = Join-Path $Work 'bench.json'
Invoke-Om -Name 'bench-mine' -ArgList @('--json', 'bench', 'mine', '--out', (Join-Path $Work 'mined.jsonl'), '--limit', '5') -DataDir $DirA | Out-Null
Invoke-Om -Name 'bench-run' -ArgList @('--json', 'bench', 'run', $evalFile, '--save', $benchOut, '--verbose') -DataDir $DirA -TimeoutSec 180 | Out-Null
if (Test-Path $benchOut) {
    Invoke-Om -Name 'bench-baseline' -ArgList @('--json', 'bench', 'run', $evalFile, '--baseline', $benchOut) -DataDir $DirA -TimeoutSec 180 | Out-Null
}
Invoke-Om -Name 'keygen-refuse' -ArgList @('--json', 'keygen') -DataDir $DirA -AllowStatus @('fail') -Note '已有云端密钥，必须拒绝覆盖' | Out-Null
Invoke-Om -Name 'secret-masked' -ArgList @('--json', 'secret') -DataDir $DirA -Secret | Out-Null
Invoke-Om -Name 'keys-export' -ArgList @('--json', 'keys-export', '--out', (Join-Path $Secrets 'keys.txt')) -DataDir $DirA -Secret | Out-Null
Invoke-Om -Name 'account-list' -ArgList @('--json', 'account', 'list') -DataDir $DirA | Out-Null
$otherUser = "oth$stamp"
$otherPass = New-Pass
$otherReg = Invoke-Om -Name 'register-second-user' -ArgList @('--json', 'register', '--addr', $Server, '--user', $otherUser, '--pass', $otherPass) -DataDir $DirA -Secret
if (-not $otherReg.Ok) { throw '已有主账号时 register 第二个用户失败，不能报 none in the local keyring。' }
if (-not $otherReg.Envelope.summary.super) { throw '第二个用户 register 没有发出新的 super' }
Invoke-Om -Name 'account-back-after-second-register' -ArgList @('--json', 'account', 'use', 'main') -DataDir $DirA | Out-Null
Invoke-Om -Name 'space-list' -ArgList @('--json', 'space', 'list') -DataDir $DirA | Out-Null
Invoke-Om -Name 'space-create' -ArgList @('--json', 'space', 'create', 'sweepspace') -DataDir $DirA | Out-Null
$spaceUser = "sps$stamp"
$spacePass = New-Pass
$spaceReg = Invoke-Om -Name 'space-register' -ArgList @('--json', 'register', '--addr', $Server, '--user', $spaceUser, '--pass', $spacePass) -DataDir $DirA -Secret
if (-not $spaceReg.Ok) { throw 'space 档案上 register 失败。空档案应发新的 super，不能报 none in the local keyring。' }
if (-not $spaceReg.Envelope.summary.super) { throw 'space register 没有发出新的 super' }
$inv = Invoke-Om -Name 'space-invite' -ArgList @('--json', 'space', 'invite', '--note', 'sweep') -DataDir $DirA -Secret
Invoke-Om -Name 'space-members' -ArgList @('--json', 'space', 'members') -DataDir $DirA | Out-Null
$inviteCode = ''
$memberSid = ''
if ($inv.Envelope.details.code) { $inviteCode = [string]$inv.Envelope.details.code }
if ($inv.Envelope.details.session_id) { $memberSid = [string]$inv.Envelope.details.session_id }
$DirC = Join-Path $Root 'c'
if ($inviteCode) {
    Invoke-Om -Name 'config-addr-c' -ArgList @('--json', 'config', '--addr', $Server) -DataDir $DirC | Out-Null
    Invoke-Om -Name 'space-join' -ArgList @('--json', 'space', 'join', $inviteCode) -DataDir $DirC -Secret | Out-Null
    Invoke-Om -Name 'space-use-c' -ArgList @('--json', 'space', 'use', 'sweepspace') -DataDir $DirC | Out-Null
    $stC = Invoke-Om -Name 'status-c' -ArgList @('--json', 'status') -DataDir $DirC
    $addrC = ''
    if ($stC.Envelope.summary.server_addr) { $addrC = [string]$stC.Envelope.summary.server_addr }
    if ($addrC -ne $Server) { throw "space join 后 server_addr=$addrC" }
}
if ($memberSid) {
    Invoke-Om -Name 'space-kick' -ArgList @('--json', 'space', 'kick', '--session', $memberSid) -DataDir $DirA | Out-Null
}
Invoke-Om -Name 'web-stop-before-space-remove' -ArgList @('web', '--stop') -DataDir $DirA -Raw -ExpectExit @(0, 2) | Out-Null
Stop-OurRuntimes
Start-Sleep -Seconds 1
Invoke-Om -Name 'account-use-main' -ArgList @('--direct', '--json', 'account', 'use', 'main') -DataDir $DirA -Note 'web --stop 可能在进程仍存活时返回，先结束本轮 runtime 再用 --direct' | Out-Null
Invoke-Om -Name 'space-remove' -ArgList @('--direct', '--json', 'space', 'remove', 'sweepspace', '--yes') -DataDir $DirA | Out-Null
Invoke-Om -Name 'root-create' -ArgList @('--json', 'root-create', "sweep根$stamp", '--content', '一次性验收根', '--yes') -DataDir $DirA | Out-Null
$grant = Invoke-Om -Name 'grant-create' -ArgList @('--json', 'grant', 'create', '--root', $id, '--label', 'sweep') -DataDir $DirA -Secret
Invoke-Om -Name 'grant-list' -ArgList @('--json', 'grant', 'list') -DataDir $DirA | Out-Null
$grantId = ''
if ($grant.Envelope.details.grant.id) { $grantId = [string]$grant.Envelope.details.grant.id }
elseif ($grant.Envelope.details.id) { $grantId = [string]$grant.Envelope.details.id }
if ($grantId) {
    Invoke-Om -Name 'grant-revoke' -ArgList @('--json', 'grant', 'revoke', $grantId) -DataDir $DirA | Out-Null
} else {
    Invoke-Om -Name 'grant-revoke-missing' -ArgList @('--json', 'grant', 'revoke', '00000000') -DataDir $DirA -ExpectExit @(1, 2) -Note '无 id 时用假 id 看失败路径' | Out-Null
}
Invoke-Om -Name 'session-list' -ArgList @('--json', 'session', 'list') -DataDir $DirA -TimeoutSec 120 | Out-Null
Invoke-Om -Name 'session-revoke-bogus' -ArgList @('--json', 'session', 'revoke', '00000000-0000-0000-0000-000000000000') -DataDir $DirA -ExpectExit @(0, 1) -Note '不撤销当前会话' | Out-Null
Invoke-Om -Name 'model-install-rerank' -ArgList @('--json', 'model', 'install-rerank') -DataDir $DirA -TimeoutSec 180 -Note '已存在则跳过，不重下' | Out-Null

$syncA = Invoke-Om -Name 'sync-a' -ArgList @('--json', 'sync') -DataDir $DirA -TimeoutSec 180
if (-not $syncA.Ok) { throw 'A 同步失败' }
Assert-Count 'A sync' $syncA.Envelope 'pushed' 1
Invoke-Om -Name 'sync-human' -ArgList @('sync') -DataDir $DirA -Raw -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'sync-conflicts' -ArgList @('--json', 'sync-conflicts') -DataDir $DirA -TimeoutSec 120 | Out-Null
Invoke-Om -Name 'sync-conflicts-all' -ArgList @('--json', 'sync-conflicts', '--all') -DataDir $DirA -TimeoutSec 120 | Out-Null
$hist = Invoke-Om -Name 'sync-history' -ArgList @('--json', 'sync-history', '--id', $short) -DataDir $DirA -TimeoutSec 120
Invoke-Om -Name 'sync-history-remote' -ArgList @('--json', 'sync-history', '--id', $short, '--remote') -DataDir $DirA -TimeoutSec 120 | Out-Null
Invoke-Om -Name 'sync-resolve-bogus' -ArgList @(
    '--json', 'sync-resolve', '--epoch', '0', '--rev', '0', '--head-rev', '0', '--action', 'keep-current'
) -DataDir $DirA -AllowStatus @('fail') -Note '无冲突时必须失败' | Out-Null

Invoke-Om -Name 'config-addr-b' -ArgList @('--json', 'config', '--addr', $Server) -DataDir $DirB | Out-Null
$loginB = Invoke-Om -Name 'login-b' -ArgList @('--json', 'login', '--addr', $Server, '--user', $user, '--pass', $pass, '--super', $super) -DataDir $DirB -Secret -TimeoutSec 180
if (-not $loginB.Ok) { throw 'B 登录失败。super 必须用 register 响应里的 summary.super。已中止，避免后续命令走默认正式服。' }
$stB = Invoke-Om -Name 'status-b' -ArgList @('--json', 'status') -DataDir $DirB
$addrB = ''
if ($stB.Envelope.summary.server_addr) { $addrB = [string]$stB.Envelope.summary.server_addr }
if ($addrB -ne $Server) { throw "B server_addr=$addrB" }
$syncB = Invoke-Om -Name 'sync-b' -ArgList @('--json', 'sync') -DataDir $DirB -TimeoutSec 180
if (-not $syncB.Ok) { throw 'B 下载同步失败' }
Assert-Count 'B sync' $syncB.Envelope 'pulled' 1
$recB = Invoke-Om -Name 'recall-b' -ArgList @('--json', 'recall', $marker, '--limit', '3') -DataDir $DirB -TimeoutSec 180
if ($recB.Stdout -notlike "*$marker*") { throw "B recall 没有召回 A 写入的标记 $marker" }
Invoke-Om -Name 'show-b' -ArgList @('--json', 'show', $short) -DataDir $DirB | Out-Null
$bad = Join-Path $Root 'bad'
Invoke-Om -Name 'config-addr-bad' -ArgList @('--json', 'config', '--addr', $Server) -DataDir $bad | Out-Null
Invoke-Om -Name 'login-wrong-pass' -ArgList @('--json', 'login', '--addr', $Server, '--user', $user, '--pass', 'wrong-pass-000') -DataDir $bad -AllowStatus @('fail') -Secret -Note '错误口令应失败' | Out-Null

# The second device uses fivekeys. Read material from device A without printing it.
$sessionPath = Join-Path $DirA 'session.json'
if (-not (Test-Path $sessionPath)) {
    $sessionPath = Get-ChildItem -Path $DirA -Filter session.json -Recurse | Select-Object -First 1 -ExpandProperty FullName
}
if ($sessionPath -and (Test-Path $sessionPath)) {
    Invoke-Om -Name 'config-addr-d' -ArgList @('--json', 'config', '--addr', $Server) -DataDir $DirD | Out-Null
    $sess = Get-Content $sessionPath -Raw -Encoding utf8 | ConvertFrom-Json
    Invoke-Om -Name 'fivekeys-d' -ArgList @(
        '--json', 'fivekeys',
        '--addr', $Server,
        '--user', $user,
        '--pass', $pass,
        '--secret', ([string]$sess.secret_key),
        '--kdf-salt', ([string]$sess.kdf_salt),
        '--wrapped-urk', ([string]$sess.wrapped_urk),
        '--urk-nonce', ([string]$sess.urk_nonce),
        '--super', $super
    ) -DataDir $DirD -Secret -TimeoutSec 180 | Out-Null
}

Invoke-Om -Name 'config-autosync-off-a' -ArgList @('--json', 'config', '--autosync', 'false') -DataDir $DirA | Out-Null
Invoke-Om -Name 'config-autosync-off-b' -ArgList @('--json', 'config', '--autosync', 'false') -DataDir $DirB | Out-Null
Invoke-Om -Name 'update-a-offline' -ArgList @('--json', 'update', $short, '--content', "conflict-a $marker") -DataDir $DirA -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'update-b-offline' -ArgList @('--json', 'update', $short, '--content', "conflict-b $marker") -DataDir $DirB -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'sync-a-after-edit' -ArgList @('--json', 'sync') -DataDir $DirA -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'sync-b-conflict' -ArgList @('--json', 'sync') -DataDir $DirB -TimeoutSec 180 | Out-Null
$conf = Invoke-Om -Name 'sync-conflicts-after' -ArgList @('--json', 'sync-conflicts', '--refresh') -DataDir $DirB -TimeoutSec 180
$epoch = ''
$rev = 0
$head = 0
$conflict = $null
if ($conf.Envelope.details -is [System.Array] -and $conf.Envelope.details.Count -gt 0) {
    $conflict = $conf.Envelope.details[0]
} elseif ($conf.Envelope.details -and $conf.Envelope.details.epoch) {
    $conflict = $conf.Envelope.details
}
if ($conflict) {
    $epoch = [string]$conflict.epoch
    $rev = [int]$conflict.rev
    $head = [int]$conflict.current.rev
}
if ($epoch) {
    Invoke-Om -Name 'sync-resolve' -ArgList @(
        '--json', 'sync-resolve', '--epoch', $epoch, '--rev', "$rev", '--head-rev', "$head",
        '--action', 'merge', '--content', "merged $marker"
    ) -DataDir $DirB -TimeoutSec 180 | Out-Null
} else {
    $Rows.Add([pscustomobject]@{
        Step = 0; Name = 'sync-resolve'; Exit = 0; Status = 'skip'; Ok = $true; Leak = ''; Note = '未产生冲突，LWW 或无待决。失败路径已在 sync-resolve-bogus 覆盖。'
    }) | Out-Null
}

if ($dispId) {
    Invoke-Om -Name 'forget' -ArgList @('--json', 'forget', $dispId) -DataDir $DirA | Out-Null
    Invoke-Om -Name 'restore' -ArgList @('--json', 'restore', $dispId) -DataDir $DirA | Out-Null
    Invoke-Om -Name 'purge' -ArgList @('--json', 'purge', $dispId) -DataDir $DirA | Out-Null
}
Invoke-Om -Name 'logout' -ArgList @('--json', 'logout') -DataDir $DirB | Out-Null
$loginAgain = Invoke-Om -Name 'login-b-again' -ArgList @('--json', 'login', '--addr', $Server, '--user', $user, '--pass', $pass, '--super', $super) -DataDir $DirB -Secret -TimeoutSec 180
if (-not $loginAgain.Ok) { throw '重新登录失败' }
$recallAgain = Invoke-Om -Name 'recall-after-relogin' -ArgList @('--json', 'recall', $marker, '--limit', '3') -DataDir $DirB -TimeoutSec 180
if ($recallAgain.Stdout -notlike "*$marker*") { throw '重新登录后没有检索到标记' }
$syncAgain = Invoke-Om -Name 'sync-after-relogin' -ArgList @('--json', 'sync') -DataDir $DirB -TimeoutSec 180
if (-not $syncAgain.Ok) { throw '重新登录后同步失败' }
Invoke-Om -Name 'super-reset' -ArgList @('--json', 'super-reset') -DataDir $DirA -Secret -TimeoutSec 180 | Out-Null
Invoke-Om -Name 'sync-reset' -ArgList @('--json', 'sync-reset') -DataDir $DirA -TimeoutSec 180 -Note '一次性账号上的快照重建' | Out-Null

# Inspect the autostarted runtime, stop it, then start it without opening a browser.
$webStatus = Invoke-Om -Name 'web-status' -ArgList @('--json', 'web', '--status') -DataDir $DirA -ExpectExit @(0, 2) -Raw -Note '未运行时允许非 0'
$url = ''
$endpointFile = Join-Path $DirA 'runtime\endpoint.json'
if (Test-Path $endpointFile) {
    $ep = Get-Content $endpointFile -Raw | ConvertFrom-Json
    $url = [string]$ep.url
    $runtimeUri = [Uri]$url
    if ($runtimeUri.Host -notin @('127.0.0.1', 'localhost', '::1')) { throw "Runtime endpoint is not loopback: $url" }
    try {
        $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10
        $body = [string]$resp.Content
        $pageOk = ($resp.StatusCode -eq 200) -and ($body -match '(?i)<!doctype html>')
        $Rows.Add([pscustomobject]@{
            Step = 0; Name = 'web-http'; Exit = $(if ($pageOk) { 0 } else { 1 }); Status = "$($resp.StatusCode)"; Ok = $pageOk; Leak = ''; Note = $url
        }) | Out-Null
        Write-Host "$(if ($pageOk) {'PASS'} else {'FAIL'}) web-http $url"
    } catch {
        $Rows.Add([pscustomobject]@{
            Step = 0; Name = 'web-http'; Exit = 1; Status = 'fail'; Ok = $false; Leak = ''; Note = $_.Exception.Message
        }) | Out-Null
        Write-Host "FAIL web-http $($_.Exception.Message)"
    }
}
$rpcToken = ''
$tokenFile = Join-Path $DirA 'runtime\token'
if (Test-Path -LiteralPath $tokenFile) {
    $rpcToken = (Get-Content -LiteralPath $tokenFile -Raw).Trim()
}
$origin = $url
if ($origin -match '^(https?://[^/?]+)') { $origin = $Matches[1] }
$mcpUrl = ''
if ($origin) { $mcpUrl = ($origin.TrimEnd('/') + '/mcp') }
$mcpSse = ''
if ($origin) { $mcpSse = ($origin.TrimEnd('/') + '/sse') }
$mcpHeaders = @{}
if ($rpcToken) { $mcpHeaders['Authorization'] = "Bearer $rpcToken" }
$wantTools = @(
    'memory_status','memory_remember','memory_recall','memory_list','memory_show','memory_update',
    'memory_attach','memory_tree','memory_history','memory_diary','memory_chain','memory_query_log_mark',
    'memory_forget','memory_restore','memory_taxonomy'
)
if ($mcpUrl) {
    try {
        $sse = Invoke-WebRequest -Uri $mcpSse -Headers $mcpHeaders -UseBasicParsing -TimeoutSec 15
        $sseText = [string]$sse.Content
        Add-SweepRow 'mcp-http-sse' (($sse.StatusCode -eq 200) -and ($sseText -like '*event: endpoint*') -and ($sseText -like '*/mcp*')) $mcpSse
    } catch {
        Add-SweepRow 'mcp-http-sse' $false $_.Exception.Message
    }
    function Invoke-McpHttpRpc($Name, $Payload) {
        try {
            $body = $Payload | ConvertTo-Json -Compress -Depth 12
            $resp = Invoke-WebRequest -Uri $mcpUrl -Method POST -Headers $mcpHeaders -ContentType 'application/json; charset=utf-8' -Body $body -UseBasicParsing -TimeoutSec 90
            $parsed = $resp.Content | ConvertFrom-Json
            Add-SweepRow $Name ($resp.StatusCode -eq 200 -and $null -ne $parsed) $mcpUrl
            return $parsed
        } catch {
            Add-SweepRow $Name $false $_.Exception.Message
            return $null
        }
    }
    $httpInit = Invoke-McpHttpRpc 'mcp-http-initialize' @{ jsonrpc='2.0'; id=1; method='initialize'; params=@{ protocolVersion='2025-03-26'; capabilities=@{}; clientInfo=@{ name='sweep'; version='0' } } }
    Add-SweepRow 'mcp-http-initialize-version' ($null -ne $httpInit -and [string]$httpInit.result.protocolVersion -eq '2025-03-26') ([string]$httpInit.result.protocolVersion)
    $httpList = Invoke-McpHttpRpc 'mcp-http-tools-list' @{ jsonrpc='2.0'; id=2; method='tools/list' }
    $httpNames = @()
    if ($httpList -and $httpList.result.tools) { $httpNames = @($httpList.result.tools | ForEach-Object { [string]$_.name }) }
    $missingHttp = @($wantTools | Where-Object { $httpNames -notcontains $_ })
    Add-SweepRow 'mcp-http-tools-complete' ($missingHttp.Count -eq 0) ("have=$($httpNames.Count) missing=$($missingHttp -join ',')")
    Invoke-McpHttpRpc 'mcp-http-ping' @{ jsonrpc='2.0'; id=3; method='ping' } | Out-Null
}

$mcpStdinList = (@(
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"sweep","version":"0"}}}'
    '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
    '{"jsonrpc":"2.0","id":3,"method":"ping"}'
) -join "`n") + "`n"
$mcpListRun = Invoke-Om -Name 'mcp-stdio-initialize-list' -ArgList @('mcp') -DataDir $DirA -Raw -TimeoutSec 90 -StdinText $mcpStdinList -Note 'initialize + tools/list + ping'
$mcpInit = Get-JsonRpc $mcpListRun.Stdout 1
$mcpList = Get-JsonRpc $mcpListRun.Stdout 2
$mcpPing = Get-JsonRpc $mcpListRun.Stdout 3
Add-SweepRow 'mcp-stdio-initialize-version' ($null -ne $mcpInit -and [string]$mcpInit.result.protocolVersion -eq '2025-03-26') ([string]$mcpInit.result.protocolVersion)
$stdioNames = @()
if ($mcpList -and $mcpList.result.tools) { $stdioNames = @($mcpList.result.tools | ForEach-Object { [string]$_.name }) }
$missingStdio = @($wantTools | Where-Object { $stdioNames -notcontains $_ })
Add-SweepRow 'mcp-stdio-tools-complete' ($missingStdio.Count -eq 0) ("have=$($stdioNames.Count) missing=$($missingStdio -join ',')")
Add-SweepRow 'mcp-stdio-ping' ($null -ne $mcpPing -and $null -ne $mcpPing.result) 'ping'

$mcpMarker = "mcp-business-$stamp"
$statusTool = Invoke-McpStdioTool -Name 'mcp-stdio-status' -Tool 'memory_status' -DataDir $DirA
Add-SweepRow 'mcp-stdio-status-envelope' ($null -ne $statusTool.Envelope -and [string]$statusTool.Envelope.command -eq 'status') ([string]$statusTool.Envelope.command)
$taxTool = Invoke-McpStdioTool -Name 'mcp-stdio-taxonomy' -Tool 'memory_taxonomy' -DataDir $DirA
Add-SweepRow 'mcp-stdio-taxonomy-envelope' ($null -ne $taxTool.Envelope -and [string]$taxTool.Envelope.command -eq 'taxonomy') ([string]$taxTool.Envelope.command)
$rememberTool = Invoke-McpStdioTool -Name 'mcp-stdio-remember' -Tool 'memory_remember' -Arguments @{
    content = "【前因】扫测 MCP 业务。【行为】写入标记 $mcpMarker。【后果】供 recall/show/update/attach/forget 断言。"
    title = "MCP扫测标记"
    importance = 'important'
    parent = '编程开发'
    force = $true
} -DataDir $DirA
$mcpId = ''
if ($rememberTool.Envelope -and $rememberTool.Envelope.summary.id) { $mcpId = [string]$rememberTool.Envelope.summary.id }
if (-not $mcpId -and $rememberTool.Envelope -and $rememberTool.Envelope.summary.entry_id) { $mcpId = [string]$rememberTool.Envelope.summary.entry_id }
if (-not $mcpId -and $rememberTool.Stdout -match '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})') { $mcpId = $Matches[1] }
Add-SweepRow 'mcp-stdio-remember-id' ([bool]$mcpId) $mcpId
$recallTool = Invoke-McpStdioTool -Name 'mcp-stdio-recall' -Tool 'memory_recall' -Arguments @{ query = $mcpMarker; limit = 3 } -DataDir $DirA
Add-SweepRow 'mcp-stdio-recall-hit' ($recallTool.Run.Stdout -like "*$mcpMarker*") 'recall contains marker'
$listTool = Invoke-McpStdioTool -Name 'mcp-stdio-list' -Tool 'memory_list' -Arguments @{ limit = 5 } -DataDir $DirA
Add-SweepRow 'mcp-stdio-list-envelope' ($null -ne $listTool.Envelope -and [string]$listTool.Envelope.command -eq 'list') ([string]$listTool.Envelope.command)
if ($mcpId) {
    $showTool = Invoke-McpStdioTool -Name 'mcp-stdio-show' -Tool 'memory_show' -Arguments @{ id = $mcpId } -DataDir $DirA
    Add-SweepRow 'mcp-stdio-show-hit' ($showTool.Run.Stdout -like "*$mcpMarker*") 'show contains marker'
    $updTool = Invoke-McpStdioTool -Name 'mcp-stdio-update' -Tool 'memory_update' -Arguments @{ id = $mcpId; title = 'MCP扫测标记已改' } -DataDir $DirA
    Add-SweepRow 'mcp-stdio-update-envelope' ($null -ne $updTool.Envelope -and [string]$updTool.Envelope.command -eq 'update') ([string]$updTool.Envelope.command)
    $parentPrefix = ''
    if ($listTool.Envelope -and $listTool.Envelope.items) {
        $parentPrefix = [string](@($listTool.Envelope.items | Where-Object { [string]$_.name -ne $mcpId.Substring(0, [Math]::Min(8, $mcpId.Length)) } | Select-Object -First 1).name)
    }
    if (-not $parentPrefix) { $parentPrefix = $mcpId }
    $attachTool = Invoke-McpStdioTool -Name 'mcp-stdio-attach' -Tool 'memory_attach' -Arguments @{ id = $mcpId; parent = $parentPrefix } -DataDir $DirA
    $attachOk = $null -ne $attachTool.Envelope -and [string]$attachTool.Envelope.command -eq 'attach' -and [string]$attachTool.Envelope.status -ne 'fail'
    Add-SweepRow 'mcp-stdio-attach-envelope' $attachOk ([string]$attachTool.Envelope.status + ' parent=' + $parentPrefix)
    $histTool = Invoke-McpStdioTool -Name 'mcp-stdio-history' -Tool 'memory_history' -Arguments @{ id = $mcpId; limit = 10 } -DataDir $DirA
    Add-SweepRow 'mcp-stdio-history-envelope' ($null -ne $histTool.Envelope -and [string]$histTool.Envelope.command -eq 'history') ([string]$histTool.Envelope.command)
    $chainTool = Invoke-McpStdioTool -Name 'mcp-stdio-chain' -Tool 'memory_chain' -Arguments @{ id = $mcpId; depth = 2 } -DataDir $DirA
    Add-SweepRow 'mcp-stdio-chain-envelope' ($null -ne $chainTool.Envelope -and [string]$chainTool.Envelope.command -eq 'chain') ([string]$chainTool.Envelope.command)
    $markTool = Invoke-McpStdioTool -Name 'mcp-stdio-query-log-mark' -Tool 'memory_query_log_mark' -Arguments @{ ids = $mcpId; good = $true } -DataDir $DirA
    Add-SweepRow 'mcp-stdio-query-log-mark-ran' ($null -ne $markTool.Rpc) ([string]$markTool.Envelope.status)
    $forgetTool = Invoke-McpStdioTool -Name 'mcp-stdio-forget' -Tool 'memory_forget' -Arguments @{ id = $mcpId } -DataDir $DirA
    Add-SweepRow 'mcp-stdio-forget-envelope' ($null -ne $forgetTool.Envelope -and [string]$forgetTool.Envelope.command -eq 'forget') ([string]$forgetTool.Envelope.command)
    $restoreTool = Invoke-McpStdioTool -Name 'mcp-stdio-restore' -Tool 'memory_restore' -Arguments @{ id = $mcpId } -DataDir $DirA
    Add-SweepRow 'mcp-stdio-restore-envelope' ($null -ne $restoreTool.Envelope -and [string]$restoreTool.Envelope.command -eq 'restore') ([string]$restoreTool.Envelope.command)
} else {
    foreach ($n in @('mcp-stdio-show-hit','mcp-stdio-update-envelope','mcp-stdio-attach-envelope','mcp-stdio-history-envelope','mcp-stdio-chain-envelope','mcp-stdio-query-log-mark-ran','mcp-stdio-forget-envelope','mcp-stdio-restore-envelope')) {
        Add-SweepRow $n $false 'no remember id'
    }
}
$treeTool = Invoke-McpStdioTool -Name 'mcp-stdio-tree' -Tool 'memory_tree' -Arguments @{ outline = $true } -DataDir $DirA
Add-SweepRow 'mcp-stdio-tree-envelope' ($null -ne $treeTool.Envelope -and [string]$treeTool.Envelope.command -eq 'tree') ([string]$treeTool.Envelope.command)
$diaryTool = Invoke-McpStdioTool -Name 'mcp-stdio-diary' -Tool 'memory_diary' -Arguments @{ limit = 5 } -DataDir $DirA
Add-SweepRow 'mcp-stdio-diary-envelope' ($null -ne $diaryTool.Envelope -and [string]$diaryTool.Envelope.command -eq 'diary') ([string]$diaryTool.Envelope.command)
$badTool = Invoke-McpStdioTool -Name 'mcp-stdio-unknown-tool' -Tool 'memory_nope' -DataDir $DirA
$badIsError = $false
if ($badTool.Rpc -and $badTool.Rpc.result) { $badIsError = [bool]$badTool.Rpc.result.isError }
Add-SweepRow 'mcp-stdio-unknown-is-error' $badIsError 'unknown tool'
$missingContent = Invoke-McpStdioTool -Name 'mcp-stdio-remember-missing' -Tool 'memory_remember' -Arguments @{ title = 'x' } -DataDir $DirA
$missingIsError = $false
if ($missingContent.Rpc -and $missingContent.Rpc.result) { $missingIsError = [bool]$missingContent.Rpc.result.isError }
Add-SweepRow 'mcp-stdio-remember-missing-is-error' $missingIsError 'missing content'

if ($mcpUrl -and $mcpId) {
    $httpRemember = Invoke-McpHttpRpc 'mcp-http-remember' @{
        jsonrpc = '2.0'; id = 10; method = 'tools/call'
        params = @{ name = 'memory_recall'; arguments = @{ query = $mcpMarker; limit = 3 } }
    }
    $httpText = ''
    if ($httpRemember -and $httpRemember.result -and $httpRemember.result.content) {
        $httpText = [string]$httpRemember.result.content[0].text
    }
    Add-SweepRow 'mcp-http-recall-hit' ($httpText -like "*$mcpMarker*") 'http recall contains marker'
}

Invoke-Om -Name 'web-stop' -ArgList @('--json', 'web', '--stop') -DataDir $DirA -ExpectExit @(0, 2) -Raw | Out-Null

$failed = @($Rows | Where-Object { -not $_.Ok })
$passed = @($Rows | Where-Object { $_.Ok })
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# CLI dev 扫测 $cliVersion") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("- 时间: $([DateTimeOffset]::UtcNow.ToString('o'))") | Out-Null
$lines.Add("- 包: $Package") | Out-Null
$lines.Add("- 版本: $cliVersion") | Out-Null
$lines.Add("- 服务器: $Server") | Out-Null
$lines.Add("- latest: $($tags.latest)") | Out-Null
$lines.Add("- 目录: $resolvedRoot") | Out-Null
$lines.Add("- 通过: $($passed.Count)  失败: $($failed.Count)") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("| 步骤 | 命令 | 退出 | 状态 | 结果 | 备注 |") | Out-Null
$lines.Add("| --- | --- | --- | --- | --- | --- |") | Out-Null
foreach ($row in $Rows) {
    $mark = if ($row.Ok) { 'PASS' } else { 'FAIL' }
    $note = (($row.Note + ' ' + $row.Leak).Trim()) -replace '\|', '/'
    $lines.Add("| $($row.Step) | $($row.Name) | $($row.Exit) | $($row.Status) | $mark | $note |") | Out-Null
}
[System.IO.File]::WriteAllText($ReportPath, ($lines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
Write-Host "REPORT $ReportPath"
Write-Host "PASS $($passed.Count) FAIL $($failed.Count)"
Stop-OurRuntimes
if ($failed.Count -gt 0) { exit 1 }
exit 0
