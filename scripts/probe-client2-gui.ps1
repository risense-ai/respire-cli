[CmdletBinding(DefaultParameterSetName="Official")]
param(
    [Parameter(Mandatory)][Alias('Cli')][string]$FixtureCli,
    [Parameter(Mandatory)][string]$RuntimeArchive,
    [Parameter(Mandatory)][string]$RuntimeVersion,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [switch]$OfflineAcceptance,
    [string]$OfflineModelDirectory,
    [Parameter(Mandatory,ParameterSetName='CoreQuery')][switch]$CoreConfigQuery,
    [Parameter(Mandatory,ParameterSetName='CoreQuery')][string]$CoreQueryInputs,
    [Parameter(Mandatory,ParameterSetName='CoreQuery')][string]$SealedClient2Directory,
    [Parameter(Mandatory,ParameterSetName='SourceCandidate')][switch]$SourceCandidate,
    [Parameter(Mandatory,ParameterSetName='SourceCandidate')][string]$SourceClient2Exe,
    [Parameter(Mandatory,ParameterSetName='SourceCandidate')][string]$SourceClient2Manifest,
    [Parameter(Mandatory,ParameterSetName='SourceCandidate')][string]$SourceClient2Commit,
    [Parameter(Mandatory,ParameterSetName='Official')][string]$Client2Release,
    [Parameter(Mandatory,ParameterSetName='DesktopCandidate')][string]$Client2CandidateRunId,
    [Parameter(ParameterSetName='DesktopCandidate')][switch]$LegacyGuiCli,
    [Parameter(Mandatory,ParameterSetName='Official')][Parameter(Mandatory,ParameterSetName='DesktopCandidate')][Parameter(Mandatory,ParameterSetName='CoreQuery')][string]$Client2Commit
)
$ErrorActionPreference = 'Stop'
$publishedAssets = $env:ARTIFACT_SOURCE -ceq 'published-assets'
$client2Candidate = $SourceCandidate -or $PSCmdlet.ParameterSetName -ceq 'DesktopCandidate'
$publishedOnline = $publishedAssets -and -not $client2Candidate
$candidateAssets = $env:ARTIFACT_SOURCE -ceq 'build' -and -not [string]::IsNullOrEmpty($env:CANDIDATE_ASSETS)
$candidate = if ($candidateAssets) { $env:CANDIDATE_ASSETS | ConvertFrom-Json }
$fullFixture = $publishedOnline -or $candidateAssets
if ($LegacyGuiCli -and ($fullFixture -or $publishedAssets)) { throw 'Legacy GUI CLI staging is restricted to the historical launcher diagnostic' }
$checkGuiCli = -not ($CoreConfigQuery -or $LegacyGuiCli)
if ($PSCmdlet.ParameterSetName -ne 'SourceCandidate' -and $Client2Commit -cnotmatch '\A[0-9a-f]{40}\z') { throw 'Require the exact protocol-compatible Client2 source commit' }
if ($PSCmdlet.ParameterSetName -eq 'Official' -and $Client2Release -cnotmatch '\Av[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?\z') { throw 'Require an explicit new protocol-compatible Client2 release' }
if ($publishedAssets -and (-not $OfflineAcceptance -or
    $env:RSRS_ARTIFACT_SOURCE -cne 'published-assets' -or $env:REQUEST_PUBLISH -cne 'false' -or
    $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch')) { throw 'Online installation requires verified published assets and the official offline subset' }
$report = [ordered]@{
    scope = 'protocol-compatible Client2 Windows GUI subset; not full GUI acceptance'
    source_sha = $Client2Commit
    release = $Client2Release
    environment_ready = $false; official_exe_verified = $false
    native_window_visible = $false; isolated_webview_bound = $false
    native_accessibility_read = $false; foreground_verified = $false; gui_input_observed = $false
    target_desktop_screenshot_saved = $false
    cleanup_exit_confirmed = $false; cleanup_pending_absence = @()
    cli_independence = @{mode='external-fixture-only'; phases=@(); process_start_trace_clear=$false}
    full_gui_acceptance = 'not-evaluated'; g1_passed = $false; status = 'failed'
    cloud_login = 'not-evaluated-no-gui-account-fixture'
}
if ($PSCmdlet.ParameterSetName -ceq 'SourceCandidate' -and -not $SourceCandidate) { throw 'Source candidate mode must be explicitly enabled' }
if ($SourceCandidate) {
    $report.scope='source Client2 Windows GUI subset; not official asset or release acceptance'
    foreach ($key in @('release','asset_id','source_sha','expected_exe_sha256')) { $report.Remove($key) }
    $report.fixture_mode='source-client2-ui-candidate'; $report.source_candidate_verified=$false
}
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'This probe is restricted to GitHub-hosted Windows; do not run on a host desktop'
}
$root = [IO.Path]::GetFullPath($OutputDirectory)
$tempRoot = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
if (-not $root.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $root)) {
    throw 'Require a new output directory strictly inside RUNNER_TEMP'
}
New-Item -ItemType Directory -Path $root | Out-Null
$desktopProcess = $null
$accountFixture = $null
$coreProxy = $null
$coreRuntimeRecord = $null
$cliTrace = $null
$cliTraceActors = [Collections.Generic.List[int]]::new()
$cliTraceFixtures = [Collections.Generic.List[int]]::new()
$tracked = @()
function Assert-SourceClient2Manifest($Manifest, [string]$ExpectedCommit, [string]$RunId, [string]$RunAttempt, [string]$Job) {
    $keys=@('schema_version','mode','repository','source_commit','platform','exe_file','exe_sha256','build_version','build_command','run_id','run_attempt','job')
    $actual=@($Manifest.PSObject.Properties.Name)
    if ($actual.Count -ne $keys.Count -or @($actual | Where-Object { $_ -cnotin $keys }).Count -ne 0) { throw 'Source candidate manifest schema differs' }
    foreach ($key in $keys | Where-Object { $_ -ne 'schema_version' }) {
        if ($Manifest.$key -isnot [string] -or -not $Manifest.$key) { throw 'Source candidate manifest fields must be strings' }
    }
    if ($Manifest.schema_version -isnot [int] -and $Manifest.schema_version -isnot [long]) { throw 'Source candidate manifest version is not integer' }
    if ($Manifest.schema_version -ne 1 -or $Manifest.mode -cne 'source-client2-ui-candidate' -or
        $Manifest.repository -cne 'risense-ai/respire-client2' -or $Manifest.platform -cne 'windows-amd64' -or
        $Manifest.exe_file -cne 'respire-windows-amd64.exe' -or
        $ExpectedCommit -cnotmatch '\A[0-9a-f]{40}\z' -or $Manifest.source_commit -cne $ExpectedCommit -or
        $Manifest.exe_sha256 -cnotmatch '\A[0-9a-f]{64}\z') { throw 'Source candidate identity differs' }
    if ($Manifest.build_version -cnotmatch '\A[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?\z' -or
        $Manifest.build_command -cne ('./scripts/build.ps1 -Version ' + $Manifest.build_version + ' -Arch amd64')) { throw 'Source candidate build command differs' }
    if ($RunId -cnotmatch '\A[1-9][0-9]*\z' -or $RunAttempt -cnotmatch '\A[1-9][0-9]*\z' -or
        $Job -cnotmatch '\A[A-Za-z0-9_-]+\z' -or $Manifest.run_id -cne $RunId -or
        $Manifest.run_attempt -cne $RunAttempt -or $Manifest.job -cne $Job) { throw 'Source candidate must be built in this Actions job' }
}
function Assert-CandidateRegularPath([string]$Path, [switch]$File) {
    $full=[IO.Path]::GetFullPath($Path)
    if ($full -notmatch '\A[A-Za-z]:\\' -or $full.Substring(2).Contains(':')) { throw 'Source candidate requires a local filesystem path' }
    $inside=$false
    foreach ($allowed in @($env:GITHUB_WORKSPACE,$env:RUNNER_TEMP)) {
        if ($allowed) {
            $prefix=[IO.Path]::GetFullPath($allowed).TrimEnd('\')+'\'
            if ($full.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { $inside=$true }
        }
    }
    if (-not $inside) { throw 'Source candidate path is outside isolated CI roots' }
    $item=Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($File -and $item.PSIsContainer) { throw 'Source candidate requires a regular file' }
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Source candidate paths may not contain reparse points' }
        $parent=Split-Path -Parent $item.FullName
        if (-not $parent -or $parent -eq $item.FullName) { break }
        $item=Get-Item -LiteralPath $parent -Force -ErrorAction Stop
    }
    return $full
}
function Copy-SourceClient2Candidate([string]$ExePath, [string]$ManifestPath, [string]$ExpectedCommit, [string]$Destination) {
    $source=Assert-CandidateRegularPath $ExePath -File
    $manifestFile=Assert-CandidateRegularPath $ManifestPath -File
    if ((Get-Item -LiteralPath $manifestFile).Length -gt 65536) { throw 'Source candidate manifest exceeds its bound' }
    $manifest=Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
    Assert-SourceClient2Manifest $manifest $ExpectedCommit $env:GITHUB_RUN_ID $env:GITHUB_RUN_ATTEMPT $env:GITHUB_JOB
    if ([IO.Path]::GetFileName($source) -cne $manifest.exe_file -or
        (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifest.exe_sha256) { throw 'Source candidate executable bytes differ' }
    $null=Assert-CandidateRegularPath (Split-Path -Parent $Destination)
    if (Test-Path -LiteralPath $Destination) { throw 'Source candidate destination must be new' }
    Copy-Item -LiteralPath $source -Destination $Destination
    $null=Assert-CandidateRegularPath $Destination -File
    if ((Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifest.exe_sha256) { throw 'Copied source candidate bytes differ' }
    return $manifest
}
function Assert-DesktopClient2Candidate($Run, $Artifact, [string]$ExpectedCommit, [string]$RunId) {
    if ($RunId -cnotmatch '\A[1-9][0-9]*\z' -or $Run.id.ToString() -cne $RunId -or
        $Run.head_sha -cne $ExpectedCommit -or $Run.repository.full_name -cne 'risense-ai/respire-client2' -or
        $Run.head_repository.full_name -cne 'risense-ai/respire-client2' -or
        $Run.path -cne '.github/workflows/desktop.yml' -or $Run.event -cne 'pull_request' -or
        $Run.status -cne 'completed' -or $Run.conclusion -cne 'success' -or
        $Artifact.workflow_run.id.ToString() -cne $RunId -or $Artifact.workflow_run.head_sha -cne $ExpectedCommit -or
        $Artifact.name -cne 'respire-windows-amd64' -or $Artifact.expired -ne $false -or
        $Artifact.id -le 0 -or $Artifact.size_in_bytes -le 0 -or $Artifact.digest -cnotmatch '\Asha256:[0-9a-f]{64}\z') {
        throw 'Client2 Desktop candidate provenance differs'
    }
}
function Save-SealedClient2([string]$Destination) {
    $selected = $candidate.client2
    $seal = $selected.sealed
    if (-not $OfflineAcceptance -or $PSCmdlet.ParameterSetName -cne 'Official' -or
        $selected.source_sha -cne $Client2Commit -or $selected.release -cne $Client2Release) {
        throw 'Sealed Client2 requires matching full offline candidate inputs'
    }
    if (-not $env:GH_TOKEN) { throw 'Client2 seal verification requires an authenticated GitHub read token' }
    $reader = Join-Path $env:GITHUB_WORKSPACE '.client2-seal-verifier/scripts/desktop-candidate.py'
    $directory = Join-Path $root 'sealed-client2'
    $verified = @'
import json, os, runpy, sys
from pathlib import Path
reader, root, run, attempt, source, version = sys.argv[1:]
os.environ.update(GITHUB_REPOSITORY="risense-ai/respire-client2", INPUT_RUN_ID=run,
                  INPUT_ATTEMPT=attempt, CANDIDATE_SOURCE=source, CANDIDATE_VERSION=version)
os.chdir(Path(root).parent)
runpy.run_path(reader)["producer"](Path(root))
'@ | python - $reader $directory $seal.run_id $seal.run_attempt $Client2Commit $Client2Release.Substring(1)
    if ($LASTEXITCODE) { throw 'Sealed Client2 producer verification failed' }
    $verified = $verified | ConvertFrom-Json
    if ($verified.artifact_id -ne $seal.artifact_id -or $verified.artifact_zip_digest -cne $seal.artifact_zip_digest) {
        throw 'Client2 package seal differs from the selected artifact'
    }
    $manifestPath = Join-Path $directory 'candidate.json'
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    $filename = 'respire-windows-amd64.exe'
    $expected = $manifest.files.$filename
    Copy-Item -LiteralPath (Join-Path $directory $filename) -Destination $Destination
    $hash = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ((Get-Item -LiteralPath $Destination).Length -ne $expected.size -or $hash -cne $expected.sha256) {
        throw 'Copied sealed Client2 executable differs'
    }
    $report.exe_sha256 = $hash
    $report.source_candidate_verified = $true
    $report.sealed_client2 = @{
        repository = $verified.producer.repository; source_sha = $manifest.source; version = $manifest.version
        run_id = $seal.run_id; run_attempt = $seal.run_attempt
        artifact_id = $verified.artifact_id; artifact_zip_digest = $verified.artifact_zip_digest
        manifest_sha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        exe_sha256 = $hash; six_package_receipts_verified = $true
    }
}
function Save-DownloadedClient2([string]$Destination) {
    if (-not $env:GH_TOKEN) { throw 'Client2 download requires an authenticated GitHub read token' }
    $headers = @{Authorization="Bearer $env:GH_TOKEN"; Accept='application/vnd.github+json'}
    $api = 'https://api.github.com/repos/risense-ai/respire-client2'
    if ($Client2CandidateRunId) {
        $run = Invoke-RestMethod -Headers $headers -Uri "$api/actions/runs/$Client2CandidateRunId" -TimeoutSec 60
        $inventory = Invoke-RestMethod -Headers $headers -Uri "$api/actions/runs/$Client2CandidateRunId/artifacts?per_page=100" -TimeoutSec 60
        $matches = @($inventory.artifacts | Where-Object { $_.name -ceq 'respire-windows-amd64' })
        if ($inventory.total_count -ne $inventory.artifacts.Count -or $matches.Count -ne 1) { throw 'Client2 Desktop candidate inventory is incomplete or ambiguous' }
        $artifact = $matches[0]
        Assert-DesktopClient2Candidate $run $artifact $Client2Commit $Client2CandidateRunId
        $zip = Join-Path $root 'client2-desktop.zip'
        Invoke-WebRequest -Headers $headers -Uri "$api/actions/artifacts/$($artifact.id)/zip" -OutFile $zip -TimeoutSec 120
        if ((Get-Item -LiteralPath $zip).Length -ne $artifact.size_in_bytes -or
            ('sha256:'+(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()) -cne $artifact.digest) { throw 'Client2 Desktop artifact digest differs' }
        $archive = [IO.Compression.ZipFile]::OpenRead($zip)
        try {
            $entries = @($archive.Entries | Where-Object { $_.FullName -ceq 'respire-windows-amd64.exe' })
            if ($entries.Count -ne 1) { throw 'Client2 Desktop artifact must contain exactly one executable' }
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entries[0], $Destination, $false)
        } finally { $archive.Dispose() }
        $report.fixture_mode = 'source-client2-ui-candidate'
        $report.source_candidate_verified = $true
        $report.source_candidate = @{source_commit=$Client2Commit; run_id=$Client2CandidateRunId; run_attempt=$run.run_attempt
            artifact_id=$artifact.id; artifact_digest=$artifact.digest; build_version="0.2.56-dev.$($run.run_number)"}
        $report.Remove('release')
    } else {
        $release = Invoke-RestMethod -Headers $headers -Uri "$api/releases/tags/$Client2Release" -TimeoutSec 60
        $commit = Invoke-RestMethod -Headers $headers -Uri "$api/commits/$Client2Release" -TimeoutSec 60
        $matches = @($release.assets | Where-Object { $_.name -ceq 'respire-windows-amd64.exe' })
        if ($release.draft -ne $false -or $release.tag_name -cne $Client2Release -or
            $commit.sha -cne $Client2Commit -or $matches.Count -ne 1) { throw 'Published Client2 release/source identity differs' }
        $asset = $matches[0]
        if ($asset.id -le 0 -or $asset.size -le 0 -or $asset.digest -cnotmatch '\Asha256:[0-9a-f]{64}\z') { throw 'Published Client2 asset identity is missing' }
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $Destination -TimeoutSec 120
        if ((Get-Item -LiteralPath $Destination).Length -ne $asset.size -or
            ('sha256:'+(Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()) -cne $asset.digest) { throw 'Published Client2 executable digest differs' }
        $report.asset_id = $asset.id
        $report.expected_exe_sha256 = $asset.digest.Substring(7)
        $report.official_exe_verified = $true
    }
    $report.exe_sha256 = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Assert-GuiCliAbsent {
    $directories = @($root, (Join-Path $taskProfile 'bin'), (Join-Path $taskHome '.rsrs/bin')) + ($childEnv['PATH'] -split ';')
    foreach ($directory in $directories) {
        if (Test-Path -LiteralPath (Join-Path $directory 'rsrs.exe')) { throw "CLI is present on a Client2 lookup path: $directory" }
    }
    if (Get-CimInstance Win32_Process -Filter "Name = 'rsrs.exe' AND SessionId = $($report.environment.session_id)") {
        throw 'A live CLI is present in the isolated Client2 session'
    }
}
function Assert-GuiProcessTrace($Events, $DesktopIds, $FixtureIds, [int]$ParentId) {
    $unexpected = @($Events | Where-Object { $_.ProcessName -ieq 'rsrs.exe' -and
        ($_.ParentProcessID -ne $ParentId -or $_.ProcessID -notin $FixtureIds) })
    if ($unexpected.Count) { throw 'Process start trace observed a CLI outside explicit fixture execution' }
    $desktopEvents = @($Events | Where-Object { $_.ProcessName -ieq 'respire-windows-amd64.exe' -and $_.ParentProcessID -eq $ParentId })
    foreach ($actor in $DesktopIds) {
        if ($actor -notin $desktopEvents.ProcessID) { throw 'Process start trace did not observe an expected Client2 launch' }
    }
}
function Save-Report { $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $root 'report.json') -Encoding utf8NoBOM }
function Descendants([int]$parentId) {
    $all = @(Get-CimInstance Win32_Process)
    $ids = [Collections.Generic.HashSet[int]]::new(); [void]$ids.Add($parentId)
    do {
        $added = $false
        foreach ($item in $all) { if ($ids.Contains([int]$item.ParentProcessId) -and $ids.Add([int]$item.ProcessId)) { $added = $true } }
    } while ($added)
    @($all | Where-Object { $ids.Contains([int]$_.ProcessId) })
}
# Checkpoint dates from Windows PowerShell 5 JSON lose sub-millisecond precision.
# Only a decimal string preserves the full CIM UTC birth identity across hosts.
function Read-CheckpointCreationDate($Record) {
    $text = $Record.creation_utc_ticks
    if ($text -isnot [string] -or $text -cnotmatch '\A[1-9][0-9]{0,18}\z') { throw 'Detached cleanup requires exact creation ticks' }
    $ticks = [long]0
    if (-not [long]::TryParse($text, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$ticks) -or
        $ticks -gt [datetime]::MaxValue.Ticks) { throw 'Detached cleanup creation ticks out of range' }
    return [datetime]::new($ticks, [DateTimeKind]::Utc)
}
function Test-TrackedCreationIdentity($Current, $Expected) {
    if ($Current.CreationDate -isnot [datetime] -or $Expected.CreationDate -isnot [datetime]) { throw 'Cleanup process birth evidence is not typed' }
    return $Current.CreationDate.ToUniversalTime().Ticks -eq $Expected.CreationDate.ToUniversalTime().Ticks
}
function Confirm-TrackedAbsent($Item) {
    for ($probe=0; $probe -lt 2; $probe++) {
        $current = Get-CimInstance Win32_Process -Filter "ProcessId=$($Item.ProcessId)"
        if ($current) {
            if (-not (Test-TrackedCreationIdentity $current $Item)) { throw "Process identity changed during cleanup: $($Item.ProcessId)" }
            return $false
        }
        if ($probe -eq 0) { Start-Sleep -Milliseconds 100 }
    }
    return $true
}
function Stop-TrackedOwned($Item) {
    $identityChanged = $false
    try {
        $current = Get-CimInstance Win32_Process -Filter "ProcessId=$($Item.ProcessId)"
        if ($current) {
            if (-not (Test-TrackedCreationIdentity $current $Item)) { $identityChanged = $true; throw "Process identity changed before cleanup: $($Item.ProcessId)" }
            $owned = Get-Process -Id $Item.ProcessId -ErrorAction Stop
            $null = $owned.SafeHandle
            $held = Get-CimInstance Win32_Process -Filter "ProcessId=$($Item.ProcessId)"
            if ($held) {
                if (-not (Test-TrackedCreationIdentity $held $Item)) { $identityChanged = $true; throw "Process identity changed before cleanup: $($Item.ProcessId)" }
                Stop-Process -InputObject $owned -ErrorAction Stop
                if (-not $owned.WaitForExit(5000)) { throw "Owned process did not exit: $($Item.ProcessId)" }
            }
        }
    } catch {
        # A process can exit between CIM/Get-Process/Stop-Process. Confirm absence twice;
        # never clear an observed birth mismatch, or kill a reused PID.
        if ($identityChanged) { throw }
        if (-not (Confirm-TrackedAbsent $Item)) {
            if ($_.FullyQualifiedErrorId -cne 'NoProcessFoundForGivenId,Microsoft.PowerShell.Commands.GetProcessCommand') { throw }
            # Only a vanished Get-Process lookup can defer to the unchanged final
            # two-sample absence gate; a survivor or reused PID still fails there.
            $report.cleanup_pending_absence = @($report.cleanup_pending_absence) + @(@{
                pid=$Item.ProcessId; creation_utc_ticks=$Item.CreationDate.ToUniversalTime().Ticks.ToString([Globalization.CultureInfo]::InvariantCulture)
            })
        }
        return
    }
    if (-not (Confirm-TrackedAbsent $Item)) { throw "Owned process survived cleanup: $($Item.ProcessId)" }
}
try {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class RespireGuiNative {
    public delegate bool EnumProc(IntPtr hwnd, IntPtr arg);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc callback, IntPtr arg);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] static extern bool GetClientRect(IntPtr hwnd, out RECT rect);
    [DllImport("dwmapi.dll")] static extern int DwmGetWindowAttribute(IntPtr hwnd, int attribute, out int value, int size);
    [DllImport("user32.dll", SetLastError=true)] static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll")] static extern bool CloseDesktop(IntPtr desktop);
    [StructLayout(LayoutKind.Sequential)] struct RECT { public int Left, Top, Right, Bottom; }
    public static bool InputDesktopAvailable() {
        var handle = OpenInputDesktop(0, false, 1);
        if (handle == IntPtr.Zero) return false;
        CloseDesktop(handle); return true;
    }
    public static object[] Windows(uint processId) {
        var rows = new List<object>();
        EnumWindows((hwnd, arg) => {
            uint owner; GetWindowThreadProcessId(hwnd, out owner);
            if (owner != processId) return true;
            RECT rect; bool rectOk = GetClientRect(hwnd, out rect);
            int cloaked; int hr = DwmGetWindowAttribute(hwnd, 14, out cloaked, sizeof(int));
            rows.Add(new { hwnd = hwnd.ToInt64(), visible = IsWindowVisible(hwnd),
                width = rect.Right - rect.Left, height = rect.Bottom - rect.Top,
                rect_ok = rectOk, cloak_query_ok = hr == 0, cloaked = cloaked });
            return true;
        }, IntPtr.Zero);
        return rows.ToArray();
    }
}
'@
    $report.environment = [ordered]@{
        image_os = $env:ImageOS; image_version = $env:ImageVersion
        os_version = [Environment]::OSVersion.VersionString
        session_id = (Get-Process -Id $PID).SessionId
        user_interactive = [Environment]::UserInteractive
        input_desktop_available = [RespireGuiNative]::InputDesktopAvailable()
    }
    $webviewRoots = @(${env:ProgramFiles(x86)}, $env:ProgramFiles) | Where-Object { $_ }
    $webview = @($webviewRoots | ForEach-Object {
        Get-ChildItem -Path (Join-Path $_ 'Microsoft/EdgeWebView/Application/*/msedgewebview2.exe') -ErrorAction SilentlyContinue
    })
    $report.environment.webview2_installed = $webview.Count -gt 0
    $report.environment.webview2_versions = @($webview | ForEach-Object { $_.VersionInfo.FileVersion })
    if (-not $report.environment.user_interactive -or -not $report.environment.input_desktop_available -or -not $webview.Count) {
        $report.status = 'environment-blocked'
        throw 'Hosted image lacks an interactive input desktop or discoverable WebView2 Runtime; no installation attempted'
    }
    $report.environment_ready = $true
    $exe = Join-Path $root 'respire-windows-amd64.exe'
    if ($CoreConfigQuery) {
        if ($OfflineAcceptance -or $publishedAssets -or $candidateAssets -or $RuntimeVersion -cne '2.0.0-dev.24') { throw 'Core query is a separate real Runtime24 diagnostic' }
        $queryInputs = Get-Content -Raw -LiteralPath $CoreQueryInputs | ConvertFrom-Json
        $sealedManifestPath = Join-Path $SealedClient2Directory 'candidate.json'
        $sealed = Get-Content -Raw -LiteralPath $sealedManifestPath | ConvertFrom-Json
        $sourceExe = Join-Path $SealedClient2Directory 'respire-windows-amd64.exe'
        if ($queryInputs.schema -ne 1 -or $queryInputs.mode -cne 'core-query-diagnostic-inputs' -or
            $queryInputs.harness_sha -cne $env:GITHUB_SHA -or $queryInputs.client2_source -cne $Client2Commit -or
            $sealed.source -cne $Client2Commit -or $sealed.version -cne '2.0.0-dev.17' -or
            (Get-FileHash -LiteralPath $sealedManifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $queryInputs.client2_manifest_sha256 -or
            (Get-FileHash -LiteralPath $sourceExe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sealed.files.'respire-windows-amd64.exe'.sha256) { throw 'Sealed desktop/input binding differs' }
        Copy-Item -LiteralPath $sourceExe -Destination $exe
        if ((Get-Item -LiteralPath $exe).Length -ne $sealed.files.'respire-windows-amd64.exe'.size -or
            (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sealed.files.'respire-windows-amd64.exe'.sha256) { throw 'Copied sealed executable differs' }
        $report.scope = 'real WebView core-config original-query diagnostic only'
        $report.diagnostic_only = $true; $report.core_test_mode = $false
        $report.exe_sha256 = $sealed.files.'respire-windows-amd64.exe'.sha256
        $report.core_query_inputs = $queryInputs
    } elseif ($SourceCandidate) {
        if (-not $OfflineAcceptance) { throw 'Source candidate requires the complete offline GUI subset' }
        $manifest=Copy-SourceClient2Candidate $SourceClient2Exe $SourceClient2Manifest $SourceClient2Commit $exe
        $report.scope='source Client2 Windows GUI subset; not official asset or release acceptance'
        foreach ($key in @('release','asset_id','source_sha','expected_exe_sha256')) { $report.Remove($key) }
        $report.fixture_mode='source-client2-ui-candidate'
        $report.source_candidate=$manifest
        $report.source_candidate_verified=$true
        $report.exe_sha256=$manifest.exe_sha256
        $report.unverified_ui_scenarios=@('pending','error','cancel')
    } elseif ($candidate.client2.sealed) {
        Save-SealedClient2 $exe
    } else {
        if ($client2Candidate -and -not $OfflineAcceptance) { throw 'Desktop candidate requires the complete offline GUI subset' }
        Save-DownloadedClient2 $exe
    }
    $cliPath = (Resolve-Path -LiteralPath $FixtureCli).Path
    $archivePath = (Resolve-Path -LiteralPath $RuntimeArchive).Path
    $report.cli_sha256 = (Get-FileHash -LiteralPath $cliPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $report.runtime_archive_sha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($CoreConfigQuery -and ($report.cli_sha256 -cne $queryInputs.cli_sha256 -or
        $report.runtime_archive_sha256 -cne $queryInputs.runtime_archive_sha256)) { throw 'Verified CLI/Runtime input bytes differ' }
    $candidateProofPath = Join-Path (Split-Path $archivePath) 'candidate-source.json'
    if (Test-Path -LiteralPath $candidateProofPath) {
        if ((Get-Item -LiteralPath $candidateProofPath).Length -gt 65536) { throw 'Candidate provenance exceeds its bound' }
        $candidateProof = Get-Content -Raw -LiteralPath $candidateProofPath | ConvertFrom-Json
        if ($candidateProof.mode -ne 'frozen-runtime-candidate' -or $candidateProof.target -ne 'x86_64-pc-windows-msvc' -or
            $candidateProof.runtime_version -ne $RuntimeVersion -or $candidateProof.archive_sha256 -ne $report.runtime_archive_sha256 -or
            $candidateProof.actual_native_sdk_archive -ne 'not-evaluated' -or $candidateProof.full_gui_acceptance -ne 'not-evaluated' -or
            $candidateProof.g1_passed -ne $false) { throw 'Candidate archive/provenance binding differs' }
        $report.runtime_candidate = $candidateProof
    }
    if ($candidateAssets) {
        $manifestHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($env:CANDIDATE_ASSETS))).ToLowerInvariant()
        $consumer = Get-Content -Raw -LiteralPath (Join-Path (Split-Path $cliPath) 'candidate-consumer-identity.json') | ConvertFrom-Json
        $metadataPath = (Resolve-Path -LiteralPath $env:RSRS_PUBLISHED_RUNTIME_METADATA).Path
        $runtimeMetadata = Get-Content -Raw -LiteralPath $metadataPath | ConvertFrom-Json
        if ($candidate.kind -cne 'unpublished-cli-candidate' -or $candidate.source.sha -cne $env:GITHUB_SHA -or
            $candidate.source.run_id -ne [long]$env:GITHUB_RUN_ID -or $candidate.source.run_attempt -ne [int]$env:GITHUB_RUN_ATTEMPT -or
            $consumer.manifest_sha256 -cne $manifestHash -or $consumer.target -cne 'x86_64-pc-windows-msvc' -or
            $consumer.harness_sha -cne $env:GITHUB_SHA -or $consumer.product_sources.cli -cne $candidate.source.sha -or
            $consumer.product_sources.runtime -cne $candidate.runtime.source_sha -or $consumer.cli_binary_sha256 -cne $report.cli_sha256 -or
            $consumer.runtime_bundle_sha256 -cne $report.runtime_archive_sha256 -or $candidate.runtime.version -cne $RuntimeVersion -or
            $runtimeMetadata.runtime_version -cne $RuntimeVersion -or $runtimeMetadata.target_triple -cne 'x86_64-pc-windows-msvc' -or $runtimeMetadata.source_commit -cne $candidate.runtime.source_sha -or
            $runtimeMetadata.binary_sha256 -cne $consumer.runtime_binary_sha256 -or $runtimeMetadata.archive_sha256 -cne $report.runtime_archive_sha256 -or
            (Get-FileHash -LiteralPath $metadataPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $env:RSRS_PUBLISHED_RUNTIME_METADATA_SHA256) {
            throw 'Candidate CLI/Runtime reference identity differs from verified consumer receipt'
        }
        $report.candidate_inputs = @{manifest_sha256=$manifestHash; cli_source=$candidate.source.sha; runtime_source=$candidate.runtime.source_sha}
        $report.online_install = @{mode='not-evaluated'; completed=$false; reason='unpublished CLI candidate; exact local asset installation'}
    }
    if ($RuntimeVersion -notmatch '^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$') { throw 'Invalid pinned Runtime version' }
    $taskHome = Join-Path $root 'profile/home'
    $taskProfile = if ($publishedOnline) { Join-Path $taskHome '.rsrs' } else { Join-Path $root 'profile' }
    if ($publishedAssets) {
        if ($candidateProof) { throw 'Published acceptance cannot consume a Runtime candidate' }
        $manifestHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($env:PUBLISHED_ASSETS))).ToLowerInvariant()
        $published = $env:PUBLISHED_ASSETS | ConvertFrom-Json
        $consumer = Get-Content -Raw -LiteralPath (Join-Path (Split-Path $cliPath) 'published-consumer-identity.json') | ConvertFrom-Json
        $metadataPath = (Resolve-Path -LiteralPath $env:RSRS_PUBLISHED_RUNTIME_METADATA).Path
        $runtimeMetadata = Get-Content -Raw -LiteralPath $metadataPath | ConvertFrom-Json
        if ($manifestHash -cne $env:PUBLISHED_ASSETS_SHA256 -or $consumer.manifest_sha256 -cne $manifestHash -or
            $consumer.target -cne 'x86_64-pc-windows-msvc' -or $consumer.harness_sha -cne $env:GITHUB_SHA -or
            $consumer.product_sources.cli -cne $published.cli.source_sha -or $consumer.product_sources.runtime -cne $published.runtime.source_sha -or
            $consumer.cli_binary_sha256 -cne $report.cli_sha256 -or $consumer.runtime_bundle_sha256 -cne $report.runtime_archive_sha256 -or
            $published.runtime.version -cne $RuntimeVersion -or $runtimeMetadata.runtime_version -cne $RuntimeVersion -or
            $runtimeMetadata.source_commit -cne $published.runtime.source_sha -or $runtimeMetadata.binary_sha256 -cne $consumer.runtime_binary_sha256 -or
            $runtimeMetadata.archive_sha256 -cne $report.runtime_archive_sha256 -or
            (Get-FileHash -LiteralPath $metadataPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $env:RSRS_PUBLISHED_RUNTIME_METADATA_SHA256) {
            throw 'Published CLI/Runtime reference identity differs from the verified consumer receipt'
        }
        $report.published_inputs = @{manifest_sha256=$manifestHash; cli_source=$published.cli.source_sha; runtime_source=$published.runtime.source_sha}
        if ($publishedOnline) {
            $report.online_install = @{mode='published-assets'; manifest_sha256=$manifestHash
                runtime_version=$RuntimeVersion; runtime_source=$published.runtime.source_sha; runtime_release_id=$published.runtime.release_id
                home=$taskHome; data_root=$taskProfile; channel_source='product-default'; completed=$false}
            $releases = Invoke-RestMethod -Uri 'https://api.github.com/repos/risense-ai/respire-runtime/releases?per_page=20' -TimeoutSec 60
            $releases | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $root 'online-runtime-releases-before.json') -Encoding utf8NoBOM
            $latest = $releases | Where-Object { -not $_.draft -and $_.tag_name -cmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$' } |
                Sort-Object -Property @{Expression={[semver]$_.tag_name.Substring(1)}; Descending=$true} | Select-Object -First 1
            if ($latest.tag_name -cne ('v'+$published.runtime.version) -or $latest.id -ne $published.runtime.release_id) {
                throw 'Dev discovery does not select the exact published Runtime reference; no product installation attempted'
            }
        } else {
            $report.online_install = @{mode='not-evaluated'; completed=$false; reason='authenticated Client2 CI candidate; not public product upgrade evidence'}
        }
    }
    foreach ($dir in @('home','appdata','local','temp','bin')) { New-Item -ItemType Directory -Path (Join-Path $taskProfile $dir) | Out-Null }
    # Original Client2 reads these exact keys; RSRS_UPDATE_CHECK does not control its background loop.
    New-Item -ItemType Directory -Path (Join-Path $taskProfile 'client2') | Out-Null
    $preferencesJson = @'
{
  "autoRuntime": false,
  "autoUpdate": false,
  "clientAutoUpdate": false,
  "clientAutoRestart": false,
  "runtimeAutoUpdate": false,
  "runtimeAutoRestart": false,
  "onboardingVersion": 1,
  "onboardingCompleted": false,
  "onboardingStep": "language",
  "onboardingSyncChoice": ""
}
'@
    $preferencesPath = Join-Path $taskProfile 'client2/preferences.json'
    $preferencesJson | Set-Content -LiteralPath $preferencesPath -Encoding utf8NoBOM
    if ($CoreConfigQuery) {
        $queryPreferences = Get-Content -Raw -LiteralPath $preferencesPath | ConvertFrom-Json
        $queryPreferences.onboardingCompleted = $true
        $queryPreferences | Add-Member -NotePropertyName language -NotePropertyValue 'zh'
        $queryPreferences | ConvertTo-Json | Set-Content -LiteralPath $preferencesPath -Encoding utf8NoBOM
    }
    $report.original_client_preferences = Get-Content -Raw -LiteralPath $preferencesPath | ConvertFrom-Json
    function Free-Port {
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $listener.Start(); $number = $listener.LocalEndpoint.Port; $listener.Stop(); return $number
    }
    $rpcPort = Free-Port
    # Explicit environment allowlist: never copy GitHub/download/runtime-service tokens into children.
    $childEnv = @{}
    foreach ($key in @('SystemRoot','WINDIR','COMSPEC','PATHEXT','ProgramFiles','ProgramFiles(x86)','ProgramData')) {
        $value = [Environment]::GetEnvironmentVariable($key); if ($value) { $childEnv[$key] = $value }
    }
    $childEnv['PATH'] = "$($childEnv['SystemRoot'])\System32;$($childEnv['SystemRoot'])"
    $childEnv['HOME'] = $taskHome; $childEnv['USERPROFILE'] = $childEnv['HOME']
    $childEnv['APPDATA'] = Join-Path $taskProfile 'appdata'; $childEnv['LOCALAPPDATA'] = Join-Path $taskProfile 'local'
    $childEnv['TEMP'] = Join-Path $taskProfile 'temp'; $childEnv['TMP'] = $childEnv['TEMP']
    $childEnv['RSRS_DATA_DIR'] = $taskProfile; $childEnv['RSRS_BIN_DIR'] = Join-Path $taskProfile 'bin'
    $childEnv['RSRS_RPC_PORT'] = "$rpcPort"; $childEnv['RSRS_INSTANCE_ID'] = [Guid]::NewGuid().ToString('N')
    $childEnv['RSRS_CORE_TEST_MODE'] = '1'; $childEnv['RSRS_NO_AUTOSYNC'] = '1'; $childEnv['RSRS_UPDATE_CHECK'] = '0'
    if ($CoreConfigQuery) { $childEnv.Remove('RSRS_CORE_TEST_MODE') }
    function Child-Start([string]$file, [string[]]$argv, [switch]$CaptureOutput, [switch]$CaptureInput) {
        $start = [Diagnostics.ProcessStartInfo]::new($file)
        $start.UseShellExecute = $false; $start.WorkingDirectory = $root
        $start.RedirectStandardOutput = [bool]$CaptureOutput; $start.RedirectStandardError = [bool]$CaptureOutput
        $start.RedirectStandardInput = [bool]$CaptureInput
        $start.Environment.Clear()
        foreach ($key in $childEnv.Keys) { $start.Environment[$key] = $childEnv[$key] }
        foreach ($arg in $argv) { [void]$start.ArgumentList.Add($arg) }
        return [Diagnostics.Process]::Start($start)
    }
    if ($checkGuiCli) {
        $session = $report.environment.session_id
        $traceId = 'respire-gui-process-start-' + [Guid]::NewGuid()
        $traceQuery = "SELECT * FROM Win32_ProcessStartTrace WHERE SessionID = $session AND (ProcessName = 'rsrs.exe' OR ProcessName = 'respire-windows-amd64.exe')"
        Register-CimIndicationEvent -Query $traceQuery -SourceIdentifier $traceId | Out-Null
        $cliTrace = $true
        Assert-GuiCliAbsent
    } else {
        $report.cli_independence = @{mode='legacy-diagnostic'}
    }
    $managed = Join-Path $taskProfile "bin/runtime/$RuntimeVersion"
    if ($publishedOnline) {
        $report.online_install.cli_absent_before = $true
        $report.online_install.runtime_absent_before = -not (Test-Path -LiteralPath (Join-Path $taskProfile 'bin/runtime.json'))
        if (-not $report.online_install.runtime_absent_before -or
            (Test-Path -LiteralPath (Join-Path $root 'bootstrap'))) { throw 'Online installation requires absent CLI, Runtime and bootstrap payload' }
        $install = Child-Start $exe @('--headless','install-runtime') -CaptureOutput
        $cliTraceActors.Add($install.Id)
        $stdout = $install.StandardOutput.ReadToEndAsync(); $stderr = $install.StandardError.ReadToEndAsync()
        if (-not $install.WaitForExit(960000)) { $install.Kill($true); throw 'Client2 online installation exceeded its bounded deadline' }
        $installText = $stdout.GetAwaiter().GetResult()
        $installText | Set-Content -LiteralPath (Join-Path $root 'online-install.stdout.json') -Encoding utf8NoBOM
        $stderr.GetAwaiter().GetResult() | Set-Content -LiteralPath (Join-Path $root 'online-install.stderr.txt') -Encoding utf8NoBOM
        $report.online_install.exit_code = $install.ExitCode
        if ($install.ExitCode -ne 0 -or ($installText | ConvertFrom-Json).ok -ne $true) { throw 'Released Client2 online installation failed' }
        Assert-GuiCliAbsent
        $report.cli_independence.phases += 'install-runtime'
        $selection = Get-Content -Raw -LiteralPath (Join-Path $taskProfile 'bin/runtime.json') | ConvertFrom-Json
        if ($selection.version -cne $RuntimeVersion -or $selection.sha256 -cne $consumer.runtime_binary_sha256 -or
            (Get-FileHash -LiteralPath (Join-Path $managed 'rsrs-runtime.exe') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $consumer.runtime_binary_sha256) { throw 'Online installed Runtime differs from the exact published asset' }
        # The installer verifies the full archive, then removes release-only core-notices.
        foreach ($file in @($runtimeMetadata.files | Where-Object { -not $_.path.StartsWith('core-notices/', [StringComparison]::Ordinal) })) {
            $installedFile = Join-Path $managed $file.path
            if ((Get-Item -LiteralPath $installedFile).Length -ne $file.size -or
                (Get-FileHash -LiteralPath $installedFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne $file.sha256) {
                throw 'Online installed Runtime payload differs from the published inventory'
            }
        }
        if (@(Get-ChildItem -LiteralPath (Join-Path $taskProfile 'client2') -Directory -Filter '.cli-download-*').Count) { throw 'CLI download staging survived installation' }
        $releases = Invoke-RestMethod -Uri 'https://api.github.com/repos/risense-ai/respire-runtime/releases?per_page=20' -TimeoutSec 60
        $releases | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $root 'online-runtime-releases-after.json') -Encoding utf8NoBOM
        $report.online_install.runtime_sha256 = $selection.sha256
        $report.online_install.completed = $true
    } else {
        if ((Get-FileHash -LiteralPath $cliPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $report.cli_sha256) { throw 'Fixture CLI image changed before Runtime staging' }
        $install = Child-Start $cliPath @('--json','runtime','install','--file',$archivePath,'--version',$RuntimeVersion)
        if ($checkGuiCli) { $cliTraceFixtures.Add($install.Id) }
        if (-not $install.WaitForExit(60000)) { $install.Kill($true); throw 'Staged Runtime installation timed out' }
        if ($install.ExitCode -ne 0) { throw 'Staged Runtime installation failed' }
        $selection = Get-Content -Raw -LiteralPath (Join-Path $taskProfile 'bin/runtime.json') | ConvertFrom-Json
        if ($candidateAssets) {
            if ($selection.version -cne $RuntimeVersion -or $selection.sha256 -cne $consumer.runtime_binary_sha256 -or
                (Get-FileHash -LiteralPath (Join-Path $managed 'rsrs-runtime.exe') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $consumer.runtime_binary_sha256) { throw 'Installed candidate Runtime image differs' }
            # The installer verifies the full archive, then removes release-only core-notices.
            foreach ($file in @($runtimeMetadata.files | Where-Object { -not $_.path.StartsWith('core-notices/', [StringComparison]::Ordinal) })) {
                $name = if ($file.path -ceq $runtimeMetadata.binary_file) { 'rsrs-runtime.exe' } else { $file.path }
                $installedFile = Join-Path $managed $name
                if ((Get-Item -LiteralPath $installedFile).Length -ne $file.size -or
                    (Get-FileHash -LiteralPath $installedFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne $file.sha256) { throw 'Installed candidate Runtime payload differs' }
            }
        }
        if (-not $checkGuiCli) { Copy-Item -LiteralPath $cliPath -Destination (Join-Path $taskProfile 'bin/rsrs.exe') }
    }
    Write-Output 'GUI probe: Runtime installed'
    if ($CoreConfigQuery) {
        if ($selection.sha256 -cne $queryInputs.runtime_binary_sha256 -or
            (Get-FileHash -LiteralPath (Join-Path $managed 'rsrs-runtime.exe') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $queryInputs.runtime_binary_sha256) { throw 'Real installed Runtime image differs' }
        # Fresh profile: no preparation setter. The native helper verifies the
        # initial selection before issuing the single live GUI save.
        $startRuntime = Child-Start (Join-Path $taskProfile 'bin/rsrs.exe') @('--json','runtime','start') -CaptureOutput
        $startOut = $startRuntime.StandardOutput.ReadToEndAsync(); $startErr = $startRuntime.StandardError.ReadToEndAsync()
        if (-not $startRuntime.WaitForExit(60000)) { $startRuntime.Kill(); $startRuntime.WaitForExit(); throw 'Real Runtime startup timed out' }
        $startOut.GetAwaiter().GetResult() | Out-Null; $startErr.GetAwaiter().GetResult() | Out-Null
        if ($startRuntime.ExitCode -ne 0) { throw 'Real Runtime startup failed' }
        $directHealth = Invoke-RestMethod -Uri "http://127.0.0.1:$rpcPort/api/health" -Headers @{'X-Respire-Health'='runtime-v1'} -TimeoutSec 10
        $coreRuntimeRecord = Get-CimInstance Win32_Process -Filter "ProcessId=$($directHealth.pid)"
        if (-not $coreRuntimeRecord -or -not [string]::Equals($coreRuntimeRecord.ExecutablePath,(Join-Path $managed 'rsrs-runtime.exe'),[StringComparison]::OrdinalIgnoreCase)) { throw 'Cannot bind real Runtime cleanup actor' }
        $directPort = $rpcPort
        $readyPath = Join-Path $root 'core-query-proxy-ready.json'
        $python = (Get-Command python -CommandType Application | Select-Object -First 1).Source
        $coreProxy = Child-Start $python @((Join-Path $PSScriptRoot 'dev-core-config-query-fixture.py'),'serve','--port',"$rpcPort",'--profile',$taskProfile,
            '--image',(Join-Path $managed 'rsrs-runtime.exe'),'--image-sha256',$queryInputs.runtime_binary_sha256,'--ready',$readyPath)
        $clock = [Diagnostics.Stopwatch]::StartNew()
        while (-not (Test-Path -LiteralPath $readyPath) -and $clock.Elapsed.TotalSeconds -lt 15 -and -not $coreProxy.HasExited) { Start-Sleep -Milliseconds 100 }
        $queryProxy = Get-Content -Raw -LiteralPath $readyPath | ConvertFrom-Json
        $rpcPort = ([uri]$queryProxy.address).Port
        $childEnv['RSRS_RPC_PORT'] = "$rpcPort"
    }
    if ($candidateProof -and (Get-FileHash -LiteralPath (Join-Path $managed 'rsrs-runtime.exe') -Algorithm SHA256).Hash.ToLowerInvariant() -ne $candidateProof.binary_sha256) {
        throw 'Installed candidate binary differs from the frozen original archive'
    }
    if ($OfflineAcceptance) {
        $modelRoot = [IO.Path]::GetFullPath($OfflineModelDirectory)
        if (-not $modelRoot.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Offline models must be staged under RUNNER_TEMP' }
        $modelHashes = @{
            'tokenizer.json'='6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790'
            'onnx/model_quantized.onnx'='0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d'
            'onnx/model_quantized.cpu-v1.ort'='7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff'
        }
        foreach ($name in $modelHashes.Keys) {
            $modelFile = Join-Path $modelRoot $name
            foreach ($checkPath in @($modelRoot,(Split-Path $modelFile),$modelFile)) {
                if ((Get-Item -LiteralPath $checkPath).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Offline model input may not be linked' }
            }
            if ((Get-FileHash -LiteralPath $modelFile -Algorithm SHA256).Hash.ToLowerInvariant() -ne $modelHashes[$name]) { throw 'Pinned offline CPU model bytes differ' }
        }
        $report.offline_model_hashes = $modelHashes
        $childEnv['RSRS_M3_DIR'] = $modelRoot; $childEnv['RSRS_ENGINE'] = 'cpu'
    }
    $phases = if ($fullFixture -and $OfflineAcceptance) { @('initial','restart','recovery-issue','recovery-resume','recovery-verified') } else { @('initial') }
    if ($CoreConfigQuery) { $phases = @('core-issue','core-resume') }
    foreach ($phase in $phases) {
        $recoveryPhase = $phase.StartsWith('recovery-', [StringComparison]::Ordinal)
        if ($phase -ceq 'recovery-issue') {
            # Preserve the completed offline/restart proof. The account fixture uses
            # a fresh profile; issue and resume share this exact profile and WebView.
            $originalBin = Join-Path $taskProfile 'bin'
            $originalPreferences = Get-Content -Raw -LiteralPath $preferencesPath | ConvertFrom-Json
            $taskHome = Join-Path $root 'recovery-profile/home'
            $taskProfile = Join-Path $taskHome '.rsrs'
            foreach ($dir in @('client2','appdata','local','temp')) {
                New-Item -ItemType Directory -Path (Join-Path $taskProfile $dir) | Out-Null
            }
            Copy-Item -LiteralPath $originalBin -Destination (Join-Path $taskProfile 'bin') -Recurse
            $preferencesPath = Join-Path $taskProfile 'client2/preferences.json'
            $originalPreferences.autoRuntime = $false
            $originalPreferences | ConvertTo-Json | Set-Content -LiteralPath $preferencesPath -Encoding utf8NoBOM
            $childEnv['HOME'] = $taskHome; $childEnv['USERPROFILE'] = $taskHome
            $childEnv['APPDATA'] = Join-Path $taskProfile 'appdata'; $childEnv['LOCALAPPDATA'] = Join-Path $taskProfile 'local'
            $childEnv['TEMP'] = Join-Path $taskProfile 'temp'; $childEnv['TMP'] = $childEnv['TEMP']
            $childEnv['RSRS_DATA_DIR'] = $taskProfile; $childEnv['RSRS_BIN_DIR'] = Join-Path $taskProfile 'bin'
            $managed = Join-Path $taskProfile "bin/runtime/$RuntimeVersion"
            $accountReceipt = Join-Path $root 'account-fixture-counts.json'
            $serverStart = [Diagnostics.ProcessStartInfo]::new((Get-Command python -CommandType Application | Select-Object -First 1).Source)
            $serverStart.UseShellExecute = $false; $serverStart.CreateNoWindow = $true
            $serverStart.RedirectStandardOutput = $true; $serverStart.RedirectStandardError = $true
            $serverStart.Environment.Clear()
            foreach ($key in $childEnv.Keys) { $serverStart.Environment[$key] = $childEnv[$key] }
            $serverStart.Environment['GITHUB_ACTIONS'] = 'true'; $serverStart.Environment['RUNNER_ENVIRONMENT'] = 'github-hosted'
            foreach ($arg in @((Join-Path $PSScriptRoot 'dev-login-interruption-smoke.py'),'--gui-recovery-server','--receipt',$accountReceipt)) {
                [void]$serverStart.ArgumentList.Add($arg)
            }
            $accountFixture = [Diagnostics.Process]::Start($serverStart)
            $ready = $accountFixture.StandardOutput.ReadLineAsync()
            if (-not $ready.Wait(10000)) { throw 'Loopback account fixture did not become ready' }
            $accountAddress = ($ready.GetAwaiter().GetResult() | ConvertFrom-Json).addr
            if ($accountFixture.HasExited -or $accountAddress -cnotmatch '\Ahttp://127\.0\.0\.1:[0-9]+\z') { throw 'Loopback account fixture failed' }
            $report.recovery = @{status='failed'; fixture='loopback synthetic account; real CLI setup and GUI reset'; exit_method='guarded-process-termination'}
            # The verified external CLI seeds the loopback account before the desktop starts.
            if ((Get-FileHash -LiteralPath $cliPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $report.cli_sha256) { throw 'Fixture CLI image changed before account seeding' }
            # Registration output includes real material: drain bytes without decoding or saving.
            $recoveryStarted = [DateTime]::UtcNow
            $registration = Child-Start $cliPath @('--json','--host-rpc-stdio') -CaptureOutput -CaptureInput
            try {
                $cliTraceFixtures.Add($registration.Id)
                $discardOut = $registration.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null)
                $discardErr = $registration.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
                $registration.StandardInput.WriteLine((@{v=1;id=('desktop-'+[guid]::NewGuid());method='auth.register';
                    params=@{addr=$accountAddress;user='synthetic';password='gui-synthetic-registration-password'}} | ConvertTo-Json -Compress))
                $registration.StandardInput.Close()
                if (-not $registration.WaitForExit(180000)) { $registration.Kill($true); throw 'Real CLI account fixture registration timed out' }
                $discardOut.GetAwaiter().GetResult(); $discardErr.GetAwaiter().GetResult()
                $report.recovery.registration_exit_code = $registration.ExitCode
                if ($registration.ExitCode -ne 0) { throw 'Real CLI account fixture registration failed; private output was not retained' }
            } finally {
                if (-not $registration.HasExited) { $registration.Kill($true); $registration.WaitForExit() }
                $registration.Dispose()
            }
        }
        if ($checkGuiCli) { Assert-GuiCliAbsent }
        Write-Output ('GUI probe: starting desktop ' + $phase)
        $desktopProcess = Child-Start $exe @()
        $desktopStarted = $desktopProcess.StartTime.ToUniversalTime().Ticks
        if ($checkGuiCli) { $cliTraceActors.Add($desktopProcess.Id) }
        Write-Output 'GUI probe: desktop started'
        $nativeRoot = Get-CimInstance Win32_Process -Filter "ProcessId=$($desktopProcess.Id)"
        if (-not $nativeRoot -or -not [string]::Equals($nativeRoot.ExecutablePath, $exe, [StringComparison]::OrdinalIgnoreCase)) { throw 'Native process does not name the verified original EXE' }
        $report.desktop = @{pid=$desktopProcess.Id; session_id=$desktopProcess.SessionId; path=$nativeRoot.ExecutablePath; started_ticks=$desktopStarted}
        if ($desktopProcess.SessionId -ne $report.environment.session_id) { throw 'Desktop launched into a different session' }
        $windows = @()
        for ($attempt=0; $attempt -lt 80; $attempt++) {
            if ($desktopProcess.HasExited) { throw 'Official desktop exited before a native window appeared' }
            $windows = @([RespireGuiNative]::Windows($desktopProcess.Id))
            if (@($windows | Where-Object { $_.visible -and $_.rect_ok -and $_.width -gt 0 -and $_.height -gt 0 -and $_.cloak_query_ok -and $_.cloaked -eq 0 }).Count) { break }
            Start-Sleep -Milliseconds 250
        }
        $report.windows = $windows
        $report.native_window_visible = @($windows | Where-Object { $_.visible -and $_.rect_ok -and $_.width -gt 0 -and $_.height -gt 0 -and $_.cloak_query_ok -and $_.cloaked -eq 0 }).Count -gt 0
        if (-not $report.native_window_visible) { throw 'No visible uncloaked original native window' }
        $visible = @($windows | Where-Object { $_.visible -and $_.rect_ok -and $_.width -gt 0 -and $_.height -gt 0 -and $_.cloak_query_ok -and $_.cloaked -eq 0 })
        if ($visible.Count -ne 1) { throw 'Require one unambiguous original visible window' }
        $currentTree = @(Descendants $desktopProcess.Id)
        $tracked = @($tracked) + $currentTree
        $report.processes = @($tracked | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine,CreationDate,SessionId)
        $expectedProfile = [IO.Path]::GetFullPath((Join-Path $taskProfile 'client2/webview2/EBWebView'))
        $profileArg = '--user-data-dir=(?:"' + [regex]::Escape($expectedProfile) + '"|' + [regex]::Escape($expectedProfile) + '(?=\s|$))'
        $browser = @($currentTree | Where-Object { [IO.Path]::GetFileName($_.ExecutablePath) -eq 'msedgewebview2.exe' -and $_.CommandLine -match $profileArg -and $_.CommandLine -notmatch '(?:^|\s)--type=' })
        if ($browser.Count -ne 1 -or $browser[0].SessionId -ne $desktopProcess.SessionId) { throw 'Original WebView browser/profile/session binding failed' }
        $report.isolated_webview_bound = $true
        $report.native_binding = @{
            desktop_pid=$desktopProcess.Id; desktop_started_ticks=$desktopStarted; exe=$exe; exe_sha256=$report.exe_sha256
            session_id=$desktopProcess.SessionId; hwnd=$visible[0].hwnd
            browser_pid=$browser[0].ProcessId; browser_started_ticks=(Get-Process -Id $browser[0].ProcessId).StartTime.ToUniversalTime().Ticks
            webview_profile=$expectedProfile; full_gui_acceptance='not-evaluated'; g1_passed=$false
            rpc_port=$rpcPort; data_directory=$taskProfile; preferences_path=$preferencesPath
            final_public_assets=$publishedOnline
            verified_candidate_assets=$candidateAssets
            runtime_exe=(Join-Path $managed 'rsrs-runtime.exe')
            runtime_sha256=(Get-FileHash -LiteralPath (Join-Path $managed 'rsrs-runtime.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        if ($client2Candidate) { $report.native_binding.fixture_mode='source-client2-ui-candidate'; $report.native_binding.source_commit=if ($SourceCandidate) { $SourceClient2Commit } else { $Client2Commit } }
        if ($phase -eq 'restart') {
            $report.native_binding.restart_memory = $report.initial_native_gui.offline.restart_memory
            $report.native_binding.previous_runtime_pid = $report.initial_native_gui.offline.runtime_process.ProcessId
            $report.native_binding.previous_runtime_ticks = $report.initial_native_gui.offline.runtime_process.creation_utc_ticks
        }
        if ($recoveryPhase) {
            $report.native_binding.account_fixture_addr = $accountAddress
            $report.native_binding.recovery_phase = $phase
            if ($phase -in @('recovery-resume','recovery-verified')) { $report.native_binding.recovery_request = $report.recovery.request }
        }
        $bindingPath = Join-Path $root 'native-binding.json'
        if ($CoreConfigQuery) {
            $report.native_binding.core_query = @{phase=$phase; address=$queryProxy.address}
            $report.native_binding.cli_exe = Join-Path $taskProfile 'bin/rsrs.exe'
            $report.native_binding.cli_sha256 = $report.cli_sha256
        }
        $driverBinding = @{}
        foreach ($key in $report.native_binding.Keys) { $driverBinding[$key] = $report.native_binding[$key] }
        if ($CoreConfigQuery) {
            # Private binding/control files are never selected by the upload.
            # Keep control credentials out of the report's native_binding.
            $driverBinding.core_query = @{phase=$phase; address=$queryProxy.address; control_file=$readyPath}
        }
        $driverBinding | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $bindingPath -Encoding utf8NoBOM
        Write-Output 'GUI probe: window and WebView bound'
        $systemPowerShell = [IO.Path]::GetFullPath((Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'))
        $helperPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'probe-client2-gui-native.ps1')).Path
        $helperArgs = @('-NoLogo','-NoProfile','-NonInteractive','-Mta','-File',$helperPath,'-BindingPath',$bindingPath,'-OutputDirectory',$root)
        if ($OfflineAcceptance) { $helperArgs += '-OfflineAcceptance' }
        if ($phase -eq 'restart') { $helperArgs += '-ExistingKeys' }
        if ($recoveryPhase) { $helperArgs += @('-RecoveryPhase', $phase.Substring('recovery-'.Length)) }
        if ($client2Candidate) { $helperArgs += '-SourceCandidateStability' }
        if ($CoreConfigQuery) { $helperArgs += '-CoreConfigQuery' }
        Write-Output 'GUI probe: starting UI Automation helper'
        $driver = Child-Start $systemPowerShell $helperArgs
        Write-Output 'GUI probe: UI Automation helper started'
        $helperDeadline = if ($OfflineAcceptance -or $CoreConfigQuery) { 360000 } else { 45000 }
        if (-not $driver.WaitForExit($helperDeadline)) {
            Write-Output 'GUI probe: UI Automation helper timed out; stopping helper'
            $driver.Kill($true); throw 'System UI Automation helper timed out'
        }
        Write-Output 'GUI probe: UI Automation helper exited'
        $native = Get-Content -Raw -LiteralPath (Join-Path $root 'native-gui.json') | ConvertFrom-Json
        if ($recoveryPhase) { $report.recovery_native_gui = $native } else { $report.native_gui = $native }
        if ($client2Candidate -and ($native.fixture_mode -cne 'source-client2-ui-candidate' -or
            $native.offline.account_focus_stability.status -cne 'timed-window-passed' -or
            $native.offline.account_focus_stability.completed_poll_count -cne 'not-observed')) { throw 'Source candidate focus stability was not verified' }
        if ($OfflineAcceptance -and -not $recoveryPhase -and ($native.offline.status -ne 'offline-subset-passed' -or
            -not $native.offline.runtime_normal_stop_confirmed -or $native.offline.full_gui_acceptance -ne 'not-evaluated' -or
            $native.offline.g1_passed -ne $false)) { throw 'Original offline GUI subset failed; full GUI remains not-evaluated' }
        $report.native_accessibility_read = $native.accessibility_tree_read -eq $true
        $report.foreground_verified = $native.foreground_verified -eq $true
        $report.gui_input_observed = $native.native_tab_sent -eq $true -and $native.focus_changed_in_target_document -eq $true
        $report.target_desktop_screenshot_saved = $native.target_desktop_screenshot_saved -eq $true
        if ($driver.ExitCode -ne 0 -or $native.status -ne 'native-connectivity-passed' -or -not $native.identity_verified -or
            -not $report.native_accessibility_read -or -not $report.foreground_verified -or -not $report.gui_input_observed -or
            -not $report.target_desktop_screenshot_saved -or $native.full_gui_acceptance -ne 'not-evaluated' -or $native.g1_passed -ne $false) { throw 'Original native GUI connectivity probe failed; see native-gui.json' }
        if ($CoreConfigQuery) {
            if ($native.core_query.status -cne ($phase + '-passed')) { throw 'Core query phase failed' }
            Copy-Item -LiteralPath (Join-Path $root 'native-gui.json') -Destination (Join-Path $root "$phase.json")
            if ($phase -ceq 'core-issue') {
                $report.core_query_original = $native.core_query.transaction
            } elseif (($native.core_query.transaction | ConvertTo-Json -Compress -Depth 6) -cne
                ($report.core_query_original | ConvertTo-Json -Compress -Depth 6)) { throw 'Restart changed RequestBound identity' }
        }
        if ($CoreConfigQuery -and $phase -ceq 'core-issue') {
            $tracked = @($tracked) + @(Descendants $desktopProcess.Id)
            foreach ($item in $tracked) { Stop-TrackedOwned $item }
            foreach ($item in $tracked) { if (-not (Confirm-TrackedAbsent $item)) { throw 'Original desktop survived core query restart' } }
            $tracked = @()
        }
        if ($publishedOnline) {
            $persistedPreferences = Get-Content -Raw -LiteralPath $preferencesPath | ConvertFrom-Json
            $report.online_install.runtime_channel = $persistedPreferences.runtimeChannel
            if ($persistedPreferences.runtimeChannel -cne 'dev') { throw 'Fresh product preferences did not retain the default dev discovery channel' }
        }
        if ($fullFixture -and $OfflineAcceptance) {
            if (-not $recoveryPhase -and -not $native.offline.recall_hit) { throw 'Published Client2 recall was not verified' }
            if ($phase -eq 'initial') {
                $report.initial_native_gui = $native
                Copy-Item -LiteralPath (Join-Path $root 'native-gui.json') -Destination (Join-Path $root 'native-gui-initial.json')
                $tracked = @($tracked) + @(Descendants $desktopProcess.Id)
                # Guarded process termination tests restart after desktop exit, not tray-menu shutdown.
                foreach ($item in $tracked) { Stop-TrackedOwned $item }
                foreach ($item in $tracked) {
                    if (-not (Confirm-TrackedAbsent $item)) { throw 'Original desktop tree survived before restart' }
                }
                if (Get-CimInstance Win32_Process -Filter "ProcessId=$($native.offline.runtime_process.ProcessId)") { throw 'Original Runtime survived before desktop restart' }
                # Every recorded actor is now confirmed absent; do not carry its PID into a later phase.
                $tracked = @()
                $report.restart = @{exit_method='guarded-process-termination'; original_tree_absent=$true; completed=$false}
            } elseif ($phase -ceq 'restart') {
                if (-not $native.offline.automatic_start -or -not $native.offline.automatic_key_handoff) { throw 'Published desktop automatic start/key handoff was not verified' }
                $report.restart.completed = $true
                $report.restart_native_gui = $native
            } else {
                if ($native.recovery.status -cne 'recovery-subset-passed' -or
                    ($phase -cne 'recovery-verified' -and -not $native.recovery.unchecked_blocked)) {
                    throw 'Real reset recovery acknowledgement gate was not verified'
                }
                $counts = Get-Content -Raw -LiteralPath $accountReceipt | ConvertFrom-Json
                if ($counts.registers -ne 1 -or $counts.logins -ne 0 -or $counts.posts -ne 2) {
                    throw 'CLI fixture registration and GUI reset did not publish exactly once each'
                }
                if ($phase -ceq 'recovery-issue') {
                    $report.recovery.request = $native.recovery.request
                    $report.recovery.counts_before_exit = $counts
                    $report.recovery.issue = $native.recovery
                } elseif ($phase -ceq 'recovery-resume') {
                    if (-not $native.recovery.material_saved) { throw 'Recovery confirmation was not persisted' }
                    $report.recovery.resume = $native.recovery
                    $report.recovery.original_operation_not_repeated = $true
                } else {
                    if (-not $native.recovery.saved_restart_no_prompt) { throw 'Saved acknowledgement was not verified after another restart' }
                    $report.recovery.saved_restart = $native.recovery
                    $report.recovery.status = 'recovery-subset-passed'
                }
            }
            if ($phase -in @('restart','recovery-issue','recovery-resume')) {
                $tracked = @($tracked) + @(Descendants $desktopProcess.Id)
                foreach ($item in $tracked) { Stop-TrackedOwned $item }
                foreach ($item in $tracked) {
                    if (-not (Confirm-TrackedAbsent $item)) { throw 'Desktop tree survived before account recovery restart' }
                }
                # The absence barrier above retires only this completed phase's actor records.
                $tracked = @()
                if ($phase -ceq 'recovery-issue') { $report.recovery.unacknowledged_tree_absent = $true }
            }
        }
        if ($checkGuiCli) {
            Assert-GuiCliAbsent
            $report.cli_independence.phases += $phase
        }
    }
    $report.status = 'connectivity-passed'
} catch {
    $report.error = $_.Exception.Message
} finally {
    # Stop only the original process tree observed in this fresh hosted VM, with creation-time guards.
    try {
        Write-Output 'GUI probe: cleaning up tracked processes'
        if ($desktopProcess) {
            if ($report.native_binding.recovery_phase) {
                # This fresh account profile has its own verified Runtime image path.
                # Include a detached actor only with the same image, session and birth scope.
                $actors = @(Get-CimInstance Win32_Process -Filter "Name='rsrs-runtime.exe'" | Where-Object {
                    [string]::Equals($_.ExecutablePath,$report.native_binding.runtime_exe,[StringComparison]::OrdinalIgnoreCase)
                })
                foreach ($actor in $actors) {
                    if ($actor.SessionId -ne $desktopProcess.SessionId -or $actor.CreationDate.ToUniversalTime() -lt $recoveryStarted) {
                        throw 'Account fixture Runtime cleanup identity is outside the original scope'
                    }
                    $tracked += $actor
                }
            }
            if ($OfflineAcceptance -and $report.native_binding) {
              try {
                $checkpointPath = Join-Path $root 'native-gui.json'
                if (-not (Test-Path -LiteralPath $checkpointPath)) { throw 'No detached Runtime identity checkpoint; cleanup cannot be certified' }
                $checkpoint = Get-Content -Raw -LiteralPath $checkpointPath | ConvertFrom-Json
                if ($checkpoint.offline.runtime_process) {
                    $runtimeRecord = $checkpoint.offline.runtime_process
                    if (-not [string]::Equals($runtimeRecord.ExecutablePath,$report.native_binding.runtime_exe,[StringComparison]::OrdinalIgnoreCase) -or
                        $runtimeRecord.SessionId -ne $desktopProcess.SessionId) { throw 'Detached cleanup record is not the bound staged Runtime' }
                    $runtimeRecord.CreationDate = Read-CheckpointCreationDate $runtimeRecord
                    if ($runtimeRecord.CreationDate.ToUniversalTime().Ticks -lt $desktopStarted) { throw 'Detached actor predates the original desktop' }
                    $tracked += $runtimeRecord
                } elseif ($checkpoint.offline -and -not $report.native_binding.recovery_phase) { $report.cleanup_error = 'Offline Runtime identity not established; detached cleanup is not certified' }
              } catch { $report.cleanup_error = $_.Exception.Message }
            }
            $sameRoot = Get-Process -Id $desktopProcess.Id -ErrorAction SilentlyContinue
            if ($sameRoot -and $sameRoot.StartTime.ToUniversalTime().Ticks -eq $desktopStarted) {
                $tracked = @($tracked) + @(Descendants $desktopProcess.Id)
                $report.processes_before_cleanup = @($tracked | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine,CreationDate,SessionId)
            }
            foreach ($item in $tracked) {
                try { Stop-TrackedOwned $item } catch { $report.cleanup_error = $_.Exception.Message }
            }
            foreach ($item in $tracked) {
                if (-not (Confirm-TrackedAbsent $item)) { throw "Owned process survived cleanup: $($item.ProcessId)" }
            }
            $report.cleanup_exit_confirmed = -not $report.cleanup_error
        }
    } catch { $report.cleanup_error = $_.Exception.Message }
    if ($accountFixture) {
        try {
            if (-not $accountFixture.HasExited) { $accountFixture.Kill($true); $accountFixture.WaitForExit() }
        } catch { $report.cleanup_error = 'Loopback account fixture cleanup failed'; $report.cleanup_exit_confirmed = $false }
        $accountFixture.Dispose()
    }
    if ($CoreConfigQuery) {
        if ($report.status -ceq 'connectivity-passed') {
            try {
                $finalQuery = Invoke-RestMethod -Uri ($queryProxy.address + '/__fixture') -Headers @{'X-Fixture-Control'=$queryProxy.nonce} -TimeoutSec 10
                $publicKeys = @('operation_id','apply_ids','result_ids','result_issued','result_forwarded','result_response_lost','dropped_apply_replies','errors','core_test_mode','scope','apply_fusion','effective_fusion')
                $actualKeys = @($finalQuery.PSObject.Properties.Name)
                if ($actualKeys.Count -ne $publicKeys.Count -or @($actualKeys | Where-Object { $_ -cnotin $publicKeys }).Count) { throw 'Forwarding proof has non-public fields' }
                if (@($finalQuery.errors).Count -or @($finalQuery.apply_ids).Count -ne 1 -or $finalQuery.dropped_apply_replies -ne 1 -or
                    $finalQuery.apply_fusion -cne 'attention' -or $finalQuery.effective_fusion -cne 'attention' -or
                    $finalQuery.result_issued -ne @($finalQuery.result_ids).Count -or $finalQuery.result_forwarded -ne $finalQuery.result_issued -or
                    $finalQuery.result_response_lost -lt 1 -or $finalQuery.result_response_lost -ge $finalQuery.result_forwarded -or
                    @($finalQuery.result_ids).Count -lt 2 -or @($finalQuery.result_ids | Where-Object { $_ -cne $report.core_query_original.operation_id }).Count) { throw 'Final forwarding evidence is not one original apply with original-only result queries' }
                $report.core_query_final_counts = $finalQuery
            } catch { $report.core_query_evidence_error = $_.Exception.Message; $report.status = 'failed' }
        }
        try {
            if (-not $coreRuntimeRecord) { throw 'Real Runtime cleanup identity was not established' }
            $currentRuntime = Get-CimInstance Win32_Process -Filter "ProcessId=$($coreRuntimeRecord.ProcessId)"
            if (-not $currentRuntime -or -not (Test-TrackedCreationIdentity $currentRuntime $coreRuntimeRecord)) { throw 'Real Runtime identity changed before drain' }
            $live = Invoke-RestMethod -Uri "http://127.0.0.1:$directPort/api/health" -Headers @{'X-Respire-Health'='runtime-v1'} -TimeoutSec 10
            foreach ($key in @('pid','process_start_id','image_sha256','installation_id','account_id','instance_id','generation')) {
                if ($live.$key -cne $directHealth.$key) { throw 'Real Runtime owner changed before drain' }
            }
            $stopBody = @{installation_id=$live.installation_id;instance_id=$live.instance_id;account_id=$live.account_id;generation=$live.generation}
            $stopped = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$directPort/api/runtime/stop" -ContentType 'application/json' -Headers @{'X-Respire-Lifecycle'='coordinator-v1'} -Body ($stopBody | ConvertTo-Json -Compress) -TimeoutSec 10
            if (-not $stopped.ok) { throw 'Real Runtime drain request failed' }
            $draining = Get-Process -Id $coreRuntimeRecord.ProcessId -ErrorAction SilentlyContinue
            if ($draining -and -not $draining.WaitForExit(10000)) { throw 'Real Runtime drain did not exit' }
            if (-not (Confirm-TrackedAbsent $coreRuntimeRecord)) { throw 'Real Runtime survived drain' }
            $receipt = Get-Content -Raw -LiteralPath (Join-Path $taskProfile "runtime/stop-$($live.instance_id).json") | ConvertFrom-Json
            if ($receipt.state -cne 'drained' -or @($receipt.unfinished).Count) { throw 'Real Runtime drain has unfinished work' }
            foreach ($key in @('pid','process_start_id','image_sha256','installation_id','account_id','instance_id','generation')) {
                if ($receipt.$key -cne $live.$key) { throw 'Real Runtime stop receipt identity differs' }
            }
            $report.core_query_drain_verified = $true
        } catch { $report.cleanup_error = $_.Exception.Message; $report.cleanup_exit_confirmed = $false }
        finally {
            if ($coreProxy) {
                try {
                    if (-not $coreProxy.HasExited) { $coreProxy.Kill(); $coreProxy.WaitForExit() }
                    $coreProxy.Dispose()
                } catch { $report.cleanup_error = 'Real forwarding helper cleanup failed'; $report.cleanup_exit_confirmed = $false }
            }
        }
    }
    if ($cliTrace) {
        try {
            try {
                if ($report.status -ceq 'connectivity-passed') {
                    Assert-GuiCliAbsent
                    $events = @(Get-Event -SourceIdentifier $traceId -ErrorAction SilentlyContinue | ForEach-Object { $_.SourceEventArgs.NewEvent })
                    Assert-GuiProcessTrace $events $cliTraceActors $cliTraceFixtures $PID
                    $report.cli_independence.process_start_trace_clear = $true
                }
            } finally {
                Unregister-Event -SourceIdentifier $traceId
                Get-Event -SourceIdentifier $traceId -ErrorAction SilentlyContinue | Remove-Event
            }
        } catch {
            if (-not $report.cleanup_error) { $report.cleanup_error = $_.Exception.Message }
            $report.cleanup_exit_confirmed = $false
        }
    }
    Save-Report
}
if ($report.status -ne 'connectivity-passed' -or -not $report.cleanup_exit_confirmed -or $report.cleanup_error) { exit 1 }
exit 0
