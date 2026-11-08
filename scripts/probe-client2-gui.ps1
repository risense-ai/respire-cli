param(
    [Parameter(Mandatory)][string]$Cli,
    [Parameter(Mandatory)][string]$RuntimeArchive,
    [Parameter(Mandatory)][string]$RuntimeVersion,
    [Parameter(Mandatory)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$report = [ordered]@{
    scope = 'original Client2 Windows GUI connectivity only; not candidate/full GUI acceptance'
    source_sha = '57bc070826949994c3f7ce9a64277160704bdfe5'
    release = 'v0.2.56'; asset_id = 707442960
    expected_exe_sha256 = 'c04b3941119bfab3a5a436345ecd4442894e40075eb79ab84aeb22e3dd3c65a0'
    environment_ready = $false; official_exe_verified = $false
    native_window_visible = $false; isolated_webview_bound = $false
    cdp_connected_to_original_webview = $false; gui_input_observed = $false
    cleanup_exit_confirmed = $false
    full_gui_acceptance = 'not-evaluated'; g1_passed = $false; status = 'failed'
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
$tracked = @()
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
    Invoke-WebRequest -Uri 'https://github.com/risense-ai/respire-client2/releases/download/v0.2.56/respire-windows-amd64.exe' -OutFile $exe -TimeoutSec 60
    $report.exe_sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($report.exe_sha256 -ne $report.expected_exe_sha256) { throw 'Official original EXE digest mismatch' }
    $report.official_exe_verified = $true
    $cliPath = (Resolve-Path -LiteralPath $Cli).Path
    $archivePath = (Resolve-Path -LiteralPath $RuntimeArchive).Path
    $report.cli_sha256 = (Get-FileHash -LiteralPath $cliPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $report.runtime_archive_sha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($RuntimeVersion -notmatch '^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$') { throw 'Invalid pinned Runtime version' }
    $taskProfile = Join-Path $root 'profile'
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
    $report.original_client_preferences = Get-Content -Raw -LiteralPath $preferencesPath | ConvertFrom-Json
    function Free-Port {
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $listener.Start(); $number = $listener.LocalEndpoint.Port; $listener.Stop(); return $number
    }
    $rpcPort = Free-Port; do { $cdpPort = Free-Port } while ($rpcPort -eq $cdpPort)
    # Explicit environment allowlist: never copy GitHub/download/runtime-service tokens into children.
    $childEnv = @{}
    foreach ($key in @('SystemRoot','WINDIR','COMSPEC','PATHEXT','ProgramFiles','ProgramFiles(x86)','ProgramData')) {
        $value = [Environment]::GetEnvironmentVariable($key); if ($value) { $childEnv[$key] = $value }
    }
    $childEnv['PATH'] = "$($childEnv['SystemRoot'])\System32;$($childEnv['SystemRoot'])"
    $childEnv['HOME'] = Join-Path $taskProfile 'home'; $childEnv['USERPROFILE'] = $childEnv['HOME']
    $childEnv['APPDATA'] = Join-Path $taskProfile 'appdata'; $childEnv['LOCALAPPDATA'] = Join-Path $taskProfile 'local'
    $childEnv['TEMP'] = Join-Path $taskProfile 'temp'; $childEnv['TMP'] = $childEnv['TEMP']
    $childEnv['RSRS_DATA_DIR'] = $taskProfile; $childEnv['RSRS_BIN_DIR'] = Join-Path $taskProfile 'bin'
    $childEnv['RSRS_RPC_PORT'] = "$rpcPort"; $childEnv['RSRS_INSTANCE_ID'] = [Guid]::NewGuid().ToString('N')
    $childEnv['RSRS_CORE_TEST_MODE'] = '1'; $childEnv['RSRS_NO_AUTOSYNC'] = '1'; $childEnv['RSRS_UPDATE_CHECK'] = '0'
    function Child-Start([string]$file, [string[]]$argv) {
        $start = [Diagnostics.ProcessStartInfo]::new($file)
        $start.UseShellExecute = $false; $start.WorkingDirectory = $root
        $start.Environment.Clear()
        foreach ($key in $childEnv.Keys) { $start.Environment[$key] = $childEnv[$key] }
        foreach ($arg in $argv) { [void]$start.ArgumentList.Add($arg) }
        return [Diagnostics.Process]::Start($start)
    }
    $install = Child-Start $cliPath @('--json','runtime','install','--file',$archivePath,'--version',$RuntimeVersion)
    if (-not $install.WaitForExit(60000)) { $install.Kill($true); throw 'Staged Runtime installation timed out' }
    if ($install.ExitCode -ne 0) { throw 'Staged Runtime installation failed' }
    $selection = Get-Content -Raw -LiteralPath (Join-Path $taskProfile 'runtime.json') | ConvertFrom-Json
    $managed = Join-Path $taskProfile "client2/runtime/$RuntimeVersion"
    if (-not (Test-Path -LiteralPath (Split-Path $managed))) {
        New-Item -ItemType Directory -Path (Split-Path $managed) | Out-Null
    }
    Copy-Item -LiteralPath (Join-Path $taskProfile "runtime/$RuntimeVersion") -Destination $managed -Recurse
    @{version=$RuntimeVersion; sha256=$selection.sha256} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $taskProfile 'client2/runtime.json') -Encoding utf8NoBOM
    Copy-Item -LiteralPath $cliPath -Destination (Join-Path $taskProfile 'bin/rsrs.exe')
    $childEnv['WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS'] = "--remote-debugging-port=$cdpPort"
    $desktopProcess = Child-Start $exe @()
    $desktopStarted = $desktopProcess.StartTime.ToUniversalTime().Ticks
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
    $node = (Get-Command node -ErrorAction Stop).Source
    $driver = Child-Start $node @((Join-Path $PSScriptRoot 'probe-client2-gui-cdp.mjs'), "$cdpPort", $root, 'discover')
    if (-not $driver.WaitForExit(50000)) { $driver.Kill($true); throw 'CDP driver timed out' }
    $discovery = Get-Content -Raw -LiteralPath (Join-Path $root 'cdp-discovery.json') | ConvertFrom-Json
    $report.cdp_discovery = $discovery
    if ($driver.ExitCode -ne 0 -or -not $discovery.cdp_connected -or -not $discovery.workspace_loaded) { throw 'CDP discovery failed before any input' }
    if ($desktopProcess.HasExited) { throw 'Original desktop exited before native binding' }
    $tracked = @(Descendants $desktopProcess.Id)
    $report.processes = @($tracked | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine,CreationDate,SessionId)
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $cdpPort -ErrorAction SilentlyContinue)
    $report.listeners = @($listeners | Select-Object LocalAddress,LocalPort,OwningProcess)
    if (-not $listeners.Count -or @($listeners | Where-Object { $_.LocalAddress -notin @('127.0.0.1','::1') }).Count) { throw 'CDP must listen only on loopback' }
    $browser = @($tracked | Where-Object { [int]$_.ProcessId -eq [int]$discovery.browser_pid -and [IO.Path]::GetFileName($_.ExecutablePath) -eq 'msedgewebview2.exe' })
    $expectedProfile = Join-Path $taskProfile 'client2/webview2'
    $taskProfileArg = '--user-data-dir=(?:"' + [regex]::Escape($expectedProfile) + '"|' + [regex]::Escape($expectedProfile) + '(?=\s|$))'
    if ($browser.Count -ne 1 -or $browser[0].CommandLine -notmatch $taskProfileArg -or
        $browser[0].SessionId -ne $desktopProcess.SessionId -or
        @($listeners | Where-Object { [int]$_.OwningProcess -ne [int]$discovery.browser_pid }).Count) { throw 'CDP browser/parent/profile/session/port binding failed' }
    $report.isolated_webview_bound = $true
    $report.native_binding = @{browser_pid=$discovery.browser_pid; port=$cdpPort; target_id=$discovery.target.id}
    $report.native_binding | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'native-bound.json') -Encoding utf8NoBOM
    # The second connection must match the native-bound browser and target before emitting input.
    $driver = Child-Start $node @((Join-Path $PSScriptRoot 'probe-client2-gui-cdp.mjs'), "$cdpPort", $root, 'input')
    if (-not $driver.WaitForExit(50000)) { $driver.Kill($true); throw 'CDP input driver timed out' }
    $cdp = Get-Content -Raw -LiteralPath (Join-Path $root 'cdp.json') | ConvertFrom-Json
    $report.cdp = $cdp
    $report.cdp_connected_to_original_webview = $cdp.cdp_connected -eq $true -and $cdp.workspace_loaded -eq $true
    $report.gui_input_observed = $cdp.gui_input_observed -eq $true
    if ($driver.ExitCode -ne 0 -or -not $report.cdp_connected_to_original_webview -or -not $report.gui_input_observed -or -not $cdp.screenshot_saved) { throw 'Original WebView GUI connectivity probe failed; see cdp.json' }
    $report.status = 'connectivity-passed'
} catch {
    $report.error = $_.Exception.Message
} finally {
    # Stop only the original process tree observed in this fresh hosted VM, with creation-time guards.
    try {
        if ($desktopProcess) {
            $sameRoot = Get-Process -Id $desktopProcess.Id -ErrorAction SilentlyContinue
            if ($sameRoot -and $sameRoot.StartTime.ToUniversalTime().Ticks -eq $desktopStarted) {
                $tracked = @($tracked) + @(Descendants $desktopProcess.Id)
            }
            foreach ($item in $tracked) {
                try {
                    $current = Get-CimInstance Win32_Process -Filter "ProcessId=$($item.ProcessId)"
                    if ($current -and $current.CreationDate -eq $item.CreationDate) {
                        $owned = Get-Process -Id $item.ProcessId -ErrorAction Stop
                        $null = $owned.SafeHandle
                        $held = Get-CimInstance Win32_Process -Filter "ProcessId=$($item.ProcessId)"
                        if (-not $held -or $held.CreationDate -ne $item.CreationDate) { throw "Process identity changed before cleanup: $($item.ProcessId)" }
                        Stop-Process -InputObject $owned -ErrorAction Stop
                        if (-not $owned.WaitForExit(5000)) { throw "Owned process did not exit: $($item.ProcessId)" }
                    }
                } catch { $report.cleanup_error = $_.Exception.Message }
            }
            foreach ($item in $tracked) {
                $survivor = Get-CimInstance Win32_Process -Filter "ProcessId=$($item.ProcessId)"
                if ($survivor -and $survivor.CreationDate -eq $item.CreationDate) { throw "Owned process survived cleanup: $($item.ProcessId)" }
            }
            $report.cleanup_exit_confirmed = -not $report.cleanup_error
        }
    } catch { $report.cleanup_error = $_.Exception.Message }
    Save-Report
}
if ($report.status -ne 'connectivity-passed' -or -not $report.cleanup_exit_confirmed -or $report.cleanup_error) { exit 1 }
