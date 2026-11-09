param(
    [Parameter(Mandatory)][string]$BindingPath,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [switch]$OfflineAcceptance
)
$ErrorActionPreference = 'Stop'
$report = [ordered]@{
    method = 'Windows UI Automation + OS SendInput Tab + desktop target-window capture'
    identity_verified = $false; accessibility_tree_read = $false; foreground_verified = $false
    native_tab_sent = $false; focus_changed_in_target_document = $false
    target_desktop_screenshot_saved = $false; status = 'failed'
    full_gui_acceptance = 'not-evaluated'; g1_passed = $false
}

function Assert-Target([bool]$RequireForeground = $false) {
    $owner = Get-Process -Id $binding.desktop_pid -ErrorAction Stop
    if ($owner.StartTime.ToUniversalTime().Ticks -ne $binding.desktop_started_ticks -or
        $owner.SessionId -ne $binding.session_id -or
        -not [string]::Equals($owner.Path, $binding.exe, [StringComparison]::OrdinalIgnoreCase)) { throw 'Original EXE identity/session changed' }
    $all = @(Get-CimInstance Win32_Process)
    $ids = [Collections.Generic.HashSet[int]]::new(); [void]$ids.Add([int]$binding.desktop_pid)
    do {
        $added = $false
        foreach ($item in $all) { if ($ids.Contains([int]$item.ParentProcessId) -and $ids.Add([int]$item.ProcessId)) { $added = $true } }
    } while ($added)
    $browser = @($all | Where-Object { $_.ProcessId -eq $binding.browser_pid })
    $browserProcess = Get-Process -Id $binding.browser_pid -ErrorAction Stop
    $profileArg = '--user-data-dir=(?:"' + [regex]::Escape($binding.webview_profile) + '"|' + [regex]::Escape($binding.webview_profile) + '(?=\s|$))'
    if ($browser.Count -ne 1 -or -not $ids.Contains([int]$binding.browser_pid) -or
        $browserProcess.StartTime.ToUniversalTime().Ticks -ne $binding.browser_started_ticks -or
        $browser[0].SessionId -ne $binding.session_id -or
        [IO.Path]::GetFileName($browser[0].ExecutablePath) -ne 'msedgewebview2.exe' -or
        $browser[0].CommandLine -notmatch $profileArg) { throw 'Original WebView descendant/profile/birth changed' }
    $window = [RespireNativeInput]::Window([IntPtr][long]$binding.hwnd)
    if ($window.pid -ne $binding.desktop_pid -or -not $window.visible -or $window.cloaked -ne 0 -or
        $window.bounds[2] -le $window.bounds[0] -or $window.bounds[3] -le $window.bounds[1] -or
        $window.client_bounds[2] -le $window.client_bounds[0] -or $window.client_bounds[3] -le $window.client_bounds[1]) { throw 'Target HWND is no longer a visible original window/client area' }
    if ($RequireForeground -and [RespireNativeInput]::Foreground().ToInt64() -ne $binding.hwnd) { throw 'Foreground is not the bound target HWND; no input/capture permitted' }
    $script:ownedIds = $ids
    return @{ bounds = @($window.bounds); client_bounds = @($window.client_bounds); foreground = [RespireNativeInput]::Foreground().ToInt64() }
}

function Element-Info($Element) {
    $current = $Element.Current
    return @{ runtime_id = ($Element.GetRuntimeId() -join '.'); process_id = $current.ProcessId
        control_type = $current.ControlType.ProgrammaticName; automation_id = $current.AutomationId
        class_name = $current.ClassName; name = $(if ($current.IsPassword) { '' } else { $current.Name.Substring(0, [Math]::Min(128, $current.Name.Length)) })
        keyboard_focusable = $current.IsKeyboardFocusable; offscreen = $current.IsOffscreen }
}

function Read-TargetTree {
    $window = [Windows.Automation.AutomationElement]::FromHandle([IntPtr][long]$binding.hwnd)
    $walker = [Windows.Automation.TreeWalker]::ControlViewWalker
    $queue = [Collections.Generic.Queue[object]]::new(); $queue.Enqueue(@{element=$window; depth=0})
    $rows = [Collections.Generic.List[object]]::new(); $clock = [Diagnostics.Stopwatch]::StartNew()
    $nodeLimited = $false; $depthLimited = $false; $timeLimited = $false
    while ($queue.Count -gt 0 -and $rows.Count -lt 256 -and $clock.Elapsed.TotalSeconds -lt 5) {
        $next = $queue.Dequeue(); $info = Element-Info $next.element; $info.depth = $next.depth
        if (-not $ownedIds.Contains([int]$info.process_id)) { throw 'UIA node belongs to an unbound process' }
        $rows.Add($info)
        if ($next.depth -lt 32) {
            $child = $walker.GetFirstChild($next.element)
            while ($child -and $queue.Count + $rows.Count -lt 256 -and $clock.Elapsed.TotalSeconds -lt 5) {
                $queue.Enqueue(@{element=$child; depth=$next.depth+1}); $child = $walker.GetNextSibling($child)
            }
            if ($child) {
                if ($queue.Count + $rows.Count -ge 256) { $nodeLimited = $true }
                if ($clock.Elapsed.TotalSeconds -ge 5) { $timeLimited = $true }
            }
        } elseif ($walker.GetFirstChild($next.element)) { $depthLimited = $true }
    }
    if ($queue.Count -gt 0) {
        if ($rows.Count -ge 256) { $nodeLimited = $true }
        if ($clock.Elapsed.TotalSeconds -ge 5) { $timeLimited = $true }
    }
    $reasons = @()
    if ($timeLimited) { $reasons += 'time-budget' }
    if ($nodeLimited) { $reasons += 'node-limit' }
    if ($depthLimited) { $reasons += 'depth-limit' }
    return @{ nodes = @($rows.ToArray()); bounded = $true; truncation_reasons = $reasons
        traversal_complete = $reasons.Count -eq 0; elapsed_ms = $clock.ElapsedMilliseconds
        max_nodes = 256; max_depth = 32; time_budget_seconds = 5
        document_count = @($rows | Where-Object { $_.control_type -eq 'ControlType.Document' -and -not $_.offscreen }).Count
        focusable_count = @($rows | Where-Object { $_.keyboard_focusable -and -not $_.offscreen }).Count }
}

function Wait-TargetDocument([double]$Seconds = 15) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $attempts = [Collections.Generic.List[object]]::new()
    while ($clock.Elapsed.TotalSeconds -lt $Seconds) {
        $null = Assert-Target $true
        $tree = Read-TargetTree
        $report.accessibility_tree = $tree
        $attempts.Add(@{ document_count=$tree.document_count; focusable_count=$tree.focusable_count
            traversal_complete=$tree.traversal_complete; truncation_reasons=$tree.truncation_reasons; elapsed_ms=$tree.elapsed_ms })
        $report.document_readiness = @{ attempts=@($attempts.ToArray()); budget_seconds=$Seconds
            elapsed_ms=$clock.ElapsedMilliseconds; ready=$false }
        if ($tree.document_count -ge 1 -and $tree.focusable_count -ge 1) {
            $report.document_readiness.ready = $true
            return
        }
        Pause-Probe
    }
    throw 'Original WebView UIA Document/focusable controls not observed within readiness budget; inspect traversal truncation reasons'
}

function Read-TargetFocus {
    $element = [Windows.Automation.AutomationElement]::FocusedElement
    if (-not $element) { throw 'UIA has no focused element' }
    $info = Element-Info $element
    $window = [Windows.Automation.AutomationElement]::FromHandle([IntPtr][long]$binding.hwnd)
    $rootId = $window.GetRuntimeId() -join '.'
    $info.belongs_to_target = $false; $info.in_document = $false
    for ($depth=0; $element -and $depth -lt 32; $depth++) {
        if (-not $ownedIds.Contains([int]$element.Current.ProcessId)) { break }
        if ($element.Current.ControlType -eq [Windows.Automation.ControlType]::Document) { $info.in_document = $true }
        if (($element.GetRuntimeId() -join '.') -eq $rootId) { $info.belongs_to_target = $true; break }
        $element = [Windows.Automation.TreeWalker]::RawViewWalker.GetParent($element)
    }
    return $info
}

function Focus-Target {
    if ([RespireNativeInput]::Foreground().ToInt64() -ne $binding.hwnd -and
        -not [RespireNativeInput]::SetForegroundWindow([IntPtr][long]$binding.hwnd)) { throw 'SetForegroundWindow was denied; no privilege/focus-policy changes attempted' }
}
function Send-TargetTab { return [RespireNativeInput]::Tab([IntPtr][long]$binding.hwnd) }
function Pause-Probe { Start-Sleep -Milliseconds 100 }

function Read-DesktopGeometry($Guard) {
    $virtual = [Windows.Forms.SystemInformation]::VirtualScreen
    $work = [Windows.Forms.Screen]::FromHandle([IntPtr][long]$binding.hwnd).WorkingArea
    $dpi = [RespireNativeInput]::GetDpiForWindow([IntPtr][long]$binding.hwnd)
    if ($dpi -eq 0) { throw 'Cannot read bound window DPI' }
    return @{ window_bounds=$Guard.bounds; client_bounds=$Guard.client_bounds; dpi=$dpi
        virtual_screen=@($virtual.Left,$virtual.Top,$virtual.Right,$virtual.Bottom)
        working_area=@($work.Left,$work.Top,$work.Right,$work.Bottom) }
}
function Move-TargetWindow([int[]]$Bounds) {
    [RespireNativeInput]::RestoreAndPosition([IntPtr][long]$binding.hwnd, [uint32]$binding.desktop_pid,
        $Bounds[0],$Bounds[1],$Bounds[2]-$Bounds[0],$Bounds[3]-$Bounds[1])
}
function Prepare-TargetWindow {
    $before = Assert-Target
    $geometry = Read-DesktopGeometry $before
    $report.window_placement_before = $geometry
    $work = $geometry.working_area
    $width = [Math]::Min($before.bounds[2]-$before.bounds[0],$work[2]-$work[0]-16)
    $height = [Math]::Min($before.bounds[3]-$before.bounds[1],$work[3]-$work[1]-16)
    # Fixed Wails WM_GETMINMAXINFO scales the original 800x600 minimum track size by window DPI.
    $minWidth = [Math]::Ceiling(800*$geometry.dpi/96.0)
    $minHeight = [Math]::Ceiling(600*$geometry.dpi/96.0)
    if ($width -lt $minWidth -or $height -lt $minHeight) { throw 'Hosted working area cannot fit the original minimum window size' }
    $requested = @(($work[0]+8),($work[1]+8),($work[0]+8+$width),($work[1]+8+$height))
    $report.window_placement_request = @{bounds=$requested; original_min_window_dips=@(800,600)}
    $null = Assert-Target
    Move-TargetWindow $requested
    $after = Assert-Target
    $placed = Read-DesktopGeometry $after
    $report.window_placement_after = $placed
    $client = $after.client_bounds
    if (($placed.working_area -join ',') -ne ($work -join ',') -or
        $after.bounds[0] -lt $work[0] -or $after.bounds[1] -lt $work[1] -or $after.bounds[2] -gt $work[2] -or $after.bounds[3] -gt $work[3] -or
        $client[0] -lt $work[0] -or $client[1] -lt $work[1] -or $client[2] -gt $work[2] -or $client[3] -gt $work[3] -or
        $after.bounds[2]-$after.bounds[0] -lt [Math]::Ceiling(800*$placed.dpi/96.0) -or
        $after.bounds[3]-$after.bounds[1] -lt [Math]::Ceiling(600*$placed.dpi/96.0)) { throw 'Restored target did not retain its original minimum window size with client area inside the working area' }
}

function Capture-Target([int[]]$ExpectedBounds) {
    $before = Assert-Target $true
    $report.capture_geometry_before = Read-DesktopGeometry $before
    if (($before.client_bounds -join ',') -ne ($ExpectedBounds -join ',')) { throw 'Target client bounds changed before desktop capture' }
    $rectangle = [Drawing.Rectangle]::new($ExpectedBounds[0], $ExpectedBounds[1], $ExpectedBounds[2]-$ExpectedBounds[0], $ExpectedBounds[3]-$ExpectedBounds[1])
    if (-not [Windows.Forms.SystemInformation]::VirtualScreen.Contains($rectangle)) { throw 'Target client area extends outside the visible desktop' }
    $bitmap = [Drawing.Bitmap]::new($rectangle.Width, $rectangle.Height)
    try {
        $graphics = [Drawing.Graphics]::FromImage($bitmap)
        try { $graphics.CopyFromScreen($rectangle.Location, [Drawing.Point]::Empty, $rectangle.Size, [Drawing.CopyPixelOperation]::SourceCopy) }
        finally { $graphics.Dispose() }
        $after = Assert-Target $true
        $report.capture_geometry_after = Read-DesktopGeometry $after
        if (($after.client_bounds -join ',') -ne ($ExpectedBounds -join ',') -or
            ($after.bounds -join ',') -ne ($before.bounds -join ',')) { throw 'Target client/window bounds changed during desktop capture' }
        $path = Join-Path $OutputDirectory 'workspace.png'
        $bitmap.Save($path, [Drawing.Imaging.ImageFormat]::Png)
        if ((Get-Item -LiteralPath $path).Length -le 0) { throw 'Desktop capture produced no PNG bytes' }
        return @{ source='desktop-target-client-area'; bounds=$ExpectedBounds; window_bounds=$before.bounds; foreground_before=$before.foreground
            foreground_after=$after.foreground; sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
    } finally { $bitmap.Dispose() }
}

function Invoke-NativeGuiProbe {
    $report.initial_guard = Assert-Target
    $report.identity_verified = $true
    Prepare-TargetWindow
    Focus-Target
    $report.input_guard = Assert-Target $true
    $report.foreground_verified = $true
    Wait-TargetDocument
    $report.accessibility_tree_read = $true
    $report.focus_before = Read-TargetFocus
    if (-not $report.focus_before.belongs_to_target -or -not $report.focus_before.runtime_id) { throw 'Initial focus is not in the bound target tree' }
    $null = Assert-Target $true
    $report.sendinput_count = Send-TargetTab
    if ($report.sendinput_count -ne 2) { throw 'SendInput did not accept both Tab key events; UIPI or input blocking may apply' }
    $report.native_tab_sent = $true
    for ($attempt=0; $attempt -lt 10; $attempt++) {
        $null = Assert-Target $true
        $report.focus_after = Read-TargetFocus
        if (-not $report.focus_after.belongs_to_target) { throw 'Focus left the bound target tree' }
        if ($report.focus_after.runtime_id -and $report.focus_after.runtime_id -ne $report.focus_before.runtime_id -and
            $report.focus_after.in_document -and $report.focus_after.keyboard_focusable) { break }
        Pause-Probe
    }
    if (-not $report.focus_after.runtime_id -or $report.focus_after.runtime_id -eq $report.focus_before.runtime_id -or
        -not $report.focus_after.in_document -or -not $report.focus_after.keyboard_focusable) { throw 'No observed focus change within the original WebView document after Tab' }
    $report.focus_changed_in_target_document = $true
    $guard = Assert-Target $true
    $report.screenshot = Capture-Target $guard.client_bounds
    $report.target_desktop_screenshot_saved = $true
    $report.status = 'native-connectivity-passed'
}

# Inserted into the existing system-PS5 helper. These functions do not execute when parsed.
function Find-OfflineControl([string]$Type, [string]$Name, [double]$Seconds = 10) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        $null = Assert-Target $true
        $window = [Windows.Automation.AutomationElement]::FromHandle([IntPtr][long]$binding.hwnd)
        $queue = [Collections.Generic.Queue[object]]::new()
        $queue.Enqueue(@{element=$window; depth=0; document=$false})
        $found = [Collections.Generic.List[object]]::new(); $visited = 0
        $walk = [Diagnostics.Stopwatch]::StartNew()
        while ($queue.Count -and $visited -lt 512 -and $walk.Elapsed.TotalSeconds -lt 5) {
            $next = $queue.Dequeue(); $visited++; $current = $next.element.Current
            if (-not $ownedIds.Contains([int]$current.ProcessId)) {
                $report.offline.foreign_node_matches_selector = ($current.ControlType.ProgrammaticName -eq $Type -and $current.Name -match $Name)
                if ($report.offline.foreign_node_matches_selector) { throw 'Offline UIA node escaped the bound process tree' }
                continue
            }
            $document = $next.document -or $current.ControlType -eq [Windows.Automation.ControlType]::Document
            # Only a selector match is retained. Never serialize arbitrary UIA names or values:
            # the normal key-generation dialog contains recovery material.
            if ($document -and $current.ControlType.ProgrammaticName -eq $Type -and
                $current.Name -match $Name -and $current.IsEnabled) { $found.Add($next.element) }
            if ($next.depth -lt 32) {
                $child = [Windows.Automation.TreeWalker]::ControlViewWalker.GetFirstChild($next.element)
                while ($child -and $visited + $queue.Count -lt 512 -and $walk.Elapsed.TotalSeconds -lt 5) {
                    $queue.Enqueue(@{element=$child; depth=$next.depth+1; document=$document})
                    $child = [Windows.Automation.TreeWalker]::ControlViewWalker.GetNextSibling($child)
                }
                if ($child) { throw 'Offline selector traversal truncated before uniqueness could be established' }
            } elseif ([Windows.Automation.TreeWalker]::ControlViewWalker.GetFirstChild($next.element)) {
                throw 'Offline selector depth limit prevents uniqueness verification'
            }
        }
        if ($queue.Count) { throw 'Offline selector traversal exceeded its node/time bound' }
        if ($found.Count -gt 1) { throw 'Offline selector is ambiguous' }
        if ($found.Count -eq 1) { return $found[0] }
        Pause-Probe
    } while ($clock.Elapsed.TotalSeconds -lt $Seconds)
    throw "Expected offline control unavailable: $Type / $Name"
}

function Focus-OfflineControl($Element) {
    $null = Assert-Target $true
    $expected = $Element.GetRuntimeId() -join '.'
    $Element.SetFocus()
    $null = Assert-Target $true
    $focus = Read-TargetFocus
    if (-not $focus.belongs_to_target -or -not $focus.in_document -or $focus.runtime_id -ne $expected -or $focus.offscreen) {
        throw 'Offline control did not receive real target-document keyboard focus'
    }
}
# Only known UIA stale/disabled failures permit reacquisition; arbitrary provider
# exceptions remain failures. Never serialize exception messages or control values.
function Test-OfflineFocusRetryable($Exception) {
    $current = $Exception
    for ($depth=0; $current -and $depth -lt 4; $depth++) {
        if ($current -is [Windows.Automation.ElementNotAvailableException] -or
            $current -is [Windows.Automation.ElementNotEnabledException]) { return $true }
        $current = $current.InnerException
    }
    return $false
}
function Find-FocusedOfflineButton([string]$Name) {
    $scrollAttempts = 0
    for ($attempt=0; $attempt -lt 5; $attempt++) {
        $null = Assert-Target $true
        # Selector traversal still proves ownership and uniqueness. Selector errors,
        # including ambiguity, are deliberately outside the retry handler.
        $element = Find-OfflineControl 'ControlType.Button' $Name 10
        try {
            $state = $element.Current
            $report.offline.focus_readiness = @{ enabled=[bool]$state.IsEnabled
                focusable=[bool]$state.IsKeyboardFocusable; offscreen=[bool]$state.IsOffscreen }
            if ($state.IsEnabled -and $state.IsKeyboardFocusable -and $state.IsOffscreen) {
                if ($scrollAttempts -ge 2) { $report.offline.focus_scroll = 'ineffective'; throw 'Offline button remained offscreen after bounded normal scrolling' }
                $scroll = $null
                if (-not $element.TryGetCurrentPattern([Windows.Automation.ScrollItemPattern]::Pattern, [ref]$scroll)) {
                    $report.offline.focus_scroll = 'unsupported'
                    throw 'Offline offscreen button does not support normal UIA scrolling'
                }
                $null = Assert-Target $true
                $scrollAttempts++
                $report.offline.focus_scroll = 'requested'
                $report.offline.focus_scroll_attempts = $scrollAttempts
                $scroll.ScrollIntoView()
                $null = Assert-Target $true
                # Never focus or invoke the pre-scroll element: reacquire it through
                # the complete ownership/document/uniqueness traversal next time.
                Pause-Probe
                continue
            }
            if (-not $state.IsEnabled -or -not $state.IsKeyboardFocusable -or $state.IsOffscreen) {
                Pause-Probe
                continue
            }
            if ($scrollAttempts -gt 0) { $report.offline.focus_scroll = 'visible' }
            Focus-OfflineControl $element
            return $element
        } catch {
            if (-not (Test-OfflineFocusRetryable $_.Exception)) {
                throw 'Offline button focus failed without a retryable UIA readiness condition'
            }
        }
        Pause-Probe
    }
    throw 'Offline button did not become focus-ready within the bounded attempts'
}
function Send-OfflineKey([int]$Key, [string]$ExpectedRuntimeId = '') {
    $null = Assert-Target $true
    $focus = Read-TargetFocus
    if (-not $focus.belongs_to_target -or -not $focus.in_document -or $focus.offscreen) { throw 'Offline input focus escaped the original visible document' }
    if ($ExpectedRuntimeId -and $focus.runtime_id -ne $ExpectedRuntimeId) { throw 'Offline button focus changed before key dispatch' }
    if ([RespireNativeInput]::Key([IntPtr][long]$binding.hwnd, [uint16]$Key) -ne 2) { throw 'Offline SendInput key was rejected' }
    $null = Assert-Target $true
}
function Press-OfflineButton([string]$Name) {
    $element = Find-FocusedOfflineButton $Name
    $expected = $element.GetRuntimeId() -join '.'
    $pattern = $null
    if (-not $element.TryGetCurrentPattern([Windows.Automation.InvokePattern]::Pattern, [ref]$pattern)) {
        throw 'Offline button does not support the normal UIA Invoke action'
    }
    $null = Assert-Target $true
    $focus = Read-TargetFocus
    if (-not $focus.belongs_to_target -or -not $focus.in_document -or $focus.offscreen -or $focus.runtime_id -ne $expected) {
        throw 'Offline button focus changed before UIA Invoke'
    }
    $pattern.Invoke()
    $null = Assert-Target $true
}
function Fill-OfflineField([string]$Name, [string]$Text) {
    $element = Find-OfflineControl 'ControlType.Edit' ('^' + [regex]::Escape($Name) + '$')
    if ($element.Current.IsPassword) { throw 'Offline fixture refuses password inputs' }
    $pattern = $element.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern)
    if ($pattern.Current.Value -ne '') { throw 'Offline synthetic field was not empty' }
    Focus-OfflineControl $element
    $null = Assert-Target $true
    $focus = Read-TargetFocus
    if ($focus.runtime_id -ne ($element.GetRuntimeId() -join '.') -or -not $focus.in_document -or $focus.offscreen) { throw 'Visible text focus changed before SendInput' }
    if ([RespireNativeInput]::Text([IntPtr][long]$binding.hwnd, $Text) -ne 2*$Text.Length) { throw 'Offline Unicode SendInput was incomplete' }
    $null = Assert-Target $true
    if ($pattern.Current.Value -ne $Text) { throw 'Synthetic text was not observed in the original visible control' }
}

function Read-OfflineHttp([string]$Path, $Body = $null) {
    if ($Path -notin @('/api/health','/api/rpc')) { throw 'Offline oracle permits only fixed local health/RPC paths' }
    $request = [Net.HttpWebRequest]::Create('http://127.0.0.1:' + $binding.rpc_port + $Path)
    $request.Proxy = $null; $request.Timeout = 10000; $request.ReadWriteTimeout = 10000
    if ($null -ne $Body) {
        $request.Method = 'POST'; $request.ContentType = 'application/json'
        $bytes = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Compress -Depth 6))
        $request.ContentLength = $bytes.Length
        $stream = $request.GetRequestStream()
        try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
    }
    $response = $request.GetResponse()
    try {
        $stream = $response.GetResponseStream(); $output = [IO.MemoryStream]::new()
        try {
            $buffer = [byte[]]::new(8192)
            while (($count = $stream.Read($buffer,0,$buffer.Length)) -gt 0) {
                if ($output.Length + $count -gt 8*1024*1024) { throw 'Offline oracle response exceeded 8 MiB' }
                $output.Write($buffer,0,$count)
            }
            return ([Text.Encoding]::UTF8.GetString($output.ToArray()) | ConvertFrom-Json)
        } finally { $stream.Dispose(); $output.Dispose() }
    } finally { $response.Dispose() }
}
function Bind-OfflineRuntime {
    $health = Read-OfflineHttp '/api/health'
    $process = Get-Process -Id $health.pid -ErrorAction Stop
    $record = Get-CimInstance Win32_Process -Filter "ProcessId=$($health.pid)"
    if ($health.server -ne 'respire' -or $health.v -ne 1 -or
        -not [string]::Equals($health.exe,$binding.runtime_exe,[StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($process.Path,$binding.runtime_exe,[StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([IO.Path]::GetFullPath($health.data_dir),$binding.data_directory,[StringComparison]::OrdinalIgnoreCase) -or
        -not $record -or $process.SessionId -ne $binding.session_id -or
        (Get-FileHash -LiteralPath $process.Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $binding.runtime_sha256) {
        throw 'Offline Runtime health/process/profile/hash binding failed'
    }
    $script:offlineRuntime = @{pid=$process.Id; started_ticks=$process.StartTime.ToUniversalTime().Ticks; record=$record}
    # Store process identity only, never the session/keygen payload.
    $report.offline.runtime_process = $record | Select-Object ProcessId,ParentProcessId,ExecutablePath,CreationDate,SessionId
    $report.offline.runtime_bound = $true
    # Persist only the guarded actor record before any key-generation dialog or business action.
    # The parent can still clean this detached actor if this helper reaches its watchdog.
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'native-gui.json'),
        ($report | ConvertTo-Json -Depth 12) + "`n", [Text.UTF8Encoding]::new($false))
}
function Assert-OfflineRuntime {
    $health = Read-OfflineHttp '/api/health'
    $process = Get-Process -Id $offlineRuntime.pid -ErrorAction Stop
    if ($health.pid -ne $offlineRuntime.pid -or $process.StartTime.ToUniversalTime().Ticks -ne $offlineRuntime.started_ticks -or
        -not [string]::Equals($process.Path,$binding.runtime_exe,[StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([IO.Path]::GetFullPath($health.data_dir),$binding.data_directory,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Offline Runtime actor changed during business acceptance'
    }
}
function Read-OfflineRpc([string[]]$Arguments) {
    # Read-only oracle: no CLI/API writes may stand in for visible UI operations.
    if (($Arguments -join '|') -notmatch '^--json\|(list\|--limit\|100|show\|[A-Za-z0-9_-]+|diary)$') { throw 'Offline oracle command is not allowlisted' }
    Assert-OfflineRuntime
    $id = 'offline-gui-' + [Guid]::NewGuid().ToString('N')
    $reply = Read-OfflineHttp '/api/rpc' @{v=1; id=$id; method='cli.exec'; args=$Arguments}
    if ($reply.v -ne 1 -or $reply.id -ne $id -or $reply.ok -ne $true -or
        $reply.envelope.status -ne 'ok' -or $reply.envelope.command -ne $Arguments[1] -or
        @($reply.envelope.errors).Count -ne 0) { throw 'Read-only oracle did not return a matching successful receipt' }
    Assert-OfflineRuntime
    return $reply.envelope
}
function Wait-OfflinePreferences([string]$Field, $Expected) {
    for ($attempt=0; $attempt -lt 50; $attempt++) {
        $preferences = Get-Content -Raw -LiteralPath $binding.preferences_path | ConvertFrom-Json
        if ($preferences.$Field -eq $Expected) { return }
        Pause-Probe
    }
    $report.offline.preference_observation = @{
        onboarding_completed=($preferences.onboardingCompleted -eq $true)
        step=$(if ($preferences.onboardingStep -in @('language','sync','model','done')) { $preferences.onboardingStep } else { 'other' })
        sync_choice=$(if ($preferences.onboardingSyncChoice -in @('offline','cloud','')) { $preferences.onboardingSyncChoice } else { 'other' })
    }
    throw "Original preferences did not persist the visible action: $Field"
}
function Create-OfflineMemory([string]$Title, [string]$Content, [bool]$Diary) {
    Press-OfflineButton ([regex]::Unescape('\u005e\u8bb0\u5fc6\u0028\u003f\u003a\u005c\u0073\u007c\u0024\u0029'))
    Press-OfflineButton ([regex]::Unescape('\u005e\u65b0\u5efa\u8bb0\u5fc6\u0024'))
    Fill-OfflineField ([regex]::Unescape('\u6807\u9898')) $Title
    Fill-OfflineField ([regex]::Unescape('\u6b63\u6587')) $Content
    if ($Diary) {
        Focus-OfflineControl (Find-OfflineControl 'ControlType.ComboBox' ([regex]::Unescape('\u005e\u5b58\u50a8\u533a\u57df\u0024')))
        Send-OfflineKey 35 # End selects the actual final option: \u65e5\u8bb0 \xb7 \u7410\u4e8b.
        Send-OfflineKey 9
    }
    Focus-OfflineControl (Find-OfflineControl 'ControlType.CheckBox' ([regex]::Unescape('\u005e\u660e\u786e\u65b0\u5efa\uff0c\u8df3\u8fc7\u5224\u91cd')))
    Send-OfflineKey 32
    Press-OfflineButton ([regex]::Unescape('\u005e\u4fdd\u5b58\u0024'))
    # Wait for the editor to close and the actual reader to render the supplied content.
    $null = Find-OfflineControl 'ControlType.Button' ([regex]::Unescape('\u005e\u7f16\u8f91\u0024')) 60
    $body = Find-OfflineControl 'ControlType.Text' ([regex]::Escape($Content))
    if ($body.Current.IsOffscreen) { throw 'Synthetic memory body is present in UIA but not visible' }
}
function Convert-OfflineEntry($Value) {
    # The fixed frontend memory/model.js::entry accepts these exact envelope/entry shapes.
    if ($Value.details.entry) { $Value = $Value.details.entry }
    elseif ($Value.entry) { $Value = $Value.entry }
    if (-not ($Value.id -is [string]) -or -not $Value.id) { throw 'Runtime returned no valid memory entry' }
    return $Value
}
function Invoke-OfflineGuiAcceptance {
    $report.offline = [ordered]@{status='failed'; onboarding_completed=$false; runtime_bound=$false
        local_keys_initialized=$false; important_memory_readback=$false; diary_readback=$false
        settings_persisted=$false; runtime_normal_stop_confirmed=$false
        full_gui_acceptance='not-evaluated'; g1_passed=$false}
    $report.offline.onboarding_stage = 'choose_offline'
    # Normal first-run route; do not use the separate \u201cskip wizard\u201d action or edit completion markers.
    Press-OfflineButton ([regex]::Unescape('\u005e\u4ec5\u5728\u6b64\u8bbe\u5907\u4f7f\u7528\u0028\u003f\u003a\u005c\u0073\u007c\u0024\u0029'))
    $report.offline.onboarding_stage = 'advance_sync'
    Press-OfflineButton ([regex]::Unescape('\u005e\u4e0b\u4e00\u6b65\u0024'))
    $report.offline.onboarding_stage = 'await_model_step'
    Wait-OfflinePreferences 'onboardingStep' 'model'
    Wait-OfflinePreferences 'onboardingSyncChoice' 'offline'
    $report.offline.onboarding_stage = 'open_model_confirmation'
    Press-OfflineButton ([regex]::Unescape('\u005e\u6682\u4e0d\u4e0b\u8f7d\u0024'))
    $confirmation = Find-OfflineControl 'ControlType.Text' ([regex]::Unescape('\u005e\u6682\u4e0d\u4e0b\u8f7d\u6a21\u578b\u0024'))
    if ($confirmation.Current.IsOffscreen) { throw 'Original model confirmation title is not visible' }
    $report.offline.onboarding_stage = 'confirm_model_skip'
    Press-OfflineButton ([regex]::Unescape('\u005e\u6682\u4e0d\u4e0b\u8f7d\u0024')) # Original confirmation dialog.
    Wait-OfflinePreferences 'onboardingCompleted' $true
    Wait-OfflinePreferences 'onboardingSyncChoice' 'offline'
    $report.offline.onboarding_completed = $true
    $report.offline.onboarding_stage = 'completed'
    $report.offline.action_stage = 'overview_navigation'
    Press-OfflineButton ([regex]::Unescape('\u005e\u6982\u89c8\u0024'))
    $report.offline.action_stage = 'runtime_start'
    Press-OfflineButton ([regex]::Unescape('\u005e\u542f\u52a8\u0020\u0052\u0075\u006e\u0074\u0069\u006d\u0065\u0024'))
    $null = Find-OfflineControl 'ControlType.Button' ([regex]::Unescape('\u005e\u505c\u6b62\u0020\u0052\u0075\u006e\u0074\u0069\u006d\u0065\u0024')) 60
    Bind-OfflineRuntime
    Press-OfflineButton ([regex]::Unescape('\u005e\u8d26\u6237\u4e0e\u7a7a\u95f4\u0024'))
    Press-OfflineButton ([regex]::Unescape('\u005e\u521d\u59cb\u5316\u79bb\u7ebf\u8bb0\u5fc6\u5e93\u0024'))
    Press-OfflineButton ([regex]::Unescape('\u005e\u521b\u5efa\u672c\u673a\u5bc6\u94a5\u0024'))
    # Never read arbitrary tree nodes/values, capture a screenshot, copy or archive recovery material.
    $null = Find-OfflineControl 'ControlType.Edit' ([regex]::Unescape('\u005e\u8bf7\u4fdd\u5b58\u672c\u673a\u6062\u590d\u6750\u6599\u0024')) 60
    Send-OfflineKey 27 # Normal Escape closes the recovery display; generated VM keys are disposable.
    $null = Find-OfflineControl 'ControlType.Text' ([regex]::Unescape('\u005e\u5df2\u4fdd\u5b58\u0024'))
    $report.offline.local_keys_initialized = $true
    $marker = 'gui-offline-' + [Guid]::NewGuid().ToString('N')
    $importantTitle = $marker + '-important'; $importantContent = $marker + ' important body'
    Create-OfflineMemory $importantTitle $importantContent $false
    $list = Read-OfflineRpc @('--json','list','--limit','100')
    if (-not ($list.details -is [Array])) { throw 'Runtime list details is not the original array contract' }
    $matches = @($list.details | ForEach-Object { Convert-OfflineEntry $_ } | Where-Object { $_.title -eq $importantTitle })
    if ($matches.Count -ne 1) { throw 'Important UI write did not produce one real Runtime entry' }
    $show = Read-OfflineRpc @('--json','show',$matches[0].id)
    $entry = Convert-OfflineEntry $show
    if ($entry.id -ne $matches[0].id -or $entry.title -ne $importantTitle -or
        $entry.content -ne $importantContent -or $entry.importance -ne 'important') { throw 'Important UI/Runtime readback mismatch' }
    $report.offline.important_memory_readback = $true
    $report.offline.important_id = $entry.id
    $diaryContent = $marker + ' diary body'
    Create-OfflineMemory ($marker + '-diary') $diaryContent $true
    $diary = Read-OfflineRpc @('--json','diary')
    if (-not ($diary.details -is [Array])) { throw 'Runtime diary details is not the original array contract' }
    $days = @($diary.details | ForEach-Object { Convert-OfflineEntry $_ } | Where-Object { $_.importance -eq 'trivial' -and $_.content -like ('*'+$diaryContent+'*') })
    if ($days.Count -ne 1) { throw 'Trivial UI write did not appear exactly once in the real diary' }
    Press-OfflineButton ([regex]::Unescape('\u005e\u65e5\u8bb0\u0024'))
    Press-OfflineButton ('^' + [regex]::Escape($days[0].title) + '$')
    $body = Find-OfflineControl 'ControlType.Text' ([regex]::Escape($diaryContent))
    if ($body.Current.IsOffscreen) { throw 'Synthetic diary body is present in UIA but not visible' }
    $report.offline.diary_readback = $true; $report.offline.diary_id = $days[0].id
    $guard = Assert-Target $true
    $report.screenshot = Capture-Target $guard.client_bounds
    $report.offline.screenshot_stage = 'real diary UI after synthetic write and Runtime readback; recovery dialog closed'
    Press-OfflineButton ([regex]::Unescape('\u005e\u8bbe\u7f6e\u0024'))
    $preference = Find-OfflineControl 'ControlType.CheckBox' ([regex]::Unescape('\u005e\u81ea\u52a8\u8fde\u63a5\u0020\u0052\u0075\u006e\u0074\u0069\u006d\u0065\u0024'))
    $toggle = $preference.GetCurrentPattern([Windows.Automation.TogglePattern]::Pattern)
    if ($toggle.Current.ToggleState -ne [Windows.Automation.ToggleState]::Off) { throw 'AutoRuntime was not initially disabled' }
    Focus-OfflineControl $preference; Send-OfflineKey 32
    Wait-OfflinePreferences 'autoRuntime' $true
    Focus-OfflineControl (Find-OfflineControl 'ControlType.CheckBox' ([regex]::Unescape('\u005e\u81ea\u52a8\u8fde\u63a5\u0020\u0052\u0075\u006e\u0074\u0069\u006d\u0065\u0024'))); Send-OfflineKey 32
    Wait-OfflinePreferences 'autoRuntime' $false
    $report.offline.settings_persisted = $true
    Assert-OfflineRuntime
    Press-OfflineButton ([regex]::Unescape('\u005e\u6982\u89c8\u0024'))
    Press-OfflineButton ([regex]::Unescape('\u005e\u505c\u6b62\u0020\u0052\u0075\u006e\u0074\u0069\u006d\u0065\u0024'))
    $process = Get-Process -Id $offlineRuntime.pid -ErrorAction SilentlyContinue
    if ($process) {
        if ($process.StartTime.ToUniversalTime().Ticks -ne $offlineRuntime.started_ticks) { throw 'Runtime PID reused before normal-stop observation' }
        if (-not $process.WaitForExit(30000)) { throw 'Runtime did not exit after visible normal Stop' }
    }
    for ($attempt=0; $attempt -lt 2; $attempt++) {
        if (Get-CimInstance Win32_Process -Filter "ProcessId=$($offlineRuntime.pid)") { throw 'Runtime PID still exists or was reused after normal Stop' }
        Pause-Probe
    }
    $report.offline.runtime_normal_stop_confirmed = $true
    $report.offline.status = 'offline-subset-passed'
}

try {
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) { throw 'Require the system 64-bit Windows PowerShell 5.1 helper' }
    $binding = Get-Content -Raw -LiteralPath $BindingPath | ConvertFrom-Json
    if ($binding.full_gui_acceptance -ne 'not-evaluated' -or $binding.g1_passed -ne $false -or
        (Get-Process -Id $PID).SessionId -ne $binding.session_id) { throw 'Invalid isolated native binding/session' }
    if ((Get-FileHash -LiteralPath $binding.exe -Algorithm SHA256).Hash.ToLowerInvariant() -ne $binding.exe_sha256) { throw 'Original EXE bytes changed' }
    Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes,System.Drawing,System.Windows.Forms
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class RespireNativeInput {
    [StructLayout(LayoutKind.Sequential)] struct RECT { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] struct POINT { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)] struct MOUSEINPUT { public int dx,dy; public uint data,flags,time; public UIntPtr extra; }
    [StructLayout(LayoutKind.Sequential)] struct KEYBDINPUT { public ushort vk,scan; public uint flags,time; public UIntPtr extra; }
    [StructLayout(LayoutKind.Explicit)] struct UNION { [FieldOffset(0)] public MOUSEINPUT mouse; [FieldOffset(0)] public KEYBDINPUT keyboard; }
    [StructLayout(LayoutKind.Sequential)] struct INPUT { public uint type; public UNION input; }
    [DllImport("user32.dll", SetLastError=true)] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll", SetLastError=true)] static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll", SetLastError=true)] static extern bool GetClientRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll", SetLastError=true)] static extern bool ClientToScreen(IntPtr hwnd, ref POINT point);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("dwmapi.dll")] static extern int DwmGetWindowAttribute(IntPtr hwnd,int attribute,out int value,int size);
    [DllImport("user32.dll", EntryPoint="GetForegroundWindow")] public static extern IntPtr Foreground();
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr SetThreadDpiAwarenessContext(IntPtr context);
    [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr hwnd);
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr hwnd, int command);
    [DllImport("user32.dll")] static extern bool IsIconic(IntPtr hwnd);
    [DllImport("user32.dll")] static extern bool IsZoomed(IntPtr hwnd);
    [DllImport("user32.dll", SetLastError=true)] static extern bool SetWindowPos(IntPtr hwnd,IntPtr after,int x,int y,int width,int height,uint flags);
    [DllImport("user32.dll", SetLastError=true)] static extern uint SendInput(uint count, INPUT[] events, int size);
    public static object Window(IntPtr hwnd) {
        uint pid; RECT rect,client; int cloaked;
        if (GetWindowThreadProcessId(hwnd,out pid)==0 || !GetWindowRect(hwnd,out rect)) throw new Win32Exception();
        if(!GetClientRect(hwnd,out client)) throw new Win32Exception();
        var origin=new POINT { X=client.Left, Y=client.Top }; var end=new POINT { X=client.Right, Y=client.Bottom };
        if(!ClientToScreen(hwnd,ref origin) || !ClientToScreen(hwnd,ref end)) throw new Win32Exception();
        int hr=DwmGetWindowAttribute(hwnd,14,out cloaked,sizeof(int)); if(hr!=0) Marshal.ThrowExceptionForHR(hr);
        return new { pid=pid, visible=IsWindowVisible(hwnd), cloaked=cloaked, bounds=new[]{rect.Left,rect.Top,rect.Right,rect.Bottom}, client_bounds=new[]{origin.X,origin.Y,end.X,end.Y} };
    }
    public static uint Key(IntPtr target,ushort key) {
        if(Foreground()!=target) throw new InvalidOperationException("Foreground changed immediately before real keyboard input");
        var events=new INPUT[2]; events[0].type=1; events[0].input.keyboard.vk=key;
        events[1].type=1; events[1].input.keyboard.vk=key; events[1].input.keyboard.flags=2;
        return SendInput(2,events,Marshal.SizeOf(typeof(INPUT)));
    }
    public static uint Text(IntPtr target,string text) {
        if(Foreground()!=target) throw new InvalidOperationException("Foreground changed immediately before real text input");
        var events=new INPUT[text.Length*2];
        for(int i=0;i<text.Length;i++) {
            events[i*2].type=1; events[i*2].input.keyboard.scan=text[i]; events[i*2].input.keyboard.flags=4;
            events[i*2+1].type=1; events[i*2+1].input.keyboard.scan=text[i]; events[i*2+1].input.keyboard.flags=6;
        }
        return SendInput((uint)events.Length,events,Marshal.SizeOf(typeof(INPUT)));
    }
    public static uint Tab(IntPtr target) {
        if(Foreground()!=target) throw new InvalidOperationException("Foreground changed immediately before SendInput");
        var events=new INPUT[2]; events[0].type=1; events[0].input.keyboard.vk=9;
        events[1].type=1; events[1].input.keyboard.vk=9; events[1].input.keyboard.flags=2;
        return SendInput(2,events,Marshal.SizeOf(typeof(INPUT)));
    }
    public static void RestoreAndPosition(IntPtr target,uint expectedPid,int x,int y,int width,int height) {
        uint pid;
        if(GetWindowThreadProcessId(target,out pid)==0 || pid!=expectedPid) throw new InvalidOperationException("Target HWND owner changed before restore");
        ShowWindow(target,9); // SW_RESTORE. Return value is prior visibility, not success.
        if(GetWindowThreadProcessId(target,out pid)==0 || pid!=expectedPid) throw new InvalidOperationException("Target HWND owner changed before positioning");
        if(!SetWindowPos(target,IntPtr.Zero,x,y,width,height,0x0014)) throw new Win32Exception(); // NOZORDER | NOACTIVATE
        if(IsIconic(target) || IsZoomed(target)) throw new InvalidOperationException("Target did not restore to a normal window");
    }
}
'@
    if ([RespireNativeInput]::SetThreadDpiAwarenessContext([IntPtr](-4)) -eq [IntPtr]::Zero) { throw 'Cannot establish per-monitor-v2 thread coordinates for target desktop capture' }
    $report.capture_coordinate_context = 'per-monitor-v2 helper thread; ends with helper process'
    Invoke-NativeGuiProbe
    if ($OfflineAcceptance) { Invoke-OfflineGuiAcceptance }
} catch { $report.error = $_.Exception.Message }
finally {
    $json = $report | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'native-gui.json'), $json + "`n", [Text.UTF8Encoding]::new($false))
}
if ($report.status -ne 'native-connectivity-passed' -or ($OfflineAcceptance -and $report.offline.status -ne 'offline-subset-passed')) { exit 1 }
