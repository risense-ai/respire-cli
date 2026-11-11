param(
    [Parameter(Mandatory)][string]$BindingPath,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [switch]$OfflineAcceptance,
    [switch]$SourceCandidateStability
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
    $script:candidateProcessSnapshot = $all # Existing successful guard snapshot; diagnostic only.
    return @{ bounds = @($window.bounds); client_bounds = @($window.client_bounds); foreground = [RespireNativeInput]::Foreground().ToInt64() }
}

function Element-Info($Element) {
    $current = $Element.Current
    # UIA may expose an unnamed transient node; diagnostic names are optional.
    $name = if ($current.IsPassword) { '' } else { [string]$current.Name }
    return @{ runtime_id = ($Element.GetRuntimeId() -join '.'); process_id = $current.ProcessId
        control_type = $current.ControlType.ProgrammaticName; automation_id = $current.AutomationId
        class_name = $current.ClassName; name = $name.Substring(0, [Math]::Min(128, $name.Length))
        keyboard_focusable = $current.IsKeyboardFocusable; offscreen = $current.IsOffscreen }
}

function Get-DocumentUnavailableException([Exception]$Exception) {
    # Only known method-call wrappers, never arbitrary InnerException chains,
    # message text, HRESULT guesses, or provider/COM errors.
    $current = $Exception
    for ($depth=0; $null -ne $current -and $depth -le 4; $depth++) {
        if ($current.GetType() -eq [Windows.Automation.ElementNotAvailableException]) { return $current }
        if ($current.GetType() -ne [Management.Automation.MethodInvocationException] -and
            $current.GetType() -ne [Reflection.TargetInvocationException]) { return $null }
        $current = $current.InnerException
    }
    return $null
}
function New-DocumentReadinessClock { return [Diagnostics.Stopwatch]::StartNew() }
function Read-DocumentProperty($Element, $Property, [switch]$Readiness) {
    try { $value = $Element.GetCurrentPropertyValue($Property, $true) } catch {
        $unavailable = Get-DocumentUnavailableException $_.Exception
        if ($Readiness -and $null -ne $unavailable) {
            $report.document_pid_diagnostic = 'element_unavailable'
            return $unavailable
        }
        throw 'UIA document property method failed'
    }
    # Envelope preserves null, arrays and the exact provider type for validation.
    return @{value=$value}
}
function Read-DocumentRuntimeId($Element, [switch]$Readiness) {
    try { $value = @($Element.GetRuntimeId()) } catch {
        $unavailable = Get-DocumentUnavailableException $_.Exception
        if ($Readiness -and $null -ne $unavailable) {
            $report.document_pid_diagnostic = 'element_unavailable'
            return $unavailable
        }
        throw 'UIA document runtime identity method failed'
    }
    return @{value=$value}
}
function Assert-DocumentInspectionPid($Value, [int]$ExpectedPid, $AdmittedIds, $LiveIdentities) {
    if ($Value -isnot [int] -or $Value -le 0 -or $Value -ne $ExpectedPid -or -not $AdmittedIds.Contains($Value)) {
        throw 'UIA node process changed during inspection'
    }
    if ($null -ne $LiveIdentities) { Assert-DocumentNodeIdentity $Value $LiveIdentities }
}
function Read-DocumentNodeInfo($Element, [int]$ExpectedPid, $AdmittedIds, $LiveIdentities, [switch]$Readiness) {
    # Each provider method has its own narrow catch. All validation is outside
    # those catches and can never become a resample signal.
    $sample = Read-DocumentProperty $Element ([Windows.Automation.AutomationElement]::ProcessIdProperty) -Readiness:$Readiness
    if ($sample -is [Windows.Automation.ElementNotAvailableException]) { return $sample }
    Assert-DocumentInspectionPid $sample.value $ExpectedPid $AdmittedIds $LiveIdentities
    # Startup readiness never needs text or descriptive metadata. Do not read
    # Name, AutomationId, ClassName or IsPassword, even for diagnostics.
    $info = @{process_id=$ExpectedPid}
    $sample = Read-DocumentRuntimeId $Element -Readiness:$Readiness
    if ($sample -is [Windows.Automation.ElementNotAvailableException]) { return $sample }
    if ($sample.value.Count -eq 0 -or @($sample.value | Where-Object { $_ -isnot [int] }).Count -gt 0) { throw 'UIA node runtime identity is unknown' }
    $info.runtime_id = $sample.value -join '.'
    foreach ($field in @(
        @{key='control_type';property=[Windows.Automation.AutomationElement]::ControlTypeProperty;type=[Windows.Automation.ControlType]},
        @{key='keyboard_focusable';property=[Windows.Automation.AutomationElement]::IsKeyboardFocusableProperty;type=[bool]},
        @{key='offscreen';property=[Windows.Automation.AutomationElement]::IsOffscreenProperty;type=[bool]}
    )) {
        $sample = Read-DocumentProperty $Element $field.property -Readiness:$Readiness
        if ($sample -is [Windows.Automation.ElementNotAvailableException]) { return $sample }
        if ($null -eq $sample.value -or -not $field.type.IsInstanceOfType($sample.value)) {
            if (-not $Readiness) { throw 'UIA node diagnostic property type is unknown' }
            # Unknown is not false and cannot supply a readiness witness. Other
            # nodes may prove readiness, but every node still needs full identity.
            $info[$field.key] = $null
            continue
        }
        if ($field.key -eq 'control_type') { $info[$field.key]=$sample.value.ProgrammaticName }
        else { $info[$field.key]=$sample.value }
    }
    $sample = Read-DocumentProperty $Element ([Windows.Automation.AutomationElement]::ProcessIdProperty) -Readiness:$Readiness
    if ($sample -is [Windows.Automation.ElementNotAvailableException]) { return $sample }
    Assert-DocumentInspectionPid $sample.value $ExpectedPid $AdmittedIds $LiveIdentities
    return $info
}
function Read-TargetTree([switch]$ReportUnknownProcess, [Collections.Generic.HashSet[int]]$AdmittedIds = $null, $LiveIdentities = $null) {
    if ($null -eq $AdmittedIds) { $AdmittedIds = $ownedIds }
    $window = Get-OfflineReplacementRoot
    $walker = Get-OfflineReplacementWalker
    $queue = [Collections.Generic.Queue[object]]::new(); $queue.Enqueue(@{element=$window; depth=0})
    $rows = [Collections.Generic.List[object]]::new(); $clock = [Diagnostics.Stopwatch]::StartNew()
    $nodeLimited = $false; $depthLimited = $false; $timeLimited = $false
    while ($queue.Count -gt 0 -and $rows.Count -lt 256 -and $clock.Elapsed.TotalSeconds -lt 5) {
        $next = $queue.Dequeue()
        # Never inspect diagnostic names/values of a node whose process is unproven.
        # Explicit method invocation preserves provider exceptions rather than
        # relying on PowerShell's property-getter exception handling.
        try { $rawPid = $next.element.GetCurrentPropertyValue([Windows.Automation.AutomationElement]::ProcessIdProperty, $true) } catch {
            $unavailable = Get-DocumentUnavailableException $_.Exception
            if ($null -ne $unavailable -and $ReportUnknownProcess) {
                $report.document_pid_diagnostic = 'element_unavailable'
                # Private typed signal; no partial rows or exception details enter
                # the report. Only Wait-TargetDocument handles this exact type.
                return $unavailable
            }
            $report.document_pid_diagnostic = 'unavailable'
            throw
        }
        if ($null -eq $rawPid) {
            $report.document_pid_diagnostic = 'unavailable'
            throw 'UIA node belongs to an unbound process'
        }
        if ($rawPid -isnot [int]) {
            $report.document_pid_diagnostic = 'invalid_type'
            throw 'UIA node belongs to an unbound process'
        }
        $nodePid = $rawPid
        if ($nodePid -le 0) {
            $report.document_pid_diagnostic = 'nonpositive'
            throw 'UIA node belongs to an unbound process'
        }
        if (-not $AdmittedIds.Contains($nodePid)) {
            $report.document_pid_diagnostic = 'unbound_positive'
            # Private typed result: an Int32 means discard this entire traversal.
            if ($ReportUnknownProcess -and $nodePid -gt 0) { return [int]$nodePid }
            throw 'UIA node belongs to an unbound process'
        }
        if ($null -ne $LiveIdentities) { Assert-DocumentNodeIdentity $nodePid $LiveIdentities }
        $info = Read-DocumentNodeInfo $next.element $nodePid $AdmittedIds $LiveIdentities -Readiness:$ReportUnknownProcess
        if ($info -is [Windows.Automation.ElementNotAvailableException]) { return $info }
        $info.depth = $next.depth
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
    # Complete traversal proves enumeration, not complete property knowledge.
    # Unknown observations remain explicit and cannot provide positive witnesses.
    return @{ nodes = @($rows.ToArray()); bounded = $true; truncation_reasons = $reasons
        traversal_complete = $reasons.Count -eq 0; elapsed_ms = $clock.ElapsedMilliseconds
        max_nodes = 256; max_depth = 32; time_budget_seconds = 5
        document_count = @($rows | Where-Object { $_.control_type -ceq 'ControlType.Document' -and $_.offscreen -is [bool] -and $_.offscreen -eq $false }).Count
        focusable_count = @($rows | Where-Object { $_.keyboard_focusable -is [bool] -and $_.keyboard_focusable -eq $true -and $_.offscreen -is [bool] -and $_.offscreen -eq $false }).Count
        unknown_control_type_count = @($rows | Where-Object { $null -eq $_.control_type }).Count
        unknown_keyboard_focusable_count = @($rows | Where-Object { $null -eq $_.keyboard_focusable }).Count
        unknown_offscreen_count = @($rows | Where-Object { $null -eq $_.offscreen }).Count }
}

function Assert-DocumentProcessHandle($Process) {
    try {
        $handle = $Process.SafeHandle
        if ($null -eq $handle) { throw 'Document process handle acquisition failed' }
        $invalid = $handle.IsInvalid
        $closed = $handle.IsClosed
        if ($invalid -isnot [bool] -or $closed -isnot [bool] -or $invalid -or $closed) {
            throw 'Document process handle acquisition failed'
        }
    } catch { throw 'Document process handle acquisition failed' }
}
function Assert-DocumentNodeIdentity([int]$NodePid, $LiveIdentities) {
    if (-not $LiveIdentities.ContainsKey($NodePid)) { throw 'Document node has no held process identity' }
    $identity = $LiveIdentities[$NodePid]
    $process = $identity.process
    Assert-DocumentProcessHandle $process
    if ($process.HasExited -or $process.StartTime.ToUniversalTime().Ticks -ne $identity.birth -or
        $process.SessionId -ne $identity.session -or
        -not [string]::Equals($process.Path,$identity.image,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Document node process identity changed after admission'
    }
}
function Read-ProvenWebViewChain([int]$NodePid, [Diagnostics.Stopwatch]$BudgetClock, [double]$Seconds, $RetainedHandles = $null) {
    $transferred = $false
    $held = [Collections.Generic.List[object]]::new()
    try {
    $browser = Get-Process -Id $binding.browser_pid -ErrorAction Stop
    $held.Add($browser)
    Assert-DocumentProcessHandle $browser
    if ($browser.HasExited -or $browser.StartTime.ToUniversalTime().Ticks -ne $binding.browser_started_ticks -or
        $browser.SessionId -ne $binding.session_id -or
        [IO.Path]::GetFileName($browser.Path) -ne 'msedgewebview2.exe') { throw 'WebView chain browser identity changed' }
    $chain = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[int]]::new()
    $cursor = $NodePid
      for ($depth=0; $depth -lt 32; $depth++) {
        if ($BudgetClock.Elapsed.TotalSeconds -ge $Seconds) { throw 'Document readiness budget exhausted during descendant verification' }
        if (-not $seen.Add($cursor)) { throw 'WebView process chain contains a cycle' }
        $live = Get-Process -Id $cursor -ErrorAction Stop
        $held.Add($live)
        Assert-DocumentProcessHandle $live
        if ($live.HasExited) { throw 'WebView chain process exited during verification' }
        $matches = @(Get-CimInstance Win32_Process -Filter "ProcessId=$cursor")
        if ($matches.Count -ne 1 -or $matches[0].ProcessId -ne $cursor) { throw 'WebView process chain is missing or ambiguous' }
        $item = $matches[0]
        # Keep the live process handle across CIM sampling. Its uninterrupted
        # lifetime binds PID to this sample without equating API time precision.
        if ($live.HasExited) { throw 'WebView chain process exited during verification' }
        if ($item.CreationDate -isnot [datetime] -or
            $item.SessionId -ne $binding.session_id -or $live.SessionId -ne $binding.session_id -or
            -not [string]::Equals($item.ExecutablePath,$browser.Path,[StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals($live.Path,$browser.Path,[StringComparison]::OrdinalIgnoreCase)) { throw 'WebView process chain identity is unproven' }
        $birth = $live.StartTime.ToUniversalTime().Ticks
        if ($chain.Count -gt 0 -and $birth -gt $chain[$chain.Count-1].birth) { throw 'WebView process parent is younger than its child' }
        $chain.Add(@{pid=$cursor; parent=[int]$item.ParentProcessId; birth=$birth
            cim_birth=$item.CreationDate.ToUniversalTime().Ticks; image=$live.Path; session=$live.SessionId; process=$live})
        if ($cursor -eq $binding.browser_pid) {
            if ($birth -ne $binding.browser_started_ticks -or $chain.Count -lt 2) { throw 'Unknown node is not a new WebView descendant' }
            foreach ($process in $held) { if ($process.HasExited) { throw 'WebView chain process exited during verification' } }
            if ($null -ne $RetainedHandles) {
                foreach ($process in $held) { $RetainedHandles.Add($process) }
                $transferred = $true
            }
            return $chain.ToArray()
        }
        $cursor = [int]$item.ParentProcessId
      }
      throw 'WebView process chain exceeds its bound'
    } finally { if (-not $transferred) { foreach ($process in $held) { $process.Dispose() } } }
}
function Confirm-NewWebViewDescendant([int]$NodePid, [Diagnostics.Stopwatch]$BudgetClock, [double]$Seconds, $RetainedHandles) {
    $null = Assert-Target $true
    $before = @(Read-ProvenWebViewChain $NodePid $BudgetClock $Seconds)
    $null = Assert-Target $true
    $after = @(Read-ProvenWebViewChain $NodePid $BudgetClock $Seconds $RetainedHandles)
    if ($before.Count -ne $after.Count) { throw 'WebView process chain changed during verification' }
    for ($i=0; $i -lt $before.Count; $i++) {
        foreach ($field in @('pid','parent','birth','cim_birth','image','session')) {
            if ($before[$i][$field] -cne $after[$i][$field]) { throw 'WebView process chain changed during verification' }
        }
    }
    $null = Assert-Target $true
    return $after
}

function Wait-TargetDocument([double]$Seconds = 15) {
    $clock = New-DocumentReadinessClock
    $report.document_discarded_samples = 0
    $attempts = [Collections.Generic.List[object]]::new()
    $refreshed = $false
    $admitted = $null
    $held = [Collections.Generic.List[object]]::new()
    $identities = @{}
    try {
    while ($clock.Elapsed.TotalSeconds -lt $Seconds) {
        $report.document_readiness_phase = 'target_guard'
        $null = Assert-Target $true
        if ($null -eq $admitted) {
            $admitted = [Collections.Generic.HashSet[int]]::new()
            foreach ($knownPid in $ownedIds) {
                if ($clock.Elapsed.TotalSeconds -ge $Seconds) { throw 'Document readiness budget exhausted during identity acquisition' }
                $process = Get-Process -Id $knownPid -ErrorAction Stop
                $held.Add($process)
                Assert-DocumentProcessHandle $process
                $identities[[int]$knownPid] = @{process=$process; birth=$process.StartTime.ToUniversalTime().Ticks
                    session=$process.SessionId; image=$process.Path}
                Assert-DocumentNodeIdentity ([int]$knownPid) $identities
                [void]$admitted.Add([int]$knownPid)
            }
            # Sample ancestry while these exact process lifetimes remain held.
            $null = Assert-Target $true
            foreach ($knownPid in $admitted) {
                if (-not $ownedIds.Contains($knownPid)) { throw 'Initial document process ancestry changed' }
                Assert-DocumentNodeIdentity $knownPid $identities
            }
        }
        foreach ($knownPid in $admitted) {
            if (-not $ownedIds.Contains($knownPid)) { throw 'Document process ancestry changed before sampling' }
            Assert-DocumentNodeIdentity $knownPid $identities
        }
        $report.document_readiness_phase = 'read_tree'
        if ($clock.Elapsed.TotalSeconds -ge $Seconds) { break }
        $tree = Read-TargetTree -ReportUnknownProcess -AdmittedIds $admitted -LiveIdentities $identities
        if ($null -ne $tree -and $tree.GetType() -eq [Windows.Automation.ElementNotAvailableException]) {
            $report.document_discarded_samples++
            if ($clock.Elapsed.TotalSeconds -ge $Seconds) { break }
            $report.document_readiness_phase = 'discard_unavailable_sample'
            Pause-Probe
            # Keep held lifetimes, admitted IDs, proof allowance and clock intact.
            continue
        }
        if ($tree -is [int]) {
            if ($refreshed) { throw 'UIA node belongs to an unbound process after one verified refresh' }
            if ($clock.Elapsed.TotalSeconds -ge $Seconds) { break }
            $refreshed = $true
            $report.document_readiness_phase = 'verify_new_descendant'
            $proven = @(Confirm-NewWebViewDescendant $tree $clock $Seconds $held)
            foreach ($identity in $proven) {
                $identities[[int]$identity.pid] = $identity
                [void]$admitted.Add([int]$identity.pid)
            }
            $report.document_descendant_refresh = 'verified_discard_and_rescan'
            # No partial rows survive. The next iteration revalidates and starts at HWND.
            continue
        }
        if ($clock.Elapsed.TotalSeconds -ge $Seconds) { break }
        foreach ($knownPid in $admitted) { Assert-DocumentNodeIdentity $knownPid $identities }
        if ($clock.Elapsed.TotalSeconds -ge $Seconds) { break }
        $report.accessibility_tree = $tree
        $report.document_readiness_phase = 'record_tree'
        $attempts.Add(@{ document_count=$tree.document_count; focusable_count=$tree.focusable_count
            unknown_control_type_count=$tree.unknown_control_type_count
            unknown_keyboard_focusable_count=$tree.unknown_keyboard_focusable_count; unknown_offscreen_count=$tree.unknown_offscreen_count
            traversal_complete=$tree.traversal_complete; truncation_reasons=$tree.truncation_reasons; elapsed_ms=$tree.elapsed_ms })
        $report.document_readiness = @{ attempts=@($attempts.ToArray()); budget_seconds=$Seconds
            elapsed_ms=$clock.ElapsedMilliseconds; ready=$false }
        if ($tree.traversal_complete -eq $true -and @($tree.truncation_reasons).Count -eq 0 -and
            $tree.document_count -ge 1 -and $tree.focusable_count -ge 1) {
            $report.document_readiness.ready = $true
            $report.document_readiness_phase = 'ready'
            return
        }
        $report.document_readiness_phase = 'wait_document'
        Pause-Probe
    }
    $report.document_readiness_phase = 'budget_exhausted'
    throw 'Original WebView UIA Document/focusable controls not observed within readiness budget; inspect traversal truncation reasons'
    } finally { foreach ($process in $held) { $process.Dispose() } }
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
function Find-OfflineControl([string]$Type, [string]$Name, [double]$Seconds = 10, [switch]$AllowAbsent, [switch]$ObserveStartStopSelector) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    if ($ObserveStartStopSelector) {
        # Historical selector observations only, never an acceptance condition.
        $report.offline.runtime_start_stop_selector = @{state='unobservable';complete_samples=0}
    }
    do {
        if ($ObserveStartStopSelector) {
            $report.offline.runtime_start_stop_selector.state='unobservable'
            $selectorMatches=0; $lastSelectorEnabled=$null; $selectorFieldsUnknown=$false
        }
        $null = Assert-Target $true
        $window = Get-OfflineReplacementRoot
        $walker = Get-OfflineReplacementWalker
        $queue = [Collections.Generic.Queue[object]]::new()
        $queue.Enqueue(@{element=$window; depth=0; document=$false})
        $found = [Collections.Generic.List[object]]::new(); $visited = 0
        $walk = [Diagnostics.Stopwatch]::StartNew()
        while ($queue.Count -and $visited -lt 512 -and $walk.Elapsed.TotalSeconds -lt 5) {
            $next = $queue.Dequeue(); $visited++; $current = $next.element.Current
            # Cache each original getter independently at its original short-circuit point.
            # Never merge the repeated ControlType reads or add diagnostic UIA reads.
            $unread=[object]::new()
            $selectorPid=$unread
            if (-not $ownedIds.Contains([int]($selectorPid=$current.ProcessId))) {
                $foreignType=$unread; $foreignTypeName=$unread; $foreignName=$unread
                $report.offline.foreign_node_matches_selector = (($foreignTypeName=($foreignType=$current.ControlType).ProgrammaticName) -eq $Type -and ($foreignName=$current.Name) -match $Name)
                if ($ObserveStartStopSelector) {
                    if ($null -eq $current -or $selectorPid -isnot [int] -or $selectorPid -le 0 -or
                        $foreignType -isnot [Windows.Automation.ControlType] -or $foreignTypeName -isnot [string] -or
                        (-not [object]::ReferenceEquals($foreignName,$unread) -and $foreignName -isnot [string])) { $selectorFieldsUnknown=$true }
                }
                if ($report.offline.foreign_node_matches_selector) { throw 'Offline UIA node escaped the bound process tree' }
                continue
            }
            $documentType=$unread
            $document = $next.document -or ($documentType=$current.ControlType) -eq [Windows.Automation.ControlType]::Document
            $matchType=$unread; $matchTypeName=$unread; $matchName=$unread; $selectorEnabled=$unread
            # Only a selector match is retained. Never serialize arbitrary UIA names or values:
            # the normal key-generation dialog contains recovery material.
            if ($document -and ($matchTypeName=($matchType=$current.ControlType).ProgrammaticName) -eq $Type -and
                ($matchName=$current.Name) -match $Name) {
                if ($ObserveStartStopSelector) { $selectorMatches++ }
                # Cache the original short-circuit getter; retain its original truthiness.
                if ($AllowAbsent -or ($selectorEnabled=$current.IsEnabled)) { $found.Add($next.element) }
                if ($ObserveStartStopSelector) { $lastSelectorEnabled=$selectorEnabled }
            }
            if ($ObserveStartStopSelector) {
                if ($null -eq $current -or $selectorPid -isnot [int] -or $selectorPid -le 0 -or
                    (-not [object]::ReferenceEquals($documentType,$unread) -and $documentType -isnot [Windows.Automation.ControlType]) -or
                    (-not [object]::ReferenceEquals($matchType,$unread) -and $matchType -isnot [Windows.Automation.ControlType]) -or
                    (-not [object]::ReferenceEquals($matchTypeName,$unread) -and $matchTypeName -isnot [string]) -or
                    (-not [object]::ReferenceEquals($matchName,$unread) -and $matchName -isnot [string]) -or
                    (-not [object]::ReferenceEquals($selectorEnabled,$unread) -and $selectorEnabled -isnot [bool])) { $selectorFieldsUnknown=$true }
            }
            if ($next.depth -lt 32) {
                $child = $walker.GetFirstChild($next.element)
                while ($child -and $visited + $queue.Count -lt 512 -and $walk.Elapsed.TotalSeconds -lt 5) {
                    $queue.Enqueue(@{element=$child; depth=$next.depth+1; document=$document})
                    $child = $walker.GetNextSibling($child)
                }
                if ($child) { throw 'Offline selector traversal truncated before uniqueness could be established' }
            } elseif ($walker.GetFirstChild($next.element)) {
                throw 'Offline selector depth limit prevents uniqueness verification'
            }
        }
        if ($queue.Count) { throw 'Offline selector traversal exceeded its node/time bound' }
        if ($ObserveStartStopSelector) {
            $diagnostic=$report.offline.runtime_start_stop_selector
            # Saturates: counts complete samples, not application poll completions.
            if ($diagnostic.complete_samples -lt 256) { $diagnostic.complete_samples++ }
            if ($selectorFieldsUnknown) { $diagnostic.state='unobservable' }
            elseif ($selectorMatches -eq 0) { $diagnostic.state='absent' }
            elseif ($selectorMatches -gt 1) { $diagnostic.state='ambiguous' }
            elseif ($lastSelectorEnabled -is [bool]) {
                if ($lastSelectorEnabled) { $diagnostic.state='enabled' } else { $diagnostic.state='disabled' }
            }
        }
        if ($found.Count -gt 1) { throw 'Offline selector is ambiguous' }
        if ($found.Count -eq 1) { return $found[0] }
        if ($AllowAbsent) { return $null }
        Pause-Probe
    } while ($clock.Elapsed.TotalSeconds -lt $Seconds)
    throw "Expected offline control unavailable: $Type / $Name"
}

function Focus-OfflineControl($Element, [ref]$MismatchEvidence) {
    if ($null -ne $MismatchEvidence) { $MismatchEvidence.Value = $null }
    $diagnostic = @{phase='target_before'; kind='pending'}
    $report.offline.focus_diagnostic = $diagnostic
    try {
        $null = Assert-Target $true
        $diagnostic.phase = 'expected_id'
        $expected = $Element.GetRuntimeId() -join '.'
        $diagnostic.phase = 'set_focus'
        $Element.SetFocus()
        $focusClock = [Diagnostics.Stopwatch]::StartNew()
        $diagnostic.phase = 'target_after'
        $null = Assert-Target $true
        $diagnostic.phase = 'read_focus'
        $focus = Read-TargetFocus
        $diagnostic.phase = 'match_focus'
        $diagnostic.after_focus_ms = [Math]::Round($focusClock.Elapsed.TotalMilliseconds)
        if ($expected -cmatch '\A-?[0-9]+(?:\.-?[0-9]+)*\z' -and
            $focus.runtime_id -is [string] -and $focus.runtime_id -cmatch '\A-?[0-9]+(?:\.-?[0-9]+)*\z') {
            $diagnostic.runtime_ids = @{expected=$expected;actual=$focus.runtime_id}
        }
        $diagnostic.observed = @{belongs_to_target=[bool]$focus.belongs_to_target
            in_document=[bool]$focus.in_document; expected_id_match=($focus.runtime_id -eq $expected)
            offscreen=[bool]$focus.offscreen}
        if (-not $focus.belongs_to_target -or -not $focus.in_document -or $focus.runtime_id -ne $expected -or $focus.offscreen) {
            $diagnostic.kind = 'focus_mismatch'
            if ($null -ne $MismatchEvidence -and $expected -and
                $focus.belongs_to_target -is [bool] -and $focus.belongs_to_target -and
                $focus.in_document -is [bool] -and $focus.in_document -and
                $focus.offscreen -is [bool] -and -not $focus.offscreen -and $focus.runtime_id -ne $expected) {
                # Private evidence only; never include RuntimeIds in the report.
                $MismatchEvidence.Value = @{original_id=$expected}
            }
            $detail = @{requested_id_available=$false; requested_id_matches_original=$false
                requested_focus_available=$false; requested_has_keyboard_focus=$false
                focused_type_available=$false; focused_is_button=$false}
            $diagnostic.mismatch_detail = $detail
            # Independent best-effort observations never replace the primary failure
            # or turn a mismatch into a retryable stale/disabled exception.
            try {
                $requestedId = @($Element.GetRuntimeId())
                if ($requestedId.Count -gt 0 -and @($requestedId | Where-Object { $_ -isnot [int] }).Count -eq 0) {
                    $detail.requested_id_available = $true
                    $detail.requested_id_matches_original = (($requestedId -join '.') -ceq $expected)
                }
            } catch {}
            try {
                $requestedFocus = $Element.Current.HasKeyboardFocus
                if ($requestedFocus -is [bool]) {
                    $detail.requested_focus_available = $true
                    $detail.requested_has_keyboard_focus = $requestedFocus
                }
            } catch {}
            try {
                $focusedType = $focus.control_type
                if ($focusedType -is [string] -and $focusedType.Length -gt 0) {
                    $detail.focused_type_available = $true
                    $detail.focused_is_button = ($focusedType -ceq 'ControlType.Button')
                }
            } catch {}
            throw 'Offline control did not receive real target-document keyboard focus'
        }
        $diagnostic.kind = 'verified'
    } catch {
        # Closed categories only. Preserve the original exception for the existing
        # stale/disabled retry policy, never serialize its message or UI properties.
        if ($diagnostic.kind -ne 'focus_mismatch') {
            $diagnostic.kind = 'other_exception'
            $current = $_.Exception
            for ($depth=0; $current -and $depth -lt 4; $depth++) {
                if ($current -is [Windows.Automation.ElementNotAvailableException]) { $diagnostic.kind='stale'; break }
                if ($current -is [Windows.Automation.ElementNotEnabledException]) { $diagnostic.kind='disabled'; break }
                $current = $current.InnerException
            }
        }
        throw
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
function Get-OfflineReplacementRoot {
    return [Windows.Automation.AutomationElement]::FromHandle([IntPtr][long]$binding.hwnd)
}
function Get-OfflineReplacementWalker { return [Windows.Automation.TreeWalker]::ControlViewWalker }
function Test-OfflineButtonReplacement([string]$Name, [string]$OriginalId, $AttemptClock, [double]$Seconds = 10) {
    if (-not $OriginalId -or $AttemptClock.Elapsed.TotalSeconds -ge $Seconds) { return $false }
    $null = Assert-Target $true
    if ($AttemptClock.Elapsed.TotalSeconds -ge $Seconds) { return $false }
    $held = [Collections.Generic.List[object]]::new()
    $identities = @{}
    $walk = [Diagnostics.Stopwatch]::StartNew()
    try {
    $ids = [Collections.Generic.HashSet[int]]::new()
    foreach ($knownPid in $ownedIds) {
        if ($walk.Elapsed.TotalSeconds -ge 5 -or $AttemptClock.Elapsed.TotalSeconds -ge $Seconds) { return $false }
        $process = Get-Process -Id $knownPid -ErrorAction Stop
        $held.Add($process)
        Assert-DocumentProcessHandle $process
        $identities[[int]$knownPid] = @{process=$process; birth=$process.StartTime.ToUniversalTime().Ticks
            session=$process.SessionId; image=$process.Path}
        [void]$ids.Add([int]$knownPid)
    }
    # Ancestry is resampled while these exact process lifetimes remain held.
    $null = Assert-Target $true
    foreach ($knownPid in $ids) {
        if (-not $ownedIds.Contains($knownPid)) { return $false }
        Assert-DocumentNodeIdentity $knownPid $identities
    }
    if ($walk.Elapsed.TotalSeconds -ge 5 -or $AttemptClock.Elapsed.TotalSeconds -ge $Seconds) { return $false }
    $window = Get-OfflineReplacementRoot
    $walker = Get-OfflineReplacementWalker
    $queue = [Collections.Generic.Queue[object]]::new()
    $queue.Enqueue(@{element=$window; depth=0; document=$false})
    $visited = 0; $candidate = $null; $candidateId = ''; $replacementMatchCount = 0
    while ($queue.Count -gt 0) {
        if ($visited -ge 512 -or $walk.Elapsed.TotalSeconds -ge 5 -or $AttemptClock.Elapsed.TotalSeconds -ge $Seconds) { return $false }
        $next = $queue.Dequeue(); $visited++
        $current = $next.element.Current
        # Foreign processes fail before any Name or other diagnostic value is read.
        if (-not $ids.Contains([int]$current.ProcessId)) { return $false }
        Assert-DocumentNodeIdentity ([int]$current.ProcessId) $identities
        $runtimeParts = @($next.element.GetRuntimeId())
        if ($runtimeParts.Count -eq 0 -or @($runtimeParts | Where-Object { $_ -isnot [int] }).Count -gt 0) { return $false }
        $runtimeId = $runtimeParts -join '.'
        if ($runtimeId -ceq $OriginalId) { return $false }
        $controlType = $current.ControlType
        if ($controlType -isnot [Windows.Automation.ControlType]) { return $false }
        $document = $next.document -or $controlType -eq [Windows.Automation.ControlType]::Document
        $matchesName = $false
        if ($document -and $controlType -eq [Windows.Automation.ControlType]::Button) {
            $nodeName = $current.Name
            if ($nodeName -isnot [string]) { return $false }
            $matchesName = $nodeName -match $Name
        }
        # Disabled/hidden matches still count: they must not hide ambiguity.
        if ($matchesName) {
            $replacementMatchCount++
            if ($replacementMatchCount -gt 1) { return $false }
            $candidate = $next.element; $candidateId = $runtimeId
        }
        $child = $walker.GetFirstChild($next.element)
        if ($child -and $next.depth -ge 32) { return $false }
        while ($child) {
            if ($visited + $queue.Count -ge 512 -or $walk.Elapsed.TotalSeconds -ge 5 -or $AttemptClock.Elapsed.TotalSeconds -ge $Seconds) { return $false }
            $queue.Enqueue(@{element=$child; depth=$next.depth+1; document=$document})
            $child = $walker.GetNextSibling($child)
        }
    }
    if ($replacementMatchCount -ne 1 -or $candidateId -ceq $OriginalId -or
        $walk.Elapsed.TotalSeconds -ge 5 -or $AttemptClock.Elapsed.TotalSeconds -ge $Seconds) { return $false }
    $null = Assert-Target $true
    foreach ($knownPid in $ids) {
        if (-not $ownedIds.Contains($knownPid)) { return $false }
        Assert-DocumentNodeIdentity $knownPid $identities
    }
    $current = $candidate.Current
    if (-not $ids.Contains([int]$current.ProcessId) -or -not $ownedIds.Contains([int]$current.ProcessId)) { return $false }
    Assert-DocumentNodeIdentity ([int]$current.ProcessId) $identities
    $controlType = $current.ControlType
    if ($controlType -isnot [Windows.Automation.ControlType] -or $controlType -ne [Windows.Automation.ControlType]::Button) { return $false }
    $nodeName = $current.Name
    if ($nodeName -isnot [string]) { return $false }
    $enabled=$current.IsEnabled; $focusable=$current.IsKeyboardFocusable; $offscreen=$current.IsOffscreen
    if (($candidate.GetRuntimeId() -join '.') -cne $candidateId -or
        $nodeName -notmatch $Name -or
        $enabled -isnot [bool] -or -not $enabled -or
        $focusable -isnot [bool] -or -not $focusable -or
        $offscreen -isnot [bool] -or $offscreen) { return $false }
    foreach ($knownPid in $ids) { Assert-DocumentNodeIdentity $knownPid $identities }
    return ($walk.Elapsed.TotalSeconds -lt 5 -and $AttemptClock.Elapsed.TotalSeconds -lt $Seconds)
    } finally { foreach ($process in $held) { $process.Dispose() } }
}
function Find-FocusedOfflineButton([string]$Name, [switch]$PrepareInvoke, [ValidateSet('normal_stop')][string]$DiagnosticStage) {
    if ($PrepareInvoke) { $report.offline.final_preparation_history = @() }
    $diagnosticArgs = @{}
    if ($DiagnosticStage) { $diagnosticArgs.DiagnosticStage = $DiagnosticStage }
    $scrollAttempts = 0
    for ($attempt=0; $attempt -lt 5; $attempt++) {
        $attemptClock = [Diagnostics.Stopwatch]::StartNew()
        $mismatchEvidence = $null
        $preparingInvoke = $false
        $preparationTimedOut = $false
        if ($PrepareInvoke) {
            $report.offline.preinvoke_identity = $null
            $report.offline.final_preparation = @{route='bounded_attempt';attempt=($attempt+1);kind='not_reached';proof='not_eligible'}
            $report.offline.final_preparation_history = @($report.offline.final_preparation_history) + @($report.offline.final_preparation)
        }
        if ($DiagnosticStage) { $report.offline.action_stage = 'normal_stop_select' }
        $report.offline.focus_diagnostic = $null
        $null = Assert-Target $true
        # Selector traversal still proves ownership and uniqueness. Selector errors,
        # including ambiguity, are deliberately outside the retry handler.
        $remaining = 10 - $attemptClock.Elapsed.TotalSeconds
        if ($remaining -le 0) { throw 'Offline button focus failed without a retryable UIA readiness condition' }
        $element = Find-OfflineControl 'ControlType.Button' $Name $remaining
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
            $invocation = $null
            if ($PrepareInvoke) {
                # A stale initial identity uses the existing focus retry path;
                # pattern acquisition and final preparation remain fail-closed.
                if ($DiagnosticStage) { $report.offline.action_stage = 'normal_stop_pattern' }
                $runtimeParts = @($element.GetRuntimeId())
                $preparingInvoke = $true
                if ($attemptClock.Elapsed.TotalSeconds -ge 10) { $preparationTimedOut=$true; throw 'Offline button preparation exceeded its existing attempt budget' }
                # Acquire the pattern and its full guard before establishing focus:
                # overview refreshes replace buttons while these UIA/CIM reads run.
                $invocation = Get-OfflineButtonInvoke $element @diagnosticArgs -RuntimeParts $runtimeParts
                if ($attemptClock.Elapsed.TotalSeconds -ge 10) { $preparationTimedOut=$true; throw 'Offline button preparation exceeded its existing attempt budget' }
                $preparingInvoke = $false
            }
            Focus-OfflineControl $element ([ref]$mismatchEvidence)
            if ($PrepareInvoke) {
                # Continue this same attempt, never start a second retry budget.
                $preparingInvoke = $true
                $mismatchEvidence = $null
                if ($attemptClock.Elapsed.TotalSeconds -ge 10) { $preparationTimedOut=$true; throw 'Offline button preparation exceeded its existing attempt budget' }
                $prepared = Prepare-OfflineButtonInvoke $element ([ref]$mismatchEvidence) -Invocation $invocation @diagnosticArgs
                if ($attemptClock.Elapsed.TotalSeconds -ge 10) { $preparationTimedOut=$true; throw 'Offline button preparation exceeded its existing attempt budget' }
                return $prepared
            }
            return $element
        } catch {
            $primaryException = $_.Exception
            # Mirror the original short-circuit budget checks exactly once.
            $canProve = $false
            if ($null -ne $mismatchEvidence) {
                if ($attempt -lt 4) {
                    if ($attemptClock.Elapsed.TotalSeconds -lt 10) { $canProve=$true }
                    elseif ($preparingInvoke) { $report.offline.final_preparation.proof='budget_exhausted' }
                } elseif ($preparingInvoke) { $report.offline.final_preparation.proof='attempts_exhausted' }
            }
            if ($preparingInvoke -and $preparationTimedOut) { $report.offline.final_preparation.proof='budget_exhausted' }
            if ($canProve) {
                $replacement = $false
                if ($preparingInvoke) { $report.offline.final_preparation.proof='false' }
                try { $replacement = Test-OfflineButtonReplacement $Name $mismatchEvidence.original_id $attemptClock 10 } catch {
                    if ($preparingInvoke) { $report.offline.final_preparation.proof='exception' }
                }
                if ($replacement -is [bool] -and $replacement) {
                    if ($preparingInvoke) { $report.offline.final_preparation.proof='verified' }
                    # No effect was dispatched. Consume this existing attempt and
                    # reacquire through the ordinary full selector on the next one.
                    continue
                }
            }
            # Preparation is not a generic stale/disabled retry region. Only the
            # complete replacement proof above can consume another attempt.
            if ($preparingInvoke) { throw $primaryException }
            if (-not (Test-OfflineFocusRetryable $primaryException)) {
                throw 'Offline button focus failed without a retryable UIA readiness condition'
            }
        }
        Pause-Probe
    }
    throw 'Offline button did not become focus-ready within the bounded attempts'
}
function Send-OfflineKey([int]$Key, [string]$ExpectedRuntimeId = '', [switch]$RecoveryDismiss) {
    if ($RecoveryDismiss) { $report.offline.recovery_dismiss_detail = 'before_guard' }
    $null = Assert-Target $true
    if ($RecoveryDismiss) { $report.offline.recovery_dismiss_detail = 'before_focus' }
    $focus = Read-TargetFocus
    if (-not $focus.belongs_to_target -or -not $focus.in_document -or $focus.offscreen) { throw 'Offline input focus escaped the original visible document' }
    if ($ExpectedRuntimeId -and $focus.runtime_id -ne $ExpectedRuntimeId) { throw 'Offline button focus changed before key dispatch' }
    if ($RecoveryDismiss) { $report.offline.recovery_dismiss_detail = 'escape_send' }
    if ([RespireNativeInput]::Key([IntPtr][long]$binding.hwnd, [uint16]$Key) -ne 2) { throw 'Offline SendInput key was rejected' }
    if ($RecoveryDismiss) { $report.offline.recovery_dismiss_detail = 'after_guard' }
    $null = Assert-Target $true
}
function New-AccountStabilityClock { return [Diagnostics.Stopwatch]::StartNew() }
function Pause-AccountStability { Start-Sleep -Milliseconds 100 }
function New-AccountStabilityPidDiagnostic($RawPid, $HeldMember, $Depth, $AncestorDocument, $Snapshot) {
    # Existing failed sample only: no provider reads, coercion, identity admission or retries.
    $kind='non_int'
    if ($null -eq $RawPid) { $kind='null' }
    elseif ($RawPid -is [int]) {
        if ($RawPid -le 0) { $kind='nonpositive' } else { $kind='positive_not_in_tree' }
    }
    $value=@{pid_kind=$kind;held_member='unknown';depth='unknown';ancestor_document='unknown';in_same_snapshot='unknown'}
    if ($HeldMember -is [bool]) { $value.held_member=$HeldMember }
    if ($Depth -is [int] -and $Depth -ge 0 -and $Depth -le 32) { $value.depth=$Depth }
    if ($AncestorDocument -is [bool]) { $value.ancestor_document=$AncestorDocument }
    # Inspect only the already captured local CIM objects, and only after rejection.
    # Absent from this snapshot does not establish a legitimate descendant race.
    if ($RawPid -is [int] -and $RawPid -gt 0 -and $Snapshot -is [array]) {
        try {
            $present=$false; $complete=$true
            foreach ($item in $Snapshot) {
                $snapshotPid=$item.ProcessId
                if (($snapshotPid -isnot [int] -and $snapshotPid -isnot [uint32]) -or $snapshotPid -lt 0) { $complete=$false; continue }
                if ($snapshotPid -eq $RawPid) { $present=$true }
            }
            if ($complete) { $value.in_same_snapshot=$present }
        } catch { $value.in_same_snapshot='unknown' }
    }
    return $value
}
function Read-AccountStabilityButton([string]$Name, $Identities, $WindowClock) {
    $null=Assert-Target $true
    $window=Get-OfflineReplacementRoot; $walker=Get-OfflineReplacementWalker
    $walk=[Diagnostics.Stopwatch]::StartNew()
    $queue=[Collections.Generic.Queue[object]]::new(); $queue.Enqueue(@{element=$window;depth=0;document=$false})
    $visited=0; $found=$null; $foundId=''; $buttonCount=0
    while ($queue.Count -gt 0) {
        if ($visited -ge 512 -or $walk.Elapsed.TotalSeconds -ge 5 -or $WindowClock.Elapsed.TotalSeconds -ge 15) { throw 'Candidate stability traversal exceeded its bound' }
        $next=$queue.Dequeue(); $visited++
        $current=$next.element.Current; $rawNodePid=$null; $nodePid=[int]($rawNodePid=$current.ProcessId)
        if (-not $ownedIds.Contains($nodePid)) {
            $report.offline.account_stability_pid=New-AccountStabilityPidDiagnostic $rawNodePid ($Identities.ContainsKey($nodePid)) $next.depth $next.document $script:candidateProcessSnapshot
            throw 'Candidate stability process left the bound tree'
        }
        Assert-DocumentNodeIdentity $nodePid $Identities
        $type=$current.ControlType
        if ($type -isnot [Windows.Automation.ControlType]) { throw 'Candidate stability control type unavailable' }
        $document=$next.document -or $type -eq [Windows.Automation.ControlType]::Document
        if ($document -and $type -eq [Windows.Automation.ControlType]::Button) {
            $nodeName=$current.Name
            if ($nodeName -isnot [string]) { throw 'Candidate stability button name unavailable' }
            if ($nodeName -match $Name) {
                $buttonCount++
                if ($buttonCount -gt 1) { throw 'Candidate stability selector is ambiguous' }
                $parts=@($next.element.GetRuntimeId())
                if ($parts.Count -eq 0 -or @($parts | Where-Object { $_ -isnot [int] }).Count -gt 0) { throw 'Candidate stability RuntimeId unavailable' }
                $enabled=$current.IsEnabled; $focusable=$current.IsKeyboardFocusable; $offscreen=$current.IsOffscreen
                if ($enabled -isnot [bool] -or -not $enabled -or
                    $focusable -isnot [bool] -or -not $focusable -or
                    $offscreen -isnot [bool] -or $offscreen) { throw 'Candidate stability button is not focus-ready' }
                $found=$next.element; $foundId=$parts -join '.'
            }
        }
        $child=$walker.GetFirstChild($next.element)
        if ($child -and $next.depth -ge 32) { throw 'Candidate stability depth bound reached' }
        while ($child) {
            if ($visited+$queue.Count -ge 512 -or $walk.Elapsed.TotalSeconds -ge 5 -or $WindowClock.Elapsed.TotalSeconds -ge 15) { throw 'Candidate stability traversal exceeded its bound' }
            $queue.Enqueue(@{element=$child;depth=$next.depth+1;document=$document})
            $child=$walker.GetNextSibling($child)
        }
    }
    if ($buttonCount -ne 1 -or $walk.Elapsed.TotalSeconds -ge 5 -or $WindowClock.Elapsed.TotalSeconds -ge 15) { throw 'Candidate stability unique button unavailable' }
    foreach ($id in $Identities.Keys) { Assert-DocumentNodeIdentity ([int]$id) $Identities }
    return @{element=$found;runtime_id=$foundId}
}
function Get-AccountStabilityFocusedElement { return [Windows.Automation.AutomationElement]::FocusedElement }
function Get-AccountStabilityRawWalker { return [Windows.Automation.TreeWalker]::RawViewWalker }
function Read-AccountStabilityFocus($Identities, $WindowClock) {
    if ($WindowClock.Elapsed.TotalSeconds -ge 15) { throw 'Candidate stability focus observation exceeded its bound' }
    $null=Assert-Target $true
    $window=Get-OfflineReplacementRoot
    $rootPid=[int]$window.Current.ProcessId
    if (-not $ownedIds.Contains($rootPid)) { throw 'Candidate stability root is foreign' }
    Assert-DocumentNodeIdentity $rootPid $Identities
    $rootParts=@($window.GetRuntimeId())
    if ($rootParts.Count -eq 0 -or @($rootParts | Where-Object { $_ -isnot [int] }).Count -gt 0) { throw 'Candidate stability root identity unavailable' }
    $rootId=$rootParts -join '.'
    $element=Get-AccountStabilityFocusedElement
    if ($null -eq $element) { throw 'Candidate stability has no focused element' }
    $walker=Get-AccountStabilityRawWalker
    $focusedId=''; $offscreen=$null; $inDocument=$false; $belongs=$false
    for ($depth=0; $null -ne $element -and $depth -lt 32; $depth++) {
        if ($WindowClock.Elapsed.TotalSeconds -ge 15) { throw 'Candidate stability focus observation exceeded its bound' }
        # Only PID is read before the held lifetime is verified. No Name, Value,
        # AutomationId or ClassName is read anywhere in this focus observer.
        $current=$element.Current; $nodePid=[int]$current.ProcessId
        if (-not $ownedIds.Contains($nodePid)) { throw 'Candidate stability focused ancestry is foreign' }
        Assert-DocumentNodeIdentity $nodePid $Identities
        $parts=@($element.GetRuntimeId())
        if ($parts.Count -eq 0 -or @($parts | Where-Object { $_ -isnot [int] }).Count -gt 0) { throw 'Candidate stability focused identity unavailable' }
        $id=$parts -join '.'
        if ($depth -eq 0) {
            $focusedId=$id; $offscreen=$current.IsOffscreen
            if ($offscreen -isnot [bool]) { throw 'Candidate stability focused visibility unavailable' }
        }
        $type=$current.ControlType
        if ($type -isnot [Windows.Automation.ControlType]) { throw 'Candidate stability focused control type unavailable' }
        if ($type -eq [Windows.Automation.ControlType]::Document) { $inDocument=$true }
        if ($id -ceq $rootId) { $belongs=$true; break }
        $element=$walker.GetParent($element)
    }
    if (-not $belongs -or -not $inDocument) { throw 'Candidate stability focus is outside the original document' }
    foreach ($id in $Identities.Keys) { Assert-DocumentNodeIdentity ([int]$id) $Identities }
    if ($WindowClock.Elapsed.TotalSeconds -ge 15) { throw 'Candidate stability focus observation exceeded its bound' }
    return @{runtime_id=$focusedId;belongs_to_target=$belongs;in_document=$inDocument;offscreen=$offscreen}
}
function Assert-AccountFocusStable($Element, [string]$Name) {
    $observation=@{status='observing';requested_seconds=10;completed_poll_count='not-observed';observations=0
        scope='source-candidate timed UI stability only';pending_error_cancel='not-evaluated'}
    $report.offline.account_focus_stability=$observation
    $parts=@($Element.GetRuntimeId())
    if ($parts.Count -eq 0 -or @($parts | Where-Object { $_ -isnot [int] }).Count -gt 0) { throw 'Candidate initial RuntimeId unavailable' }
    $expected=$parts -join '.'
    $clock=New-AccountStabilityClock
    $observedStart=$null
    $held=[Collections.Generic.List[object]]::new(); $identities=@{}
    try {
        $null=Assert-Target $true
        foreach ($id in $ownedIds) {
            if ($clock.Elapsed.TotalSeconds -ge 15) { throw 'Candidate stability identity acquisition exceeded its bound' }
            $process=Get-Process -Id $id -ErrorAction Stop; $held.Add($process)
            Assert-DocumentProcessHandle $process
            $identities[[int]$id]=@{process=$process;birth=$process.StartTime.ToUniversalTime().Ticks;session=$process.SessionId;image=$process.Path}
        }
        $null=Assert-Target $true
        foreach ($id in $identities.Keys) {
            if (-not $ownedIds.Contains([int]$id)) { throw 'Candidate stability initial ancestry changed' }
            Assert-DocumentNodeIdentity ([int]$id) $identities
        }
        do {
            $button=Read-AccountStabilityButton $Name $identities $clock
            if ($button.runtime_id -cne $expected) { throw 'Candidate account button was replaced during stability window' }
            $null=Assert-Target $true
            $focus=Read-AccountStabilityFocus $identities $clock
            if ($focus.belongs_to_target -isnot [bool] -or -not $focus.belongs_to_target -or
                $focus.in_document -isnot [bool] -or -not $focus.in_document -or
                $focus.offscreen -isnot [bool] -or $focus.offscreen -or $focus.runtime_id -cne $expected) { throw 'Candidate account focus changed during stability window' }
            foreach ($id in $identities.Keys) { Assert-DocumentNodeIdentity ([int]$id) $identities }
            if ($clock.Elapsed.TotalSeconds -ge 15) { throw 'Candidate stability observation exceeded its bound' }
            if ($null -eq $observedStart) { $observedStart=$clock.Elapsed.TotalSeconds }
            $observation.observations++
            if ($clock.Elapsed.TotalSeconds-$observedStart -ge 10) { break }
            Pause-AccountStability
        } while ($true)
        $observation.status='timed-window-passed'; $observation.elapsed_ms=$clock.Elapsed.TotalMilliseconds
        $observation.observed_window_ms=($clock.Elapsed.TotalSeconds-$observedStart)*1000
    } finally { foreach ($process in $held) { $process.Dispose() } }
}
function Get-OfflineButtonInvoke($Element, [ValidateSet('normal_stop')][string]$DiagnosticStage, $RuntimeParts = $null) {
    $report.offline.preinvoke_identity = $null
    $report.offline.final_preparation.kind='unknown'
    $report.offline.final_preparation.proof='not_eligible'
    if ($DiagnosticStage) { $report.offline.action_stage = 'normal_stop_pattern' }
    if (-not $PSBoundParameters.ContainsKey('RuntimeParts')) { $RuntimeParts = @($Element.GetRuntimeId()) }
    $pattern = $null
    if (-not $Element.TryGetCurrentPattern([Windows.Automation.InvokePattern]::Pattern, [ref]$pattern)) {
        throw 'Offline button does not support the normal UIA Invoke action'
    }
    if ($DiagnosticStage) { $report.offline.action_stage = 'normal_stop_focus_guard' }
    $null = Assert-Target $true
    return @{element=$Element;parts=$RuntimeParts;pattern=$pattern}
}
function Prepare-OfflineButtonInvoke($Element, [ref]$MismatchEvidence, [ValidateSet('normal_stop')][string]$DiagnosticStage, $Invocation = $null) {
    $MismatchEvidence.Value = $null
    if ($null -eq $report.offline.final_preparation) {
        $report.offline.final_preparation = @{route='bounded_attempt';attempt=0;kind='not_reached';proof='not_eligible'}
    }
    $report.offline.final_preparation.kind='unknown'
    $report.offline.final_preparation.proof='not_eligible'
    $preparationClock = [Diagnostics.Stopwatch]::StartNew()
    if ($null -eq $Invocation) {
        # Source-candidate stability keeps its already established focus window.
        $diagnosticArgs = @{}
        if ($DiagnosticStage) { $diagnosticArgs.DiagnosticStage = $DiagnosticStage }
        $Invocation = Get-OfflineButtonInvoke $Element @diagnosticArgs
    }
    $parts = @($Invocation.parts)
    $expected = $parts -join '.'
    $pattern = $Invocation.pattern
    $focus = Read-TargetFocus
    # Read each observation exactly once: PS5 may suppress a failing property
    # getter to null. Missing, unknown or malformed observations fail closed.
    $belongs = $focus.belongs_to_target
    $inDocument = $focus.in_document
    $offscreen = $focus.offscreen
    $focusedId = $focus.runtime_id
    if ($belongs -isnot [bool] -or $inDocument -isnot [bool] -or $offscreen -isnot [bool] -or
        $focusedId -isnot [string] -or $focusedId -cnotmatch '\A-?[0-9]+(?:\.-?[0-9]+)*\z' -or
        $parts.Count -eq 0 -or @($parts | Where-Object { $_ -isnot [int] }).Count -gt 0) {
        if ($belongs -isnot [bool] -or $inDocument -isnot [bool] -or $offscreen -isnot [bool]) {
            $report.offline.final_preparation.kind='invalid_focus_fields'
        } elseif ($focusedId -isnot [string] -or $focusedId -cnotmatch '\A-?[0-9]+(?:\.-?[0-9]+)*\z') {
            $report.offline.final_preparation.kind='invalid_focused_id'
        } else { $report.offline.final_preparation.kind='invalid_requested_id' }
        throw 'Offline button focus changed before UIA Invoke'
    }
    # These are the already validated observations, not additional provider reads.
    $report.offline.preinvoke_identity = @{expected=$expected;actual=$focusedId
        preparation_ms=[Math]::Round($preparationClock.Elapsed.TotalMilliseconds)}
    if (-not $belongs -or -not $inDocument -or $offscreen -or $focusedId -cne $expected) {
        if (-not $belongs) { $report.offline.final_preparation.kind='outside_target' }
        elseif (-not $inDocument) { $report.offline.final_preparation.kind='outside_document' }
        elseif ($offscreen) { $report.offline.final_preparation.kind='offscreen' }
        else { $report.offline.final_preparation.kind='id_mismatch' }
        # A mismatch alone is not replacement evidence. Only permit a complete
        # fresh-tree proof when focus remains in the original visible document.
        if ($belongs -and $inDocument -and -not $offscreen) {
            $MismatchEvidence.Value = @{original_id=$expected}
        }
        throw 'Offline button focus changed before UIA Invoke'
    }
    $report.offline.final_preparation.kind='verified'
    return @{element=$Element;pattern=$pattern}
}
function Press-OfflineButton([string]$Name, [switch]$VerifySourceStability, [ValidateSet('normal_stop')][string]$DiagnosticStage) {
    $report.offline.final_preparation = $null
    $report.offline.final_preparation_history = @()
    $report.offline.preinvoke_identity = $null
    $diagnosticArgs = @{}
    if ($DiagnosticStage) { $diagnosticArgs.DiagnosticStage = $DiagnosticStage }
    if ($DiagnosticStage) { $report.offline.action_stage = 'normal_stop_select' }
    if ($VerifySourceStability) {
        $report.offline.final_preparation = @{route='candidate_window';attempt=0;kind='not_reached';proof='not_eligible'}
        $report.offline.final_preparation_history = @($report.offline.final_preparation)
        # Candidate stability remains a separate observation window. Never refocus
        # or retry after this window and never borrow its time for replacement.
        $element = Find-FocusedOfflineButton $Name
        Assert-AccountFocusStable $element $Name
        $mismatchEvidence = $null
        $prepared = Prepare-OfflineButtonInvoke $element ([ref]$mismatchEvidence) @diagnosticArgs
    } else {
        $prepared = Find-FocusedOfflineButton $Name -PrepareInvoke @diagnosticArgs
    }
    # Effects and their postcondition checks are outside every retry handler.
    if ($DiagnosticStage) { $report.offline.action_stage = 'normal_stop_invoke' }
    $prepared.pattern.Invoke()
    if ($DiagnosticStage) { $report.offline.action_stage = 'normal_stop_post_invoke_guard' }
    $null = Assert-Target $true
}
function New-OfflineFieldClock { return [Diagnostics.Stopwatch]::StartNew() }
function Assert-OfflineFieldIdentity($Element, [string]$ExpectedId, $Identities) {
    $null = Assert-Target $true
    foreach ($id in $Identities.Keys) {
        if (-not $ownedIds.Contains([int]$id)) { throw 'Original field process ancestry changed' }
        Assert-DocumentNodeIdentity ([int]$id) $Identities
    }
    $nodePid = $Element.GetCurrentPropertyValue([Windows.Automation.AutomationElement]::ProcessIdProperty, $true)
    if ($nodePid -isnot [int] -or -not $ownedIds.Contains($nodePid)) { throw 'Original field process is unproven' }
    Assert-DocumentNodeIdentity $nodePid $Identities
    $parts = @($Element.GetRuntimeId())
    if ($parts.Count -eq 0 -or @($parts | Where-Object { $_ -isnot [int] }).Count -gt 0) { throw 'Original field identity unavailable' }
    $id = $parts -join '.'
    if ($ExpectedId -and $id -cne $ExpectedId) { throw 'Original field identity changed' }
    $password = $Element.GetCurrentPropertyValue([Windows.Automation.AutomationElement]::IsPasswordProperty, $true)
    $offscreen = $Element.GetCurrentPropertyValue([Windows.Automation.AutomationElement]::IsOffscreenProperty, $true)
    $enabled = $Element.GetCurrentPropertyValue([Windows.Automation.AutomationElement]::IsEnabledProperty, $true)
    if ($password -isnot [bool] -or $password -or $offscreen -isnot [bool] -or $offscreen -or
        $enabled -isnot [bool] -or -not $enabled) { throw 'Original field is not a known visible non-password input' }
    return $id
}
function Read-OfflineFieldValue($Element, [string]$ExpectedId, $Pattern, $Identities, $Clock, [switch]$Postcondition) {
    if ($Postcondition -and $Clock.Elapsed.TotalSeconds -ge 3) { throw 'Synthetic text was not observed in the original visible control' }
    $null = Assert-OfflineFieldIdentity $Element $ExpectedId $Identities
    # This reviewed focus reader validates PID/lifetime before ancestry and never
    # reads arbitrary names, values, AutomationId or ClassName.
    $focus = Read-AccountStabilityFocus $Identities $Clock
    if ($focus.belongs_to_target -isnot [bool] -or -not $focus.belongs_to_target -or
        $focus.in_document -isnot [bool] -or -not $focus.in_document -or
        $focus.offscreen -isnot [bool] -or $focus.offscreen -or
        $focus.runtime_id -isnot [string] -or $focus.runtime_id -cne $ExpectedId) {
        throw 'Visible text focus changed before readback'
    }
    if ($Postcondition -and $Clock.Elapsed.TotalSeconds -ge 3) { throw 'Synthetic text was not observed in the original visible control' }
    $value = $Pattern.Current.Value
    foreach ($id in $Identities.Keys) { Assert-DocumentNodeIdentity ([int]$id) $Identities }
    if ($Postcondition -and $Clock.Elapsed.TotalSeconds -ge 3) { throw 'Synthetic text was not observed in the original visible control' }
    if ($value -isnot [string]) { throw 'Original field value is unavailable' }
    return $value
}
function Fill-OfflineField([string]$Name, [string]$Text) {
    $element = Find-OfflineControl 'ControlType.Edit' ('^' + [regex]::Escape($Name) + '$')
    $held = [Collections.Generic.List[object]]::new(); $identities = @{}
    try {
        $null = Assert-Target $true
        foreach ($id in $ownedIds) {
            $process = Get-Process -Id $id -ErrorAction Stop; $held.Add($process)
            Assert-DocumentProcessHandle $process
            $identities[[int]$id] = @{process=$process;birth=$process.StartTime.ToUniversalTime().Ticks;session=$process.SessionId;image=$process.Path}
        }
        $originalId = Assert-OfflineFieldIdentity $element '' $identities
        $pattern = $element.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern)
        $initialValue = $pattern.Current.Value
        if ($initialValue -isnot [string] -or -not [string]::Equals($initialValue,'',[StringComparison]::Ordinal)) { throw 'Offline synthetic field was not empty' }
        Focus-OfflineControl $element
        $clock = New-OfflineFieldClock
        $beforeInput = Read-OfflineFieldValue $element $originalId $pattern $identities $clock
        if (-not [string]::Equals($beforeInput,'',[StringComparison]::Ordinal)) { throw 'Offline synthetic field was not empty' }
        if ([RespireNativeInput]::Text([IntPtr][long]$binding.hwnd, $Text) -ne 2*$Text.Length) { throw 'Offline Unicode SendInput was incomplete' }
        # New, explicit postcondition budget: at most three seconds after the one
        # input dispatch. No refocus, replacement lookup, or input replay occurs.
        $clock.Restart()
        while ($clock.Elapsed.TotalSeconds -lt 3) {
            $value = Read-OfflineFieldValue $element $originalId $pattern $identities $clock -Postcondition
            if ($clock.Elapsed.TotalSeconds -ge 3) { break }
            if ([string]::Equals($value,$Text,[StringComparison]::Ordinal)) { return }
            Pause-Probe
        }
        throw 'Synthetic text was not observed in the original visible control'
    } finally { foreach ($process in $held) { $process.Dispose() } }
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
    $report.offline.runtime_process = $record | Select-Object ProcessId,ParentProcessId,ExecutablePath,CreationDate,SessionId,@{Name="creation_utc_ticks";Expression={$_.CreationDate.ToUniversalTime().Ticks.ToString([Globalization.CultureInfo]::InvariantCulture)}}
    $report.offline.runtime_bound = $true
    # Persist only the guarded actor record before credential verification or business action.
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
    if (($Arguments -join '|') -notmatch '^--json\|(list\|--limit\|100|show\|[A-Za-z0-9_-]+|diary|status)$') { throw 'Offline oracle command is not allowlisted' }
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
    $report.offline.action_stage = $(if ($Diary) { 'diary_editor_open' } else { 'important_editor_open' })
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
    $report.offline.action_stage = $(if ($Diary) { 'diary_save' } else { 'important_save' })
    Press-OfflineButton ([regex]::Unescape('\u005e\u4fdd\u5b58\u0024'))
    # Wait for the editor to close and the actual reader to render the supplied content.
    $null = Find-OfflineControl 'ControlType.Button' ([regex]::Unescape('\u005e\u7f16\u8f91\u0024')) 60
    $report.offline.action_stage = $(if ($Diary) { 'diary_created_reader' } else { 'important_created_reader' })
    $body = Find-OfflineControl 'ControlType.Text' ([regex]::Escape($Content))
    if ($body.Current.IsOffscreen) { throw 'Synthetic memory body is present in UIA but not visible' }
}
function Get-OfflineDiaryNavigationPattern {
    # Default Latin-digit locale counts: zero or comma-grouped positive integers.
    # Other separators/digit scripts remain unproven and fail closed.
    return ('\A' + [regex]::Unescape('\u65e5\u8bb0') + '(?: (?:0|[1-9][0-9]{0,2}(?:,[0-9]{3})*))?\z')
}
function Assert-OfflineDiaryReader([string]$Title, [string]$Content) {
    # Only the exact synthetic diary dialog is readable, never arbitrary Edit values.
    Wait-OfflineRecoveryDismissed
    $element = Find-OfflineControl 'ControlType.Edit' ('^' + [regex]::Escape($Title) + '$')
    if ($element.Current.IsOffscreen) { throw 'Synthetic diary reader is not visible' }
    $null = Assert-Target $true
    $pattern = $null
    if (-not $element.TryGetCurrentPattern([Windows.Automation.ValuePattern]::Pattern, [ref]$pattern)) { throw 'Synthetic diary reader has no value pattern' }
    if (-not $pattern.Current.IsReadOnly) { throw 'Synthetic diary reader is not read-only' }
    $value = [string]$pattern.Current.Value
    if (-not $value.Contains($Content)) { throw 'Synthetic diary reader does not contain the saved body' }
    $null = Assert-Target $true
}
function Close-OfflineDiaryReader([string]$Title) {
    $selector = '^' + [regex]::Escape($Title) + '$'
    $null = Find-OfflineControl 'ControlType.Edit' $selector
    Press-OfflineButton ([regex]::Unescape('\u005e\u5173\u95ed\u0024'))
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        $null = Assert-Target $true
        if (-not (Find-OfflineControl 'ControlType.Edit' $selector 1 -AllowAbsent)) { return }
        Pause-Probe
    } while ($clock.Elapsed.TotalSeconds -lt 10)
    throw 'Synthetic diary dialog did not close'
}
function Wait-OfflineRecoveryDismissed {
    $report.offline.recovery_dismiss_detail = 'observe_absence'
    $selector = '^' + [regex]::Escape([regex]::Unescape('\u8bf7\u4fdd\u5b58\u672c\u673a\u6062\u590d\u6750\u6599')) + '$'
    # Only fixed-name existence is inspected. Never read Edit.Value or arbitrary
    # tree text; a disabled recovery field still means the dialog is not dismissed.
    for ($attempt=0; $attempt -lt 10; $attempt++) {
        $edit = Find-OfflineControl 'ControlType.Edit' $selector 1 -AllowAbsent
        $title = Find-OfflineControl 'ControlType.Text' $selector 1 -AllowAbsent
        if ($null -eq $edit -and $null -eq $title) {
            $report.offline.recovery_dismiss_detail = 'complete'
            $report.offline.recovery_controls_absent = $true
            return
        }
        Pause-Probe
    }
    throw 'Original recovery dialog controls did not disappear within the bounded checks'
}
function Assert-OfflineLocalKeys($Envelope) {
    $value = $Envelope.summary.session.has_local_keys
    if ($value -isnot [bool]) { throw 'Offline status local-key flag is missing or not boolean' }
    $report.offline.has_local_keys = $value
    if (-not $value) { throw 'Offline status does not confirm local keys' }
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
        settings_persisted=$false; runtime_normal_stop_confirmed=$false; failure_kind='unknown'
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
    # Host keygen intentionally completes without automatically starting a serving owner.
    # Initialize first, then use the normal explicit Start action and bind the first actor.
    $report.offline.action_stage = 'account_navigation'
    Press-OfflineButton ([regex]::Unescape('\u005e\u8d26\u6237\u4e0e\u7a7a\u95f4\u0024'))
    $report.offline.action_stage = 'offline_initialization'
    Press-OfflineButton ([regex]::Unescape('\u005e\u521d\u59cb\u5316\u79bb\u7ebf\u8bb0\u5fc6\u5e93\u0024')) -VerifySourceStability:$SourceCandidateStability
    $report.offline.action_stage = 'key_generation'
    Press-OfflineButton ([regex]::Unescape('\u005e\u521b\u5efa\u672c\u673a\u5bc6\u94a5\u0024'))
    # Never read arbitrary tree nodes/values, capture a screenshot, copy or archive recovery material.
    $null = Find-OfflineControl 'ControlType.Edit' ([regex]::Unescape('\u005e\u8bf7\u4fdd\u5b58\u672c\u673a\u6062\u590d\u6750\u6599\u0024')) 60
    $report.offline.action_stage = 'recovery_dismiss'
    Send-OfflineKey 27 -RecoveryDismiss # Normal Escape closes the recovery display; generated VM keys are disposable.
    Wait-OfflineRecoveryDismissed
    $report.offline.action_stage = 'overview_navigation'
    Press-OfflineButton ([regex]::Unescape('\u005e\u6982\u89c8\u0024'))
    $report.offline.action_stage = 'runtime_start'
    Press-OfflineButton ([regex]::Unescape('\u005e\u542f\u52a8\u0020\u0052\u0075\u006e\u0074\u0069\u006d\u0065\u0024'))
    $null = Find-OfflineControl 'ControlType.Button' ([regex]::Unescape('\u005e\u505c\u6b62\u0020\u0052\u0075\u006e\u0074\u0069\u006d\u0065\u0024')) 60 -ObserveStartStopSelector
    Bind-OfflineRuntime
    $report.offline.action_stage = 'account_verification'
    Press-OfflineButton ([regex]::Unescape('\u005e\u8d26\u6237\u4e0e\u7a7a\u95f4\u0024'))
    $report.offline.action_stage = 'credential_persistence'
    Assert-OfflineLocalKeys (Read-OfflineRpc @('--json','status'))
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
    $report.offline.action_stage = 'diary_runtime_readback'
    $diary = Read-OfflineRpc @('--json','diary')
    if (-not ($diary.details -is [Array])) { throw 'Runtime diary details is not the original array contract' }
    $days = @($diary.details | ForEach-Object { Convert-OfflineEntry $_ } | Where-Object { $_.importance -eq 'trivial' -and $_.content -like ('*'+$diaryContent+'*') })
    if ($days.Count -ne 1) { throw 'Trivial UI write did not appear exactly once in the real diary' }
    if ($days[0].title -cne ($marker + '-diary')) { throw 'Diary title differs from the explicit synthetic UI write' }
    $report.offline.action_stage = 'diary_navigation'
    Press-OfflineButton (Get-OfflineDiaryNavigationPattern)
    $report.offline.action_stage = 'diary_select_saved_day'
    Press-OfflineButton ('^' + [regex]::Escape($days[0].title) + '$')
    $report.offline.action_stage = 'diary_saved_reader'
    Assert-OfflineDiaryReader $days[0].title $diaryContent
    $report.offline.diary_readback = $true; $report.offline.diary_id = $days[0].id
    $guard = Assert-Target $true
    $report.screenshot = Capture-Target $guard.client_bounds
    $report.offline.screenshot_stage = 'real diary UI after synthetic write and Runtime readback; recovery dialog closed'
    $report.offline.action_stage = 'diary_close_reader'
    Close-OfflineDiaryReader $days[0].title
    $report.offline.action_stage = 'settings_navigation'
    Press-OfflineButton ([regex]::Unescape('\u005e\u8bbe\u7f6e\u0024'))
    $report.offline.action_stage = 'settings_locate'
    $preference = Find-OfflineControl 'ControlType.CheckBox' ([regex]::Unescape('\u005e\u81ea\u52a8\u8fde\u63a5\u0020\u0052\u0075\u006e\u0074\u0069\u006d\u0065\u0024'))
    $report.offline.action_stage = 'settings_initial_state'
    $toggle = $preference.GetCurrentPattern([Windows.Automation.TogglePattern]::Pattern)
    if ($toggle.Current.ToggleState -ne [Windows.Automation.ToggleState]::Off) { throw 'AutoRuntime was not initially disabled' }
    $report.offline.action_stage = 'settings_enable'
    Focus-OfflineControl $preference; Send-OfflineKey 32
    $report.offline.action_stage = 'settings_enable_persist'
    Wait-OfflinePreferences 'autoRuntime' $true
    $report.offline.action_stage = 'settings_disable'
    Focus-OfflineControl (Find-OfflineControl 'ControlType.CheckBox' ([regex]::Unescape('\u005e\u81ea\u52a8\u8fde\u63a5\u0020\u0052\u0075\u006e\u0074\u0069\u006d\u0065\u0024'))); Send-OfflineKey 32
    $report.offline.action_stage = 'settings_disable_persist'
    Wait-OfflinePreferences 'autoRuntime' $false
    $report.offline.settings_persisted = $true
    $report.offline.action_stage = 'runtime_pre_stop_check'
    Assert-OfflineRuntime
    $report.offline.action_stage = 'overview_navigation'
    Press-OfflineButton ([regex]::Unescape('\u005e\u6982\u89c8\u0024'))
    Press-OfflineButton ([regex]::Unescape('\u005e\u505c\u6b62\u0020\u0052\u0075\u006e\u0074\u0069\u006d\u0065\u0024')) -DiagnosticStage 'normal_stop'
    $report.offline.action_stage = 'normal_stop_process_lookup'
    $process = Get-Process -Id $offlineRuntime.pid -ErrorAction SilentlyContinue
    if ($process) {
        $report.offline.action_stage = 'normal_stop_birth_check'
        if ($process.StartTime.ToUniversalTime().Ticks -ne $offlineRuntime.started_ticks) { $report.offline.failure_kind = 'pid_reused'; throw 'Runtime PID reused before normal-stop observation' }
        $report.offline.action_stage = 'normal_stop_wait_exit'
        if (-not $process.WaitForExit(30000)) { $report.offline.failure_kind = 'exit_timeout'; throw 'Runtime did not exit after visible normal Stop' }
    }
    for ($attempt=0; $attempt -lt 2; $attempt++) {
        if ($attempt -eq 0) { $report.offline.action_stage = 'normal_stop_cim_first' } else { $report.offline.action_stage = 'normal_stop_cim_second' }
        if (Get-CimInstance Win32_Process -Filter "ProcessId=$($offlineRuntime.pid)") { $report.offline.failure_kind = 'pid_present_after_stop'; throw 'Runtime PID still exists or was reused after normal Stop' }
        Pause-Probe
    }
    $report.offline.action_stage = 'normal_stop_confirmed'
    $report.offline.runtime_normal_stop_confirmed = $true
    $report.offline.status = 'offline-subset-passed'
}

try {
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) { throw 'Require the system 64-bit Windows PowerShell 5.1 helper' }
    $binding = Get-Content -Raw -LiteralPath $BindingPath | ConvertFrom-Json
    if ($SourceCandidateStability) {
        if (-not $OfflineAcceptance -or $binding.fixture_mode -cne 'source-client2-ui-candidate' -or
            $binding.source_commit -cnotmatch '\A[0-9a-f]{40}\z') { throw 'Candidate stability requires an explicit source binding and offline subset' }
        $report.fixture_mode='source-client2-ui-candidate'
    } elseif ($binding.fixture_mode -eq 'source-client2-ui-candidate') { throw 'Candidate source binding requires stability verification' }
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
exit 0
