param(
    [Parameter(Mandatory)][string]$BindingPath,
    [Parameter(Mandatory)][string]$OutputDirectory
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
        $window.bounds[2] -le $window.bounds[0] -or $window.bounds[3] -le $window.bounds[1]) { throw 'Target HWND is no longer a visible original window' }
    if ($RequireForeground -and [RespireNativeInput]::Foreground().ToInt64() -ne $binding.hwnd) { throw 'Foreground is not the bound target HWND; no input/capture permitted' }
    $script:ownedIds = $ids
    return @{ bounds = @($window.bounds); foreground = [RespireNativeInput]::Foreground().ToInt64() }
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
    while ($queue.Count -gt 0 -and $rows.Count -lt 256 -and $clock.Elapsed.TotalSeconds -lt 5) {
        $next = $queue.Dequeue(); $info = Element-Info $next.element; $info.depth = $next.depth
        if (-not $ownedIds.Contains([int]$info.process_id)) { throw 'UIA node belongs to an unbound process' }
        $rows.Add($info)
        if ($next.depth -lt 12) {
            $child = $walker.GetFirstChild($next.element)
            while ($child -and $queue.Count + $rows.Count -lt 256 -and $clock.Elapsed.TotalSeconds -lt 5) {
                $queue.Enqueue(@{element=$child; depth=$next.depth+1}); $child = $walker.GetNextSibling($child)
            }
        }
    }
    return @{ nodes = @($rows.ToArray()); bounded = $true
        document_count = @($rows | Where-Object { $_.control_type -eq 'ControlType.Document' -and -not $_.offscreen }).Count
        focusable_count = @($rows | Where-Object { $_.keyboard_focusable -and -not $_.offscreen }).Count }
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

function Capture-Target([int[]]$ExpectedBounds) {
    $before = Assert-Target $true
    if (($before.bounds -join ',') -ne ($ExpectedBounds -join ',')) { throw 'Target bounds changed before desktop capture' }
    $rectangle = [Drawing.Rectangle]::new($ExpectedBounds[0], $ExpectedBounds[1], $ExpectedBounds[2]-$ExpectedBounds[0], $ExpectedBounds[3]-$ExpectedBounds[1])
    if (-not [Windows.Forms.SystemInformation]::VirtualScreen.Contains($rectangle)) { throw 'Target window extends outside the visible desktop' }
    $bitmap = [Drawing.Bitmap]::new($rectangle.Width, $rectangle.Height)
    try {
        $graphics = [Drawing.Graphics]::FromImage($bitmap)
        try { $graphics.CopyFromScreen($rectangle.Location, [Drawing.Point]::Empty, $rectangle.Size, [Drawing.CopyPixelOperation]::SourceCopy) }
        finally { $graphics.Dispose() }
        $after = Assert-Target $true
        if (($after.bounds -join ',') -ne ($ExpectedBounds -join ',')) { throw 'Target bounds changed during desktop capture' }
        $path = Join-Path $OutputDirectory 'workspace.png'
        $bitmap.Save($path, [Drawing.Imaging.ImageFormat]::Png)
        if ((Get-Item -LiteralPath $path).Length -le 0) { throw 'Desktop capture produced no PNG bytes' }
        return @{ source='desktop-target-window'; bounds=$ExpectedBounds; foreground_before=$before.foreground
            foreground_after=$after.foreground; sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
    } finally { $bitmap.Dispose() }
}

function Invoke-NativeGuiProbe {
    $report.initial_guard = Assert-Target
    $report.identity_verified = $true
    $report.accessibility_tree = Read-TargetTree
    if ($report.accessibility_tree.document_count -lt 1 -or $report.accessibility_tree.focusable_count -lt 1) { throw 'Original WebView UIA document/focusable controls not available' }
    $report.accessibility_tree_read = $true
    Focus-Target
    $report.input_guard = Assert-Target $true
    $report.foreground_verified = $true
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
    $report.screenshot = Capture-Target $guard.bounds
    $report.target_desktop_screenshot_saved = $true
    $report.status = 'native-connectivity-passed'
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
    [StructLayout(LayoutKind.Sequential)] struct MOUSEINPUT { public int dx,dy; public uint data,flags,time; public UIntPtr extra; }
    [StructLayout(LayoutKind.Sequential)] struct KEYBDINPUT { public ushort vk,scan; public uint flags,time; public UIntPtr extra; }
    [StructLayout(LayoutKind.Explicit)] struct UNION { [FieldOffset(0)] public MOUSEINPUT mouse; [FieldOffset(0)] public KEYBDINPUT keyboard; }
    [StructLayout(LayoutKind.Sequential)] struct INPUT { public uint type; public UNION input; }
    [DllImport("user32.dll", SetLastError=true)] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll", SetLastError=true)] static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("dwmapi.dll")] static extern int DwmGetWindowAttribute(IntPtr hwnd,int attribute,out int value,int size);
    [DllImport("user32.dll", EntryPoint="GetForegroundWindow")] public static extern IntPtr Foreground();
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr SetThreadDpiAwarenessContext(IntPtr context);
    [DllImport("user32.dll", SetLastError=true)] static extern uint SendInput(uint count, INPUT[] events, int size);
    public static object Window(IntPtr hwnd) {
        uint pid; RECT rect; int cloaked;
        if (GetWindowThreadProcessId(hwnd,out pid)==0 || !GetWindowRect(hwnd,out rect)) throw new Win32Exception();
        int hr=DwmGetWindowAttribute(hwnd,14,out cloaked,sizeof(int)); if(hr!=0) Marshal.ThrowExceptionForHR(hr);
        return new { pid=pid, visible=IsWindowVisible(hwnd), cloaked=cloaked, bounds=new[]{rect.Left,rect.Top,rect.Right,rect.Bottom} };
    }
    public static uint Tab(IntPtr target) {
        if(Foreground()!=target) throw new InvalidOperationException("Foreground changed immediately before SendInput");
        var events=new INPUT[2]; events[0].type=1; events[0].input.keyboard.vk=9;
        events[1].type=1; events[1].input.keyboard.vk=9; events[1].input.keyboard.flags=2;
        return SendInput(2,events,Marshal.SizeOf(typeof(INPUT)));
    }
}
'@
    if ([RespireNativeInput]::SetThreadDpiAwarenessContext([IntPtr](-4)) -eq [IntPtr]::Zero) { throw 'Cannot establish per-monitor-v2 thread coordinates for target desktop capture' }
    $report.capture_coordinate_context = 'per-monitor-v2 helper thread; ends with helper process'
    Invoke-NativeGuiProbe
} catch { $report.error = $_.Exception.Message }
finally {
    $json = $report | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'native-gui.json'), $json + "`n", [Text.UTF8Encoding]::new($false))
}
if ($report.status -ne 'native-connectivity-passed') { exit 1 }
