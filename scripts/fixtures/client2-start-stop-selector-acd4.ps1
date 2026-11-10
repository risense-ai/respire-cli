function Find-OfflineControl([string]$Type, [string]$Name, [double]$Seconds = 10, [switch]$AllowAbsent) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        $null = Assert-Target $true
        $window = Get-OfflineReplacementRoot
        $walker = Get-OfflineReplacementWalker
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
                $current.Name -match $Name -and ($AllowAbsent -or $current.IsEnabled)) { $found.Add($next.element) }
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
        if ($found.Count -gt 1) { throw 'Offline selector is ambiguous' }
        if ($found.Count -eq 1) { return $found[0] }
        if ($AllowAbsent) { return $null }
        Pause-Probe
    } while ($clock.Elapsed.TotalSeconds -lt $Seconds)
    throw "Expected offline control unavailable: $Type / $Name"
}
