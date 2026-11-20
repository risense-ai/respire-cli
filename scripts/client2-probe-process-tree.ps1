function Get-Client2ProbeProcessTree($Snapshot, [int]$RootId, [long]$RootBirth, [int]$SessionId, [string]$RootImage) {
    $roots = @($Snapshot | Where-Object ProcessId -eq $RootId)
    # CIM reports birth at microsecond precision. Process.StartTime uses 100 ns ticks.
    if ($roots.Count -ne 1 -or $roots[0].CreationDate -isnot [datetime] -or
        $roots[0].SessionId -ne $SessionId -or
        -not [string]::Equals($roots[0].ExecutablePath,$RootImage,[StringComparison]::OrdinalIgnoreCase) -or
        [Math]::Abs($roots[0].CreationDate.ToUniversalTime().Ticks - $RootBirth) -gt 9) {
        throw 'Client2 process snapshot does not contain the original desktop'
    }

    $births = @{$RootId = $roots[0].CreationDate.ToUniversalTime().Ticks}
    do {
        $added = $false
        foreach ($item in $Snapshot) {
            $id = [int]$item.ProcessId
            $parentId = [int]$item.ParentProcessId
            if ($births.ContainsKey($id) -or -not $births.ContainsKey($parentId) -or
                $item.SessionId -ne $SessionId -or $item.CreationDate -isnot [datetime]) { continue }

            # Windows can reuse a parent PID while the original parent's children still exist.
            $birth = $item.CreationDate.ToUniversalTime().Ticks
            if ($birth -le $births[$parentId]) { continue }
            $births[$id] = $birth
            $added = $true
        }
    } while ($added)
    $Snapshot | Where-Object { $births.ContainsKey([int]$_.ProcessId) }
}
