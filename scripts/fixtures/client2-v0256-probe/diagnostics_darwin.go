package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// Observe the same kernel interfaces as the unchanged Client2 stop path.
// Never retain process arguments, environment, or raw kernel records.
func processDiagnostics(pid uint32) map[string]any {
	result := map[string]any{"pid": pid, "expected_record_bytes": unix.SizeofKinfoProc}
	for name, value := range map[string]int{"target": int(pid), "probe": os.Getpid()} {
		_, err := unix.SysctlKinfoProc("kern.proc.pid", value)
		if err != nil {
			result[name+"_kinfo_error"] = err.Error()
		}
		raw, rawErr := unix.SysctlRaw("kern.proc.pid", value)
		result[name+"_record_bytes"] = len(raw)
		if rawErr != nil {
			result[name+"_raw_error"] = rawErr.Error()
		}
	}
	return result
}
