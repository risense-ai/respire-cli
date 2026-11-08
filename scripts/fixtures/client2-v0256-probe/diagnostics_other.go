//go:build !darwin

package main

func processDiagnostics(pid uint32) map[string]any {
	return map[string]any{"pid": pid}
}
