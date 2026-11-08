package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"respire-client2/internal/host"
	"time"
)

type hostOperationCheck struct {
	Name             string `json:"name"`
	Passed           bool   `json:"passed"`
	TerminalEnvelope bool   `json:"terminal_envelope"`
	RepeatedIDStable bool   `json:"repeated_id_stable"`
}

func checkHostOperations(m *host.Manager) (bool, []hostOperationCheck) {
	requests := []struct {
		name, input, secret, state, status string
	}{
		{"auth_register", `{"addr":"not-an-origin","user":"compat-fixture"}`, "", "failed", "fail"},
		{"auth_login", `{"addr":"not-an-origin","user":"compat-fixture"}`, "", "failed", "fail"},
		{"auth_recover", `{"addr":"not-an-origin"}`, "", "failed", "fail"},
		{"auth_reset", `{}`, `{"totp":"bad"}`, "failed", "fail"},
		{"inject_targets", `{}`, "", "done", "ok"},
	}
	checks := make([]hostOperationCheck, 0, len(requests))
	allPassed := true
	for index, request := range requests {
		check := hostOperationCheck{Name: request.name}
		id := fmt.Sprintf("desktop-00000000-0000-4000-8000-%012d", index+1)
		operation, err := m.Submit(request.name, id, json.RawMessage(request.input), true, request.secret)
		deadline := time.Now().Add(15 * time.Second)
		for err == nil && operation.State == "running" && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
			operation, err = m.Operation(id)
		}
		var envelope struct {
			Status string `json:"status"`
		}
		check.TerminalEnvelope = err == nil && operation.State == request.state &&
			operation.Finished != nil && json.Unmarshal(operation.Envelope, &envelope) == nil && envelope.Status == request.status
		if check.TerminalEnvelope {
			// The original Manager must inspect a repeated desktop ID without rerunning it.
			repeated, repeatErr := m.Submit(request.name, id, json.RawMessage(request.input), true, request.secret)
			check.RepeatedIDStable = repeatErr == nil && repeated.State == operation.State &&
				repeated.Finished != nil && repeated.Finished.Equal(*operation.Finished) &&
				bytes.Equal(repeated.Envelope, operation.Envelope)
		}
		check.Passed = check.TerminalEnvelope && check.RepeatedIDStable
		checks = append(checks, check)
		allPassed = allPassed && check.Passed
		if operation.State == "running" {
			// Do not start another host command after an uncertain timeout.
			break
		}
	}
	return allPassed, checks
}
