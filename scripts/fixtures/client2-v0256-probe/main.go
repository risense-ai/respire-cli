package main

import (
	"context"
	"encoding/json"
	"os"
	"respire-client2/internal/host"
	"time"
)

func main() {
	m, e := host.New()
	if e != nil {
		panic(e)
	}
	if len(os.Args) > 1 {
		var actionErr error
		if os.Args[1] == "start" {
			actionErr = m.Start()
		} else if os.Args[1] == "stop" {
			actionErr = m.Stop(false)
		} else {
			panic("unknown action")
		}
		if actionErr != nil {
			json.NewEncoder(os.Stdout).Encode(map[string]any{"action_error": actionErr.Error()})
			os.Exit(1)
		}
		if os.Args[1] == "stop" {
			json.NewEncoder(os.Stdout).Encode(map[string]bool{"stopped": true})
			return
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, h, he := m.Health(ctx)
	r, re := m.RPC("status")
	s, se := m.RuntimeStatus(ctx)
	catalog, ce := m.ModelCatalogRPC(ctx)
	progress, pe := m.ModelProgress(ctx)
	variants, ve := m.ModelVariants(ctx, "m3")
	errText := func(e error) string {
		if e == nil {
			return ""
		}
		return e.Error()
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"catalog": catalog, "catalog_error": errText(ce), "progress": progress, "progress_error": errText(pe), "variants": variants, "variants_error": errText(ve), "health": h, "health_error": errText(he), "diagnostic_rpc": r, "diagnostic_error": errText(re), "business_status": s, "business_error": errText(se)})
	if he != nil || re != nil || se != nil || ce != nil || pe != nil || ve != nil {
		os.Exit(1)
	}
}
