// evidenced exposes only source-safe capability discovery in R0.
// Capture, key access, network listening, and export are intentionally absent.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type capabilities struct {
	Schema               string `json:"schema"`
	Stage                string `json:"stage"`
	CaptureEnabled       bool   `json:"capture_enabled"`
	PayloadExportEnabled bool   `json:"payload_export_enabled"`
	SecretHandling       string `json:"secret_handling"`
}

func main() {
	if len(os.Args) != 2 || os.Args[1] != "capabilities" {
		fmt.Fprintln(os.Stderr, "usage: evidenced capabilities")
		os.Exit(2)
	}
	_ = json.NewEncoder(os.Stdout).Encode(capabilities{
		Schema: "evidence-service.capabilities/v1", Stage: "synthetic-r0",
		CaptureEnabled: false, PayloadExportEnabled: false,
		SecretHandling: "test-only, library API; no daemon secret collection",
	})
}
