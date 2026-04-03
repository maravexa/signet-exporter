package main_test

import (
	"encoding/json"
	"os"
	"testing"
)

func TestGrafanaDirectoryExists(t *testing.T) {
	const path = "grafana/signet-overview.json"

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("grafana/signet-overview.json missing or unreadable: %v", err)
	}

	if !json.Valid(data) {
		t.Fatalf("grafana/signet-overview.json is not valid JSON")
	}
}
