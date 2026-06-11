package main

import (
	"bytes"
	"testing"
)

func TestParseAppCommandArgsAcceptsFlagsAroundAppID(t *testing.T) {
	cases := []struct {
		name          string
		args          []string
		wantApp       string
		wantSubstrate string
		wantJSON      bool
	}{
		{
			name:          "flags after app",
			args:          []string{"opencode", "--json", "--substrate", "local-container"},
			wantApp:       "opencode",
			wantSubstrate: "local-container",
			wantJSON:      true,
		},
		{
			name:          "flags before app",
			args:          []string{"--json", "--substrate", "local-container", "kilocode"},
			wantApp:       "kilocode",
			wantSubstrate: "local-container",
			wantJSON:      true,
		},
		{
			name:          "equals forms",
			args:          []string{"opencode", "--substrate=local-container", "--json=true"},
			wantApp:       "opencode",
			wantSubstrate: "local-container",
			wantJSON:      true,
		},
		{
			name:          "single-dash forms",
			args:          []string{"-json", "-substrate", "local-container", "opencode"},
			wantApp:       "opencode",
			wantSubstrate: "local-container",
			wantJSON:      true,
		},
		{
			name:          "json=false equals form",
			args:          []string{"--json=false", "kilocode"},
			wantApp:       "kilocode",
			wantSubstrate: "local-container",
			wantJSON:      false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			appID, substrateID, jsonOut, code := parseAppCommandArgs("app preflight", tc.args, &bytes.Buffer{})
			if code != 0 {
				t.Fatalf("parseAppCommandArgs code=%d", code)
			}
			if appID != tc.wantApp || substrateID != tc.wantSubstrate || jsonOut != tc.wantJSON {
				t.Fatalf("parseAppCommandArgs = app=%s substrate=%s json=%v", appID, substrateID, jsonOut)
			}
		})
	}
}
