package redact

import (
	"testing"
)

func TestRedactString_APIKeys(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"sk- prefix", "token is sk-abc123XYZ_long", "token is [REDACTED]"},
		{"key- prefix", "use key-proj_abcdef99", "use [REDACTED]"},
		{"AKIA prefix", "creds AKIAIOSFODNN7EXAMPLE end", "creds [REDACTED] end"},
		{"multiple keys", "sk-aaaa1234 and key-bbbb5678", "[REDACTED] and [REDACTED]"},
		{"short sk- no match", "sk-ab", "sk-ab"}, // too short to trigger (prefix + 1 char < 4)
		{"short key- no match", "key-ab", "key-ab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactString(tt.input)
			if got != tt.want {
				t.Errorf("RedactString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedactString_FilePaths(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"macOS path", "file at /Users/ivan/secrets.json loaded", "file at [REDACTED] loaded"},
		{"linux path", "reading /home/deploy/.env", "reading [REDACTED]"},
		{"windows path backslash", `open C:\Users\admin\key.pem`, "open [REDACTED]"},
		{"windows path double backslash", `open C:\\Users\\admin\\key.pem`, "open [REDACTED]"},
		{"no path", "just a normal string", "just a normal string"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactString(tt.input)
			if got != tt.want {
				t.Errorf("RedactString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedactString_NonSensitive(t *testing.T) {
	inputs := []string{
		"hello world",
		"42",
		"",
		"sk",        // too short overall
		"user@host", // not a key pattern
	}
	for _, input := range inputs {
		got := RedactString(input)
		if got != input {
			t.Errorf("RedactString(%q) should pass through unchanged, got %q", input, got)
		}
	}
}

func TestRedact_NilAndEmpty(t *testing.T) {
	if got := Redact(nil); got != nil {
		t.Errorf("Redact(nil) = %v, want nil", got)
	}
	got := Redact(map[string]interface{}{})
	if got == nil || len(got) != 0 {
		t.Errorf("Redact(empty) = %v, want empty map", got)
	}
}

func TestRedact_SecretEnvKeys(t *testing.T) {
	payload := map[string]interface{}{
		"DATABASE_PASSWORD": "hunter2",
		"API_KEY":           "some-value",
		"AUTH_TOKEN":        "tok_abc",
		"MY_SECRET":         "shh",
		"USERNAME":          "admin",
		"PORT":              8080,
	}
	got := Redact(payload)

	for _, key := range []string{"DATABASE_PASSWORD", "API_KEY", "AUTH_TOKEN", "MY_SECRET"} {
		if got[key] != placeholder {
			t.Errorf("Redact[%q] = %v, want %q", key, got[key], placeholder)
		}
	}
	if got["USERNAME"] != "admin" {
		t.Errorf("Redact[USERNAME] = %v, want 'admin'", got["USERNAME"])
	}
	if got["PORT"] != 8080 {
		t.Errorf("Redact[PORT] = %v, want 8080", got["PORT"])
	}
}

func TestRedact_NestedMaps(t *testing.T) {
	payload := map[string]interface{}{
		"config": map[string]interface{}{
			"db": map[string]interface{}{
				"CONNECTION_SECRET": "postgres://user:pass@host/db",
				"host":             "localhost",
			},
			"path": "/Users/ivan/config.yaml",
		},
		"api_key": "sk-proj_abcdef1234",
	}
	got := Redact(payload)

	config, ok := got["config"].(map[string]interface{})
	if !ok {
		t.Fatal("config should be a map")
	}
	db, ok := config["db"].(map[string]interface{})
	if !ok {
		t.Fatal("config.db should be a map")
	}
	if db["CONNECTION_SECRET"] != placeholder {
		t.Errorf("nested secret = %v, want %q", db["CONNECTION_SECRET"], placeholder)
	}
	if db["host"] != "localhost" {
		t.Errorf("nested host = %v, want 'localhost'", db["host"])
	}
	if config["path"] != placeholder {
		t.Errorf("path with /Users/ = %v, want %q", config["path"], placeholder)
	}
	if got["api_key"] != placeholder {
		t.Errorf("api_key = %v, want %q", got["api_key"], placeholder)
	}
}

func TestRedact_SliceValues(t *testing.T) {
	payload := map[string]interface{}{
		"paths": []interface{}{
			"/Users/ivan/a.txt",
			"safe-string",
			"/home/deploy/b.log",
		},
	}
	got := Redact(payload)
	paths, ok := got["paths"].([]interface{})
	if !ok {
		t.Fatal("paths should be a slice")
	}
	if paths[0] != placeholder {
		t.Errorf("paths[0] = %v, want %q", paths[0], placeholder)
	}
	if paths[1] != "safe-string" {
		t.Errorf("paths[1] = %v, want 'safe-string'", paths[1])
	}
	if paths[2] != placeholder {
		t.Errorf("paths[2] = %v, want %q", paths[2], placeholder)
	}
}

func TestRedact_OriginalNotMutated(t *testing.T) {
	original := map[string]interface{}{
		"API_KEY": "secret-value",
	}
	_ = Redact(original)
	if original["API_KEY"] != "secret-value" {
		t.Error("Redact must not mutate the original map")
	}
}
