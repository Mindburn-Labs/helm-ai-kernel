package kernel

import (
	"encoding/json"
	"testing"
)

func TestValidateSecretRef(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "Valid SecretRef",
			input:   `{"secret_id": "db-pass", "materialization": {"mode": "RUNTIME_ONLY"}}`,
			wantErr: false,
		},
		{
			name:    "Plaintext Password",
			input:   `{"config": {"password": "hunter2"}}`,
			wantErr: true,
		},
		{
			name:    "Plaintext API Key",
			input:   `{"api_key": "sk_live_12345"}`,
			wantErr: true,
		},
		{
			name:    "Nested Plaintext",
			input:   `{"level1": {"level2": {"key": "-----BEGIN PRIVATE KEY-----"}}}`,
			wantErr: true,
		},
		{
			name:    "Safe Config",
			input:   `{"host": "localhost", "port": 5432}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v interface{}
			if err := json.Unmarshal([]byte(tt.input), &v); err != nil {
				t.Fatalf("Failed to unmarshal input: %v", err)
			}

			err := ScanForPlaintextSecrets(v)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScanForPlaintextSecrets() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSecretRefAdditionalFields(t *testing.T) {
	valid := SecretRef{
		RefID:                "secret-db",
		Provider:             SecretProviderVault,
		Path:                 "kv/data/prod/db",
		MaterializationScope: MaterializationScopeRuntime,
	}
	if err := ValidateSecretRef(valid); err != nil {
		t.Fatalf("valid SecretRef should pass: %v", err)
	}

	tests := []struct {
		name string
		ref  SecretRef
	}{
		{name: "missing ref id", ref: SecretRef{Provider: SecretProviderVault, Path: "kv/x", MaterializationScope: MaterializationScopeRuntime}},
		{name: "missing provider", ref: SecretRef{RefID: "s", Path: "kv/x", MaterializationScope: MaterializationScopeRuntime}},
		{name: "missing path", ref: SecretRef{RefID: "s", Provider: SecretProviderVault, MaterializationScope: MaterializationScopeRuntime}},
		{name: "missing scope", ref: SecretRef{RefID: "s", Provider: SecretProviderVault, Path: "kv/x"}},
		{name: "unknown provider", ref: SecretRef{RefID: "s", Provider: SecretProvider("unknown"), Path: "kv/x", MaterializationScope: MaterializationScopeRuntime}},
		{name: "invalid scope", ref: SecretRef{RefID: "s", Provider: SecretProviderVault, Path: "kv/x", MaterializationScope: MaterializationScope("deploy_time")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateSecretRef(tt.ref); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestScanForPlaintextSecretsAdditionalArrayPath(t *testing.T) {
	artifact := []interface{}{
		map[string]interface{}{"password": "hunter2"},
	}
	if err := ScanForPlaintextSecrets(artifact); err == nil {
		t.Fatal("expected plaintext secret in array element")
	}
}
