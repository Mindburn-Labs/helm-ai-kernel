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
