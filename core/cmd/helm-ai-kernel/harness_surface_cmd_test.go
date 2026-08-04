package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestHarnessCLIProducersPreserveExplicitReceiptRefs(t *testing.T) {
	tests := []struct {
		name string
		run  func([]string, io.Writer, io.Writer) int
		body string
	}{
		{
			name: "verification scope",
			run:  runEvidenceScopes,
			body: `{"verification_scope_id":"scope-cli-refs","receipt_refs":["rcpt-scope"],"subject_hash":"sha256:subject","checks_performed":["hash"],"verifier_hash":"sha256:verifier","policy_hash":"sha256:policy"}`,
		},
		{
			name: "plan transaction",
			run:  runPlanTransactions,
			body: `{"plan_transaction_id":"tx-cli-refs","receipt_refs":["rcpt-tx"],"plan_hash":"sha256:plan","read_set":["artifact:read"],"write_set":["artifact:write"],"assumption_set":["assumption"],"verification_obligations":["verify"],"conflict_policy":"deny"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := filepath.Join(t.TempDir(), "input.json")
			if err := os.WriteFile(input, []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			if code := tt.run([]string{"put", "--input", input}, &stdout, &stderr); code != 0 {
				t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
			}
			var output struct {
				ReceiptRefs []string `json:"receipt_refs"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
				t.Fatalf("decode output: %v\n%s", err, stdout.String())
			}
			if len(output.ReceiptRefs) != 1 || output.ReceiptRefs[0] == "" {
				t.Fatalf("receipt_refs = %v", output.ReceiptRefs)
			}
		})
	}
}
