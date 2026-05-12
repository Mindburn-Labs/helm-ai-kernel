package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTONActonGoldenPacksPresent(t *testing.T) {
	root := filepath.Join("golden", "ton-acton")
	required := []string{
		"build_ok",
		"fmt_check_failed_receipted",
		"check_failed_no_deploy",
		"test_failed_no_deploy",
		"coverage_threshold_failed_escalate",
		"mutation_threshold_failed_escalate",
		"local_script_ok",
		"fork_script_ok_no_broadcast",
		"testnet_deploy_allowed",
		"testnet_spend_cap_denied",
		"mainnet_generic_script_denied",
		"mainnet_deploy_escalated_for_approval",
		"mainnet_deploy_allowed_after_ceremony",
		"wallet_mnemonic_workspace_denied",
		"verify_dry_run_ok",
		"verify_mainnet_escalated",
		"compiler_version_mismatch_denied",
		"library_fetch_readonly_ok",
		"library_publish_mainnet_escalated",
		"library_publish_generic_denied",
		"acton_output_schema_drift_denied",
		"evidencepack_replay_ok",
	}
	for _, name := range required {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, name, "case.json"))
			if err != nil {
				t.Fatal(err)
			}
			var payload map[string]any
			if err := json.Unmarshal(data, &payload); err != nil {
				t.Fatal(err)
			}
			if payload["case_id"] != name {
				t.Fatalf("case_id = %v, want %s", payload["case_id"], name)
			}
			if payload["action_urn"] == "" || payload["expected_verdict"] == "" {
				t.Fatalf("golden case missing action_urn or expected_verdict: %s", data)
			}
		})
	}
}
