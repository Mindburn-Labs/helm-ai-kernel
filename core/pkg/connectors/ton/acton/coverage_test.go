package acton

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
)

func TestCoverageClassificationAndLibraryHelpers(t *testing.T) {
	spec, ok := ClassifyAction(ActionScriptMainnet)
	if !ok || spec.RiskClass != RiskT3 || spec.Network != NetworkMainnet {
		t.Fatalf("unexpected mainnet classification: %#v ok=%v", spec, ok)
	}
	if _, ok := ClassifyAction(ActionURN("missing")); ok {
		t.Fatal("unknown action classified")
	}
	for _, action := range []ActionURN{ActionScriptTestnet, ActionScriptMainnet, ActionLibraryPublishTN, ActionLibraryTopupMN} {
		if !IsMoneyMoving(action) || !IsIrreversible(action) || !IsSecretRisk(action) {
			t.Fatalf("expected money/irreversible/secret risk for %s", action)
		}
	}
	if IsMoneyMoving(ActionBuild) || IsIrreversible(ActionBuild) || IsSecretRisk(ActionBuild) {
		t.Fatal("local build should not be money-moving, irreversible, or wallet-secret risk")
	}
	if RiskForNetwork(NetworkMainnet, true) != RiskT2 || RiskForNetwork(NetworkMainnet, false) != RiskT3 {
		t.Fatal("mainnet risk classification mismatch")
	}
	for _, network := range []NetworkProfile{NetworkTestnet, NetworkForkMainnet, NetworkForkTestnet} {
		if RiskForNetwork(network, true) != RiskT2 {
			t.Fatalf("expected T2 for %s", network)
		}
	}
	if RiskForNetwork(NetworkLocal, false) != RiskT1 || RiskForNetwork(NetworkNone, true) != RiskT1 {
		t.Fatal("local/default network risk mismatch")
	}
	for _, action := range []ActionURN{ActionLibraryInfo, ActionLibraryFetch, ActionLibraryPublishTN, ActionLibraryPublishMN, ActionLibraryTopupTN, ActionLibraryTopupMN} {
		if !IsLibraryAction(action) {
			t.Fatalf("expected library action for %s", action)
		}
	}
	if IsLibraryAction(ActionBuild) {
		t.Fatal("build should not be a library action")
	}
	if !LibraryActionIsReadOnly(ActionLibraryInfo) || !LibraryActionIsReadOnly(ActionLibraryFetch) || LibraryActionIsReadOnly(ActionLibraryPublishTN) {
		t.Fatal("library read-only classification mismatch")
	}
}

func TestCoverageBuildArgvMatrixAndValidationBranches(t *testing.T) {
	cases := []struct {
		name   string
		action ActionURN
		params map[string]any
		want   []string
		absent []string
	}{
		{"project_new", ActionProjectNew, map[string]any{"project_name": "demo/../ton-demo"}, []string{"acton", "new", "ton-demo"}, nil},
		{"format_check", ActionFormatCheck, nil, []string{"acton", "fmt", "--check"}, nil},
		{"coverage", ActionCoverage, nil, []string{"acton", "test", "--coverage"}, nil},
		{"mutation_seed", ActionMutation, map[string]any{"mutation_seed": "  42  "}, []string{"acton", "test", "--mutate", "--seed", "42"}, nil},
		{"mutation_no_seed", ActionMutation, nil, []string{"acton", "test", "--mutate"}, []string{"--seed"}},
		{"wrapper", ActionWrapperGenerate, nil, []string{"acton", "wrapper", "generate"}, nil},
		{"wrapper_ts", ActionWrapperGenerateTS, nil, []string{"acton", "wrapper", "generate", "--ts"}, nil},
		{"compile", ActionCompile, map[string]any{"source_path": "contracts/../contracts/main.tolk"}, []string{"acton", "compile", "contracts/main.tolk"}, nil},
		{"disasm", ActionDisasm, map[string]any{"artifact_path": "build/main.boc"}, []string{"acton", "disasm", "build/main.boc"}, nil},
		{"doc_query", ActionDoc, map[string]any{"query": "stdlib"}, []string{"acton", "doc", "stdlib"}, nil},
		{"doc_no_query", ActionDoc, nil, []string{"acton", "doc"}, nil},
		{"retrace", ActionRetrace, map[string]any{"trace_path": "traces/run.json"}, []string{"acton", "retrace", "traces/run.json"}, nil},
		{"func2tolk", ActionFunc2Tolk, map[string]any{"source_path": "legacy/main.fc"}, []string{"acton", "func2tolk", "legacy/main.fc"}, nil},
		{"script_local", ActionScriptLocal, map[string]any{"script_path": "scripts/local.tolk"}, []string{"acton", "script", "scripts/local.tolk"}, nil},
		{"fork_testnet", ActionScriptForkTestnet, map[string]any{"script_path": "scripts/fork.tolk"}, []string{"acton", "script", "scripts/fork.tolk", "--fork-net", "testnet"}, nil},
		{"fork_mainnet", ActionScriptForkMainnet, map[string]any{"script_path": "scripts/fork.tolk"}, []string{"acton", "script", "scripts/fork.tolk", "--fork-net", "mainnet"}, nil},
		{"script_testnet_secret_manager", ActionScriptTestnet, map[string]any{"script_path": "scripts/deploy.tolk", "wallet_mode": "secret_manager"}, []string{"acton", "script", "scripts/deploy.tolk", "--net", "testnet"}, []string{"--tonconnect"}},
		{"script_mainnet_tonconnect", ActionScriptMainnet, map[string]any{"script_path": "scripts/deploy.tolk"}, []string{"acton", "script", "scripts/deploy.tolk", "--net", "mainnet", "--tonconnect"}, nil},
		{"verify_dry_run", ActionVerifyDryRun, map[string]any{"address": "EQD", "source_path": "contracts/main.tolk"}, []string{"acton", "verify", "EQD", "contracts/main.tolk", "--dry-run"}, nil},
		{"verify_testnet_secret_manager", ActionVerifyTestnet, map[string]any{"address": "EQD", "source_path": "contracts/main.tolk", "wallet_mode": "secret_manager"}, []string{"acton", "verify", "EQD", "contracts/main.tolk", "--net", "testnet"}, []string{"--tonconnect"}},
		{"verify_mainnet", ActionVerifyMainnet, map[string]any{"address": "EQD", "source_path": "contracts/main.tolk"}, []string{"acton", "verify", "EQD", "contracts/main.tolk", "--net", "mainnet", "--tonconnect"}, nil},
		{"library_info_network", ActionLibraryInfo, map[string]any{"library_ref": "stdlib", "network": "testnet"}, []string{"acton", "library", "info", "stdlib", "--net", "testnet"}, nil},
		{"library_fetch_output", ActionLibraryFetch, map[string]any{"library_ref": "stdlib", "network": "mainnet", "output_path": "out/stdlib.json"}, []string{"acton", "library", "fetch", "stdlib", "--net", "mainnet", "--out", "out/stdlib.json"}, nil},
		{"library_publish_testnet", ActionLibraryPublishTN, map[string]any{"library_path": "lib/main.tolk"}, []string{"acton", "library", "publish", "lib/main.tolk", "--net", "testnet", "--tonconnect"}, nil},
		{"library_publish_mainnet_secret_manager", ActionLibraryPublishMN, map[string]any{"library_path": "lib/main.tolk", "wallet_mode": "secret_manager"}, []string{"acton", "library", "publish", "lib/main.tolk", "--net", "mainnet"}, []string{"--tonconnect"}},
		{"library_topup_testnet", ActionLibraryTopupTN, map[string]any{"library_ref": "stdlib"}, []string{"acton", "library", "topup", "stdlib", "--net", "testnet", "--tonconnect"}, nil},
		{"library_topup_mainnet", ActionLibraryTopupMN, map[string]any{"library_ref": "stdlib"}, []string{"acton", "library", "topup", "stdlib", "--net", "mainnet", "--tonconnect"}, nil},
		{"wallet_list", ActionWalletList, nil, []string{"acton", "wallet", "list"}, nil},
		{"rpc_query", ActionRPCQuery, map[string]any{"method": "getMasterchainInfo", "network": "testnet"}, []string{"acton", "rpc", "query", "getMasterchainInfo", "--net", "testnet"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildArgv(tc.action, tc.params)
			if err != nil {
				t.Fatalf("BuildArgv error: %v", err)
			}
			if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
				t.Fatalf("argv mismatch\ngot=%#v\nwant=%#v", got, tc.want)
			}
			joined := strings.Join(got, " ")
			for _, absent := range tc.absent {
				if strings.Contains(joined, absent) {
					t.Fatalf("argv should not contain %q: %#v", absent, got)
				}
			}
		})
	}

	unchanged := appendNetworkIfPresent([]string{"acton", "library", "info", "stdlib"}, map[string]any{"network": "fork_mainnet"})
	if len(unchanged) != 4 {
		t.Fatalf("unexpected network append for fork profile: %#v", unchanged)
	}
	if _, err := BuildArgv(ActionURN("missing"), nil); reasonFromError(err, "") != ReasonUnknownCommand {
		t.Fatalf("expected unknown command, got %v", err)
	}
	for _, params := range []map[string]any{{"command": "acton build"}, {"shell": "acton build"}, {"extra_flags": []string{"--net", "mainnet"}}} {
		if err := RejectRawCommandFields(params); reasonFromError(err, "") != ReasonRawShellForbidden {
			t.Fatalf("expected raw command rejection for %#v, got %v", params, err)
		}
	}
	validationCases := []struct {
		name   string
		action ActionURN
		argv   []string
		reason ReasonCode
	}{
		{"bad_first_arg", ActionBuild, []string{"sh", "acton"}, ReasonArgvRejected},
		{"newline", ActionBuild, []string{"acton", "build\nbad"}, ReasonArgvRejected},
		{"unauthorized_mainnet", ActionBuild, []string{"acton", "script", "--net", "mainnet"}, ReasonGenericMainnetScriptDenied},
		{"unauthorized_testnet", ActionBuild, []string{"acton", "script", "--net", "testnet"}, ReasonArgvRejected},
		{"unauthorized_fork", ActionBuild, []string{"acton", "script", "--fork-net", "testnet"}, ReasonArgvRejected},
		{"local_net", ActionScriptLocal, []string{"acton", "script", "s.tolk", "--net", "sandbox"}, ReasonArgvRejected},
	}
	for _, tc := range validationCases {
		if _, err := validateArgvForAction(tc.action, tc.argv); reasonFromError(err, "") != tc.reason {
			t.Fatalf("%s: expected %s, got %v", tc.name, tc.reason, err)
		}
	}
	if action, ok := ResolveAction("ignored", map[string]any{"action_urn": string(ActionBuild)}); !ok || action != ActionBuild {
		t.Fatalf("action_urn did not resolve: %s ok=%v", action, ok)
	}
	if action, ok := ResolveAction("ignored", map[string]any{"action_urn": "missing"}); ok || action != ActionURN("missing") {
		t.Fatalf("unknown action_urn should be returned with ok=false: %s ok=%v", action, ok)
	}
	if action, ok := ResolveAction(string(ActionVersion), nil); !ok || action != ActionVersion {
		t.Fatalf("tool name did not resolve: %s ok=%v", action, ok)
	}
	if _, ok := ResolveAction("missing", nil); ok {
		t.Fatal("unknown tool name resolved")
	}
	if cleanRel(" a/../b ") != "b" || cleanRel("../escape") != "../escape" || cleanRel("/abs/path") != "/abs/path" || cleanRel("") != "" {
		t.Fatal("cleanRel branch mismatch")
	}
	if value, ok := stringParam(map[string]any{"x": "  ok  "}, "x"); !ok || value != "ok" {
		t.Fatalf("stringParam trim mismatch: %q %v", value, ok)
	}
	if value, ok := stringParam(map[string]any{"x": 7}, "x"); !ok || value != "7" {
		t.Fatalf("stringParam fmt mismatch: %q %v", value, ok)
	}
	if _, ok := stringParam(map[string]any{"x": nil}, "x"); ok {
		t.Fatal("nil stringParam should not resolve")
	}
}

func TestCoverageEnvelopeValidationAndParamParsing(t *testing.T) {
	env, err := NewEnvelope(map[string]any{
		"command_id":         "cmd-1",
		"tenant_id":          "tenant-1",
		"workspace_id":       "workspace-1",
		"principal":          "did:example:alice",
		"project_root":       "apps/../apps/ton",
		"manifest_path":      "configs/../Acton.toml",
		"manifest_hash":      "sha256:manifest",
		"source_tree_hash":   "sha256:source",
		"created_at_lamport": int64(99),
		"metadata":           map[string]interface{}{"purpose": "coverage"},
		"generic":            false,
		"raw_acton":          "redacted",
		"dry_run_fixture":    true,
	}, ActionBuild, "sha256:intent", 2)
	if err != nil {
		t.Fatal(err)
	}
	if env.CommandID != "cmd-1" || env.ProjectRoot != "apps/ton" || env.ManifestPath != "Acton.toml" || env.CreatedAtLamport != 99 {
		t.Fatalf("unexpected envelope fields: %#v", env)
	}
	if env.Metadata["purpose"] != "coverage" || env.Metadata["dry_run_fixture"] != true {
		t.Fatalf("metadata was not copied: %#v", env.Metadata)
	}
	if data, err := env.CanonicalBytes(); err != nil || len(data) == 0 {
		t.Fatalf("canonical bytes failed: len=%d err=%v", len(data), err)
	}
	if hash, err := env.Hash(); err != nil || !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("hash failed: %s %v", hash, err)
	}
	if got := DeriveIdempotencyKey("sha256:intent", string(ActionBuild), 2); got != env.IdempotencyKey {
		t.Fatalf("idempotency mismatch: %s != %s", got, env.IdempotencyKey)
	}

	bad := *env
	bad.SchemaVersion = "bad"
	if err := bad.Validate(); reasonFromError(err, "") != ReasonArgvRejected {
		t.Fatalf("expected bad schema error, got %v", err)
	}
	bad = *env
	bad.ConnectorID = "bad"
	if err := bad.Validate(); reasonFromError(err, "") != ReasonArgvRejected {
		t.Fatalf("expected bad connector error, got %v", err)
	}
	bad = *env
	bad.ActionURN = ActionURN("missing")
	if err := bad.Validate(); reasonFromError(err, "") != ReasonUnknownCommand {
		t.Fatalf("expected unknown action error, got %v", err)
	}
	bad = *env
	bad.Argv = nil
	if err := bad.Validate(); reasonFromError(err, "") != ReasonArgvRejected {
		t.Fatalf("expected argv error, got %v", err)
	}

	for _, tc := range []struct {
		name     string
		params   map[string]any
		fallback uint64
		want     uint64
	}{
		{"absent", nil, 8, 8},
		{"uint64", map[string]any{"n": uint64(7)}, 0, 7},
		{"int", map[string]any{"n": 6}, 0, 6},
		{"int64", map[string]any{"n": int64(5)}, 0, 5},
		{"float64", map[string]any{"n": float64(4)}, 0, 4},
		{"string", map[string]any{"n": "3"}, 0, 3},
		{"negative", map[string]any{"n": -1}, 2, 2},
		{"bad", map[string]any{"n": "bad"}, 2, 2},
	} {
		if got := uint64Param(tc.params, "n", tc.fallback); got != tc.want {
			t.Fatalf("%s uint64Param=%d want=%d", tc.name, got, tc.want)
		}
	}
	for _, tc := range []struct {
		name     string
		value    any
		fallback int
		want     int
		wantOK   bool
	}{
		{"int", 1, 0, 1, true},
		{"int64", int64(2), 0, 2, true},
		{"uint64", uint64(3), 0, 3, true},
		{"float64", float64(4), 0, 4, true},
		{"string", "5", 0, 5, true},
		{"fraction", 1.5, 9, 9, false},
		{"negative", -1, 9, 9, false},
		{"bad", "bad", 9, 0, false},
	} {
		got, ok := intParam(map[string]any{"n": tc.value}, "n", tc.fallback)
		if got != tc.want || ok != tc.wantOK {
			t.Fatalf("%s intParam=%d/%v want=%d/%v", tc.name, got, ok, tc.want, tc.wantOK)
		}
	}
	if got, ok := intParam(nil, "n", 12); got != 12 || !ok {
		t.Fatalf("absent intParam=%d/%v", got, ok)
	}
	if got, ok := parseNonNegativeIntString("-1"); got != 0 || ok {
		t.Fatalf("negative parse should fail: %d/%v", got, ok)
	}
}

func TestCoverageScriptManifestBranches(t *testing.T) {
	manifest := scriptManifest("contracts/scripts/deploy.tolk", "sha256:script", NetworkTestnet)
	dir := t.TempDir()
	path := filepath.Join(dir, "acton-script.json")
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadScriptManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ScriptHash != manifest.ScriptHash {
		t.Fatalf("loaded manifest mismatch: %#v", loaded)
	}
	if _, err := LoadScriptManifest(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("expected missing manifest error")
	}
	badJSONPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badJSONPath, []byte("{"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadScriptManifest(badJSONPath); err == nil {
		t.Fatal("expected invalid JSON manifest error")
	}
	for _, tc := range []struct {
		name string
		m    *ScriptManifest
	}{
		{"nil", nil},
		{"schema", &ScriptManifest{SchemaVersion: "bad", ScriptPath: "s", ScriptHash: "h", AllowedNetworks: []NetworkProfile{NetworkTestnet}}},
		{"missing_script", &ScriptManifest{SchemaVersion: ScriptManifestSchemaVersion, AllowedNetworks: []NetworkProfile{NetworkTestnet}}},
		{"missing_networks", &ScriptManifest{SchemaVersion: ScriptManifestSchemaVersion, ScriptPath: "s", ScriptHash: "h"}},
		{"bad_effect", &ScriptManifest{SchemaVersion: ScriptManifestSchemaVersion, ScriptPath: "s", ScriptHash: "h", AllowedNetworks: []NetworkProfile{NetworkTestnet}, ExpectedEffects: []ExpectedEffect{{EffectKind: ""}}}},
	} {
		if err := tc.m.Validate(); err == nil {
			t.Fatalf("%s: expected validation error", tc.name)
		}
	}

	env := newScriptEnv(t, ActionScriptTestnet, manifest, map[string]any{"tolk_compiler_version": "fixture-tolk-1.0.0"})
	if err := manifest.ValidateForEnvelope(env); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	mismatch := manifest
	mismatch.ScriptPath = "other.tolk"
	if err := mismatch.ValidateForEnvelope(env); reasonFromError(err, "") != ReasonExpectedEffectMismatch {
		t.Fatalf("expected script path mismatch, got %v", err)
	}
	mismatch = manifest
	mismatch.ScriptHash = "sha256:other"
	if err := mismatch.ValidateForEnvelope(env); reasonFromError(err, "") != ReasonScriptManifestHashMismatch {
		t.Fatalf("expected hash mismatch, got %v", err)
	}
	mismatch = manifest
	mismatch.AllowedNetworks = []NetworkProfile{NetworkMainnet}
	if err := mismatch.ValidateForEnvelope(env); reasonFromError(err, "") != ReasonExpectedEffectMismatch {
		t.Fatalf("expected network mismatch, got %v", err)
	}
	mismatch = manifest
	mismatch.ExpectedEffects = nil
	if err := mismatch.ValidateForEnvelope(env); reasonFromError(err, "") != ReasonExpectedEffectMismatch {
		t.Fatalf("expected missing expected effects, got %v", err)
	}
	if effects := expectedEffectsFromParams(map[string]any{"expected_effects": manifest.ExpectedEffects}); len(effects) != 1 {
		t.Fatalf("expected parsed effects, got %#v", effects)
	}
	if effects := expectedEffectsFromParams(map[string]any{"expected_effects": map[string]any{"bad": "shape"}}); effects != nil {
		t.Fatalf("bad expected effects should be nil: %#v", effects)
	}
	if effects := expectedEffectsFromParams(map[string]any{"expected_effects": func() {}}); effects != nil {
		t.Fatalf("unmarshalable expected effects should be nil: %#v", effects)
	}
	req := evidenceRequirementsFromParams(map[string]any{"evidence_requirements": map[string]any{"require_coverage_min": 80}}, commandSpecs[ActionBuild])
	if req.RequireCoverageMin != 80 {
		t.Fatalf("evidence requirements did not parse: %#v", req)
	}
	req = evidenceRequirementsFromParams(map[string]any{"evidence_requirements": func() {}}, commandSpecs[ActionScriptMainnet])
	if !req.RequireBuild || !req.RequireTests || !req.RequireFormatCheck || !req.RequireStaticCheck || !req.RequireVerifierDryRun || !req.RequireFullEvidencePack {
		t.Fatalf("T3 defaults missing: %#v", req)
	}
	req = evidenceRequirementsFromParams(nil, commandSpecs[ActionVerifyDryRun])
	if !req.RequireCompilerPin {
		t.Fatalf("compiler pin default missing: %#v", req)
	}
}

func TestCoverageEvidenceAndReceiptBranches(t *testing.T) {
	env, err := NewEnvelope(map[string]any{
		"acton_version":         "fixture-acton-1.0.0",
		"tolk_compiler_version": "fixture-tolk-1.0.0",
		"source_tree_hash":      "sha256:source",
		"manifest_hash":         "sha256:manifest",
	}, ActionBuild, "sha256:intent", 0)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewPreDispatchReceipt(env, PolicyDecision{Verdict: contracts.VerdictEscalate, ReasonCode: ReasonApprovalCeremonyRequired, Dispatch: false, Reason: "needs approval"})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "escalated" {
		t.Fatalf("expected escalated predispatch receipt, got %s", receipt.Status)
	}
	denied, err := NewPreDispatchReceipt(env, deny(ReasonArgvRejected, "denied"))
	if err != nil {
		t.Fatal(err)
	}
	if denied.Status != "denied" {
		t.Fatalf("expected denied status, got %s", denied.Status)
	}
	if _, err := BuildEvidencePack(EvidencePackInput{Receipt: receipt}); err == nil {
		t.Fatal("expected evidence error for missing envelope")
	}
	result, err := BuildEvidencePack(EvidencePackInput{
		Envelope:            env,
		Receipt:             receipt,
		P0Ceilings:          DefaultP0Ceilings(),
		CreatedAt:           time.Unix(1700000000, 0).UTC(),
		PlanIR:              map[string]any{"steps": []string{"build"}},
		CPIInputs:           map[string]any{"input": true},
		CPIOutput:           map[string]any{"output": true},
		KernelVerdict:       map[string]any{"verdict": "allow"},
		ApprovalCeremony:    map[string]any{"approval": "ref"},
		SandboxGrant:        sealedGrant(t, false, true),
		AdditionalArtifacts: map[string][]byte{"extra/data.json": []byte(`{"ok":true}`), "extra/readme.txt": []byte("ok"), "extra/blob.bin": []byte{1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"plan_ir.json", "cpi_inputs.json", "cpi_output.json", "kernel_verdict.json", "approval_ceremony.json", "sandbox_grant.json", "extra/data.json", "extra/readme.txt", "extra/blob.bin"} {
		if _, ok := result.Contents[required]; !ok {
			t.Fatalf("missing evidence content %s", required)
		}
	}
	if result.Manifest == nil {
		t.Fatal("manifest missing")
	}
	if contentTypeFor("a.json") != "application/json" || contentTypeFor("a.txt") != "text/plain" || contentTypeFor("a.bin") != "application/octet-stream" {
		t.Fatal("content type mapping mismatch")
	}
	if err := WriteEvidencePackDir(t.TempDir(), result); err != nil {
		t.Fatal(err)
	}
	if err := WriteEvidencePackDir(t.TempDir(), nil); err == nil {
		t.Fatal("expected nil evidence result error")
	}
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("not a dir"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := WriteEvidencePackDir(blocker, result); err == nil {
		t.Fatal("expected write error when evidence root is a file")
	}
	if data, err := receipt.CanonicalJSON(); err != nil || len(data) == 0 {
		t.Fatalf("canonical receipt failed: len=%d err=%v", len(data), err)
	}
	if hash, err := receipt.Hash(); err != nil || !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("receipt hash failed: %s %v", hash, err)
	}
	if tool := receipt.ToToolReceipt(); tool["connector_id"] != ConnectorID {
		t.Fatalf("tool receipt mismatch: %#v", tool)
	}

	for _, tc := range []struct {
		name   string
		result *actuators.ExecResult
		status string
		reason ReasonCode
	}{
		{"nil", nil, "error", ReasonArgvRejected},
		{"timeout", &actuators.ExecResult{ExitCode: 0, TimedOut: true}, "timeout", ReasonComputeTimeExhausted},
		{"oom", &actuators.ExecResult{ExitCode: 0, OOMKilled: true}, "resource_exhausted", ReasonComputeGasExhausted},
		{"nonzero", &actuators.ExecResult{ExitCode: 2, Stderr: []byte("fail")}, "tool_error", ReasonOK},
		{"success_hashes", &actuators.ExecResult{ExitCode: 0, Stdout: []byte("ok"), Stderr: []byte("warn"), Receipt: actuators.ReceiptFragment{StdoutHash: "sha256:stdout", StderrHash: "sha256:stderr", ImageDigest: "sha256:image"}}, "ok", ReasonOK},
	} {
		got, err := ReceiptFromExec(env, tc.result, "provider", DriftReceipt{})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got.Status != tc.status || got.ReasonCode != tc.reason {
			t.Fatalf("%s: got %s/%s", tc.name, got.Status, got.ReasonCode)
		}
	}
	success, err := ReceiptFromExec(env, &actuators.ExecResult{ExitCode: 0, Stdout: []byte("ok"), Receipt: actuators.ReceiptFragment{StdoutHash: "sha256:stdout"}}, "provider", DriftReceipt{})
	if err != nil {
		t.Fatal(err)
	}
	if resultExitCode(nil) != -1 || resultStdoutHash(nil) != "" || resultStderrHash(nil) != "" || success.StdoutHash != "sha256:stdout" {
		t.Fatal("result helper branch mismatch")
	}
}

func TestCoveragePolicySandboxWalletAndVerificationBranches(t *testing.T) {
	buildEnv := newBuildEnv(t, map[string]any{"acton_version": "fixture-acton-1.0.0", "tolk_compiler_version": "fixture-tolk-1.0.0"})
	if decision := EvaluatePolicy(&ActonCommandEnvelope{ActionURN: ActionURN("missing")}, DefaultP0Ceilings(), nil, nil); decision.ReasonCode != ReasonUnknownCommand {
		t.Fatalf("unknown action decision: %#v", decision)
	}
	badArgv := *buildEnv
	badArgv.Argv = []string{"acton", "script", "--net", "mainnet"}
	if decision := EvaluatePolicy(&badArgv, DefaultP0Ceilings(), sealedGrant(t, false, true), nil); decision.ReasonCode != ReasonGenericMainnetScriptDenied {
		t.Fatalf("generic argv decision: %#v", decision)
	}
	secret := *buildEnv
	secret.Metadata = map[string]interface{}{"private_key": "value"}
	if decision := EvaluatePolicy(&secret, DefaultP0Ceilings(), sealedGrant(t, false, true), nil); decision.ReasonCode != ReasonPlaintextMnemonicForbidden {
		t.Fatalf("plaintext decision: %#v", decision)
	}
	testnetManifest := scriptManifest("contracts/scripts/deploy.tolk", "sha256:script", NetworkTestnet)
	testnetEnv := newScriptEnv(t, ActionScriptTestnet, testnetManifest, map[string]any{"tolk_compiler_version": "fixture-tolk-1.0.0"})
	missingWallet := *testnetEnv
	missingWallet.WalletRef = ""
	if decision := EvaluatePolicy(&missingWallet, DefaultP0Ceilings(), sealedGrant(t, true, false), &testnetManifest); decision.ReasonCode != ReasonWalletRefRequired {
		t.Fatalf("wallet decision: %#v", decision)
	}
	if decision := EvaluatePolicy(buildEnv, DefaultP0Ceilings(), nil, nil); decision.ReasonCode != ReasonSandboxGrantRequired {
		t.Fatalf("nil grant decision: %#v", decision)
	}
	if decision := EvaluatePolicy(testnetEnv, DefaultP0Ceilings(), sealedGrant(t, true, false), nil); decision.ReasonCode != ReasonScriptManifestRequired {
		t.Fatalf("missing manifest decision: %#v", decision)
	}
	badManifest := testnetManifest
	badManifest.ScriptHash = "sha256:bad"
	if decision := EvaluatePolicy(testnetEnv, DefaultP0Ceilings(), sealedGrant(t, true, false), &badManifest); decision.ReasonCode != ReasonScriptManifestHashMismatch {
		t.Fatalf("bad manifest decision: %#v", decision)
	}
	noEffects := *testnetEnv
	noEffects.ExpectedEffects = nil
	if decision := EvaluatePolicy(&noEffects, DefaultP0Ceilings(), sealedGrant(t, true, false), &testnetManifest); decision.ReasonCode != ReasonExpectedEffectMismatch {
		t.Fatalf("missing expected effects decision: %#v", decision)
	}
	verifyNoCompiler, err := NewEnvelope(map[string]any{"address": "EQD", "source_path": "contracts/main.tolk"}, ActionVerifyDryRun, "sha256:intent", 0)
	if err != nil {
		t.Fatal(err)
	}
	if decision := EvaluatePolicy(verifyNoCompiler, DefaultP0Ceilings(), sealedGrant(t, true, false), nil); decision.ReasonCode != ReasonCompilerUnpinned {
		t.Fatalf("compiler pin decision: %#v", decision)
	}
	verifyBadCompiler, err := NewEnvelope(map[string]any{"address": "EQD", "source_path": "contracts/main.tolk", "tolk_compiler_version": "bad"}, ActionVerifyDryRun, "sha256:intent", 0)
	if err != nil {
		t.Fatal(err)
	}
	if decision := EvaluatePolicy(verifyBadCompiler, DefaultP0Ceilings(), sealedGrant(t, true, false), nil); decision.ReasonCode != ReasonCompilerMismatch {
		t.Fatalf("compiler mismatch decision: %#v", decision)
	}

	mainnetManifest := scriptManifest("contracts/scripts/deploy.tolk", "sha256:script", NetworkMainnet)
	mainnetEnv := newScriptEnv(t, ActionScriptMainnet, mainnetManifest, map[string]any{
		"tolk_compiler_version": "fixture-tolk-1.0.0",
		"max_ton_spend":         "0.05",
	})
	noVerify := *mainnetEnv
	noVerify.EvidenceRequirements.RequireVerifierDryRun = false
	mainnetCeilings := DefaultP0Ceilings()
	mainnetCeilings.MaxTONMainnetSpendPerAction = "1"
	mainnetCeilings.AllowMainnetDeploy = true
	if decision := EvaluatePolicy(&noVerify, mainnetCeilings, sealedGrant(t, true, false), &mainnetManifest); decision.ReasonCode != ReasonVerifyDryRunRequired {
		t.Fatalf("verify dry-run decision: %#v", decision)
	}
	unsupported := newBuildEnv(t, map[string]any{"acton_version": "not-supported", "tolk_compiler_version": "fixture-tolk-1.0.0"})
	if decision := EvaluatePolicy(unsupported, DefaultP0Ceilings(), sealedGrant(t, false, true), nil); decision.ReasonCode != ReasonUnsupportedVersion {
		t.Fatalf("unsupported version decision: %#v", decision)
	}
	noSpend := *testnetEnv
	noSpend.MaxTONSpend = ""
	testnetCeilings := DefaultP0Ceilings()
	testnetCeilings.MaxTONSpendPerAction = "1"
	testnetCeilings.AllowTestnetDeploy = true
	if decision := EvaluatePolicy(&noSpend, testnetCeilings, sealedGrant(t, true, false), &testnetManifest); decision.ReasonCode != ReasonSpendCeilingExceeded {
		t.Fatalf("missing spend decision: %#v", decision)
	}
	tooMuch := *testnetEnv
	tooMuch.MaxTONSpend = "2"
	if decision := EvaluatePolicy(&tooMuch, testnetCeilings, sealedGrant(t, true, false), &testnetManifest); decision.ReasonCode != ReasonSpendCeilingExceeded {
		t.Fatalf("spend ceiling decision: %#v", decision)
	}
	broadcastDenied := *testnetEnv
	broadcastDenied.MaxTONSpend = "0.05"
	testnetCeilings.AllowTestnetDeploy = false
	if decision := EvaluatePolicy(&broadcastDenied, testnetCeilings, sealedGrant(t, true, false), &testnetManifest); decision.ReasonCode != ReasonSpendCeilingExceeded {
		t.Fatalf("testnet broadcast decision: %#v", decision)
	}
	if decision := EvaluatePolicy(mainnetEnv, mainnetCeilings, sealedGrant(t, true, false), &mainnetManifest); decision.ReasonCode != ReasonApprovalCeremonyRequired || decision.Verdict != contracts.VerdictEscalate {
		t.Fatalf("mainnet approval decision: %#v", decision)
	}
	mainnetApproved := *mainnetEnv
	mainnetApproved.ApprovalRef = "approval:1"
	mainnetCeilings.AllowMainnetDeploy = false
	if decision := EvaluatePolicy(&mainnetApproved, mainnetCeilings, sealedGrant(t, true, false), &mainnetManifest); decision.ReasonCode != ReasonMainnetRequiresApproval {
		t.Fatalf("mainnet deploy allow decision: %#v", decision)
	}

	libraryEnv := newLibraryMainnetEnv(t, "0.05", "")
	libraryCeilings := DefaultP0Ceilings()
	libraryCeilings.MaxTONMainnetSpendPerAction = "1"
	if decision := EvaluatePolicy(libraryEnv, libraryCeilings, sealedGrant(t, true, false), nil); decision.ReasonCode != ReasonLibraryMainnetRequiresApproval {
		t.Fatalf("library approval decision: %#v", decision)
	}
	libraryApproved := newLibraryMainnetEnv(t, "0.05", "approval:1")
	libraryCeilings.AllowMainnetLibraryPublish = false
	if decision := EvaluatePolicy(libraryApproved, libraryCeilings, sealedGrant(t, true, false), nil); decision.ReasonCode != ReasonLibraryMainnetRequiresApproval {
		t.Fatalf("library publish allowed decision: %#v", decision)
	}
	libraryOverSpend := newLibraryMainnetEnv(t, "2", "approval:1")
	if decision := EvaluatePolicy(libraryOverSpend, libraryCeilings, sealedGrant(t, true, false), nil); decision.ReasonCode != ReasonLibrarySpendCeilingExceeded {
		t.Fatalf("library spend decision: %#v", decision)
	}
	allowCeilings := libraryCeilings
	allowCeilings.AllowMainnetLibraryPublish = true
	allowedLibrary := newLibraryMainnetEnv(t, "0.05", "approval:1")
	if decision := EvaluatePolicy(allowedLibrary, allowCeilings, sealedGrant(t, true, false), nil); decision.ReasonCode != ReasonOK || !decision.Dispatch {
		t.Fatalf("library allow decision: %#v", decision)
	}

	if policyFromParams(map[string]any{"p0_ceilings": func() {}}).Hash() != DefaultP0Ceilings().Hash() {
		t.Fatal("unmarshalable policy should fall back to defaults")
	}
	policy := policyFromParams(map[string]any{"p0_ceilings": map[string]any{"MAX_TON_SPEND_PER_ACTION": "3", "allowed_acton_versions": []string{}, "allowed_tolk_compiler_versions": []string{}}})
	if policy.MaxTONSpendPerAction != "3" || len(policy.AllowedActonVersions) == 0 || len(policy.AllowedTolkCompilerVersions) == 0 {
		t.Fatalf("policy default allowed versions missing: %#v", policy)
	}

	thresholdEnv := *buildEnv
	thresholdEnv.EvidenceRequirements.RequireCoverageMin = 80
	thresholdEnv.EvidenceRequirements.RequireMutationScoreMin = 70
	if decision := validateThresholds(&thresholdEnv, map[string]float64{"coverage_percent": 79, "mutation_score_percent": 100}); decision.ReasonCode != ReasonCoverageThresholdFailed {
		t.Fatalf("coverage threshold decision: %#v", decision)
	}
	if decision := validateThresholds(&thresholdEnv, map[string]float64{"coverage_percent": 80, "mutation_score_percent": 69}); decision.ReasonCode != ReasonMutationThresholdFailed {
		t.Fatalf("mutation threshold decision: %#v", decision)
	}
	if decision := validateThresholds(&thresholdEnv, map[string]float64{"coverage_percent": 80, "mutation_score_percent": 70}); decision.ReasonCode != ReasonOK || !decision.Dispatch {
		t.Fatalf("threshold allow decision: %#v", decision)
	}

	if err := ValidateSourceVerification(buildEnv); err != nil {
		t.Fatalf("non-verifier source validation should pass: %v", err)
	}
	badVerify := &ActonCommandEnvelope{ActionURN: ActionVerifyDryRun, TolkCompilerVersion: "fixture-tolk-1.0.0", Argv: []string{"acton", "verify", "EQD", "contracts/main.tolk", "--net", "testnet"}}
	if err := ValidateSourceVerification(badVerify); reasonFromError(err, "") != ReasonVerifyDryRunRequired {
		t.Fatalf("expected verify dry-run required, got %v", err)
	}
	if !VerifyDryRunRequiredForDeploy(mainnetEnv) || VerifyDryRunRequiredForDeploy(testnetEnv) {
		t.Fatal("verify dry-run deploy helper mismatch")
	}

	if err := ValidateSandboxGrant(buildEnv, sealedGrant(t, true, true)); reasonFromError(err, "") != ReasonNetworkGrantRequired {
		t.Fatalf("local network grant should be rejected: %v", err)
	}
	if err := ValidateSandboxGrant(testnetEnv, sealedGrant(t, false, false)); reasonFromError(err, "") != ReasonNetworkGrantRequired {
		t.Fatalf("missing network grant should be rejected: %v", err)
	}
	hashMismatch := *buildEnv
	hashMismatch.SandboxGrantHash = "sha256:mismatch"
	if err := ValidateSandboxGrant(&hashMismatch, sealedGrant(t, false, true)); reasonFromError(err, "") != ReasonSandboxGrantRequired {
		t.Fatalf("grant hash mismatch should be rejected: %v", err)
	}
	envGrant := *sealedGrant(t, false, true)
	envGrant.Env.Mode = "allowlist"
	envGrant.Env.Names = []string{"TON_PRIVATE_KEY"}
	if err := ValidateSandboxGrant(buildEnv, &envGrant); reasonFromError(err, "") != ReasonPlaintextMnemonicForbidden {
		t.Fatalf("plaintext env grant should be rejected: %v", err)
	}
	if !HasPlaintextSecretRisk(&ActonCommandEnvelope{Argv: []string{"--seed phrase"}, WalletRef: "wallet:opaque"}) {
		t.Fatal("secret risk in argv not detected")
	}
	if !HasPlaintextSecretRisk(&ActonCommandEnvelope{Metadata: map[string]interface{}{"note": "private key here"}}) {
		t.Fatal("secret risk in metadata value not detected")
	}
	unlabeledSeed := "abandon ability able about above absent absorb abstract absurd abuse access accident"
	if !HasPlaintextSecretRisk(&ActonCommandEnvelope{Argv: []string{unlabeledSeed}}) {
		t.Fatal("unlabeled seed-like argv phrase not detected")
	}
	if !HasPlaintextSecretRisk(&ActonCommandEnvelope{Metadata: map[string]interface{}{"note": unlabeledSeed}}) {
		t.Fatal("unlabeled seed-like metadata phrase not detected")
	}
	if HasPlaintextSecretRisk(nil) {
		t.Fatal("nil env should not be secret risk")
	}
	walletEnv := *testnetEnv
	walletEnv.WalletRef = "wallet:tenant-test-ton-1"
	if err := ValidateWalletPolicy(&walletEnv); err != nil {
		t.Fatalf("opaque wallet ref should be accepted: %v", err)
	}
	walletEnv.WalletRef = "wallet:tenant test ton 1"
	if err := ValidateWalletPolicy(&walletEnv); reasonFromError(err, "") != ReasonWalletRefRequired {
		t.Fatalf("freeform wallet ref should be rejected: %v", err)
	}
	walletEnv.WalletRef = "wallet:" + unlabeledSeed
	if err := ValidateWalletPolicy(&walletEnv); reasonFromError(err, "") != ReasonWalletRefRequired {
		t.Fatalf("seed-like wallet ref should be rejected before use: %v", err)
	}
	if RedactWalletRef("") != "" || RedactWalletRef("wallet:abc") != "wallet:REDACTED" || !strings.HasPrefix(RedactWalletRef("wallet:tenant-prod-ton-1"), "wallet:ten...") {
		t.Fatal("wallet redaction mismatch")
	}
}

func TestCoverageConnectorRunnerAndDriftBranches(t *testing.T) {
	connector := NewConnector(Config{Runner: Runner{Executor: &fakeExecutor{stdout: []byte(`{"ok":true}`)}, SandboxID: "s1"}, SandboxGrant: sealedGrant(t, false, true)})
	if connector.ID() != ConnectorID || connector.Graph() == nil {
		t.Fatal("connector id/graph mismatch")
	}
	if _, err := connector.Execute(context.Background(), nil, string(ActionBuild), nil); err == nil {
		t.Fatal("expected nil permit error")
	}
	badPermit := effectPermit()
	badPermit.ConnectorID = "other"
	if _, err := connector.Execute(context.Background(), badPermit, string(ActionBuild), nil); err == nil {
		t.Fatal("expected connector mismatch error")
	}
	buildParams := map[string]any{"acton_version": "fixture-acton-1.0.0", "tolk_compiler_version": "fixture-tolk-1.0.0"}
	missingBindingAny, err := connector.Execute(context.Background(), effectPermit(), string(ActionBuild), buildParams)
	if err != nil {
		t.Fatal(err)
	}
	if receipt := missingBindingAny.(*ActonReceipt); receipt.ReasonCode != ReasonSandboxGrantRequired {
		t.Fatalf("expected missing grant binding deny, got %s", receipt.ReasonCode)
	}
	mismatchedPermit := effectPermit()
	mismatchedPermit.EvidenceBindings = map[string]string{"sandbox_grant_hash": "sha256:mismatch"}
	mismatchedAny, err := connector.Execute(context.Background(), mismatchedPermit, string(ActionBuild), buildParams)
	if err != nil {
		t.Fatal(err)
	}
	if receipt := mismatchedAny.(*ActonReceipt); receipt.ReasonCode != ReasonSandboxGrantRequired {
		t.Fatalf("expected mismatched grant binding deny, got %s", receipt.ReasonCode)
	}
	callerGrantPermit := effectPermit()
	bindPermitToGrant(t, callerGrantPermit, connector.defaultGrant)
	callerGrantParams := map[string]any{
		"acton_version":         "fixture-acton-1.0.0",
		"tolk_compiler_version": "fixture-tolk-1.0.0",
		"sandbox_grant":         sealedGrant(t, false, true),
	}
	callerGrantAny, err := connector.Execute(context.Background(), callerGrantPermit, string(ActionBuild), callerGrantParams)
	if err != nil {
		t.Fatal(err)
	}
	if receipt := callerGrantAny.(*ActonReceipt); receipt.ReasonCode != ReasonSandboxGrantRequired {
		t.Fatalf("expected caller supplied grant deny, got %s", receipt.ReasonCode)
	}
	receiptAny, err := connector.Execute(context.Background(), effectPermit(), "missing.action", map[string]any{"command_id": "unknown-1"})
	if err != nil {
		t.Fatal(err)
	}
	unknown := receiptAny.(*ActonReceipt)
	if unknown.ReasonCode != ReasonUnknownCommand || unknown.ActionURN != ActionURN("missing.action") {
		t.Fatalf("unknown fallback receipt mismatch: %#v", unknown)
	}
	if firstNonEmpty("", "", "x") != "x" || firstNonEmpty("", "") != "" {
		t.Fatal("firstNonEmpty mismatch")
	}
	if sandboxGrantFromParams(nil) != nil || sandboxGrantFromParams(map[string]any{"sandbox_grant": func() {}}) != nil || sandboxGrantFromParams(map[string]any{"sandbox_grant": []string{"bad"}}) != nil {
		t.Fatal("bad sandbox grant params should return nil")
	}
	if grant := sandboxGrantFromParams(map[string]any{"sandbox_grant": sealedGrant(t, false, true)}); grant == nil || grant.GrantID == "" {
		t.Fatalf("sandbox grant did not parse: %#v", grant)
	}

	manifest := scriptManifest("contracts/scripts/deploy.tolk", "sha256:script", NetworkTestnet)
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "script.json")
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, data, 0644); err != nil {
		t.Fatal(err)
	}
	if scriptManifestFromParams(nil) != nil || scriptManifestFromParams(map[string]any{"script_manifest": func() {}}) != nil || scriptManifestFromParams(map[string]any{"script_manifest": []string{"bad"}}) != nil || scriptManifestFromParams(map[string]any{"script_manifest_path": filepath.Join(dir, "missing.json")}) != nil {
		t.Fatal("bad script manifest params should return nil")
	}
	if parsed := scriptManifestFromParams(map[string]any{"script_manifest": manifest}); parsed == nil || parsed.ScriptHash != manifest.ScriptHash {
		t.Fatalf("raw script manifest did not parse: %#v", parsed)
	}
	if parsed := scriptManifestFromParams(map[string]any{"script_manifest_path": manifestPath}); parsed == nil || parsed.ScriptHash != manifest.ScriptHash {
		t.Fatalf("path script manifest did not parse: %#v", parsed)
	}

	env := newBuildEnv(t, map[string]any{"acton_version": "fixture-acton-1.0.0", "tolk_compiler_version": "fixture-tolk-1.0.0"})
	if _, err := (Runner{}).Run(context.Background(), env, sealedGrant(t, false, true), ""); err == nil {
		t.Fatal("expected missing executor error")
	}
	if _, err := (Runner{Executor: &fakeExecutor{}}).Run(context.Background(), env, sealedGrant(t, false, true), ""); err == nil {
		t.Fatal("expected missing sandbox id error")
	}
	receipt, err := (Runner{Executor: &fakeExecutor{}, SandboxID: "s1"}).Run(context.Background(), env, sealedGrant(t, false, false), "")
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ReasonCode != ReasonSandboxGrantRequired || receipt.Status != "denied" {
		t.Fatalf("invalid grant runner receipt: %#v", receipt)
	}
	receipt, err = (Runner{Executor: errorExecutor{}, SandboxID: "s1"}).Run(context.Background(), env, sealedGrant(t, false, true), "")
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "error" || receipt.ToolError == "" {
		t.Fatalf("executor error receipt mismatch: %#v", receipt)
	}
	receipt, err = (Runner{Executor: &fakeExecutor{stdout: []byte(`{"ok":true}`)}, SandboxID: "s1"}).Run(context.Background(), env, sealedGrant(t, false, true), outputShapeHash([]byte(`{"ok":true}`)))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Environment.OS == "" || receipt.Environment.Runtime == "" || receipt.ReasonCode != ReasonOK {
		t.Fatalf("successful runner receipt incomplete: %#v", receipt)
	}
	if outputShapeHash(nil) != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal("empty shape hash mismatch")
	}
	if !strings.HasPrefix(outputShapeHash([]byte("not json")), "sha256:") {
		t.Fatal("text shape hash missing prefix")
	}
	shape := jsonShape(map[string]any{
		"s": "x",
		"n": float64(1),
		"b": true,
		"z": nil,
		"a": []any{map[string]any{"nested": "value"}},
	})
	for _, part := range []string{"s:string", "n:number", "b:bool", "z:null", "a:array[object{nested:string}]"} {
		if !strings.Contains(shape, part) {
			t.Fatalf("shape %q missing %q", shape, part)
		}
	}
	if jsonShape([]any{}) != "array[]" || jsonShape(struct{}{}) != "unknown" {
		t.Fatal("jsonShape edge mismatch")
	}
}

type errorExecutor struct{}

func (errorExecutor) Exec(context.Context, string, *actuators.ExecRequest) (*actuators.ExecResult, error) {
	return nil, errors.New("sandbox failed")
}

func (errorExecutor) Provider() string { return "error-sandbox" }

func newBuildEnv(t *testing.T, extra map[string]any) *ActonCommandEnvelope {
	t.Helper()
	params := map[string]any{}
	for key, value := range extra {
		params[key] = value
	}
	env, err := NewEnvelope(params, ActionBuild, "sha256:intent", 0)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func newScriptEnv(t *testing.T, action ActionURN, manifest ScriptManifest, extra map[string]any) *ActonCommandEnvelope {
	t.Helper()
	params := map[string]any{
		"script_path":      manifest.ScriptPath,
		"script_hash":      manifest.ScriptHash,
		"wallet_ref":       "wallet:tenant-test-ton-1",
		"max_ton_spend":    "0.05",
		"expected_effects": manifest.ExpectedEffects,
	}
	for key, value := range extra {
		params[key] = value
	}
	env, err := NewEnvelope(params, action, "sha256:intent", 0)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func newLibraryMainnetEnv(t *testing.T, spend, approval string) *ActonCommandEnvelope {
	t.Helper()
	params := map[string]any{
		"library_path":          "libs/std.tolk",
		"wallet_ref":            "wallet:tenant-prod-ton-1",
		"max_ton_spend":         spend,
		"tolk_compiler_version": "fixture-tolk-1.0.0",
		"expected_effects": []ExpectedEffect{{
			EffectKind:  "TON_LIBRARY_PUBLISH",
			EffectClass: EffectIrreversible,
			Network:     string(NetworkMainnet),
			WalletRef:   "wallet:tenant-prod-ton-1",
			MaxTONSpend: spend,
		}},
	}
	if approval != "" {
		params["approval_ref"] = approval
	}
	env, err := NewEnvelope(params, ActionLibraryPublishMN, "sha256:intent", 0)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func effectPermit() *effects.EffectPermit {
	return &effects.EffectPermit{
		PermitID:    "permit-coverage",
		IntentHash:  "sha256:intent",
		VerdictHash: "sha256:verdict",
		PolicyHash:  "sha256:policy",
		EffectType:  effects.EffectTypeExecute,
		ConnectorID: ConnectorID,
		IssuerID:    "principal:test",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	}
}
