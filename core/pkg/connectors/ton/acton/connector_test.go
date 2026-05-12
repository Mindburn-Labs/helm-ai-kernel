package acton

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts/actuators"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/effects"
)

type fakeExecutor struct {
	stdout []byte
	stderr []byte
	exit   int
	calls  int
}

func (f *fakeExecutor) Exec(_ context.Context, _ string, req *actuators.ExecRequest) (*actuators.ExecResult, error) {
	f.calls++
	spec := &actuators.SandboxSpec{Runtime: "sha256:fixture", Egress: actuators.EgressPolicy{Disabled: true}}
	return &actuators.ExecResult{
		ExitCode: f.exit,
		Stdout:   f.stdout,
		Stderr:   f.stderr,
		Duration: time.Millisecond,
		Receipt:  actuators.ComputeReceiptFragment(req, f.stdout, f.stderr, f.Provider(), time.Unix(1700000000, 0).UTC(), spec, actuators.EffectExecShell),
	}, nil
}

func (f *fakeExecutor) Provider() string { return "fake-sandbox" }

func TestBuildArgvRejectsRawCommandFields(t *testing.T) {
	_, err := BuildArgv(ActionBuild, map[string]any{"cmd": "acton build"})
	if err == nil {
		t.Fatal("expected raw command rejection")
	}
	if reasonFromError(err, "") != ReasonRawShellForbidden {
		t.Fatalf("wrong reason: %v", err)
	}
}

func TestCurrentActonVersionMappings(t *testing.T) {
	versionArgv, err := BuildArgv(ActionVersion, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(versionArgv); got != 2 || versionArgv[0] != "acton" || versionArgv[1] != "--version" {
		t.Fatalf("unexpected version argv: %#v", versionArgv)
	}
	envArgv, err := BuildArgv(ActionEnv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(envArgv); got != 2 || envArgv[0] != "acton" || envArgv[1] != "doctor" {
		t.Fatalf("unexpected env argv: %#v", envArgv)
	}
	if !stringIn("1.0.0", SupportedActonVersions) || !stringIn("1.4.0", SupportedTolkCompilerVersions) {
		t.Fatalf("validated Acton/Tolk versions are not in the connector contract")
	}
}

func TestMainnetGenericScriptDeniedWithoutDispatch(t *testing.T) {
	exec := &fakeExecutor{stdout: []byte(`{"ok":true}`)}
	connector := NewConnector(Config{Runner: Runner{Executor: exec, SandboxID: "s1"}, SandboxGrant: sealedGrant(t, true, false)})
	receipt := executeReceipt(t, connector, ActionScriptMainnet, map[string]any{
		"script_path":           "contracts/scripts/deploy.tolk",
		"script_hash":           "sha256:script",
		"tolk_compiler_version": "fixture-tolk-1.0.0",
		"wallet_ref":            "wallet:tenant-prod-ton-1",
		"max_ton_spend":         "0.01",
		"generic":               true,
		"p0_ceilings": map[string]any{
			"MAX_TON_MAINNET_SPEND_PER_ACTION": "1",
			"ALLOW_MAINNET_DEPLOY":             true,
		},
	})
	if receipt.Verdict != contracts.VerdictDeny || receipt.ReasonCode != ReasonGenericMainnetScriptDenied {
		t.Fatalf("expected generic mainnet deny, got %s/%s", receipt.Verdict, receipt.ReasonCode)
	}
	if exec.calls != 0 {
		t.Fatalf("generic mainnet should not dispatch, calls=%d", exec.calls)
	}
}

func TestLocalBuildAllowedExecutesAndReceipts(t *testing.T) {
	exec := &fakeExecutor{stdout: []byte(`{"build":"ok","artifact":"contract.boc"}`)}
	connector := NewConnector(Config{Runner: Runner{Executor: exec, SandboxID: "s1"}, SandboxGrant: sealedGrant(t, false, true)})
	receipt := executeReceipt(t, connector, ActionBuild, map[string]any{
		"acton_version":              "fixture-acton-1.0.0",
		"tolk_compiler_version":      "fixture-tolk-1.0.0",
		"source_tree_hash":           "sha256:source",
		"manifest_hash":              "sha256:manifest",
		"expected_output_shape_hash": outputShapeHash([]byte(`{"build":"ok","artifact":"contract.boc"}`)),
	})
	if receipt.Verdict != contracts.VerdictAllow || receipt.Status != "ok" {
		t.Fatalf("expected allow/ok, got %s/%s/%s", receipt.Verdict, receipt.Status, receipt.ReasonCode)
	}
	if receipt.RequestHash == "" || receipt.StdoutHash == "" {
		t.Fatalf("receipt hashes missing: %#v", receipt)
	}
	if exec.calls != 1 {
		t.Fatalf("expected one dispatch, got %d", exec.calls)
	}
}

func TestTestnetDeployAllowedRequiresManifestWalletSpendAndNetwork(t *testing.T) {
	exec := &fakeExecutor{stdout: []byte(`{"tx_hash":"abc"}`)}
	connector := NewConnector(Config{Runner: Runner{Executor: exec, SandboxID: "s1"}, SandboxGrant: sealedGrant(t, true, false)})
	manifest := scriptManifest("contracts/scripts/deploy.tolk", "sha256:script", NetworkTestnet)
	receipt := executeReceipt(t, connector, ActionScriptTestnet, map[string]any{
		"script_path":           "contracts/scripts/deploy.tolk",
		"script_hash":           "sha256:script",
		"tolk_compiler_version": "fixture-tolk-1.0.0",
		"wallet_ref":            "wallet:tenant-test-ton-1",
		"max_ton_spend":         "0.05",
		"script_manifest":       manifest,
		"expected_effects":      manifest.ExpectedEffects,
		"p0_ceilings": map[string]any{
			"MAX_TON_SPEND_PER_ACTION": "0.10",
			"ALLOW_TESTNET_DEPLOY":     true,
		},
	})
	if receipt.Verdict != contracts.VerdictAllow || exec.calls != 1 {
		t.Fatalf("expected allowed testnet dispatch, got %s/%s calls=%d", receipt.Verdict, receipt.ReasonCode, exec.calls)
	}
}

func TestPlaintextMnemonicDenied(t *testing.T) {
	exec := &fakeExecutor{}
	connector := NewConnector(Config{Runner: Runner{Executor: exec, SandboxID: "s1"}, SandboxGrant: sealedGrant(t, true, false)})
	manifest := scriptManifest("contracts/scripts/deploy.tolk", "sha256:script", NetworkTestnet)
	receipt := executeReceipt(t, connector, ActionScriptTestnet, map[string]any{
		"script_path":      "contracts/scripts/deploy.tolk",
		"script_hash":      "sha256:script",
		"wallet_ref":       "wallet:seed phrase one two three",
		"max_ton_spend":    "0.01",
		"script_manifest":  manifest,
		"expected_effects": manifest.ExpectedEffects,
		"p0_ceilings": map[string]any{
			"MAX_TON_SPEND_PER_ACTION": "1",
			"ALLOW_TESTNET_DEPLOY":     true,
		},
	})
	if receipt.Verdict != contracts.VerdictDeny || receipt.ReasonCode != ReasonPlaintextMnemonicForbidden {
		t.Fatalf("expected plaintext mnemonic deny, got %s/%s", receipt.Verdict, receipt.ReasonCode)
	}
	if exec.calls != 0 {
		t.Fatalf("secret denial should not dispatch")
	}
}

func TestVerifyDryRunRequiresCompilerPin(t *testing.T) {
	exec := &fakeExecutor{}
	connector := NewConnector(Config{Runner: Runner{Executor: exec, SandboxID: "s1"}, SandboxGrant: sealedGrant(t, true, false)})
	receipt := executeReceipt(t, connector, ActionVerifyDryRun, map[string]any{
		"address":     "EQDfixture",
		"source_path": "contracts/main.tolk",
	})
	if receipt.Verdict != contracts.VerdictDeny || receipt.ReasonCode != ReasonCompilerUnpinned {
		t.Fatalf("expected compiler pin deny, got %s/%s", receipt.Verdict, receipt.ReasonCode)
	}
}

func TestOutputDriftFailsClosed(t *testing.T) {
	exec := &fakeExecutor{stdout: []byte(`{"unexpected":true}`)}
	connector := NewConnector(Config{Runner: Runner{Executor: exec, SandboxID: "s1"}, SandboxGrant: sealedGrant(t, false, true)})
	receipt := executeReceipt(t, connector, ActionBuild, map[string]any{
		"acton_version":              "fixture-acton-1.0.0",
		"tolk_compiler_version":      "fixture-tolk-1.0.0",
		"expected_output_shape_hash": outputShapeHash([]byte(`{"build":"ok"}`)),
	})
	if receipt.Verdict != contracts.VerdictDeny || receipt.ReasonCode != ReasonConnectorContractDrift {
		t.Fatalf("expected drift deny, got %s/%s drift=%#v", receipt.Verdict, receipt.ReasonCode, receipt.Drift)
	}
}

func TestEvidencePackBuildsDeterministicContents(t *testing.T) {
	env, err := NewEnvelope(map[string]any{
		"acton_version":         "fixture-acton-1.0.0",
		"tolk_compiler_version": "fixture-tolk-1.0.0",
	}, ActionBuild, "sha256:intent", 0)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewPreDispatchReceipt(env, PolicyDecision{Verdict: contracts.VerdictAllow, ReasonCode: ReasonOK, Dispatch: true})
	if err != nil {
		t.Fatal(err)
	}
	result, err := BuildEvidencePack(EvidencePackInput{
		Envelope:   env,
		Receipt:    receipt,
		P0Ceilings: DefaultP0Ceilings(),
		CreatedAt:  time.Unix(1700000000, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"manifest.json", "acton_command_envelope.json", "connector_contract_bundle.json", "receipts/tool_receipt.json", "replay_instructions.txt"} {
		if _, ok := result.Contents[required]; !ok {
			t.Fatalf("missing evidence entry %s", required)
		}
	}
}

func TestConnectorContractAndRegistryDescriptors(t *testing.T) {
	bundle := ContractBundle()
	if bundle.ConnectorID != ConnectorID || len(bundle.AllowedCommands) != len(commandSpecs) {
		t.Fatalf("invalid contract bundle: %#v", bundle)
	}
	if !bundle.DriftDetection.FailClosed {
		t.Fatal("drift detection must fail closed")
	}
	if err := ToolDescriptor().Validate(); err != nil {
		t.Fatalf("tool descriptor invalid: %v", err)
	}
	release := ConnectorRelease("abc123", "sig://ton-acton")
	if release.ConnectorID != ConnectorID || release.SandboxProfile == "" || len(release.SchemaRefs) == 0 {
		t.Fatalf("connector release metadata incomplete: %#v", release)
	}
}

func executeReceipt(t *testing.T, connector *Connector, action ActionURN, params map[string]any) *ActonReceipt {
	t.Helper()
	permit := &effects.EffectPermit{
		PermitID:    "permit-1",
		IntentHash:  "sha256:intent",
		VerdictHash: "sha256:verdict",
		PolicyHash:  "sha256:policy",
		EffectType:  effects.EffectTypeExecute,
		ConnectorID: ConnectorID,
		IssuerID:    "principal:test",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	out, err := connector.Execute(context.Background(), permit, string(action), params)
	if err != nil {
		t.Fatal(err)
	}
	receipt, ok := out.(*ActonReceipt)
	if !ok {
		t.Fatalf("expected ActonReceipt, got %T", out)
	}
	return receipt
}

func sealedGrant(t *testing.T, network bool, writable bool) *contracts.SandboxGrant {
	t.Helper()
	mode := "ro"
	if writable {
		mode = "rw"
	}
	net := contracts.NetworkGrant{Mode: "deny-all"}
	if network {
		net = contracts.NetworkGrant{Mode: "allowlist", Destinations: []string{"toncenter.com", "testnet.toncenter.com"}}
	}
	grant, err := (contracts.SandboxGrant{
		GrantID:            "grant-1",
		Runtime:            "docker",
		Profile:            "ton-acton",
		ImageDigest:        "sha256:fixture",
		FilesystemPreopens: []contracts.FilesystemPreopen{{Path: ".", Mode: mode}},
		Env:                contracts.EnvExposurePolicy{Mode: "deny-all"},
		Network:            net,
		DeclaredAt:         time.Unix(1700000000, 0).UTC(),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	return &grant
}

func scriptManifest(path, hash string, network NetworkProfile) ScriptManifest {
	return ScriptManifest{
		SchemaVersion:   ScriptManifestSchemaVersion,
		ScriptPath:      path,
		ScriptHash:      hash,
		AllowedNetworks: []NetworkProfile{network},
		ExpectedEffects: []ExpectedEffect{{
			EffectKind:                 "TON_DEPLOY",
			EffectClass:                EffectIrreversible,
			Network:                    string(network),
			WalletRef:                  "wallet:tenant-test-ton-1",
			MaxTONSpend:                "0.05",
			ContractCodeHash:           "sha256:code",
			RequiresSourceVerification: true,
		}},
		RequiredPreflight: RequiredPreflight{Build: true, Test: true, Check: true, FormatCheck: true},
	}
}
