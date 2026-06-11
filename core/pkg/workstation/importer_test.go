package workstation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestImportFixtures(t *testing.T) {
	cases := []struct {
		name           string
		wantDenied     int
		wantMemory     int
		wantLoops      int
		wantChanged    int
		wantTaintLabel string
	}{
		{name: "allowed-observe", wantDenied: 0},
		{name: "allowed-draft", wantDenied: 0, wantChanged: 1},
		{name: "denied-network", wantDenied: 1},
		{name: "denied-memory", wantDenied: 1, wantMemory: 1},
		{name: "denied-recurring-loop", wantDenied: 1, wantLoops: 1},
		{name: "prompt-injection-tainted", wantDenied: 1, wantTaintLabel: "prompt_injection"},
		{name: "demo", wantDenied: 4, wantMemory: 1, wantLoops: 1, wantChanged: 1, wantTaintLabel: "prompt_injection"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ImportArtifactDir(filepath.Join(repoRoot(t), "fixtures", "workstation", tc.name), ImportOptions{})
			if err != nil {
				t.Fatalf("ImportArtifactDir() error = %v", err)
			}
			if got := len(result.Receipt.DeniedEffects); got != tc.wantDenied {
				t.Fatalf("denied effects = %d, want %d", got, tc.wantDenied)
			}
			if got := len(result.Receipt.MemoryEffects); got != tc.wantMemory {
				t.Fatalf("memory effects = %d, want %d", got, tc.wantMemory)
			}
			if got := len(result.Receipt.RecurringLoopEffects); got != tc.wantLoops {
				t.Fatalf("recurring loop effects = %d, want %d", got, tc.wantLoops)
			}
			if got := len(result.Receipt.ChangedFiles); got != tc.wantChanged {
				t.Fatalf("changed files = %d, want %d", got, tc.wantChanged)
			}
			if tc.wantTaintLabel != "" && !receiptHasTaint(result.Receipt, tc.wantTaintLabel) {
				t.Fatalf("receipt missing taint label %q", tc.wantTaintLabel)
			}
			ok, err := VerifyReceiptSignature(result.Receipt)
			if err != nil {
				t.Fatalf("VerifyReceiptSignature() error = %v", err)
			}
			if !ok {
				t.Fatal("receipt signature did not verify")
			}
		})
	}
}

func TestImportDeterministicForSameArtifacts(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "fixtures", "workstation", "allowed-draft")
	first, err := ImportArtifactDir(dir, ImportOptions{})
	if err != nil {
		t.Fatalf("first import error = %v", err)
	}
	second, err := ImportArtifactDir(dir, ImportOptions{})
	if err != nil {
		t.Fatalf("second import error = %v", err)
	}
	if first.Receipt.ReceiptHash != second.Receipt.ReceiptHash {
		t.Fatalf("receipt hash changed: %s != %s", first.Receipt.ReceiptHash, second.Receipt.ReceiptHash)
	}
	if first.ReplayRootHash != second.ReplayRootHash {
		t.Fatalf("replay root changed: %s != %s", first.ReplayRootHash, second.ReplayRootHash)
	}
	if len(first.ProofGraph) != len(second.ProofGraph) {
		t.Fatalf("proof graph node count changed: %d != %d", len(first.ProofGraph), len(second.ProofGraph))
	}
	for i := range first.ProofGraph {
		if first.ProofGraph[i].NodeHash != second.ProofGraph[i].NodeHash {
			t.Fatalf("proof graph node %d changed: %s != %s", i, first.ProofGraph[i].NodeHash, second.ProofGraph[i].NodeHash)
		}
	}
}

func TestReceiptProofGraphAndArtifactBinding(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "fixtures", "workstation", "allowed-draft")
	result, err := ImportArtifactDir(dir, ImportOptions{})
	if err != nil {
		t.Fatalf("ImportArtifactDir() error = %v", err)
	}
	ok, err := VerifyReceiptSignature(result.Receipt)
	if err != nil {
		t.Fatalf("VerifyReceiptSignature() error = %v", err)
	}
	if !ok {
		t.Fatal("receipt signature did not verify")
	}
	for i, node := range result.ProofGraph {
		if err := node.Validate(); err != nil {
			t.Fatalf("node %d failed validation: %v", i, err)
		}
		wantLamport := uint64(i + 1)
		if node.Lamport != wantLamport || node.PrincipalSeq != wantLamport {
			t.Fatalf("node %d clock = lamport %d seq %d, want %d", i, node.Lamport, node.PrincipalSeq, wantLamport)
		}
		if i == 0 {
			if len(node.Parents) != 0 {
				t.Fatalf("first node parents = %v, want none", node.Parents)
			}
			continue
		}
		if len(node.Parents) != 1 || node.Parents[0] != result.ProofGraph[i-1].NodeHash {
			t.Fatalf("node %d parents = %v, want previous hash %s", i, node.Parents, result.ProofGraph[i-1].NodeHash)
		}
	}
	if got, want := result.Receipt.ArtifactHashes[ManifestFile], mustHashFile(filepath.Join(dir, ManifestFile)); got != want {
		t.Fatalf("manifest artifact hash = %s, want %s", got, want)
	}
	if got, want := result.Receipt.ArtifactHashes[ToolEventsFile], mustHashFile(filepath.Join(dir, ToolEventsFile)); got != want {
		t.Fatalf("tool events artifact hash = %s, want %s", got, want)
	}
	var attestation map[string]map[string]string
	for _, node := range result.ProofGraph {
		if node.Kind != proofgraph.NodeTypeAttestation {
			continue
		}
		if err := json.Unmarshal(node.Payload, &attestation); err != nil {
			t.Fatalf("parse attestation payload: %v", err)
		}
		break
	}
	if attestation["artifact_hashes"][ManifestFile] != result.Receipt.ArtifactHashes[ManifestFile] {
		t.Fatalf("attestation manifest hash %q does not bind receipt hash %q", attestation["artifact_hashes"][ManifestFile], result.Receipt.ArtifactHashes[ManifestFile])
	}
	receiptBytes, err := json.Marshal(result.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(receiptBytes)), "raw_chat") || strings.Contains(strings.ToLower(string(receiptBytes)), "transcript") {
		t.Fatal("receipt unexpectedly contains raw chat transcript material")
	}
}

func TestDefaultProfileFailsClosedForOperateAndEgress(t *testing.T) {
	profile := DefaultObserveDraftProfile()
	verdict, reasonCode, _ := EvaluateEvent(profile, ToolEvent{
		Type:       "network_egress",
		Target:     "https://pastebin.com/raw/example",
		EffectMode: contracts.WorkstationEffectModeOperate,
	})
	if verdict != contracts.WorkstationVerdictDeny || reasonCode != "EGRESS_ALLOWLIST_EMPTY" {
		t.Fatalf("network verdict = %s/%s, want DENY/EGRESS_ALLOWLIST_EMPTY", verdict, reasonCode)
	}
	verdict, reasonCode, _ = EvaluateEvent(profile, ToolEvent{
		Type:       "memory_write",
		EffectType: contracts.EffectTypeWorkstationMemoryWrite,
		EffectMode: contracts.WorkstationEffectModeOperate,
	})
	if verdict != contracts.WorkstationVerdictDeny || reasonCode != "OPERATE_PERMISSIONS_EMPTY" {
		t.Fatalf("memory verdict = %s/%s, want DENY/OPERATE_PERMISSIONS_EMPTY", verdict, reasonCode)
	}
	verdict, reasonCode, _ = EvaluateEvent(profile, ToolEvent{
		Type:       "file_write",
		EffectType: contracts.EffectTypeWorkstationFileWrite,
		EffectMode: contracts.WorkstationEffectModeDraft,
	})
	if verdict != contracts.WorkstationVerdictAllow || reasonCode != "" {
		t.Fatalf("draft verdict = %s/%s, want ALLOW/empty", verdict, reasonCode)
	}
}

func TestExpandedOperatePolicyReasons(t *testing.T) {
	root := repoRoot(t)
	permissive, err := LoadPolicyProfileFile(filepath.Join(root, "fixtures", "workstation", "policies", "observe_draft.v1.permissive.json"))
	if err != nil {
		t.Fatalf("load permissive profile: %v", err)
	}
	mixed, err := LoadPolicyProfileFile(filepath.Join(root, "fixtures", "workstation", "policies", "observe_draft.v1.mixed.json"))
	if err != nil {
		t.Fatalf("load mixed profile: %v", err)
	}
	classRestricted := permissive
	classRestricted.Memory.AllowedClasses = []string{"M1_EPISODIC"}
	loopExpiry := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name        string
		profile     contracts.WorkstationPolicyProfile
		event       ToolEvent
		wantVerdict string
		wantReason  string
	}{
		{
			name:    "allowed network destination",
			profile: permissive,
			event: ToolEvent{
				Type:       "network_egress",
				EffectType: contracts.EffectTypeWorkstationNetworkEgress,
				EffectMode: contracts.WorkstationEffectModeOperate,
				Target:     "https://api.github.com/repos/Mindburn-Labs/helm",
			},
			wantVerdict: contracts.WorkstationVerdictAllow,
		},
		{
			name:    "memory class disallowed",
			profile: classRestricted,
			event: ToolEvent{
				Type:       "memory_write",
				EffectType: contracts.EffectTypeWorkstationMemoryWrite,
				EffectMode: contracts.WorkstationEffectModeOperate,
				MemoryEffect: &contracts.AgentMemoryEffect{
					MemoryClass: "M4_PROCEDURAL",
					TTLDays:     7,
				},
			},
			wantVerdict: contracts.WorkstationVerdictDeny,
			wantReason:  "MEMORY_CLASS_DISALLOWED",
		},
		{
			name:    "memory permission missing",
			profile: mixed,
			event: ToolEvent{
				Type:       "memory_write",
				EffectType: contracts.EffectTypeWorkstationMemoryWrite,
				EffectMode: contracts.WorkstationEffectModeOperate,
				MemoryEffect: &contracts.AgentMemoryEffect{
					MemoryClass: "M1_EPISODIC",
					TTLDays:     7,
				},
			},
			wantVerdict: contracts.WorkstationVerdictDeny,
			wantReason:  "OPERATE_PERMISSION_NOT_GRANTED",
		},
		{
			name:    "memory ttl exceeds policy",
			profile: permissive,
			event: ToolEvent{
				Type:       "memory_write",
				EffectType: contracts.EffectTypeWorkstationMemoryWrite,
				EffectMode: contracts.WorkstationEffectModeOperate,
				MemoryEffect: &contracts.AgentMemoryEffect{
					MemoryClass: "M4_PROCEDURAL",
					TTLDays:     31,
				},
			},
			wantVerdict: contracts.WorkstationVerdictDeny,
			wantReason:  "MEMORY_TTL_EXCEEDS_POLICY",
		},
		{
			name:    "recurring loop missing schedule",
			profile: permissive,
			event: ToolEvent{
				Type:       "recurring_loop",
				EffectType: contracts.EffectTypeWorkstationRecurringLoop,
				EffectMode: contracts.WorkstationEffectModeOperate,
				RecurringLoopEffect: &contracts.AgentRecurringLoopEffect{
					MaxRuntime: "10m",
					ToolScope:  []string{"shell.read"},
					ExpiresAt:  loopExpiry,
				},
			},
			wantVerdict: contracts.WorkstationVerdictDeny,
			wantReason:  "RECURRING_LOOP_MISSING_SCHEDULE",
		},
		{
			name:    "tainted mcp denied",
			profile: permissive,
			event: ToolEvent{
				Type:        "mcp_tool_call",
				EffectType:  contracts.EffectTypeWorkstationMCPToolCall,
				EffectMode:  contracts.WorkstationEffectModeOperate,
				TaintLabels: []string{"prompt_injection"},
			},
			wantVerdict: contracts.WorkstationVerdictDeny,
			wantReason:  "TAINTED_CONTEXT_REQUIRES_DENY",
		},
		{
			name:    "draft outside scope",
			profile: mixed,
			event: ToolEvent{
				Type:       "file_write",
				EffectType: contracts.EffectTypeWorkstationFileWrite,
				EffectMode: contracts.WorkstationEffectModeDraft,
				Target:     "../secrets.txt",
			},
			wantVerdict: contracts.WorkstationVerdictDeny,
			wantReason:  "DRAFT_TARGET_OUTSIDE_WORKSPACE_SCOPE",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, reason, _ := EvaluateEvent(tc.profile, tc.event)
			if verdict != tc.wantVerdict || reason != tc.wantReason {
				t.Fatalf("EvaluateEvent() = %s/%s, want %s/%s", verdict, reason, tc.wantVerdict, tc.wantReason)
			}
		})
	}
}

func TestMemoryEffectDefaultsRetentionAndDataClass(t *testing.T) {
	profile := DefaultObserveDraftProfile()
	result, err := BuildReceipt(RunManifest{
		RunID:        "run_memory_defaults",
		Goal:         "record memory default mapping",
		ActorID:      "agent.local",
		WorkspaceID:  "workspace.local",
		AgentSurface: "codex",
	}, DiffSummary{}, ValidationArtifact{}, []ToolEvent{{
		EventID:    "mem-defaults",
		Type:       "memory_write",
		EffectMode: contracts.WorkstationEffectModeOperate,
		MemoryEffect: &contracts.AgentMemoryEffect{
			MemoryClass: "M4_PROCEDURAL",
			Sensitivity: "restricted",
			ContentHash: "sha256:memory-defaults",
		},
	}}, profile, map[string]string{ManifestFile: strings.Repeat("a", 64)}, ImportOptions{})
	if err != nil {
		t.Fatalf("BuildReceipt() error = %v", err)
	}
	if got := len(result.Receipt.MemoryEffects); got != 1 {
		t.Fatalf("memory effects = %d, want 1", got)
	}
	memory := result.Receipt.MemoryEffects[0]
	if memory.TTLDays != profile.Memory.DefaultTTLDays {
		t.Fatalf("ttl_days = %d, want %d", memory.TTLDays, profile.Memory.DefaultTTLDays)
	}
	if memory.DataClass != contracts.DataClassRestricted {
		t.Fatalf("data_class = %q, want %q", memory.DataClass, contracts.DataClassRestricted)
	}
	if memory.Verdict != contracts.WorkstationVerdictDeny || memory.ReasonCode != "OPERATE_PERMISSIONS_EMPTY" {
		t.Fatalf("memory verdict = %s/%s, want DENY/OPERATE_PERMISSIONS_EMPTY", memory.Verdict, memory.ReasonCode)
	}
}

func TestDecisionReceiptsOperatorViewEvidenceAndCertification(t *testing.T) {
	root := repoRoot(t)
	profile := DefaultObserveDraftProfile()
	network, err := Decide(profile, decisionRequest("network", "https://forbidden.example"), DecisionOptions{})
	if err != nil {
		t.Fatalf("Decide(network) error = %v", err)
	}
	if network.Verdict != contracts.WorkstationVerdictDeny || network.ReasonCode != "EGRESS_ALLOWLIST_EMPTY" {
		t.Fatalf("network decision = %s/%s, want DENY/EGRESS_ALLOWLIST_EMPTY", network.Verdict, network.ReasonCode)
	}
	if ok, err := VerifyDecisionReceiptSignature(network); err != nil || !ok {
		t.Fatalf("network decision signature = %v/%v, want valid", ok, err)
	}
	draft, err := Decide(profile, decisionRequest("file", "docs/example.md"), DecisionOptions{})
	if err != nil {
		t.Fatalf("Decide(file) error = %v", err)
	}
	if draft.Verdict != contracts.WorkstationVerdictAllow {
		t.Fatalf("draft verdict = %s, want ALLOW", draft.Verdict)
	}

	imported, err := ImportArtifactDir(filepath.Join(root, "fixtures", "workstation", "denied-recurring-loop"), ImportOptions{})
	if err != nil {
		t.Fatalf("import denied-recurring-loop: %v", err)
	}
	packDir := filepath.Join(t.TempDir(), "evidencepack")
	export, err := ExportEvidencePack(imported, packDir)
	if err != nil {
		t.Fatalf("ExportEvidencePack() error = %v", err)
	}
	if export.RootHash == "" {
		t.Fatal("evidence pack root hash is empty")
	}
	if _, err := LoadEvidencePackIndex(packDir); err != nil {
		t.Fatalf("LoadEvidencePackIndex() error = %v", err)
	}

	dir := t.TempDir()
	writeJSONFixture(t, filepath.Join(dir, "network.json"), network)
	writeJSONFixture(t, filepath.Join(dir, "import.json"), imported)
	view, err := BuildOperatorView(dir)
	if err != nil {
		t.Fatalf("BuildOperatorView() error = %v", err)
	}
	if len(view.Runs) != 2 || len(view.DeniedTimeline) != 2 || len(view.RecurringLoops) != 1 {
		t.Fatalf("operator view counts = runs %d denied %d loops %d", len(view.Runs), len(view.DeniedTimeline), len(view.RecurringLoops))
	}

	cert := CertifyAdapterFixtures("codex", filepath.Join(root, "fixtures", "workstation"), CertificationHighRiskEffectCapable)
	if !cert.Passed || cert.CertifiedAs != CertificationHighRiskEffectCapable {
		t.Fatalf("certification = passed %v as %s checks=%+v", cert.Passed, cert.CertifiedAs, cert.Checks)
	}
}

func TestWorkstationSchemas(t *testing.T) {
	root := repoRoot(t)
	receiptSchema := compileSchema(t, filepath.Join(root, "protocols", "json-schemas", "workstation", "agent_run_receipt.v1.schema.json"))
	decisionSchema := compileSchema(t, filepath.Join(root, "protocols", "json-schemas", "workstation", "workstation_policy_decision_receipt.v1.schema.json"))
	scopeAuditSchema := compileSchema(t, filepath.Join(root, "protocols", "json-schemas", "workstation", "scope_audit_report.v1.schema.json"))
	profileSchema := compileSchema(t, filepath.Join(root, "protocols", "json-schemas", "policy", "workstation_policy_profile.v1.schema.json"))

	for _, fixture := range []string{"allowed-observe", "denied-memory", "denied-recurring-loop", "scope-audit-all-boundaries"} {
		result, err := ImportArtifactDir(filepath.Join(root, "fixtures", "workstation", fixture), ImportOptions{})
		if err != nil {
			t.Fatalf("import %s: %v", fixture, err)
		}
		validateSchemaValue(t, receiptSchema, result.Receipt)
	}
	for _, profile := range []string{"observe_draft.v1.allow.json", "observe_draft.v1.fail_closed.json", "observe_draft.v1.permissive.json", "observe_draft.v1.mixed.json"} {
		data, err := os.ReadFile(filepath.Join(root, "fixtures", "workstation", "policies", profile))
		if err != nil {
			t.Fatal(err)
		}
		var raw any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		if err := profileSchema.Validate(raw); err != nil {
			t.Fatalf("profile %s does not validate: %v", profile, err)
		}
	}
	decision, err := Decide(DefaultObserveDraftProfile(), decisionRequest("network", "https://forbidden.example"), DecisionOptions{})
	if err != nil {
		t.Fatalf("decision receipt: %v", err)
	}
	validateSchemaValue(t, decisionSchema, decision)

	scopeAuditImport, err := ImportArtifactDir(filepath.Join(root, "fixtures", "workstation", "scope-audit-all-boundaries"), ImportOptions{})
	if err != nil {
		t.Fatalf("scope audit fixture import: %v", err)
	}
	scopeAuditDir := t.TempDir()
	scopeAuditReceipt := filepath.Join(scopeAuditDir, "scope-audit-all-boundaries.json")
	writeJSONFixture(t, scopeAuditReceipt, scopeAuditImport.Receipt)
	scopeAuditReport, err := BuildScopeAudit(scopeAuditReceipt)
	if err != nil {
		t.Fatalf("scope audit report: %v", err)
	}
	validateSchemaValue(t, scopeAuditSchema, scopeAuditReport)

	invalidLoopReceipt := map[string]any{
		"receipt_version":        contracts.AgentRunReceiptVersion,
		"receipt_id":             "arr_bad",
		"run_id":                 "run_bad",
		"goal":                   "bad loop",
		"actor":                  map[string]any{"actor_id": "agent", "actor_type": "agent"},
		"workspace":              map[string]any{"workspace_id": "workspace"},
		"agent_surface":          "codex",
		"policy_profile":         contracts.PolicyProfileWorkstationObserveDraftV1,
		"artifact_hashes":        map[string]any{"run.manifest.json": strings.Repeat("a", 64)},
		"tool_actions":           []any{},
		"changed_files":          []any{},
		"validation_results":     []any{},
		"memory_effects":         []any{},
		"recurring_loop_effects": []any{map[string]any{"effect_id": "loop_bad", "schedule": "FREQ=DAILY"}},
		"denied_effects":         []any{},
		"proofgraph_refs":        []any{},
		"evidence_pack_refs":     []any{"artifact-root:" + strings.Repeat("b", 64)},
		"created_at":             "2026-05-20T00:00:00Z",
		"receipt_hash":           strings.Repeat("c", 64),
		"signature":              strings.Repeat("d", 128),
		"signer_key_id":          "ed25519:test",
	}
	if err := receiptSchema.Validate(invalidLoopReceipt); err == nil {
		t.Fatal("expected schema to reject recurring loop without max_runtime, tool_scope, expires_at, verdict, and observed_only")
	}
}

func compileSchema(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema %s: %v", path, err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	url := "file:///" + strings.ReplaceAll(path, string(filepath.Separator), "/")
	if err := compiler.AddResource(url, strings.NewReader(string(data))); err != nil {
		t.Fatalf("add schema %s: %v", path, err)
	}
	schema, err := compiler.Compile(url)
	if err != nil {
		t.Fatalf("compile schema %s: %v", path, err)
	}
	return schema
}

func validateSchemaValue(t *testing.T, schema *jsonschema.Schema, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(raw); err != nil {
		t.Fatalf("value does not validate: %v", err)
	}
}

func writeJSONFixture(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func receiptHasTaint(receipt *contracts.AgentRunReceipt, label string) bool {
	for _, action := range receipt.ToolActions {
		for _, candidate := range action.TaintLabels {
			if candidate == label {
				return true
			}
		}
	}
	return false
}
