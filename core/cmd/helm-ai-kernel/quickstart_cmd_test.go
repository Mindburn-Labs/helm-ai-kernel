package main

// quantum_posture: classical Ed25519/SHA-256 only; no post-quantum assurance
// is claimed or provided by this file.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
)

func TestLoadServePolicyTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "release.high_risk.v3.toml")
	if err := os.WriteFile(path, []byte(`
name = "release.high_risk.v3"
profile = "high_risk"
reference_pack = "./reference_packs/eu_ai_act_high_risk.v2.json"

[server]
bind = "127.0.0.1"
port = 7714

[receipts]
store = "sqlite"
path = "./data/receipts.db"
`), 0600); err != nil {
		t.Fatal(err)
	}

	policy, err := loadServePolicy(path)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if policy.Server.Port != 7714 || policy.Receipts.Store != "sqlite" {
		t.Fatalf("unexpected policy: %+v", policy)
	}
}

func TestLoadServePolicyRuntimeCompilesReferencePackActions(t *testing.T) {
	dir := t.TempDir()
	refDir := filepath.Join(dir, "reference_packs")
	if err := os.MkdirAll(refDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(refDir, "runtime.json"), []byte(`{
  "pack_id": "runtime-pack",
  "version": 1,
  "runtime_actions": [
    {"action": "EXECUTE_TOOL", "expression": "true", "description": "allow test tool execution"}
  ]
}`), 0600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(policyPath, []byte(`
name = "runtime"
profile = "test"
reference_pack = "./reference_packs/runtime.json"

[server]
bind = "127.0.0.1"
port = 7714

[receipts]
store = "sqlite"
path = "./data/receipts.db"
`), 0600); err != nil {
		t.Fatal(err)
	}

	runtime, err := loadServePolicyRuntime(policyPath)
	if err != nil {
		t.Fatalf("load runtime: %v", err)
	}
	if runtime.ReferencePack.PackID != "runtime-pack" {
		t.Fatalf("pack id = %q", runtime.ReferencePack.PackID)
	}
	rule, ok := runtime.Graph.Rules["EXECUTE_TOOL"]
	if !ok {
		t.Fatalf("expected EXECUTE_TOOL rule")
	}
	if len(rule.Requirements) != 1 || rule.Requirements[0].Expression != "true" {
		t.Fatalf("unexpected rule: %+v", rule)
	}
}

func TestCanonicalEUAIActMappingPackContract(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", "..", ".."))

	v1, err := os.ReadFile(filepath.Join(repoRoot, "reference_packs", "eu_ai_act_high_risk.v1.json"))
	if err != nil {
		t.Fatalf("read immutable v1 pack: %v", err)
	}
	v1Digest := sha256.Sum256(v1)
	if got, want := hex.EncodeToString(v1Digest[:]), "8a33ad51441d6d939d74da2be388c1d11c12da1e055f1aeca72ca2763ebc05c4"; got != want {
		t.Fatalf("published v1 bytes changed: sha256=%s, want %s", got, want)
	}

	type mappingControl struct {
		ControlID     string          `json:"control_id"`
		MappingStatus string          `json:"mapping_status"`
		Enforcement   json.RawMessage `json:"enforcement"`
	}
	type candidateMapping struct {
		CandidateOutcome   string `json:"candidate_outcome"`
		CandidateCondition string `json:"candidate_condition"`
		Rationale          string `json:"rationale"`
	}
	type mappingProgram struct {
		ProgramID               string             `json:"program_id"`
		Controls                []mappingControl   `json:"controls"`
		CandidatePolicyMappings []candidateMapping `json:"candidate_policy_mappings"`
		PolicyRules             json.RawMessage    `json:"policy_rules"`
	}
	type mappingPack struct {
		PackID             string           `json:"pack_id"`
		Version            int              `json:"version"`
		ArtifactKind       string           `json:"artifact_kind"`
		RuntimeEnforcement *bool            `json:"runtime_enforcement"`
		Description        string           `json:"description"`
		Programs           []mappingProgram `json:"programs"`
		ApplicabilityDates struct {
			GeneralApplication                   string `json:"general_application"`
			Article50GeneralApplication          string `json:"article_50_general_application"`
			Article50PreexistingSystemTransition string `json:"article_50_2_preexisting_system_transition"`
			AnnexIIISectionsOneToThree           string `json:"chapter_iii_sections_1_3_annex_iii"`
			AnnexISectionsOneToThree             string `json:"chapter_iii_sections_1_3_annex_i"`
			Article6Paragraph5Deferred           *bool  `json:"article_6_5_deferred"`
		} `json:"applicability_dates"`
		ApplicabilityDatesProvenance struct {
			Sources []string `json:"sources"`
		} `json:"applicability_dates_provenance"`
		EvidenceMappings     map[string]string `json:"evidence_mappings"`
		RuntimeActions       json.RawMessage   `json:"runtime_actions"`
		Actions              json.RawMessage   `json:"actions"`
		BudgetConstraints    json.RawMessage   `json:"budget_constraints"`
		EvidenceRequirements json.RawMessage   `json:"evidence_requirements"`
	}

	v2, err := os.ReadFile(filepath.Join(repoRoot, "reference_packs", "eu_ai_act_high_risk.v2.json"))
	if err != nil {
		t.Fatalf("read v2 mapping pack: %v", err)
	}
	var pack mappingPack
	if err := json.Unmarshal(v2, &pack); err != nil {
		t.Fatalf("decode v2 mapping pack: %v", err)
	}
	if pack.PackID != "eu-ai-act-high-risk-v2" || pack.Version != 2 {
		t.Fatalf("unexpected v2 identity: %q version %d", pack.PackID, pack.Version)
	}
	if pack.ArtifactKind != "COMPLIANCE_MAPPING" || pack.RuntimeEnforcement == nil || *pack.RuntimeEnforcement {
		t.Fatalf("v2 must explicitly be mapping-only: kind=%q runtime_enforcement=%v", pack.ArtifactKind, pack.RuntimeEnforcement)
	}
	if !strings.Contains(strings.ToLower(pack.Description), "does not configure runtime policy") {
		t.Fatalf("v2 description must disclose mapping-only semantics: %q", pack.Description)
	}
	if len(pack.RuntimeActions) != 0 || len(pack.Actions) != 0 || len(pack.BudgetConstraints) != 0 || len(pack.EvidenceRequirements) != 0 {
		t.Fatal("mapping-only v2 must not contain runtime actions, budgets, or enforcement-shaped evidence requirements")
	}
	if len(pack.Programs) == 0 {
		t.Fatal("v2 mapping must contain at least one program")
	}
	for _, program := range pack.Programs {
		if strings.TrimSpace(program.ProgramID) == "" || len(program.Controls) == 0 || len(program.CandidatePolicyMappings) == 0 {
			t.Fatalf("program must contain identity, controls, and candidate mappings: %+v", program)
		}
		if len(program.PolicyRules) != 0 {
			t.Fatalf("program %q must not misrepresent candidate mappings as policy_rules", program.ProgramID)
		}
		for _, control := range program.Controls {
			if strings.TrimSpace(control.ControlID) == "" || control.MappingStatus != "MAPPED" || len(control.Enforcement) != 0 {
				t.Fatalf("program %q has a misrepresented control: %+v", program.ProgramID, control)
			}
		}
		for _, mapping := range program.CandidatePolicyMappings {
			if mapping.CandidateOutcome == "" || mapping.CandidateCondition == "" || mapping.Rationale == "" {
				t.Fatalf("program %q has an empty candidate mapping: %+v", program.ProgramID, mapping)
			}
		}
	}

	dates := pack.ApplicabilityDates
	if dates.GeneralApplication != "2026-08-02" || dates.Article50GeneralApplication != "2026-08-02" ||
		dates.Article50PreexistingSystemTransition != "2026-12-02" ||
		dates.AnnexIIISectionsOneToThree != "2027-12-02" || dates.AnnexISectionsOneToThree != "2028-08-02" ||
		dates.Article6Paragraph5Deferred == nil || *dates.Article6Paragraph5Deferred {
		t.Fatalf("unexpected v2 applicability dates or Article 6(5) carve-out: %+v", dates)
	}
	if len(pack.ApplicabilityDatesProvenance.Sources) != 2 ||
		!strings.Contains(pack.ApplicabilityDatesProvenance.Sources[0], "data.europa.eu/eli/reg/2024/1689") ||
		!strings.Contains(pack.ApplicabilityDatesProvenance.Sources[1], "data.europa.eu/eli/reg/2026/1744") {
		t.Fatalf("v2 must retain both official ELI sources: %v", pack.ApplicabilityDatesProvenance.Sources)
	}
	if pack.EvidenceMappings["qtsp_timestamp_anchor"] != "OPTIONAL_MAPPING_ONLY" {
		t.Fatalf("QTSP must remain an optional evidence mapping, got %q", pack.EvidenceMappings["qtsp_timestamp_anchor"])
	}

	runtime, err := loadServePolicyRuntime(filepath.Join(repoRoot, "release.high_risk.v3.toml"))
	if err != nil {
		t.Fatalf("load canonical mapping-only policy: %v", err)
	}
	if runtime.ReferencePack.PackID != pack.PackID || len(runtime.Graph.Rules) != 0 || len(runtime.AllowMap()) != 0 {
		t.Fatalf("mapping-only pack must compile fail-closed with zero runtime rules: pack=%q rules=%d allow=%v", runtime.ReferencePack.PackID, len(runtime.Graph.Rules), runtime.AllowMap())
	}
}

func TestCompileServePolicySnapshotRequiresReferencePackDigest(t *testing.T) {
	dir := t.TempDir()
	refDir := filepath.Join(dir, "reference_packs")
	if err := os.MkdirAll(refDir, 0750); err != nil {
		t.Fatal(err)
	}
	refBytes := []byte(`{
  "pack_id": "runtime-pack",
  "version": 1,
  "runtime_actions": [
    {"action": "EXECUTE_TOOL", "expression": "true"}
  ]
}`)
	if err := os.WriteFile(filepath.Join(refDir, "runtime.json"), refBytes, 0600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.toml")
	policyBytes := []byte(`
name = "runtime"
profile = "test"
reference_pack = "./reference_packs/runtime.json"

[server]
bind = "127.0.0.1"
port = 7714

[receipts]
store = "sqlite"
path = "./data/receipts.db"
`)
	if err := os.WriteFile(policyPath, policyBytes, 0600); err != nil {
		t.Fatal(err)
	}

	head := policyreconcile.PolicyHead{
		Scope:       policyreconcile.DefaultScope,
		PolicyEpoch: 1,
		PolicyHash:  policyreconcile.HashBytes(policyBytes),
		BundleRef:   policyPath,
		SourceRefs:  []string{policyPath},
	}
	if _, err := compileServePolicySnapshot(context.Background(), head, policyBytes); err == nil || !strings.Contains(err.Error(), "missing reference_pack digest") {
		t.Fatalf("expected missing reference_pack digest error, got %v", err)
	}

	ref := "reference_pack:" + filepath.Join(refDir, "runtime.json") + "@" + policyreconcile.HashBytes(refBytes)
	head.SourceRefs = append(head.SourceRefs, ref)
	head.PolicyHash = policyreconcile.PolicyHashWithSourceRefs(policyBytes, head.SourceRefs)
	snapshot, err := compileServePolicySnapshot(context.Background(), head, policyBytes)
	if err != nil {
		t.Fatalf("digest-bound policy compile failed: %v", err)
	}
	if snapshot.PolicyHash != head.PolicyHash {
		t.Fatalf("snapshot policy hash not bound to source refs: %s != %s", snapshot.PolicyHash, head.PolicyHash)
	}
}

func TestLoadServePolicyRuntimeRequiresValidReferencePack(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(policyPath, []byte(`
name = "runtime"
profile = "test"
reference_pack = "./missing.json"

[server]
bind = "127.0.0.1"
port = 7714

[receipts]
store = "sqlite"
path = "./data/receipts.db"
`), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadServePolicyRuntime(policyPath); err == nil {
		t.Fatal("expected missing reference pack error")
	}
}

func TestRunServerCommandServeRequiresPolicy(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runServerCommand("serve", nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "requires --policy") {
		t.Fatalf("stderr missing policy error: %s", stderr.String())
	}
}

func TestVerifyCmdAcceptsPositionalBundle(t *testing.T) {
	bundle := createMinimalVerifiableBundle(t)
	var stdout, stderr bytes.Buffer

	code := runVerifyCmd([]string{"--allow-self-attested", bundle}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "VERIFIED") {
		t.Fatalf("stdout missing compact verification: %s", stdout.String())
	}
}

func TestVerifyCmdOnlineUsesLedgerURL(t *testing.T) {
	bundle := createMinimalVerifiableBundle(t)
	ledger := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"verified":true,"envelope_id":"ep_test","anchor_index":8412094,"sealed_at":"2024-11-08T10:24:18.402Z","signature_valid_count":1,"signature_total_count":1,"merkle_root":"root"}`))
	}))
	defer ledger.Close()

	var stdout, stderr bytes.Buffer
	code := runVerifyCmd([]string{"--allow-self-attested", bundle, "--online", "--ledger-url", ledger.URL}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "anchor #8412094") {
		t.Fatalf("stdout missing online anchor: %s", stdout.String())
	}
}

func TestVerifyCmdRejectsBundledConformancePublicKey(t *testing.T) {
	bundle := createMinimalVerifiableBundle(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conform.SignReport(bundle, "policy-hash", "schema-hash", "attacker", func(data []byte) (string, error) {
		return hex.EncodeToString(ed25519.Sign(priv, data)), nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "public_key.hex"), []byte(hex.EncodeToString(pub)), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runVerifyCmd([]string{"--allow-self-attested", bundle, "--json"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("verify accepted bundled public_key.hex as a trust root: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "no trusted verification key") {
		t.Fatalf("verify did not report missing external trust root: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	if err := os.Remove(filepath.Join(bundle, "public_key.hex")); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	code = runVerifyCmd([]string{"--allow-self-attested", bundle, "--json", "--trusted-public-key", hex.EncodeToString(pub)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify with explicit trusted key failed: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestReceiptsTailRequiresAgent(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runReceiptsCmd([]string{"tail"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--agent is required") {
		t.Fatalf("stderr missing agent error: %s", stderr.String())
	}
}

func TestBuildReceiptsTailURL(t *testing.T) {
	got, err := buildReceiptsTailURL("http://127.0.0.1:7714", "agent.demo.exec", "12", 5)
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://127.0.0.1:7714/api/v1/receipts/tail?agent=agent.demo.exec&limit=5&since=12" {
		t.Fatalf("url = %s", got)
	}
}

func createMinimalVerifiableBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, subdir := range []string{"02_PROOFGRAPH/receipts", "03_TELEMETRY", "04_EXPORTS", "05_DIFFS", "06_LOGS", "07_ATTESTATIONS", "08_TAPES", "09_SCHEMAS", "12_REPORTS"} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(subdir)), 0750); err != nil {
			t.Fatal(err)
		}
	}
	score := []byte(`{"pass":true}`)
	receipt := []byte(`{"decision_hash":"sha256:decision","lamport_clock":1}`)
	proofgraph := []byte(`{"nodes":[]}`)
	files := map[string][]byte{
		"01_SCORE.json":                  score,
		"02_PROOFGRAPH/proofgraph.json":  proofgraph,
		"02_PROOFGRAPH/receipts/r1.json": receipt,
		"03_TELEMETRY/.keep":             []byte("reserved\n"),
		"04_EXPORTS/.keep":               []byte("reserved\n"),
		"05_DIFFS/.keep":                 []byte("reserved\n"),
		"06_LOGS/.keep":                  []byte("reserved\n"),
		"08_TAPES/.keep":                 []byte("reserved\n"),
		"09_SCHEMAS/.keep":               []byte("reserved\n"),
		"12_REPORTS/.keep":               []byte("reserved\n"),
	}
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	entries := make([]map[string]string, 0, len(files))
	for name, data := range files {
		sum := sha256.Sum256(data)
		entries = append(entries, map[string]string{"path": name, "sha256": hex.EncodeToString(sum[:])})
	}
	indexData, err := json.MarshalIndent(map[string]any{"version": "1.0.0", "entries": entries}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "00_INDEX.json"), append(indexData, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := evidencepkg.SealEvidencePack(context.Background(), dir, evidencepkg.SealEvidencePackOptions{
		PackID:  "ep_test",
		DataDir: t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
	return dir
}
