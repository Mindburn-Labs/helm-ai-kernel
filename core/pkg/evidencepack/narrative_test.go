package evidencepack_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"
)

// buildNarrativePack assembles a realistic, signed evidence pack covering the
// full action story: a proposing actor/intent, a signed policy decision, a tool
// transcript (connector record), a workspace diff, and an attestation receipt.
// Returning the manifest AND content map lets tests assert the business
// narrative is derived from the same artifacts the manifest hash commits to.
func buildNarrativePack(t *testing.T, verdict string) (*evidencepack.Manifest, map[string][]byte) {
	t.Helper()
	b := evidencepack.NewBuilder("pack-narr-1", "did:helm:agent-7", "intent-deploy-42", "sha256:policyabc").
		WithCreatedAt(time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC))

	// Signed policy decision — the source-of-truth approval the narrative projects.
	decision := contracts.DecisionRecord{
		ID:                "dec-1",
		SubjectID:         "did:helm:agent-7",
		Action:            "github.pr.create",
		Resource:          "repo/acme/widgets",
		Verdict:           verdict,
		Reason:            "within draft policy ceiling",
		ReasonCode:        "POLICY_OK",
		PolicyVersion:     "workstation.observe_draft.v1",
		PolicyContentHash: "sha256:policycontent",
		Signature:         "ed25519:sig-decision-1",
		SignatureType:     "ed25519",
		Timestamp:         time.Date(2026, 4, 2, 12, 0, 1, 0, time.UTC),
	}
	if err := b.AddPolicyDecision("gate-1", decision); err != nil {
		t.Fatalf("AddPolicyDecision: %v", err)
	}

	if err := b.AddToolTranscript("github-create-pr", map[string]any{
		"connector": "github",
		"action":    "pulls.create",
		"status":    "ok",
	}); err != nil {
		t.Fatalf("AddToolTranscript: %v", err)
	}

	if err := b.AddGitDiff("workspace", []byte("diff --git a/x b/x\n+change\n")); err != nil {
		t.Fatalf("AddGitDiff: %v", err)
	}

	if err := b.AddReceipt("run", map[string]any{
		"receipt_id": "rcpt-1",
		"run_id":     "run-1",
	}); err != nil {
		t.Fatalf("AddReceipt: %v", err)
	}

	manifest, content, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return manifest, content
}

// TestNarrative_AnswersTheBusinessQuestions is the approver-side half of the
// MIN-442 done gate: a reader who knows nothing about Kernel internals can follow
// the action story — who proposed, who approved, under which rule, which records,
// and what happened — directly from the projection.
func TestNarrative_AnswersTheBusinessQuestions(t *testing.T) {
	manifest, content := buildNarrativePack(t, "ALLOW")

	n, err := evidencepack.GenerateNarrative(manifest, content)
	if err != nil {
		t.Fatalf("GenerateNarrative: %v", err)
	}

	// Who proposed the action?
	if n.ProposedBy != "did:helm:agent-7" {
		t.Errorf("ProposedBy = %q, want did:helm:agent-7", n.ProposedBy)
	}
	if n.IntentID != "intent-deploy-42" {
		t.Errorf("IntentID = %q, want intent-deploy-42", n.IntentID)
	}

	// Who approved/denied it, and under which policy rule?
	if len(n.Approvals) != 1 {
		t.Fatalf("len(Approvals) = %d, want 1", len(n.Approvals))
	}
	a := n.Approvals[0]
	if a.Verdict != "ALLOW" {
		t.Errorf("approval verdict = %q, want ALLOW", a.Verdict)
	}
	if a.Subject != "did:helm:agent-7" || a.Action != "github.pr.create" {
		t.Errorf("approval subject/action = %q/%q", a.Subject, a.Action)
	}
	if a.PolicyRule != "workstation.observe_draft.v1" {
		t.Errorf("approval policy rule = %q, want workstation.observe_draft.v1", a.PolicyRule)
	}
	if !a.Signed {
		t.Error("approval should be marked Signed (decision carried a signature)")
	}
	if a.ProofPath != "policy/gate-1.json" {
		t.Errorf("approval proof path = %q, want policy/gate-1.json", a.ProofPath)
	}
	if n.Outcome != "ALLOW" {
		t.Errorf("Outcome = %q, want ALLOW", n.Outcome)
	}

	// Which data/connector records were used?
	if !containsSubstr(n.DataSources, "github-create-pr") {
		t.Errorf("DataSources missing connector transcript: %v", n.DataSources)
	}

	// What happened?
	if !containsSubstr(n.WhatHappened, "Workspace change") || !containsSubstr(n.WhatHappened, "Receipt recorded") {
		t.Errorf("WhatHappened missing effects: %v", n.WhatHappened)
	}

	// Human-readable surfaces exist.
	if !strings.Contains(n.Title, "Approved") {
		t.Errorf("Title not approver-readable: %q", n.Title)
	}
	if !strings.Contains(n.Summary, "did:helm:agent-7") || !strings.Contains(n.Summary, "ALLOW") {
		t.Errorf("Summary not approver-readable: %q", n.Summary)
	}
}

// TestNarrative_DerivedFromAndConsistentWithSignedPack is the auditor-side half
// of the done gate: the narrative links back to the proof chain (manifest hash +
// per-claim content hashes) and Verify confirms it is consistent with the pack.
func TestNarrative_DerivedFromAndConsistentWithSignedPack(t *testing.T) {
	manifest, content := buildNarrativePack(t, "ALLOW")

	n, err := evidencepack.GenerateNarrative(manifest, content)
	if err != nil {
		t.Fatalf("GenerateNarrative: %v", err)
	}

	// Bound to the same signed manifest.
	if n.ManifestHash != manifest.ManifestHash {
		t.Fatalf("ManifestHash = %q, want %q", n.ManifestHash, manifest.ManifestHash)
	}

	// Every cited proof ref must resolve to a manifest entry with a matching
	// content hash — this is the "derived from the signed pack" guarantee.
	index := map[string]string{}
	for _, e := range manifest.Entries {
		index[e.Path] = e.ContentHash
	}
	if len(n.ProofRefs) == 0 {
		t.Fatal("expected proof refs linking claims to signed entries")
	}
	for _, ref := range n.ProofRefs {
		got, ok := index[ref.Path]
		if !ok {
			t.Errorf("proof ref %q not in manifest", ref.Path)
			continue
		}
		if got != ref.ContentHash {
			t.Errorf("proof ref %q hash %q != manifest %q", ref.Path, ref.ContentHash, got)
		}
	}

	// The approval claim must cite the signed decision entry specifically.
	if !proofRefExists(n, "approval", "policy/gate-1.json") {
		t.Error("expected an approval proof ref citing policy/gate-1.json")
	}

	// Node-type coverage is projected from the same entries (links to ProofGraph).
	if !containsStr(n.NodeTypes, "ATTESTATION") || !containsStr(n.NodeTypes, "INTENT") || !containsStr(n.NodeTypes, "EFFECT") {
		t.Errorf("NodeTypes missing expected coverage: %v", n.NodeTypes)
	}

	if err := n.Verify(manifest); err != nil {
		t.Fatalf("Verify against original pack failed: %v", err)
	}
}

// TestNarrative_VerifyDetectsManifestTamper ensures the business view cannot be
// re-pointed at a different (tampered) pack: if a manifest entry's content hash
// changes, the narrative no longer verifies.
func TestNarrative_VerifyDetectsManifestTamper(t *testing.T) {
	manifest, content := buildNarrativePack(t, "ALLOW")
	n, err := evidencepack.GenerateNarrative(manifest, content)
	if err != nil {
		t.Fatalf("GenerateNarrative: %v", err)
	}

	// Tamper a cited entry's content hash in the manifest.
	for i := range manifest.Entries {
		if manifest.Entries[i].Path == "policy/gate-1.json" {
			manifest.Entries[i].ContentHash = "sha256:tampered"
		}
	}

	if err := n.Verify(manifest); err == nil {
		t.Fatal("expected Verify to fail after manifest content hash tamper")
	}
}

// TestNarrative_VerifyDetectsNarrativeTamper ensures the projection itself is
// tamper-evident: editing a business field after generation breaks the hash.
func TestNarrative_VerifyDetectsNarrativeTamper(t *testing.T) {
	manifest, content := buildNarrativePack(t, "DENY")
	n, err := evidencepack.GenerateNarrative(manifest, content)
	if err != nil {
		t.Fatalf("GenerateNarrative: %v", err)
	}

	// Flip the recorded outcome from DENY to ALLOW — a forged approval.
	n.Outcome = "ALLOW"
	n.Approvals[0].Verdict = "ALLOW"

	if err := n.Verify(manifest); err == nil {
		t.Fatal("expected Verify to fail after narrative outcome tamper")
	}
}

// TestNarrative_DenyOutcomeIsReadable confirms a denial reads as a denial for an
// approver and rolls up to DENY.
func TestNarrative_DenyOutcomeIsReadable(t *testing.T) {
	manifest, content := buildNarrativePack(t, "DENY")
	n, err := evidencepack.GenerateNarrative(manifest, content)
	if err != nil {
		t.Fatalf("GenerateNarrative: %v", err)
	}
	if n.Outcome != "DENY" {
		t.Errorf("Outcome = %q, want DENY", n.Outcome)
	}
	if !strings.Contains(n.Title, "Denied") {
		t.Errorf("Title not denial-readable: %q", n.Title)
	}
	if err := n.Verify(manifest); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestNarrative_UnknownApprovalWhenContentMissing proves the business view never
// fabricates an approval the signed pack does not support: with no content map,
// the policy entry is still cited but its verdict is UNKNOWN.
func TestNarrative_UnknownApprovalWhenContentMissing(t *testing.T) {
	manifest, _ := buildNarrativePack(t, "ALLOW")

	n, err := evidencepack.GenerateNarrative(manifest, nil)
	if err != nil {
		t.Fatalf("GenerateNarrative: %v", err)
	}
	if len(n.Approvals) != 1 {
		t.Fatalf("len(Approvals) = %d, want 1", len(n.Approvals))
	}
	if n.Approvals[0].Verdict != evidencepack.VerdictUnknown {
		t.Errorf("verdict = %q, want UNKNOWN when decision content is absent", n.Approvals[0].Verdict)
	}
	if n.Outcome != evidencepack.VerdictUnknown {
		t.Errorf("Outcome = %q, want UNKNOWN", n.Outcome)
	}
	// It must still cite the proof path so an auditor can fetch the signed decision.
	if n.Approvals[0].ProofPath != "policy/gate-1.json" {
		t.Errorf("proof path = %q, want policy/gate-1.json", n.Approvals[0].ProofPath)
	}
	if err := n.Verify(manifest); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestNarrative_NilManifest guards the error path.
func TestNarrative_NilManifest(t *testing.T) {
	if _, err := evidencepack.GenerateNarrative(nil, nil); err == nil {
		t.Fatal("expected error for nil manifest")
	}
}

// TestNarrative_DeterministicProjection asserts the narrative content (excluding
// GeneratedAt) is stable across regenerations, so the business view is reproducible.
func TestNarrative_DeterministicProjection(t *testing.T) {
	manifest, content := buildNarrativePack(t, "ALLOW")

	n1, err := evidencepack.GenerateNarrative(manifest, content)
	if err != nil {
		t.Fatalf("GenerateNarrative #1: %v", err)
	}
	n2, err := evidencepack.GenerateNarrative(manifest, content)
	if err != nil {
		t.Fatalf("GenerateNarrative #2: %v", err)
	}

	if n1.Title != n2.Title || n1.Summary != n2.Summary || n1.Outcome != n2.Outcome {
		t.Error("projection content should be deterministic across regenerations")
	}
	if len(n1.ProofRefs) != len(n2.ProofRefs) {
		t.Errorf("ProofRefs count differs: %d vs %d", len(n1.ProofRefs), len(n2.ProofRefs))
	}
}

func containsStr(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func containsSubstr(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func proofRefExists(n *evidencepack.BusinessNarrative, claim, path string) bool {
	for _, r := range n.ProofRefs {
		if r.Claim == claim && r.Path == path {
			return true
		}
	}
	return false
}
