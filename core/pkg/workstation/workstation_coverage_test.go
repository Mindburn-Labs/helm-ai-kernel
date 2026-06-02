package workstation

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestCaptureLifecycleAndHelperErrors(t *testing.T) {
	if _, err := StartCapture("", CaptureStartOptions{Goal: "capture"}); err == nil {
		t.Fatal("expected empty capture output directory error")
	}
	if _, err := StartCapture(t.TempDir(), CaptureStartOptions{}); err == nil {
		t.Fatal("expected empty capture goal error")
	}
	if _, err := FinishCapture("", CaptureFinishOptions{}); err == nil {
		t.Fatal("expected empty artifact directory error")
	}
	if _, err := FinishCapture(t.TempDir(), CaptureFinishOptions{}); err == nil {
		t.Fatal("expected missing manifest error")
	}

	workspace := t.TempDir()
	runWorkstationCommand(t, workspace, "git", "init")
	runWorkstationCommand(t, workspace, "git", "config", "user.email", "agent@example.test")
	runWorkstationCommand(t, workspace, "git", "config", "user.name", "Agent")
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runWorkstationCommand(t, workspace, "git", "add", "README.md")
	runWorkstationCommand(t, workspace, "git", "-c", "commit.gpgsign=false", "commit", "-m", "initial")
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("before\nafter\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	artifactDir := t.TempDir()
	startedAt := time.Date(2026, 6, 2, 9, 0, 0, 0, time.UTC)
	manifest, err := StartCapture(artifactDir, CaptureStartOptions{
		Goal:          "capture workstation lifecycle",
		WorkspacePath: workspace,
		StartedAt:     startedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ActorID != "agent.local" || manifest.WorkspaceID != defaultWorkspaceID || manifest.AgentSurface != defaultSurface {
		t.Fatalf("unexpected manifest defaults: %+v", manifest)
	}
	decoded, err := DecodeManifest(filepath.Join(artifactDir, ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RunID != manifest.RunID || decoded.Repository != filepath.Base(workspace) {
		t.Fatalf("decoded manifest mismatch: %+v", decoded)
	}

	toolEventsPath := filepath.Join(t.TempDir(), "events.ndjson")
	eventLine, err := json.Marshal(ToolEvent{
		Type:       "network_egress",
		Target:     "https://forbidden.example/path",
		OccurredAt: startedAt.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(toolEventsPath, append(eventLine, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	completedAt := startedAt.Add(2 * time.Minute)
	result, err := FinishCapture(artifactDir, CaptureFinishOptions{
		ValidationCommand: "printf validation-ok",
		ToolEventsPath:    toolEventsPath,
		CompletedAt:       completedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Receipt.CompletedAt == nil || !result.Receipt.CompletedAt.Equal(completedAt) {
		t.Fatalf("completed_at = %v, want %v", result.Receipt.CompletedAt, completedAt)
	}
	if got := len(result.Receipt.ChangedFiles); got != 1 {
		t.Fatalf("changed files = %d, want 1", got)
	}
	if got := len(result.Receipt.ValidationResults); got != 1 || result.Receipt.ValidationResults[0].Status != "passed" {
		t.Fatalf("validation results = %+v", result.Receipt.ValidationResults)
	}
	if got := len(result.Receipt.DeniedEffects); got != 1 {
		t.Fatalf("denied effects = %d, want 1", got)
	}
	if _, err := os.Stat(filepath.Join(artifactDir, ToolEventsFile)); err != nil {
		t.Fatalf("tool events were not copied: %v", err)
	}

	failed := runValidationCommand(context.Background(), workspace, "printf err >&2; exit 7")
	if failed.Status != "failed" || failed.ExitCode != 7 || failed.StderrHash == "" {
		t.Fatalf("unexpected failed validation result: %+v", failed)
	}
	if got := gitDiffSummary(context.Background(), filepath.Join(workspace, "missing")); got != nil {
		t.Fatalf("gitDiffSummary for missing workspace = %+v", got)
	}
	if got := repositoryName(""); got != "" {
		t.Fatalf("repositoryName empty = %q", got)
	}
	nonGit := t.TempDir()
	if got := repositoryName(nonGit); got != filepath.Base(nonGit) {
		t.Fatalf("repositoryName fallback = %q, want %q", got, filepath.Base(nonGit))
	}
	if err := copyToolEvents(filepath.Join(t.TempDir(), "missing.ndjson"), filepath.Join(t.TempDir(), "out.ndjson")); err == nil {
		t.Fatal("expected missing source tool-events copy error")
	}
	copySource := filepath.Join(t.TempDir(), "events.ndjson")
	if err := os.WriteFile(copySource, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyToolEvents(copySource, filepath.Join(t.TempDir(), "missing", "events.ndjson")); err == nil {
		t.Fatal("expected create destination tool-events copy error")
	}
	if err := writeCanonicalJSON(filepath.Join(t.TempDir(), "bad.json"), map[string]any{"bad": func() {}}, 0o600); err == nil {
		t.Fatal("expected canonicalization error")
	}
	if err := writeCanonicalJSON(t.TempDir(), map[string]string{"ok": "yes"}, 0o600); err == nil {
		t.Fatal("expected write-to-directory error")
	}
	if _, err := DecodeManifest(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected missing manifest decode error")
	}
	invalidManifest := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(invalidManifest, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeManifest(invalidManifest); err == nil {
		t.Fatal("expected invalid manifest decode error")
	}
	artifactWithMissingEvents := t.TempDir()
	if _, err := StartCapture(artifactWithMissingEvents, CaptureStartOptions{Goal: "missing events", WorkspacePath: workspace, StartedAt: startedAt}); err != nil {
		t.Fatal(err)
	}
	if _, err := FinishCapture(artifactWithMissingEvents, CaptureFinishOptions{ToolEventsPath: filepath.Join(t.TempDir(), "missing.ndjson")}); err == nil {
		t.Fatal("expected FinishCapture tool-events copy error")
	}
}

func TestWorkstationResultEvidenceAndOperatorErrorCoverage(t *testing.T) {
	root := repoRoot(t)
	imported, err := ImportArtifactDir(filepath.Join(root, "fixtures", "workstation", "denied-memory"), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteResult("", imported); err != nil {
		t.Fatalf("WriteResult discard failed: %v", err)
	}
	if err := WriteResult(filepath.Join(t.TempDir(), "result.json"), nil); err == nil {
		t.Fatal("expected nil result error")
	}
	resultPath := filepath.Join(t.TempDir(), "result.json")
	if err := WriteResult(resultPath, imported); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadResult(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Receipt.ReceiptID != imported.Receipt.ReceiptID {
		t.Fatalf("loaded result receipt = %s, want %s", loaded.Receipt.ReceiptID, imported.Receipt.ReceiptID)
	}
	receiptPath := filepath.Join(t.TempDir(), "receipt.json")
	writeJSONFixture(t, receiptPath, imported.Receipt)
	loadedBare, err := LoadResult(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if loadedBare.Receipt.ReceiptID != imported.Receipt.ReceiptID {
		t.Fatalf("loaded bare receipt = %s", loadedBare.Receipt.ReceiptID)
	}
	if _, err := LoadResult(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected missing result error")
	}
	badResult := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badResult, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadResult(badResult); err == nil {
		t.Fatal("expected invalid result JSON error")
	}
	if summary := Summary(nil); len(summary) != 0 {
		t.Fatalf("nil summary = %+v", summary)
	}

	required := EvidencePackRequiredFiles()
	if !contains(required, "00_INDEX.json") || !contains(required, "99_EXT/workstation") {
		t.Fatalf("required evidence files missing expected entries: %v", required)
	}
	if _, err := ExportEvidencePack(nil, t.TempDir()); err == nil {
		t.Fatal("expected nil evidence result error")
	}
	if _, err := ExportEvidencePack(imported, ""); err == nil {
		t.Fatal("expected empty evidence output dir error")
	}
	outFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(outFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportEvidencePack(imported, outFile); err == nil {
		t.Fatal("expected evidence pack create-dir error")
	}
	if err := writeCanonical(filepath.Join(t.TempDir(), "bad.json"), map[string]any{"bad": func() {}}); err == nil {
		t.Fatal("expected writeCanonical canonicalization error")
	}
	if _, err := LoadEvidencePackIndex(t.TempDir()); err == nil {
		t.Fatal("expected missing evidence index error")
	}
	badIndexDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(badIndexDir, "00_INDEX.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEvidencePackIndex(badIndexDir); err == nil {
		t.Fatal("expected invalid evidence index error")
	}

	if _, err := BuildOperatorView(); err == nil {
		t.Fatal("expected missing operator input error")
	}
	if _, err := BuildOperatorView(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected missing operator path error")
	}
	unsupported := filepath.Join(t.TempDir(), "unsupported.json")
	if err := os.WriteFile(unsupported, []byte(`{"hello":"world"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadWorkstationReceipt(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected missing receipt load error")
	}
	if _, _, err := loadWorkstationReceipt(unsupported); err == nil {
		t.Fatal("expected unsupported workstation receipt error")
	}
	view, err := BuildOperatorView(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Runs) != 1 || len(view.MemoryReviewQueue) != 1 || len(view.DeniedTimeline) != 1 {
		t.Fatalf("operator view from file = %+v", view)
	}
	if boolCount(false) != 0 || boolCount(true) != 1 {
		t.Fatal("boolCount returned unexpected values")
	}
}

func TestWorkstationDecisionReceiptAndClassifierCoverage(t *testing.T) {
	profile := DefaultObserveDraftProfile()
	request := contracts.WorkstationDecisionRequest{
		RunID:      "run-decision",
		EffectType: contracts.EffectTypeWorkstationNetworkEgress,
		Target:     "https://forbidden.example",
	}
	receipt, err := Decide(profile, request, DecisionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "decision.json")
	writeJSONFixture(t, path, receipt)
	loaded, err := LoadDecisionReceipt(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DecisionID != receipt.DecisionID {
		t.Fatalf("loaded decision = %s, want %s", loaded.DecisionID, receipt.DecisionID)
	}
	if _, err := LoadDecisionReceipt(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected missing decision error")
	}
	invalidDecision := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(invalidDecision, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDecisionReceipt(invalidDecision); err == nil {
		t.Fatal("expected invalid decision JSON error")
	}
	notDecision := filepath.Join(t.TempDir(), "not-decision.json")
	if err := os.WriteFile(notDecision, []byte(`{"decision_id":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDecisionReceipt(notDecision); err == nil {
		t.Fatal("expected not-a-decision error")
	}
	if ok, err := VerifyDecisionReceiptSignature(nil); err == nil || ok {
		t.Fatalf("expected nil decision signature error, got ok=%v err=%v", ok, err)
	}
	badDecision := *receipt
	badDecision.SignerKeyID = "ed25519:not-hex"
	if ok, err := VerifyDecisionReceiptSignature(&badDecision); err == nil || ok {
		t.Fatalf("expected bad signer key hex error, got ok=%v err=%v", ok, err)
	}
	badDecision = *receipt
	badDecision.SignerKeyID = "ed25519:" + hex.EncodeToString([]byte{1, 2})
	if ok, err := VerifyDecisionReceiptSignature(&badDecision); err == nil || ok {
		t.Fatalf("expected short signer key error, got ok=%v err=%v", ok, err)
	}
	badDecision = *receipt
	badDecision.Signature = "not-hex"
	if ok, err := VerifyDecisionReceiptSignature(&badDecision); err == nil || ok {
		t.Fatalf("expected bad signature hex error, got ok=%v err=%v", ok, err)
	}
	badDecision = *receipt
	badDecision.Reason = "changed"
	if ok, err := VerifyDecisionReceiptSignature(&badDecision); err != nil || ok {
		t.Fatalf("expected decision hash mismatch false/nil, got ok=%v err=%v", ok, err)
	}
	badDecision = *receipt
	badDecision.Signature = flipHexByte(badDecision.Signature)
	if ok, err := VerifyDecisionReceiptSignature(&badDecision); err != nil || ok {
		t.Fatalf("expected decision signature mismatch false/nil, got ok=%v err=%v", ok, err)
	}
	if _, err := Decide(profile, request, DecisionOptions{SigningSeed: []byte("short")}); err == nil {
		t.Fatal("expected decision signing seed length error")
	}

	if ok, err := VerifyReceiptSignature(nil); err == nil || ok {
		t.Fatalf("expected nil receipt signature error, got ok=%v err=%v", ok, err)
	}
	imported, err := ImportArtifactDir(filepath.Join(repoRoot(t), "fixtures", "workstation", "allowed-observe"), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	badReceipt := *imported.Receipt
	badReceipt.SignerKeyID = "ed25519:not-hex"
	if ok, err := VerifyReceiptSignature(&badReceipt); err == nil || ok {
		t.Fatalf("expected bad receipt signer key error, got ok=%v err=%v", ok, err)
	}
	badReceipt = *imported.Receipt
	badReceipt.SignerKeyID = "ed25519:" + hex.EncodeToString([]byte{1})
	if ok, err := VerifyReceiptSignature(&badReceipt); err == nil || ok {
		t.Fatalf("expected short receipt signer key error, got ok=%v err=%v", ok, err)
	}
	badReceipt = *imported.Receipt
	badReceipt.Signature = "not-hex"
	if ok, err := VerifyReceiptSignature(&badReceipt); err == nil || ok {
		t.Fatalf("expected bad receipt signature error, got ok=%v err=%v", ok, err)
	}
	badReceipt = *imported.Receipt
	badReceipt.Goal = "changed"
	if ok, err := VerifyReceiptSignature(&badReceipt); err != nil || ok {
		t.Fatalf("expected receipt hash mismatch false/nil, got ok=%v err=%v", ok, err)
	}
	badReceipt = *imported.Receipt
	badReceipt.Signature = flipHexByte(badReceipt.Signature)
	if ok, err := VerifyReceiptSignature(&badReceipt); err != nil || ok {
		t.Fatalf("expected receipt signature mismatch false/nil, got ok=%v err=%v", ok, err)
	}
	if _, err := BuildReceipt(RunManifest{RunID: "bad-seed"}, DiffSummary{}, ValidationArtifact{}, nil, profile, map[string]string{ManifestFile: strings.Repeat("a", 64)}, ImportOptions{SigningSeed: []byte("short")}); err == nil {
		t.Fatal("expected receipt signing seed length error")
	}

	effectClasses := []string{"network", "mcp_tool", "memory", "loop", "deploy", "secret", "payment", "shell-operate", "file", "unknown"}
	for _, effectClass := range effectClasses {
		effectType, effectMode, action, toolID := EffectDefaults(effectClass)
		if effectType == "" || effectMode == "" || action == "" || toolID == "" {
			t.Fatalf("EffectDefaults(%q) returned empty field", effectClass)
		}
	}
	modeCases := map[string]string{
		contracts.EffectTypeWorkstationFileDraft:     contracts.WorkstationEffectModeDraft,
		contracts.EffectTypeWorkstationNetworkEgress: contracts.WorkstationEffectModeOperate,
		"other": contracts.WorkstationEffectModeObserve,
	}
	for effectType, want := range modeCases {
		if got := effectModeForEffect(effectType); got != want {
			t.Fatalf("effectModeForEffect(%q) = %q, want %q", effectType, got, want)
		}
	}
	eventTypeCases := map[string]string{
		contracts.EffectTypeWorkstationNetworkEgress:   "network_egress",
		contracts.EffectTypeWorkstationMCPToolCall:     "mcp_tool_call",
		contracts.EffectTypeWorkstationMemoryWrite:     "memory_write",
		contracts.EffectTypeWorkstationRecurringLoop:   "recurring_loop",
		contracts.EffectTypeWorkstationDeployPublish:   "deploy_publish",
		contracts.EffectTypeWorkstationSecretRead:      "secret_read",
		contracts.EffectTypeWorkstationPaymentInitiate: "payment_initiate",
		contracts.EffectTypeWorkstationFileDraft:       "file_write",
		contracts.EffectTypeWorkstationFileWrite:       "file_write",
		"other":                                        "shell_command",
	}
	for effectType, want := range eventTypeCases {
		if got := eventTypeForEffect(effectType); got != want {
			t.Fatalf("eventTypeForEffect(%q) = %q, want %q", effectType, got, want)
		}
	}
	for _, eventType := range []string{"file_write", "network_egress", "mcp_tool_call", "memory_write", "recurring_loop", "deploy_publish", "secret_read", "payment_initiate", "prompt_injection", "other"} {
		event := ToolEvent{Type: eventType}
		if effectTypeForEvent(event) == "" || effectModeForEvent(event) == "" {
			t.Fatalf("event defaults for %q returned empty values", eventType)
		}
	}
	permissionCases := []ToolEvent{
		{EffectType: contracts.EffectTypeWorkstationNetworkEgress},
		{EffectType: contracts.EffectTypeWorkstationMCPToolCall},
		{EffectType: contracts.EffectTypeWorkstationMemoryWrite},
		{EffectType: contracts.EffectTypeWorkstationRecurringLoop},
		{EffectType: contracts.EffectTypeWorkstationDeployPublish},
		{EffectType: contracts.EffectTypeWorkstationSecretRead},
		{EffectType: contracts.EffectTypeWorkstationPaymentInitiate},
		{EffectType: contracts.EffectTypeWorkstationShellCommand, Type: "shell_operate"},
		{EffectType: contracts.EffectTypeWorkstationShellCommand, Action: "manual operate"},
		{Type: "network_egress"},
		{Type: "mcp_tool_call"},
		{Type: "memory_write"},
		{Type: "recurring_loop"},
		{Type: "deploy_publish"},
		{Type: "secret_read"},
		{Type: "payment_initiate"},
		{Type: "shell_operate"},
		{EffectType: "custom_effect", Type: "custom"},
	}
	for _, event := range permissionCases {
		if got := workstationPermissionForEffect(event.EffectType, event.Type, event.Action); got == "" {
			t.Fatalf("workstationPermissionForEffect(%+v) returned empty", event)
		}
	}
	if contains([]string{"a", "b"}, "c") || !contains([]string{"a", "b"}, "a") {
		t.Fatal("contains returned unexpected result")
	}
	for sensitivity, want := range map[string]string{
		"public":       contracts.DataClassPublic,
		"confidential": contracts.DataClassConfidential,
		"restricted":   contracts.DataClassRestricted,
		"unknown":      contracts.DataClassInternal,
	} {
		if got := dataClassForSensitivity(sensitivity); got != want {
			t.Fatalf("dataClassForSensitivity(%q) = %q, want %q", sensitivity, got, want)
		}
	}
	if !draftTargetAllowed(nil, "") || !draftTargetAllowed([]string{"."}, "docs/file.md") {
		t.Fatal("draftTargetAllowed rejected default relative target")
	}
	if draftTargetAllowed([]string{"docs"}, "../secret.txt") {
		t.Fatal("draftTargetAllowed accepted parent traversal")
	}
	absRoot := t.TempDir()
	if !draftTargetAllowed([]string{absRoot}, filepath.Join(absRoot, "file.txt")) {
		t.Fatal("draftTargetAllowed rejected absolute target under absolute root")
	}
	if draftTargetAllowed([]string{absRoot}, filepath.Join(t.TempDir(), "file.txt")) {
		t.Fatal("draftTargetAllowed accepted absolute target outside root")
	}
	if !egressAllowed([]contracts.WorkstationEgressDestination{{Host: "api.example.com"}}, "https://api.example.com:443/v1") {
		t.Fatal("egressAllowed rejected default-protocol allowlist")
	}
	if egressAllowed([]contracts.WorkstationEgressDestination{{Host: "api.example.com", Protocol: "https"}}, "http://api.example.com/v1") {
		t.Fatal("egressAllowed accepted wrong protocol")
	}
	if host, proto := splitTarget("api.example.com/path"); host != "api.example.com" || proto != "https" {
		t.Fatalf("splitTarget default = %s/%s", host, proto)
	}
	completed := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	if got := manifestTimestamp(RunManifest{CompletedAt: &completed}); !got.Equal(completed) {
		t.Fatalf("manifestTimestamp completed = %v", got)
	}
	if got := decisionTimestamp(contracts.WorkstationDecisionRequest{}); !got.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("decisionTimestamp zero = %v", got)
	}
	normalizeReceiptCollections(&contracts.AgentRunReceipt{})
}

func TestWorkstationCertificationBranchesAndPolicyLoadErrors(t *testing.T) {
	root := filepath.Join(repoRoot(t), "fixtures", "workstation")
	defaultProfile, err := LoadPolicyProfileFile("")
	if err != nil {
		t.Fatal(err)
	}
	if defaultProfile.ID != contracts.PolicyProfileWorkstationObserveDraftV1 {
		t.Fatalf("default profile id = %q", defaultProfile.ID)
	}
	if _, err := LoadPolicyProfileFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected missing policy profile error")
	}
	invalidProfile := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(invalidProfile, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicyProfileFile(invalidProfile); err == nil {
		t.Fatal("expected invalid policy profile JSON error")
	}
	emptyProfile := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(emptyProfile, []byte(`{"id":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicyProfileFile(emptyProfile); err == nil {
		t.Fatal("expected empty policy profile id error")
	}
	artifactDir := t.TempDir()
	if _, err := readPolicyProfile(artifactDir); err != nil {
		t.Fatalf("expected default policy profile from absent file, got %v", err)
	}
	if err := os.WriteFile(filepath.Join(artifactDir, PolicyProfileFile), []byte(`{"id":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPolicyProfile(artifactDir); err == nil {
		t.Fatal("expected readPolicyProfile empty id error")
	}
	toolEvents := filepath.Join(t.TempDir(), "tool-events.ndjson")
	if err := os.WriteFile(toolEvents, []byte("\n{\"type\":\"file_write\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	events, err := readToolEvents(toolEvents)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("readToolEvents count = %d", len(events))
	}
	badEvents := filepath.Join(t.TempDir(), "bad-events.ndjson")
	if err := os.WriteFile(badEvents, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readToolEvents(badEvents); err == nil {
		t.Fatal("expected malformed tool event error")
	}
	if _, err := readToolEvents(t.TempDir()); err == nil {
		t.Fatal("expected directory tool event scan error")
	}

	observe := CertifyAdapterFixtures("", root, "")
	if !observe.Passed || observe.AdapterID != "workstation-manifest-adapter" || observe.CertifiedAs != CertificationObserveOnly || !observe.ObservedOnly {
		t.Fatalf("observe certification = %+v", observe)
	}
	enforceable := CertifyAdapterFixtures("adapter", root, CertificationEnforceable)
	if !enforceable.Passed || enforceable.CertifiedAs != CertificationEnforceable {
		t.Fatalf("enforceable certification = %+v", enforceable)
	}
	missing := CertifyAdapterFixtures("adapter", t.TempDir(), CertificationObserveOnly)
	if missing.Passed {
		t.Fatalf("expected missing fixtures certification failure: %+v", missing)
	}
	if requiredFixtureFilesExist(t.TempDir(), "missing") {
		t.Fatal("requiredFixtureFilesExist unexpectedly passed")
	}
	if allChecksPass([]CertificationCheck{{Status: "PASS"}, {Status: "FAIL"}}) {
		t.Fatal("allChecksPass accepted a failing check")
	}
	if ok, msg := certifyObserveOnly(t.TempDir()); ok || msg == "" {
		t.Fatalf("expected observe-only certification failure, got ok=%v msg=%q", ok, msg)
	}
	if ok, msg := certifyHighRiskFixtures(t.TempDir()); ok || msg == "" {
		t.Fatalf("expected high-risk certification failure, got ok=%v msg=%q", ok, msg)
	}
}

func TestWorkstationSmallHelperBranches(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "capture-file")
	if err := os.WriteFile(outFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := StartCapture(outFile, CaptureStartOptions{Goal: "cannot mkdir"}); err == nil {
		t.Fatal("expected StartCapture mkdir error")
	}
	if _, err := ImportArtifactDir("", ImportOptions{}); err == nil {
		t.Fatal("expected empty artifact dir error")
	}

	artifactDir := t.TempDir()
	started := time.Date(2026, 6, 2, 10, 0, 0, 0, time.UTC)
	if _, err := StartCapture(artifactDir, CaptureStartOptions{Goal: "minimal finish", WorkspacePath: t.TempDir(), StartedAt: started}); err != nil {
		t.Fatal(err)
	}
	minimal, err := FinishCapture(artifactDir, CaptureFinishOptions{CompletedAt: started.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if len(minimal.Receipt.ValidationResults) != 0 || len(minimal.Receipt.ToolActions) != 0 {
		t.Fatalf("minimal finish produced unexpected effects: %+v", minimal.Receipt)
	}

	if optionalDiff(nil).ChangedFiles != nil {
		t.Fatal("optionalDiff(nil) should return empty diff")
	}
	diff := &DiffSummary{Repository: "repo"}
	if optionalDiff(diff).Repository != "repo" {
		t.Fatal("optionalDiff(non-nil) did not return input value")
	}
	if optionalValidation(nil).Commands != nil {
		t.Fatal("optionalValidation(nil) should return empty validation")
	}
	validation := &ValidationArtifact{Commands: []contracts.AgentValidationResult{{Command: "test"}}}
	if optionalValidation(validation).Commands[0].Command != "test" {
		t.Fatal("optionalValidation(non-nil) did not return input value")
	}

	now := time.Date(2026, 6, 2, 11, 0, 0, 0, time.UTC)
	events := []ToolEvent{{EventID: "b", OccurredAt: now}, {EventID: "a", OccurredAt: now}}
	sortToolEvents(events)
	if events[0].EventID != "a" {
		t.Fatalf("sortToolEvents tie order = %+v", events)
	}
	actions := []contracts.AgentToolAction{{ActionID: "b", OccurredAt: now}, {ActionID: "a", OccurredAt: now}}
	sortToolActions(actions)
	if actions[0].ActionID != "a" {
		t.Fatalf("sortToolActions tie order = %+v", actions)
	}
	files := []contracts.AgentChangedFile{{Path: "z"}, {Path: "a"}}
	sortChangedFiles(files)
	if files[0].Path != "a" {
		t.Fatalf("sortChangedFiles order = %+v", files)
	}
	validations := []contracts.AgentValidationResult{{Command: "z"}, {Command: "a"}}
	sortValidation(validations)
	if validations[0].Command != "a" {
		t.Fatalf("sortValidation order = %+v", validations)
	}
	memories := []contracts.AgentMemoryEffect{{EffectID: "z"}, {EffectID: "a"}}
	sortMemoryEffects(memories)
	if memories[0].EffectID != "a" {
		t.Fatalf("sortMemoryEffects order = %+v", memories)
	}
	loops := []contracts.AgentRecurringLoopEffect{{EffectID: "z"}, {EffectID: "a"}}
	sortRecurringEffects(loops)
	if loops[0].EffectID != "a" {
		t.Fatalf("sortRecurringEffects order = %+v", loops)
	}
	denied := []contracts.AgentDeniedEffect{{EffectID: "b", OccurredAt: now}, {EffectID: "a", OccurredAt: now}}
	sortDeniedEffects(denied)
	if denied[0].EffectID != "a" {
		t.Fatalf("sortDeniedEffects tie order = %+v", denied)
	}
	view := OperatorView{
		Runs:              []OperatorRunSummary{{RunID: "late", CreatedAt: now.Add(time.Minute)}, {RunID: "early", CreatedAt: now}},
		DeniedTimeline:    []DeniedTimelineItem{{EffectID: "late", Occurred: now.Add(time.Minute)}, {EffectID: "early", Occurred: now}},
		MemoryReviewQueue: []MemoryReviewItem{{EffectID: "z"}, {EffectID: "a"}},
		RecurringLoops:    []RecurringLoopItem{{EffectID: "z"}, {EffectID: "a"}},
	}
	sortOperatorView(&view)
	if view.Runs[0].RunID != "early" || view.DeniedTimeline[0].EffectID != "early" || view.MemoryReviewQueue[0].EffectID != "a" || view.RecurringLoops[0].EffectID != "a" {
		t.Fatalf("sortOperatorView order = %+v", view)
	}

	profile := DefaultObserveDraftProfile()
	profile.Operate.Permissions = []string{contracts.WorkstationPermissionLoopRegister, contracts.WorkstationPermissionShellOperate}
	recurringBase := ToolEvent{
		Type:       "recurring_loop",
		EffectType: contracts.EffectTypeWorkstationRecurringLoop,
		EffectMode: contracts.WorkstationEffectModeOperate,
	}
	if verdict, reason, _ := EvaluateEvent(profile, recurringBase.WithLoop(contracts.AgentRecurringLoopEffect{Schedule: "FREQ=DAILY", ToolScope: []string{"shell"}, ExpiresAt: now.Add(time.Hour)})); verdict != contracts.WorkstationVerdictDeny || reason != "RECURRING_LOOP_MISSING_MAX_RUNTIME" {
		t.Fatalf("missing max runtime = %s/%s", verdict, reason)
	}
	if verdict, reason, _ := EvaluateEvent(profile, recurringBase.WithLoop(contracts.AgentRecurringLoopEffect{Schedule: "FREQ=DAILY", MaxRuntime: "10m", ExpiresAt: now.Add(time.Hour)})); verdict != contracts.WorkstationVerdictDeny || reason != "RECURRING_LOOP_MISSING_TOOL_SCOPE" {
		t.Fatalf("missing tool scope = %s/%s", verdict, reason)
	}
	if verdict, reason, _ := EvaluateEvent(profile, recurringBase.WithLoop(contracts.AgentRecurringLoopEffect{Schedule: "FREQ=DAILY", MaxRuntime: "10m", ToolScope: []string{"shell"}})); verdict != contracts.WorkstationVerdictDeny || reason != "RECURRING_LOOP_MISSING_EXPIRATION" {
		t.Fatalf("missing expiration = %s/%s", verdict, reason)
	}
	if verdict, reason, _ := EvaluateEvent(profile, recurringBase.WithLoop(contracts.AgentRecurringLoopEffect{Schedule: "FREQ=DAILY", MaxRuntime: "10m", ToolScope: []string{"shell"}, ExpiresAt: now.Add(time.Hour)})); verdict != contracts.WorkstationVerdictAllow || reason != "" {
		t.Fatalf("complete recurring loop = %s/%s", verdict, reason)
	}
	if verdict, reason, _ := EvaluateEvent(profile, ToolEvent{EffectType: contracts.EffectTypeWorkstationShellCommand, Type: "shell_operate", Action: "operate", EffectMode: contracts.WorkstationEffectModeOperate}); verdict != contracts.WorkstationVerdictAllow || reason != "" {
		t.Fatalf("shell operate = %s/%s", verdict, reason)
	}
	if verdict, reason, _ := EvaluateEvent(profile, ToolEvent{Type: "observe_only"}); verdict != contracts.WorkstationVerdictAllow || reason != "" {
		t.Fatalf("observe default = %s/%s", verdict, reason)
	}
	if draftTargetAllowed([]string{"docs"}, "src/file.md") {
		t.Fatal("draftTargetAllowed accepted relative target outside relative root")
	}
}

func runWorkstationCommand(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, stderr.String())
	}
}

func (event ToolEvent) WithLoop(loop contracts.AgentRecurringLoopEffect) ToolEvent {
	event.RecurringLoopEffect = &loop
	return event
}

func flipHexByte(in string) string {
	if len(in) == 0 {
		return "00"
	}
	if in[len(in)-1] == '0' {
		return in[:len(in)-1] + "1"
	}
	return in[:len(in)-1] + "0"
}
