package boundary

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	_ "modernc.org/sqlite"
)

func TestSurfaceRegistryStorageBackendsAndConstructors(t *testing.T) {
	now := boundaryTestNow()

	var nilRegistry *SurfaceRegistry
	if got := nilRegistry.StorageBackend(); got != "unavailable" {
		t.Fatalf("nil StorageBackend() = %q, want unavailable", got)
	}
	if got := NewSurfaceRegistry(func() time.Time { return now }).StorageBackend(); got != "memory" {
		t.Fatalf("memory StorageBackend() = %q", got)
	}
	if registry, err := NewFileBackedSurfaceRegistry("memory", func() time.Time { return now }); err != nil || registry.StorageBackend() != "memory" {
		t.Fatalf("memory file-backed registry = (%v,%v), want memory,nil", registry, err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "boundary.json")
	fileRegistry, err := NewFileBackedSurfaceRegistry(path, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewFileBackedSurfaceRegistry() error = %v", err)
	}
	if got := fileRegistry.StorageBackend(); got != "file" {
		t.Fatalf("file StorageBackend() = %q", got)
	}

	emptyPath := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(emptyPath, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileBackedSurfaceRegistry(emptyPath, func() time.Time { return now }); err != nil {
		t.Fatalf("empty snapshot should seed registry: %v", err)
	}

	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileBackedSurfaceRegistry(badPath, func() time.Time { return now }); err == nil {
		t.Fatal("invalid JSON snapshot should fail")
	}
	partialPath := filepath.Join(dir, "partial.json")
	if err := os.WriteFile(partialPath, []byte(`{"version":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	partialRegistry, err := NewFileBackedSurfaceRegistry(partialPath, func() time.Time { return now })
	if err != nil {
		t.Fatalf("partial snapshot should load with initialized maps: %v", err)
	}
	if partialRegistry.ListRecords(contracts.BoundarySearchRequest{}) == nil || partialRegistry.ListReports() == nil {
		t.Fatal("partial snapshot should initialize registry maps")
	}
	if _, err := NewFileBackedSurfaceRegistry(dir, func() time.Time { return now }); err == nil {
		t.Fatal("directory path should fail as unreadable registry snapshot")
	}

	if registry, err := NewSQLSurfaceRegistry(context.Background(), nil, func() time.Time { return now }); err != nil || registry.StorageBackend() != "memory" {
		t.Fatalf("nil SQL registry = (%v,%v), want memory,nil", registry, err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "boundary.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sqlRegistry, err := NewSQLSurfaceRegistry(nil, db, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewSQLSurfaceRegistry() error = %v", err)
	}
	if got := sqlRegistry.StorageBackend(); got != "sql" {
		t.Fatalf("sql StorageBackend() = %q", got)
	}
}

func TestSurfaceRegistryApprovalEdges(t *testing.T) {
	now := boundaryTestNow()
	registry := NewSurfaceRegistry(func() time.Time { return now })

	if approvals := registry.ListApprovals(); len(approvals) == 0 {
		t.Fatal("seeded registry should include a bootstrap approval")
	}
	if _, err := registry.TransitionApproval("missing", contracts.ApprovalCeremonyAllowed, "user", "receipt", "reason"); err == nil {
		t.Fatal("missing approval transition should fail")
	}
	if _, err := registry.CreateApprovalChallenge("missing", "", 0); err == nil {
		t.Fatal("missing approval challenge should fail")
	}
	if _, err := registry.AssertApprovalChallenge(contracts.ApprovalWebAuthnAssertion{}); err == nil {
		t.Fatal("empty assertion should fail")
	}
	if _, err := registry.AssertApprovalChallenge(contracts.ApprovalWebAuthnAssertion{ChallengeID: "missing", Actor: "user", Assertion: "sig"}); err == nil {
		t.Fatal("missing challenge assertion should fail")
	}

	expiring, err := registry.PutApproval(contracts.ApprovalCeremony{
		ApprovalID:  "approval-expiring",
		Subject:     "mcp:expiring",
		Action:      "mcp.approve",
		State:       contracts.ApprovalCeremonyPending,
		RequestedBy: "agent:test",
		ExpiresAt:   now.Add(-time.Minute),
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatal(err)
	}
	expired, err := registry.TransitionApproval(expiring.ApprovalID, contracts.ApprovalCeremonyAllowed, "user:alice", "rcpt", "reviewed")
	if err != nil {
		t.Fatal(err)
	}
	if expired.State != contracts.ApprovalCeremonyExpired {
		t.Fatalf("expired approval state = %s", expired.State)
	}

	breakGlass, err := registry.PutApproval(contracts.ApprovalCeremony{
		ApprovalID:  "approval-break-glass",
		Subject:     "mcp:break-glass",
		Action:      "mcp.approve",
		State:       contracts.ApprovalCeremonyPending,
		RequestedBy: "agent:test",
		BreakGlass:  true,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.TransitionApproval(breakGlass.ApprovalID, contracts.ApprovalCeremonyAllowed, "user:alice", "", ""); err == nil {
		t.Fatal("break-glass approval without receipt and reason should fail")
	}

	challenge, err := registry.CreateApprovalChallenge("approval-bootstrap", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Method != "passkey" || challenge.ExpiresAt.Sub(challenge.CreatedAt) != 5*time.Minute {
		t.Fatalf("default challenge = %+v, want passkey/5m", challenge)
	}
	registry.now = func() time.Time { return now.Add(10 * time.Minute) }
	if _, err := registry.AssertApprovalChallenge(contracts.ApprovalWebAuthnAssertion{
		ChallengeID: challenge.ChallengeID,
		Actor:       "user:late",
		Assertion:   "sig",
	}); err == nil {
		t.Fatal("expired approval challenge should fail")
	}
}

func TestSurfaceRegistryDurableObjectFamilies(t *testing.T) {
	now := boundaryTestNow()
	registry := NewSurfaceRegistry(func() time.Time { return now })

	degraded := registry.Status("test", false, false, 3)
	if degraded.Status != "degraded" || degraded.ReceiptStore != "unavailable" || degraded.ReceiptSigner != "unavailable" {
		t.Fatalf("degraded status = %+v", degraded)
	}

	profile, err := registry.PutAuthProfile(contracts.MCPAuthorizationProfile{
		ProfileID:       "profile-2",
		Resource:        "https://example.test/mcp",
		ScopesSupported: []string{"tools.read", "tools.call"},
		RequiredScopes:  []string{"tools.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if profile.ProfileHash == "" || len(registry.ListAuthProfiles()) == 0 {
		t.Fatalf("auth profile not stored: %+v", profile)
	}

	if _, err := registry.PutMCPServer(mcppkg.ServerQuarantineRecord{}); err == nil {
		t.Fatal("empty MCP server id should fail")
	}
	server, err := registry.PutMCPServer(mcppkg.ServerQuarantineRecord{
		ServerID:     "mcp-server-2",
		Name:         "Server 2",
		Risk:         mcppkg.ServerRiskMedium,
		State:        mcppkg.QuarantineDiscovered,
		DiscoveredAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := registry.GetMCPServer(server.ServerID); !ok || got.ServerID != server.ServerID {
		t.Fatalf("GetMCPServer() = (%+v,%v)", got, ok)
	}
	if len(registry.ListMCPServers()) == 0 {
		t.Fatal("expected MCP server list")
	}

	if _, err := registry.PutSandboxGrant(contracts.SandboxGrant{}); err == nil {
		t.Fatal("invalid sandbox grant should fail")
	}
	grant, err := registry.PutSandboxGrant(validBoundarySandboxGrant(now))
	if err != nil {
		t.Fatal(err)
	}
	if grant.GrantHash == "" {
		t.Fatalf("sandbox grant not sealed: %+v", grant)
	}
	if got, ok := registry.GetSandboxGrant(grant.GrantID); !ok || got.GrantHash != grant.GrantHash {
		t.Fatalf("GetSandboxGrant() = (%+v,%v)", got, ok)
	}
	if len(registry.ListSandboxGrants()) == 0 {
		t.Fatal("expected sandbox grant list")
	}

	snapshot, err := registry.PutSnapshot(contracts.AuthzSnapshot{
		SnapshotID:       "authz-1",
		Resolver:         "rebac",
		ModelID:          "model-1",
		RelationshipHash: "sha256:relationships",
		Subject:          "agent:worker",
		Object:           "tool:deploy",
		Relation:         "can_call",
		Decision:         true,
		CheckedAt:        now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SnapshotHash == "" || len(registry.ListSnapshots()) == 0 {
		t.Fatalf("authz snapshot not stored: %+v", snapshot)
	}
	if got, ok := registry.GetSnapshot(snapshot.SnapshotID); !ok || got.SnapshotHash != snapshot.SnapshotHash {
		t.Fatalf("GetSnapshot() = (%+v,%v)", got, ok)
	}

	manifest, err := contracts.EvidenceEnvelopeManifest{
		ManifestID:         "env-1",
		Envelope:           "dsse",
		NativeEvidenceHash: "sha256:evidence",
		NativeAuthority:    true,
		PayloadHash:        "sha256:payload",
		CreatedAt:          now,
	}.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.PutEnvelope(manifest); err != nil {
		t.Fatal(err)
	}
	if got, ok := registry.GetEnvelope(manifest.ManifestID); !ok || got.ManifestHash != manifest.ManifestHash {
		t.Fatalf("GetEnvelope() = (%+v,%v)", got, ok)
	}
	if len(registry.ListEnvelopes()) == 0 {
		t.Fatal("expected envelope list")
	}
	if err := registry.PutEnvelopePayload(contracts.EvidenceEnvelopePayload{}); err == nil {
		t.Fatal("empty envelope payload manifest id should fail")
	}
	payload := contracts.EvidenceEnvelopePayload{
		ManifestID:    manifest.ManifestID,
		Envelope:      "dsse",
		PayloadType:   "application/json",
		Payload:       map[string]any{"ok": true},
		PayloadHash:   "sha256:payload",
		GeneratedAt:   now,
		Authoritative: true,
	}
	if err := registry.PutEnvelopePayload(payload); err != nil {
		t.Fatal(err)
	}
	if got, ok := registry.GetEnvelopePayload(payload.ManifestID); !ok || got.PayloadHash != payload.PayloadHash {
		t.Fatalf("GetEnvelopePayload() = (%+v,%v)", got, ok)
	}

	budget, err := registry.PutBudget(contracts.BudgetCeiling{
		BudgetID:        "budget-2",
		Subject:         "tenant:two",
		ToolCallLimit:   7,
		Window:          "1h",
		PolicyEpoch:     "epoch-1",
		SpendLimitCents: 99,
	})
	if err != nil {
		t.Fatal(err)
	}
	if budget.UpdatedAt.IsZero() || len(registry.ListBudgets()) == 0 {
		t.Fatalf("budget not timestamped/listed: %+v", budget)
	}
	if len(registry.ListAgents()) == 0 {
		t.Fatal("seeded registry should list default agent")
	}

	if err := registry.PutReport(map[string]any{"status": "missing-id"}); err != nil {
		t.Fatal(err)
	}
	if got := registry.ListReports(); len(got) != 0 {
		t.Fatalf("missing-id report should be ignored, got %v", got)
	}
	if err := registry.PutReport(map[string]any{"report_id": "report-1", "status": "warn"}); err != nil {
		t.Fatal(err)
	}
	if err := registry.PutReport(map[string]any{"report_id": "report-2", "status": "pass"}); err != nil {
		t.Fatal(err)
	}
	if got := registry.ListReports(); len(got) != 2 || got[0]["report_id"] != "report-1" || got[1]["report_id"] != "report-2" {
		t.Fatalf("ListReports() = %v", got)
	}
}

func TestSurfaceRegistryRecordFiltersAndCheckpointVerification(t *testing.T) {
	now := boundaryTestNow()
	registry := NewSurfaceRegistry(func() time.Time { return now })

	record, err := registry.PutRecord(contracts.ExecutionBoundaryRecord{
		RecordID:      "rec-filter",
		Verdict:       contracts.VerdictDeny,
		ReasonCode:    contracts.ReasonPolicyViolation,
		ToolName:      "tool.delete",
		MCPServerID:   "mcp-server",
		PolicyEpoch:   "epoch-filter",
		ReceiptID:     "receipt-filter",
		ArgsHash:      "sha256:args",
		OAuthScopes:   []string{"tools.call"},
		OAuthResource: "https://example.test/mcp",
		CreatedAt:     now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := registry.CreateCheckpoint(2)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.PreviousHash == "" {
		t.Fatal("second checkpoint should link to previous checkpoint hash")
	}
	verify := registry.VerifyCheckpoint(checkpoint.CheckpointID)
	if verify["verified"] != true {
		t.Fatalf("checkpoint should verify: %+v", verify)
	}
	if missing := registry.VerifyCheckpoint("missing-checkpoint"); missing["verified"] != false {
		t.Fatalf("missing checkpoint should fail: %+v", missing)
	}
	checkpoint.RecordCount++
	registry.checkpoints[checkpoint.CheckpointID] = checkpoint
	if tampered := registry.VerifyCheckpoint(checkpoint.CheckpointID); tampered["verified"] != false {
		t.Fatalf("tampered checkpoint should fail: %+v", tampered)
	}

	matchingQueries := []contracts.BoundarySearchRequest{
		{Verdict: string(contracts.VerdictDeny)},
		{ReasonCode: string(contracts.ReasonPolicyViolation)},
		{ToolName: "tool.delete"},
		{MCPServerID: "mcp-server"},
		{PolicyEpoch: "epoch-filter"},
		{ReceiptID: "receipt-filter"},
		{Limit: 1},
	}
	for _, query := range matchingQueries {
		if got := registry.ListRecords(query); len(got) == 0 {
			t.Fatalf("ListRecords(%+v) did not include %s", query, record.RecordID)
		}
	}
	nonMatchingQueries := []contracts.BoundarySearchRequest{
		{Verdict: string(contracts.VerdictAllow)},
		{ReasonCode: string(contracts.ReasonPDPError)},
		{ToolName: "tool.other"},
		{MCPServerID: "other-mcp"},
		{PolicyEpoch: "other-epoch"},
		{ReceiptID: "other-receipt"},
	}
	for _, query := range nonMatchingQueries {
		for _, got := range registry.ListRecords(query) {
			if got.RecordID == record.RecordID {
				t.Fatalf("ListRecords(%+v) unexpectedly included %s", query, record.RecordID)
			}
		}
	}

	if got := appendUnique([]string{"a"}, "a"); len(got) != 1 {
		t.Fatalf("appendUnique duplicate = %v", got)
	}
	if containsString([]string{"a"}, "b") {
		t.Fatal("containsString should return false for missing value")
	}
}

func TestSurfaceRegistryHarnessVerificationFamilies(t *testing.T) {
	now := boundaryTestNow()
	registry := NewSurfaceRegistry(func() time.Time { return now })

	scope, err := registry.PutVerificationScope(contracts.VerificationScope{
		VerificationScopeID: "scope-1",
		SubjectHash:         "sha256:subject",
		RiskClass:           "T2",
		ChecksPerformed:     []string{"hash", "signature"},
		VerifierHash:        "sha256:verifier",
		PolicyHash:          "sha256:policy",
	})
	if err != nil {
		t.Fatal(err)
	}
	assertBoundaryVerification(t, registry.VerifyVerificationScope(scope.VerificationScopeID), true)
	if len(registry.ListVerificationScopes()) == 0 {
		t.Fatal("expected verification scope list")
	}
	assertBoundaryVerification(t, registry.VerifyVerificationScope("missing-scope"), false)
	scope.ScopeHash = "sha256:tampered"
	registry.verificationScopes[scope.VerificationScopeID] = scope
	assertBoundaryVerification(t, registry.VerifyVerificationScope(scope.VerificationScopeID), false)

	trace, err := registry.PutHarnessTrace(contracts.HarnessTrace{
		TraceID:      "trace-1",
		PlanHash:     "sha256:plan",
		PolicyHash:   "sha256:policy",
		ReceiptRefs:  []string{"receipt-1"},
		MemoryReads:  []string{"mem-a"},
		MemoryWrites: []string{"mem-b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := registry.GetHarnessTrace(trace.TraceID); !ok || got.TraceHash != trace.TraceHash {
		t.Fatalf("GetHarnessTrace() = (%+v,%v)", got, ok)
	}
	if len(registry.ListHarnessTraces()) == 0 {
		t.Fatal("expected harness trace list")
	}
	assertBoundaryVerification(t, registry.VerifyHarnessTrace(trace.TraceID), true)
	assertBoundaryVerification(t, registry.VerifyHarnessTrace("missing-trace"), false)
	trace.TraceHash = "sha256:tampered"
	registry.harnessTraces[trace.TraceID] = trace
	assertBoundaryVerification(t, registry.VerifyHarnessTrace(trace.TraceID), false)

	tx, err := registry.PutPlanTransaction(contracts.PlanTransaction{
		PlanTransactionID:       "tx-1",
		PlanHash:                "sha256:plan",
		ReadSet:                 []string{"file:a"},
		WriteSet:                []string{"file:b"},
		AssumptionSet:           []string{"clean tree"},
		VerificationObligations: []string{"go test"},
		ConflictPolicy:          "deny",
		ApprovalState:           "required",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := registry.GetPlanTransaction(tx.PlanTransactionID); !ok || got.TransactionHash != tx.TransactionHash {
		t.Fatalf("GetPlanTransaction() = (%+v,%v)", got, ok)
	}
	if len(registry.ListPlanTransactions()) == 0 {
		t.Fatal("expected plan transaction list")
	}
	assertBoundaryVerification(t, registry.VerifyPlanTransaction(tx.PlanTransactionID), true)
	assertBoundaryVerification(t, registry.VerifyPlanTransaction("missing-tx"), false)
	tx.TransactionHash = "sha256:tampered"
	registry.planTransactions[tx.PlanTransactionID] = tx
	assertBoundaryVerification(t, registry.VerifyPlanTransaction(tx.PlanTransactionID), false)

	change, err := registry.PutHarnessChange(validBoundaryHarnessChange(now))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := registry.GetHarnessChange(change.ChangeContractID); !ok || got.ContractHash != change.ContractHash {
		t.Fatalf("GetHarnessChange() = (%+v,%v)", got, ok)
	}
	if len(registry.ListHarnessChanges()) == 0 {
		t.Fatal("expected harness change list")
	}
	assertBoundaryVerification(t, registry.VerifyHarnessChange(change.ChangeContractID), true)
	assertBoundaryVerification(t, registry.VerifyHarnessChange("missing-change"), false)
	if _, err := registry.ApproveHarnessChange("missing-change", "receipt"); err == nil {
		t.Fatal("missing harness change approval should fail")
	}
	approved, err := registry.ApproveHarnessChange(change.ChangeContractID, "receipt-approval")
	if err != nil {
		t.Fatal(err)
	}
	if approved.ApprovalRequired || approved.ActivationReceiptRef != "receipt-approval" {
		t.Fatalf("approved harness change = %+v", approved)
	}
	approved.ContractHash = "sha256:tampered"
	registry.harnessChanges[approved.ChangeContractID] = approved
	assertBoundaryVerification(t, registry.VerifyHarnessChange(approved.ChangeContractID), false)

	action, err := registry.PutGroundedAction(validBoundaryGroundedAction(now))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := registry.GetGroundedAction(action.GroundedActionID); !ok || got.GroundingHash != action.GroundingHash {
		t.Fatalf("GetGroundedAction() = (%+v,%v)", got, ok)
	}
	if len(registry.ListGroundedActions()) == 0 {
		t.Fatal("expected grounded actions list")
	}

	receipt, err := registry.PutGUIReceipt(contracts.GUIActionReceipt{
		ReceiptID:             "gui-1",
		GroundedActionRef:     action.GroundedActionID,
		ScreenshotHash:        action.ScreenshotHash,
		DOMOrAXSnapshotHash:   action.DOMOrAXSnapshotHash,
		TargetRef:             action.TargetRef,
		BBoxOrElementID:       action.BBoxOrElementID,
		ActionType:            action.ActionType,
		Precondition:          action.Precondition,
		Postcondition:         action.Postcondition,
		PostconditionVerified: true,
		VerificationScopeRef:  action.VerificationScopeRef,
		PolicyHash:            action.PolicyHash,
		CreatedAt:             now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := registry.GetGUIReceipt(receipt.ReceiptID); !ok || got.ReceiptHash != receipt.ReceiptHash {
		t.Fatalf("GetGUIReceipt() = (%+v,%v)", got, ok)
	}
	if len(registry.ListGUIReceipts()) == 0 {
		t.Fatal("expected GUI receipt list")
	}
	assertBoundaryVerification(t, registry.VerifyGUIReceipt(receipt.ReceiptID), true)
	assertBoundaryVerification(t, registry.VerifyGUIReceipt("missing-gui"), false)
	receipt.ReceiptHash = "sha256:tampered"
	registry.guiReceipts[receipt.ReceiptID] = receipt
	assertBoundaryVerification(t, registry.VerifyGUIReceipt(receipt.ReceiptID), false)
}

func TestBoundaryPerimeterAndSyscallEdges(t *testing.T) {
	if _, err := NewPerimeterEnforcer(&PerimeterPolicy{Version: "0.0.0"}); err == nil {
		t.Fatal("unsupported policy version should fail")
	}
	pe := enforcePolicy(t, Constraints{Network: &NetworkConstraints{}})
	if err := pe.CheckNetwork(context.Background(), "\n"); err == nil {
		t.Fatal("invalid URL should fail")
	}
	pe = enforcePolicy(t, Constraints{})
	if err := pe.CheckNetwork(context.Background(), "https://example.com"); err != nil {
		t.Fatalf("missing network constraints should allow: %v", err)
	}
	if err := pe.CheckTool(context.Background(), "tool", false); err != nil {
		t.Fatalf("missing tool constraints should allow: %v", err)
	}
	if err := pe.CheckData(context.Background(), "secret"); err != nil {
		t.Fatalf("missing data constraints should allow: %v", err)
	}

	pe = enforcePolicy(t, Constraints{Network: &NetworkConstraints{AllowedPorts: []int{443}}})
	if err := pe.CheckNetwork(context.Background(), "https://example.com/path"); err != nil {
		t.Fatalf("URL without explicit port should bypass port filter: %v", err)
	}

	syscallCases := []struct {
		name    string
		op      SyscallOp
		payload any
		wantErr bool
	}{
		{"fs read missing path", OpFilesystemRead, map[string]any{"other": "x"}, true},
		{"fs write ok", OpFilesystemWrite, map[string]any{"path": "a", "content": "b"}, false},
		{"fs write not map", OpFilesystemWrite, "path", true},
		{"fs write missing path", OpFilesystemWrite, map[string]any{"content": "b"}, true},
		{"fs write missing content", OpFilesystemWrite, map[string]any{"path": "a"}, true},
		{"network ok", OpNetworkGet, "https://example.com", false},
		{"network bad", OpNetworkGet, 7, true},
		{"exec ok", OpExecRun, map[string]any{"cmd": "go", "args": []string{"test"}}, false},
		{"exec not map", OpExecRun, "go test", true},
		{"exec missing cmd", OpExecRun, map[string]any{"args": []string{"test"}}, true},
	}
	for _, tc := range syscallCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSyscall(tc.op, tc.payload)
			if tc.wantErr && err == nil {
				t.Fatal("ValidateSyscall() expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateSyscall() error = %v", err)
			}
		})
	}
}

func assertBoundaryVerification(t *testing.T, result map[string]any, wantVerified bool) {
	t.Helper()
	got, _ := result["verified"].(bool)
	if got != wantVerified {
		t.Fatalf("verification result = %+v, want verified=%v", result, wantVerified)
	}
}

func boundaryTestNow() time.Time {
	return time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
}

func validBoundarySandboxGrant(now time.Time) contracts.SandboxGrant {
	return contracts.SandboxGrant{
		GrantID:    "grant-1",
		Runtime:    "docker",
		Profile:    "locked-down",
		Env:        contracts.EnvExposurePolicy{Mode: "deny-all"},
		Network:    contracts.NetworkGrant{Mode: "deny-all"},
		DeclaredAt: now,
	}
}

func validBoundaryHarnessChange(now time.Time) contracts.HarnessChangeContract {
	return contracts.HarnessChangeContract{
		ChangeContractID:     "change-1",
		ComponentModified:    "tool_schema",
		FailureModeTargeted:  "schema drift",
		PredictedImprovement: "blocks drift",
		InvariantsPreserved:  []string{"fail closed"},
		SafetyProperties:     []string{"receipt required"},
		RegressionSuiteRefs:  []string{"suite:boundary"},
		RollbackPlan:         []byte(`{"steps":["revert"]}`),
		ApprovalRequired:     true,
		CreatedAt:            now,
	}
}

func validBoundaryGroundedAction(now time.Time) contracts.GroundedActionRef {
	return contracts.GroundedActionRef{
		GroundedActionID:     "grounded-1",
		ScreenshotHash:       "sha256:screenshot",
		DOMOrAXSnapshotHash:  "sha256:dom",
		TargetRef:            "button#deploy",
		BBoxOrElementID:      "deploy",
		ActionType:           "click",
		Precondition:         "deploy button visible",
		Postcondition:        "deployment dialog opened",
		VerificationScopeRef: "scope-1",
		PolicyHash:           "sha256:policy",
		CreatedAt:            now,
	}
}
