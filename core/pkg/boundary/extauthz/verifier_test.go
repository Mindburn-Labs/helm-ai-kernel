package extauthz

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

type durableLedger struct {
	*PermitLedger
}

func (d durableLedger) DurableCompareAndSwap() bool {
	return true
}

func fixtureVerifyOptions(consumer PermitConsumer) VerifyOptions {
	return VerifyOptions{
		ExpectedKernelTrustRootID: "root-a",
		ExpectedPolicyEpoch:       "epoch-9",
		MaxVerdictTTL:             2 * time.Minute,
		MaxPermitTTL:              time.Minute,
		PermitConsumer:            consumer,
	}
}

func TestVerifyResponseRequiresLiveSignatureAndRequestBinding(t *testing.T) {
	req, resp, store, _, now := signedFixture(t, VerdictAllow)

	if err := VerifyResponse(req, resp, store, fixtureVerifyOptions(nil), now); err != nil {
		t.Fatalf("expected valid response: %v", err)
	}

	mismatched := resp
	mismatched.SchemaVersion = "extauthz.v2"
	mismatched = resign(t, mismatched, fixturePrivateKey(t))
	if err := VerifyResponse(req, mismatched, store, fixtureVerifyOptions(nil), now); err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("expected schema_version request binding failure, got %v", err)
	}
}

func TestTrustRootBindingRejectsWrongRoot(t *testing.T) {
	req, resp, store, _, now := signedFixture(t, VerdictAllow)
	store.Keys[resp.SigningKeyRef] = TrustedKey{
		TrustRootID: "root-b",
		PublicKey:   store.Keys[resp.SigningKeyRef].PublicKey,
		Enabled:     true,
	}

	if err := VerifyResponse(req, resp, store, fixtureVerifyOptions(nil), now); err == nil || !strings.Contains(err.Error(), "trust root") {
		t.Fatalf("expected trust-root-bound key rejection, got %v", err)
	}
}

func TestMalformedRequestOrResponseFailsClosedEvenWhenSigned(t *testing.T) {
	req, resp, store, privateKey, now := signedFixture(t, VerdictAllow)

	badSchemaReq := req
	badSchemaResp := resp
	badSchemaReq.SchemaVersion = "extauthz.v0"
	badSchemaResp.SchemaVersion = badSchemaReq.SchemaVersion
	badSchemaResp = resign(t, badSchemaResp, privateKey)
	if err := VerifyResponse(badSchemaReq, badSchemaResp, store, fixtureVerifyOptions(nil), now); err == nil || !strings.Contains(err.Error(), "unsupported request schema_version") {
		t.Fatalf("expected unsupported schema rejection, got %v", err)
	}

	missingRequestHashReq := req
	missingRequestHashResp := resp
	missingRequestHashReq.RequestBodyHash = ""
	missingRequestHashResp.RequestBodyHash = ""
	missingRequestHashResp = resign(t, missingRequestHashResp, privateKey)
	if err := VerifyResponse(missingRequestHashReq, missingRequestHashResp, store, fixtureVerifyOptions(nil), now); err == nil || !strings.Contains(err.Error(), "missing request request_body_hash") {
		t.Fatalf("expected missing request hash rejection, got %v", err)
	}

	symbolicRequestHashReq := req
	symbolicRequestHashResp := resp
	symbolicRequestHashReq.RequestBodyHash = "sha256:request"
	symbolicRequestHashResp.RequestBodyHash = symbolicRequestHashReq.RequestBodyHash
	symbolicRequestHashResp = resign(t, symbolicRequestHashResp, privateKey)
	if err := VerifyResponse(symbolicRequestHashReq, symbolicRequestHashResp, store, fixtureVerifyOptions(nil), now); err == nil || !strings.Contains(err.Error(), "invalid request request_body_hash") {
		t.Fatalf("expected symbolic request hash rejection, got %v", err)
	}

	badProtocolReq := req
	badProtocolResp := resp
	badProtocolReq.Protocol = "ftp"
	badProtocolResp.Protocol = "ftp"
	badProtocolResp = resign(t, badProtocolResp, privateKey)
	if err := VerifyResponse(badProtocolReq, badProtocolResp, store, fixtureVerifyOptions(nil), now); err == nil || !strings.Contains(err.Error(), "unsupported protocol") {
		t.Fatalf("expected unsupported protocol rejection, got %v", err)
	}

	missingVerdictRef := resp
	missingVerdictRef.KernelVerdictRef = ""
	missingVerdictRef = resign(t, missingVerdictRef, privateKey)
	if err := VerifyResponse(req, missingVerdictRef, store, fixtureVerifyOptions(nil), now); err == nil || !strings.Contains(err.Error(), "missing response kernel_verdict_ref") {
		t.Fatalf("expected missing verdict ref rejection, got %v", err)
	}

	missingDeadlineReq := req
	missingDeadlineResp := resp
	missingDeadlineReq.DeadlineMS = 0
	missingDeadlineResp.DeadlineMS = 0
	missingDeadlineResp = resign(t, missingDeadlineResp, privateKey)
	if err := VerifyResponse(missingDeadlineReq, missingDeadlineResp, store, fixtureVerifyOptions(nil), now); err == nil || !strings.Contains(err.Error(), "missing request deadline_ms") {
		t.Fatalf("expected missing deadline rejection, got %v", err)
	}
}

func TestGatewayResponseFailsClosedOnKernelOutageOrUnverifiableVerdict(t *testing.T) {
	req, resp, store, _, now := signedFixture(t, VerdictAllow)
	resp.KernelVerdictSignature = "00"

	if eval, err := EvaluateGatewayResponse(req, resp, store, fixtureVerifyOptions(nil), now); err == nil || eval.DispatchAuthorized {
		t.Fatalf("bad signature must fail closed, eval=%+v err=%v", eval, err)
	}

	req, resp, store, _, now = signedFixture(t, VerdictAllow)
	if eval, err := EvaluateGatewayResponse(req, resp, store, fixtureVerifyOptions(nil), now); err == nil || eval.DispatchAuthorized || eval.ReasonCode != ReasonPermitConsumerRequired {
		t.Fatalf("verify-only ALLOW must fail closed, eval=%+v err=%v", eval, err)
	}
}

func TestEvaluateAndConsumeRequiresDurablePermitConsumer(t *testing.T) {
	req, resp, store, _, now := signedFixture(t, VerdictAllow)
	ledger := NewPermitLedger()

	if eval, _, err := EvaluateAndConsumeGatewayResponse(req, resp, store, fixtureVerifyOptions(ledger), now); err == nil || eval.ReasonCode != ReasonDurablePermitStoreRequired {
		t.Fatalf("expected durable permit store requirement, eval=%+v err=%v", eval, err)
	}

	durable := durableLedger{NewPermitLedger()}
	eval, record, err := EvaluateAndConsumeGatewayResponse(req, resp, store, fixtureVerifyOptions(durable), now)
	if err != nil || !eval.DispatchAuthorized || record.ProofState != ProofStateAuthorized {
		t.Fatalf("expected durable consume success, eval=%+v record=%+v err=%v", eval, record, err)
	}
	if _, _, err := EvaluateAndConsumeGatewayResponse(req, resp, store, fixtureVerifyOptions(durable), now); err == nil {
		t.Fatal("duplicate permit consume should fail")
	}
}

func TestExpiredPermitFailsBeforeDispatch(t *testing.T) {
	req, resp, store, privateKey, now := signedFixture(t, VerdictAllow)
	resp.PermitExpiry = now.Add(-time.Second).UTC().Format(time.RFC3339Nano)
	resp = resign(t, resp, privateKey)

	if _, _, err := EvaluateAndConsumeGatewayResponse(req, resp, store, fixtureVerifyOptions(durableLedger{NewPermitLedger()}), now); err == nil || !strings.Contains(err.Error(), "stale permit") {
		t.Fatalf("expected stale permit rejection, got %v", err)
	}
}

func TestPermitExpiryCannotOutliveVerdict(t *testing.T) {
	req, resp, store, privateKey, now := signedFixture(t, VerdictAllow)
	resp.KernelVerdictExpiresAt = now.Add(10 * time.Second).UTC().Format(time.RFC3339Nano)
	resp.PermitExpiry = now.Add(30 * time.Second).UTC().Format(time.RFC3339Nano)
	resp = resign(t, resp, privateKey)

	if _, _, err := EvaluateAndConsumeGatewayResponse(req, resp, store, fixtureVerifyOptions(durableLedger{NewPermitLedger()}), now); err == nil || !strings.Contains(err.Error(), "permit expiry exceeds verdict expiry") {
		t.Fatalf("expected permit expiry bound rejection, got %v", err)
	}
}

func TestStaleVerdictCacheableAllowAndPolicyEpochFailClosed(t *testing.T) {
	req, resp, store, privateKey, now := signedFixture(t, VerdictAllow)

	stale := resp
	stale.KernelVerdictExpiresAt = now.Add(-time.Second).UTC().Format(time.RFC3339Nano)
	stale = resign(t, stale, privateKey)
	if err := VerifyResponse(req, stale, store, fixtureVerifyOptions(nil), now); err == nil || !strings.Contains(err.Error(), "stale verdict") {
		t.Fatalf("expected stale verdict rejection, got %v", err)
	}

	cacheable := resp
	cacheable.CachePolicy = "public"
	cacheable = resign(t, cacheable, privateKey)
	if err := VerifyResponse(req, cacheable, store, fixtureVerifyOptions(nil), now); err == nil || !strings.Contains(err.Error(), "no_store") {
		t.Fatalf("expected cacheable ALLOW rejection, got %v", err)
	}

	opts := fixtureVerifyOptions(nil)
	opts.ExpectedPolicyEpoch = "epoch-10"
	if err := VerifyResponse(req, resp, store, opts, now); err == nil || !strings.Contains(err.Error(), "stale policy epoch") {
		t.Fatalf("expected stale policy epoch rejection, got %v", err)
	}
}

func TestAllowRequiresExplicitVerifierContextAndBoundedTTL(t *testing.T) {
	req, resp, store, privateKey, now := signedFixture(t, VerdictAllow)

	opts := fixtureVerifyOptions(nil)
	opts.ExpectedKernelTrustRootID = ""
	if err := VerifyResponse(req, resp, store, opts, now); err == nil || !strings.Contains(err.Error(), "expected kernel trust root") {
		t.Fatalf("expected missing trust root rejection, got %v", err)
	}

	opts = fixtureVerifyOptions(nil)
	opts.ExpectedPolicyEpoch = ""
	if err := VerifyResponse(req, resp, store, opts, now); err == nil || !strings.Contains(err.Error(), "expected policy epoch") {
		t.Fatalf("expected missing policy epoch rejection, got %v", err)
	}

	longVerdict := resp
	longVerdict.KernelVerdictExpiresAt = now.Add(3 * time.Minute).UTC().Format(time.RFC3339Nano)
	longVerdict.PermitExpiry = now.Add(30 * time.Second).UTC().Format(time.RFC3339Nano)
	longVerdict = resign(t, longVerdict, privateKey)
	if err := VerifyResponse(req, longVerdict, store, fixtureVerifyOptions(nil), now); err == nil || !strings.Contains(err.Error(), "verdict ttl exceeds maximum") {
		t.Fatalf("expected max verdict ttl rejection, got %v", err)
	}

	longPermit := resp
	longPermit.KernelVerdictExpiresAt = now.Add(100 * time.Second).UTC().Format(time.RFC3339Nano)
	longPermit.PermitExpiry = now.Add(90 * time.Second).UTC().Format(time.RFC3339Nano)
	longPermit = resign(t, longPermit, privateKey)
	if err := VerifyResponse(req, longPermit, store, fixtureVerifyOptions(nil), now); err == nil || !strings.Contains(err.Error(), "permit ttl exceeds maximum") {
		t.Fatalf("expected max permit ttl rejection, got %v", err)
	}
}

func TestPermitLedgerRejectsDirectBindingMismatchAndReplayKeys(t *testing.T) {
	req, resp, _, _, now := signedFixture(t, VerdictAllow)

	mismatchedReq := req
	mismatchedReq.WorkspaceID = "workspace-b"
	if _, err := NewPermitLedger().ConsumePermit(mismatchedReq, resp, now); err == nil || !strings.Contains(err.Error(), "binding mismatch") {
		t.Fatalf("expected direct ledger binding mismatch rejection, got %v", err)
	}

	nonceLedger := NewPermitLedger()
	if record, err := nonceLedger.ConsumePermit(req, resp, now); err != nil || record.BudgetReservationRef != resp.BudgetReservationRef {
		t.Fatalf("expected first permit consume and budget binding, record=%+v err=%v", record, err)
	}
	nonceReq := req
	nonceResp := resp
	nonceReq.IdempotencyKeyCandidate = "idem-002"
	nonceResp.IdempotencyKeyCandidate = nonceReq.IdempotencyKeyCandidate
	nonceResp.EffectPermitRef = "permit-002"
	nonceResp.KernelVerdictRef = "kernel-verdict:002"
	if _, err := nonceLedger.ConsumePermit(nonceReq, nonceResp, now); err == nil || !strings.Contains(err.Error(), "duplicate permit nonce") {
		t.Fatalf("expected duplicate nonce rejection, got %v", err)
	}

	verdictLedger := NewPermitLedger()
	if _, err := verdictLedger.ConsumePermit(req, resp, now); err != nil {
		t.Fatalf("expected first permit consume: %v", err)
	}
	verdictReq := req
	verdictResp := resp
	verdictReq.IdempotencyKeyCandidate = "idem-003"
	verdictResp.IdempotencyKeyCandidate = verdictReq.IdempotencyKeyCandidate
	verdictResp.EffectPermitRef = "permit-003"
	verdictResp.PermitNonce = "nonce-003"
	if _, err := verdictLedger.ConsumePermit(verdictReq, verdictResp, now); err == nil || !strings.Contains(err.Error(), "duplicate kernel verdict") {
		t.Fatalf("expected duplicate kernel verdict rejection, got %v", err)
	}
}

func TestDenyAndEscalateCannotCarryPermitMaterial(t *testing.T) {
	for _, verdict := range []string{VerdictDeny, VerdictEscalate} {
		req, resp, store, privateKey, now := signedFixture(t, verdict)
		if err := VerifyResponse(req, resp, store, fixtureVerifyOptions(nil), now); err != nil {
			t.Fatalf("%s should verify without permit material: %v", verdict, err)
		}
		resp.EffectPermitRef = "permit-forbidden"
		resp = resign(t, resp, privateKey)
		if err := VerifyResponse(req, resp, store, fixtureVerifyOptions(nil), now); err == nil {
			t.Fatalf("%s with permit material should fail", verdict)
		}
	}
}

func TestPermitLedgerProofLifecycleRequiresConnectorEvidenceAndIsTerminal(t *testing.T) {
	req, resp, store, _, now := signedFixture(t, VerdictAllow)
	ledger := durableLedger{NewPermitLedger()}
	_, record, err := EvaluateAndConsumeGatewayResponse(req, resp, store, fixtureVerifyOptions(ledger), now)
	if err != nil {
		t.Fatalf("consume failed: %v", err)
	}

	if _, err := ledger.FinalizeProof(record.EffectPermitRef, "evidencepack:1", "receipt:1", "proofedge:1"); err == nil {
		t.Fatal("finalization before outcome should fail")
	}
	if _, err := ledger.RecordOutcome(record.EffectPermitRef, EffectOutcomeSucceeded, "sha256:9999999999999999999999999999999999999999999999999999999999999999", "sha256:8888888888888888888888888888888888888888888888888888888888888888", "connector:receipt"); err == nil {
		t.Fatal("request hash mismatch should fail")
	}
	if _, err := ledger.RecordOutcome(record.EffectPermitRef, EffectOutcomeSucceeded, req.RequestBodyHash, "sha256:8888888888888888888888888888888888888888888888888888888888888888", ""); err == nil {
		t.Fatal("successful mutation without connector receipt should fail")
	}
	if _, err := ledger.RecordOutcome(record.EffectPermitRef, EffectOutcomeSucceeded, req.RequestBodyHash, "sha256:response", "connector:receipt"); err == nil || !strings.Contains(err.Error(), "invalid response hash") {
		t.Fatalf("expected invalid response hash rejection, got %v", err)
	}
	if got, err := ledger.RecordOutcome(record.EffectPermitRef, EffectOutcomeSucceeded, req.RequestBodyHash, "sha256:8888888888888888888888888888888888888888888888888888888888888888", "connector:receipt"); err != nil || got.ProofState != ProofStatePending {
		t.Fatalf("expected proof pending, got=%+v err=%v", got, err)
	}
	if _, err := ledger.RecordOutcome(record.EffectPermitRef, EffectOutcomeSucceeded, req.RequestBodyHash, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "connector:other"); err == nil {
		t.Fatal("recorded outcome must be immutable")
	}
	if got, err := ledger.MarkProofFinalizationFailed(record.EffectPermitRef); err != nil || got.ProofState != ProofStateFailed {
		t.Fatalf("expected proof finalization failed, got=%+v err=%v", got, err)
	}
	if got, err := ledger.FinalizeProof(record.EffectPermitRef, "evidencepack:1", "receipt:1", "proofedge:1"); err != nil || got.ProofState != ProofStateFinalized {
		t.Fatalf("expected finalized proof, got=%+v err=%v", got, err)
	}
	if _, err := ledger.RecordOutcome(record.EffectPermitRef, EffectOutcomeFailed, req.RequestBodyHash, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "connector:other"); err == nil {
		t.Fatal("finalized proof must be terminal")
	}
	if _, err := ledger.FinalizeProof(record.EffectPermitRef, "evidencepack:2", "receipt:2", "proofedge:2"); err == nil {
		t.Fatal("finalized proof must not be overwritten")
	}
}

func TestEffectFailedOutcomeCannotFinalizeProof(t *testing.T) {
	req, resp, store, _, now := signedFixture(t, VerdictAllow)
	ledger := durableLedger{NewPermitLedger()}
	_, record, err := EvaluateAndConsumeGatewayResponse(req, resp, store, fixtureVerifyOptions(ledger), now)
	if err != nil {
		t.Fatalf("consume failed: %v", err)
	}
	if got, err := ledger.RecordOutcome(record.EffectPermitRef, EffectOutcomeFailed, req.RequestBodyHash, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ""); err != nil || got.ProofState != ProofStateEffectFailed {
		t.Fatalf("expected effect failed, got=%+v err=%v", got, err)
	}
	if _, err := ledger.FinalizeProof(record.EffectPermitRef, "evidencepack:1", "receipt:1", "proofedge:1"); err == nil {
		t.Fatal("failed effect should not finalize proof")
	}
}

func signedFixture(t *testing.T, verdict string) (AuthorizationRequest, AuthorizationResponse, TrustStore, ed25519.PrivateKey, time.Time) {
	t.Helper()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	privateKey := fixturePrivateKey(t)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	req := AuthorizationRequest{
		SchemaVersion:           SchemaVersionV1,
		ContractVersion:         ContractVersionV1,
		RequestID:               "req-001",
		TenantID:                "tenant-a",
		WorkspaceID:             "workspace-a",
		PrincipalID:             "principal:agent:alpha",
		PrincipalSeq:            7,
		AgentIdentityProfileRef: "agent-profile:alpha",
		Protocol:                "mcp",
		ActionURN:               "urn:helm:action:create-ticket",
		ToolURN:                 "urn:helm:tool:linear.create_issue",
		ConnectorID:             "linear",
		ConnectorContractHash:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		ExecutorKind:            "gateway",
		EffectClass:             "ticket.write",
		RiskClass:               "P1",
		ArgsC14NHash:            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		RequestBodyHash:         "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		PlanHash:                "sha256:4444444444444444444444444444444444444444444444444444444444444444",
		PolicyHash:              "sha256:5555555555555555555555555555555555555555555555555555555555555555",
		P0Hash:                  "sha256:6666666666666666666666666666666666666666666666666666666666666666",
		PolicyEpoch:             "epoch-9",
		IdempotencyKeyCandidate: "idem-001",
		PayloadClass:            "metadata",
		RedactionProfile:        "rp-standard",
		UpstreamTraceID:         "trace-001",
		UpstreamRunID:           "run-001",
		DeadlineMS:              1500,
		RiskContextHash:         "sha256:7777777777777777777777777777777777777777777777777777777777777777",
	}
	resp := AuthorizationResponse{
		SchemaVersion:           req.SchemaVersion,
		ContractVersion:         req.ContractVersion,
		RequestID:               req.RequestID,
		TenantID:                req.TenantID,
		WorkspaceID:             req.WorkspaceID,
		PrincipalID:             req.PrincipalID,
		PrincipalSeq:            req.PrincipalSeq,
		AgentIdentityProfileRef: req.AgentIdentityProfileRef,
		Protocol:                req.Protocol,
		ActionURN:               req.ActionURN,
		ToolURN:                 req.ToolURN,
		ConnectorID:             req.ConnectorID,
		ConnectorContractHash:   req.ConnectorContractHash,
		ExecutorKind:            req.ExecutorKind,
		EffectClass:             req.EffectClass,
		RiskClass:               req.RiskClass,
		ArgsC14NHash:            req.ArgsC14NHash,
		RequestBodyHash:         req.RequestBodyHash,
		PlanHash:                req.PlanHash,
		PolicyHash:              req.PolicyHash,
		P0Hash:                  req.P0Hash,
		PolicyEpoch:             req.PolicyEpoch,
		IdempotencyKeyCandidate: req.IdempotencyKeyCandidate,
		PayloadClass:            req.PayloadClass,
		RedactionProfile:        req.RedactionProfile,
		UpstreamTraceID:         req.UpstreamTraceID,
		UpstreamRunID:           req.UpstreamRunID,
		DeadlineMS:              req.DeadlineMS,
		RiskContextHash:         req.RiskContextHash,
		Verdict:                 verdict,
		ReasonCode:              "fixture",
		KernelTrustRootID:       "root-a",
		SigningKeyRef:           "key-a",
		KernelVerdictRef:        "kernel-verdict:001",
		KernelVerdictIssuedAt:   now.Add(-time.Second).Format(time.RFC3339Nano),
		KernelVerdictExpiresAt:  now.Add(time.Minute).Format(time.RFC3339Nano),
		CachePolicy:             CachePolicyNoStore,
		ReplayHint:              "no_dispatch",
	}
	if verdict == VerdictAllow {
		resp.EffectPermitRef = "permit-001"
		resp.PermitNonce = "nonce-001"
		resp.PermitExpiry = now.Add(30 * time.Second).Format(time.RFC3339Nano)
		resp.ProofSessionRef = "proof-session:001"
		resp.EvidenceReservationRef = "evidence-reservation:001"
		resp.BudgetReservationRef = "budget-reservation:001"
		resp.ReplayHint = ReplayHintSingleUse
		resp.ProofObligation = "effect_receipt_required"
		resp.ConnectorReceiptPolicy = "required_on_success"
		resp.ProofFinalizationPolicy = "retry_then_mark_failed"
	}
	resp = resign(t, resp, privateKey)
	store := TrustStore{Keys: map[string]TrustedKey{"key-a": {
		TrustRootID: "root-a",
		PublicKey:   append([]byte(nil), publicKey...),
		Enabled:     true,
	}}}
	return req, resp, store, privateKey, now
}

func fixturePrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := []byte("0123456789abcdef0123456789abcdef")
	return ed25519.NewKeyFromSeed(seed)
}

func resign(t *testing.T, resp AuthorizationResponse, privateKey ed25519.PrivateKey) AuthorizationResponse {
	t.Helper()
	signed, err := SignResponse(resp, privateKey)
	if err != nil {
		t.Fatalf("sign response: %v", err)
	}
	return signed
}
