package admission

// quantum_posture: signs and verifies classical Ed25519 test receipts and
// recomputes SHA-256 digests; no post-quantum claim.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

const (
	sampleAttempt = "0190a5b4-0000-7000-8000-000000000001"
	sampleMandate = "0190a5b4-0000-7000-8000-0000000000aa"
	samplePermit  = "0190a5b4-0000-7000-8000-0000000000bb"
	sampleHead    = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"
)

func sum256(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func sampleDecision() storedDecision {
	return storedDecision{
		TenantID: tenantA, WorkspaceID: workspace, AttemptID: sampleAttempt, Version: 2,
		FromState: "PROPOSED", State: "ADMITTED", EffectType: noteType,
		RequesterPrincipalID: "human-a", RequesterActorID: actor, MandateID: sampleMandate, RiskClass: "low",
		RequestDigest: sum256("request"), TargetDigest: sum256("ops"), ArgumentDigest: sum256(`{"text":"hi"}`),
		Quote: []Amount{{Unit: "count", Amount: 1}}, PermitID: samplePermit,
		AuthorityVersions: []AuthorityVersion{{Kind: "tenant", Version: 3}, {Kind: "principal", Key: "human-a", Version: 1}},
		DecidedAt:         time.Date(2030, 1, 2, 3, 4, 5, 123456000, time.UTC),
	}
}

func bindingSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "protocols", "json-schemas", "gateway", "receipt-binding.v1.schema.json"))
	must(t, err)
	raw, err := os.ReadFile(path) // #nosec G304 -- repository schema path
	must(t, err)
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	url := "file:///" + strings.ReplaceAll(path, string(filepath.Separator), "/")
	must(t, compiler.AddResource(url, bytes.NewReader(raw)))
	schema, err := compiler.Compile(url)
	must(t, err)
	return schema
}

func trustTestKey() receiptverify.TrustRoot {
	return receiptverify.TrustRoot{Keys: map[string]string{testReceiptSigner.GetKeyID(): testReceiptSigner.PublicKey()}}
}

// TestReceiptChainIDFramesTenantAndWorkspace: a chain is one (tenant,
// workspace), and no tenant or workspace text can make two pairs share one.
func TestReceiptChainIDFramesTenantAndWorkspace(t *testing.T) {
	if got := receiptChainID("tenant-a", "ws-a"); got != "helm-gateway:8:tenant-a:4:ws-a" {
		t.Fatalf("chain id = %q", got)
	}
	if receiptChainID("a:1:b", "c") == receiptChainID("a", "b:1:c") {
		t.Fatal("two (tenant, workspace) pairs share a chain id")
	}
}

// TestDecisionReceiptBindsTheStoredDecision: the pure builder maps a stored
// decision to receipt.v5 fields exactly, and commits the gateway's own facts
// through output_hash, the SHA-256 of the closed JCS binding document.
func TestDecisionReceiptBindsTheStoredDecision(t *testing.T) {
	d := sampleDecision()
	r, binding, err := buildDecisionReceipt(d, "0190a5b4-0000-7000-8000-0000000000cc", 7, sampleHead)
	must(t, err)
	snapshot := `{"schema":"helm.gateway.authority-snapshot.v1","versions":[{"key":"","kind":"tenant","version":3},{"key":"human-a","kind":"principal","version":1}]}`
	output := sha256.Sum256(binding)
	want := map[string][2]string{
		"receipt_id":  {r.ReceiptID, "0190a5b4-0000-7000-8000-0000000000cc"},
		"decision_id": {r.DecisionID, sampleAttempt + ":2"},
		"effect_id":   {r.EffectID, sampleAttempt},
		"status":      {r.Status, "ADMITTED"},
		"verdict":     {r.Verdict, "ALLOW"},
		"reason_code": {r.ReasonCode, ""},
		"session_id":  {r.SessionID, "helm-gateway:8:tenant-a:4:ws-a"},
		"prev_hash":   {r.PrevHash, sampleHead},
		"args_hash":   {r.ArgsHash, hex.EncodeToString(sum256(`{"text":"hi"}`))},
		"output_hash": {r.OutputHash, hex.EncodeToString(output[:])},
		"policy_hash": {r.PolicyHash, hex.EncodeToString(sum256(snapshot))},
	}
	for field, pair := range want {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q", field, pair[0], pair[1])
		}
	}
	if r.LamportClock != 7 || !r.Timestamp.Equal(d.DecidedAt) || r.Signature != "" {
		t.Fatalf("lamport %d, timestamp %v, signature %q", r.LamportClock, r.Timestamp, r.Signature)
	}

	// The binding is closed, versioned, canonical, and names the stored row.
	var doc map[string]any
	must(t, json.Unmarshal(binding, &doc))
	canonical, err := canonicalize.JCS(doc)
	must(t, err)
	if !bytes.Equal(canonical, binding) {
		t.Fatal("the stored binding bytes are not their own JCS form")
	}
	for field, value := range map[string]any{
		"binding_version": ReceiptBindingVersion, "chain_id": r.SessionID, "seq": float64(7), "attempt_version": float64(2),
		"tenant_id": tenantA, "workspace_id": workspace, "from_state": "PROPOSED", "state": "ADMITTED", "verdict": "ALLOW",
		"permit_id": samplePermit, "mandate_id": sampleMandate, "policy_hash": r.PolicyHash, "argument_digest": r.ArgsHash,
		"decided_at": "2030-01-02T03:04:05.123456Z", "approval_digest": "", "approval_expires_at": "",
		"approver_actor_id": "", "step_up_issuer": "", "step_up_jti": "",
	} {
		if doc[field] != value {
			t.Errorf("binding %s = %v, want %v", field, doc[field], value)
		}
	}
	if q := doc["quote"].([]any); len(q) != 1 || q[0].(map[string]any)["amount"] != "1" {
		t.Errorf("binding quote = %v", doc["quote"])
	}
	schema := bindingSchema(t)
	if err := schema.Validate(doc); err != nil {
		t.Fatalf("the binding does not match its schema: %v", err)
	}
	doc["grant"] = "all"
	if err := schema.Validate(doc); err == nil {
		t.Fatal("the binding schema accepted an extra member")
	}
	delete(doc, "grant")
	delete(doc, "binding_version")
	if err := schema.Validate(doc); err == nil {
		t.Fatal("the binding schema accepted a document without binding_version")
	}

	// Any change to the stored decision changes what the receipt signs.
	for name, mutate := range map[string]func(*storedDecision){
		"state":     func(d *storedDecision) { d.State, d.ReasonCode = "DENIED", "EFFECT_OUT_OF_SCOPE" },
		"version":   func(d *storedDecision) { d.Version = 3 },
		"workspace": func(d *storedDecision) { d.WorkspaceID = "ws-b" },
		"authority": func(d *storedDecision) { d.AuthorityVersions[0].Version = 4 },
		"approver":  func(d *storedDecision) { d.ApproverPrincipalID = "human-b" },
		"actor":     func(d *storedDecision) { d.ApproverActorID = "spiffe://other" },
		"step-up":   func(d *storedDecision) { d.StepUpIssuer, d.StepUpJTI = "https://issuer.test", "jti-1" },
		"quote":     func(d *storedDecision) { d.Quote[0].Amount = 2 },
		"time":      func(d *storedDecision) { d.DecidedAt = d.DecidedAt.Add(time.Microsecond) },
	} {
		changed := sampleDecision()
		mutate(&changed)
		other, _, err := buildDecisionReceipt(changed, r.ReceiptID, 7, sampleHead)
		must(t, err)
		if other.OutputHash == r.OutputHash && other.PolicyHash == r.PolicyHash && other.DecisionID == r.DecisionID &&
			other.Status == r.Status && other.SessionID == r.SessionID {
			t.Errorf("changing the %s left the signed fields unchanged", name)
		}
	}

	// Genesis has no predecessor, and nothing else is a genesis.
	genesis, _, err := buildDecisionReceipt(d, r.ReceiptID, 1, "")
	must(t, err)
	if genesis.PrevHash != "" || genesis.LamportClock != 1 {
		t.Fatalf("genesis prev %q lamport %d", genesis.PrevHash, genesis.LamportClock)
	}
	for _, link := range []struct {
		seq  uint64
		prev string
	}{{1, sampleHead}, {2, ""}, {0, ""}, {2, "sha256:" + sampleHead}, {2, strings.ToUpper(sampleHead)}} {
		if _, _, err := buildDecisionReceipt(d, r.ReceiptID, link.seq, link.prev); err == nil {
			t.Errorf("receipt %d linked to %q", link.seq, link.prev)
		}
	}
	proposed := sampleDecision()
	proposed.State = "PROPOSED"
	if _, _, err := buildDecisionReceipt(proposed, r.ReceiptID, 1, ""); err == nil {
		t.Fatal("a receipt was built for a state that is not a decision")
	}

	// Signed, the stored bytes verify offline under the gateway key alone.
	envelope, digest, err := sealReceipt(testReceiptSigner, r)
	must(t, err)
	bundle, err := receiptverify.ParseBundle(envelope)
	must(t, err)
	if result := receiptverify.Verify(bundle.Receipts, trustTestKey()); !result.Valid {
		t.Fatalf("sealed receipt does not verify: %+v", result)
	}
	if again, _ := contracts.ReceiptChainHash(bundle.Receipts[0]); again != digest {
		t.Fatal("the stored digest is not the chain hash of the stored bytes")
	}
}

// hybridSigner labels its receipts with a profile the gateway does not record.
type hybridSigner struct{ *crypto.Ed25519Signer }

func (h hybridSigner) SignReceipt(r *contracts.Receipt) error {
	if err := h.Ed25519Signer.SignReceipt(r); err != nil {
		return err
	}
	r.SignatureProfile, r.SignatureAlgorithm = "hybrid", "ed25519+ml-dsa-65"
	return nil
}

// wrongKeySigner signs with one key and publishes another.
type wrongKeySigner struct{ published, signing *crypto.Ed25519Signer }

func (w wrongKeySigner) SignReceipt(r *contracts.Receipt) error { return w.signing.SignReceipt(r) }
func (w wrongKeySigner) PublicKey() string                      { return w.published.PublicKey() }
func (w wrongKeySigner) GetKeyID() string                       { return w.published.GetKeyID() }

// switchSigner fails once told to.
type switchSigner struct {
	*crypto.Ed25519Signer
	fail *atomic.Bool
}

func (s switchSigner) SignReceipt(r *contracts.Receipt) error {
	if s.fail.Load() {
		return errors.New("signing key unavailable")
	}
	return s.Ed25519Signer.SignReceipt(r)
}

func otherSigner(t *testing.T, keyID string) *crypto.Ed25519Signer {
	t.Helper()
	signer, err := crypto.NewEd25519SignerFromSeed(bytes.Repeat([]byte{0x11}, 32), keyID)
	must(t, err)
	return signer
}

// TestNewRefusesAMissingOrUnusableReceiptSigner: admission records no
// decision without a signer whose receipts are classical Ed25519 receipt.v5
// that verify offline under its published key (CTL-059).
func TestNewRefusesAMissingOrUnusableReceiptSigner(t *testing.T) {
	db, mock, err := sqlmock.New()
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	for name, signer := range map[string]ReceiptSigner{
		"no signer":             nil,
		"a hybrid profile":      hybridSigner{testReceiptSigner},
		"a key it does not use": wrongKeySigner{published: testReceiptSigner, signing: otherSigner(t, testReceiptSigner.GetKeyID())},
		"an unnamed key":        otherSigner(t, ""),
		"a key id with =":       otherSigner(t, "gateway=1"),
	} {
		if _, err := New(db, Config{ReceiptSigner: signer}); err == nil {
			t.Errorf("%s: New accepted the signer", name)
		}
	}
	if _, err := New(db, Config{ReceiptSigner: testReceiptSigner}); err != nil {
		t.Fatalf("the fixed-seed Ed25519 signer: %v", err)
	}
	must(t, mock.ExpectationsWereMet())
}

// bytesArg captures a driver argument.
type bytesArg struct{ got *[]byte }

func (b bytesArg) Match(v driver.Value) bool {
	raw, ok := v.([]byte)
	if ok {
		*b.got = append([]byte(nil), raw...)
	}
	return ok
}

type stringArg struct{ got *string }

func (s stringArg) Match(v driver.Value) bool {
	str, ok := v.(string)
	if ok {
		*s.got = str
	}
	return ok
}

func decisionRows(state string, version int64) *sqlmock.Rows {
	d := sampleDecision()
	return sqlmock.NewRows([]string{"workspace_id", "version", "updated_at", "state", "reason_code", "effect_type",
		"requester_principal_id", "requester_actor_id", "mandate_id", "risk_class", "request_digest", "target_digest",
		"argument_digest", "approval_digest", "approval_expires_at", "quote", "episode_id", "organization_version_id"}).
		AddRow(workspace, version, d.DecidedAt, state, "", noteType, "human-a", actor, sampleMandate, "low",
			d.RequestDigest, d.TargetDigest, d.ArgumentDigest, nil, nil, []byte(`[{"unit":"count","amount":1}]`), nil, nil)
}

// TestDecisionTransactionAppendsItsSignedReceiptLast: recording a decision
// writes the attempt row, then locks the workspace's chain head, inserts the
// signed receipt of the row the UPDATE returned and moves the head by
// compare-and-set, in that order and in the decision's own transaction
// (CTL-059).
func TestDecisionTransactionAppendsItsSignedReceiptLast(t *testing.T) {
	db, mock, err := sqlmock.New()
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	svc, err := New(db, Config{ReceiptSigner: testReceiptSigner})
	must(t, err)
	chain := receiptChainID(tenantA, workspace)
	var envelope, binding []byte
	var digest, receiptID string
	mock.ExpectBegin()
	mock.ExpectQuery(`UPDATE authority_effect_attempts\s+SET state = \$3`).
		WithArgs(tenantA, sampleAttempt, "ADMITTED", "", sampleMandate, "low", nil, nil, "PROPOSED").
		WillReturnRows(decisionRows("ADMITTED", 2))
	mock.ExpectExec(`INSERT INTO authority_receipt_chains`).WithArgs(tenantA, chain, ReceiptFormat).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT seq, head_digest, format FROM authority_receipt_chains\s+WHERE tenant_id = \$1 AND chain_id = \$2 FOR UPDATE`).
		WithArgs(tenantA, chain).
		WillReturnRows(sqlmock.NewRows([]string{"seq", "head_digest", "format"}).AddRow(int64(6), sampleHead, ReceiptFormat))
	mock.ExpectExec(`INSERT INTO authority_receipts`).
		WithArgs(tenantA, chain, int64(7), stringArg{&receiptID}, ReceiptFormat, sampleHead, stringArg{&digest}, sampleAttempt,
			int64(2), workspace, "ADMITTED", testReceiptSigner.GetKeyID(), bytesArg{&envelope}, bytesArg{&binding}).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE authority_receipt_chains SET seq = \$3, head_digest = \$4`).
		WithArgs(tenantA, chain, int64(7), sqlmock.AnyArg(), int64(6), sampleHead).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	must(t, err)
	must(t, svc.recordDecision(ctx, tx, decisionWrite{tenantID: tenantA, attemptID: sampleAttempt, from: "PROPOSED",
		state: "ADMITTED", mandate: sampleMandate, risk: "low", permitID: samplePermit,
		versions: sampleDecision().AuthorityVersions}))
	must(t, tx.Commit())
	must(t, mock.ExpectationsWereMet())

	bundle, err := receiptverify.ParseBundle(envelope)
	must(t, err)
	r := bundle.Receipts[0]
	if result := receiptverify.Verify(bundle.Receipts, trustTestKey()); !result.Valid {
		t.Fatalf("the inserted receipt does not verify: %+v", result)
	}
	want, _, err := buildDecisionReceipt(sampleDecision(), receiptID, 7, sampleHead)
	must(t, err)
	output := sha256.Sum256(binding)
	if r.ReceiptID != receiptID || r.DecisionID != want.DecisionID || r.OutputHash != hex.EncodeToString(output[:]) ||
		r.OutputHash != want.OutputHash || r.PolicyHash != want.PolicyHash || r.PrevHash != sampleHead || r.LamportClock != 7 {
		t.Fatalf("the inserted receipt %+v is not the stored decision's %+v", r, want)
	}
	if again, _ := contracts.ReceiptChainHash(r); again != digest {
		t.Fatal("the inserted digest is not the chain hash of the inserted bytes")
	}
}

// TestADecisionWhoseReceiptCannotBeSignedFailsTheTransaction: a signing
// failure, a chain in a format this binary does not write, and a head that
// moved under its lock each fail the decision before or instead of the
// receipt insert, so the caller's transaction rolls back (CTL-059).
func TestADecisionWhoseReceiptCannotBeSignedFailsTheTransaction(t *testing.T) {
	var fail atomic.Bool
	db, mock, err := sqlmock.New()
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	svc, err := New(db, Config{ReceiptSigner: switchSigner{testReceiptSigner, &fail}})
	must(t, err)
	ctx := context.Background()
	write := decisionWrite{tenantID: tenantA, attemptID: sampleAttempt, from: "PROPOSED", state: "DENIED",
		reason: contracts.ReasonEffectOutOfScope, risk: "low"}
	for name, test := range map[string]struct {
		fail   bool
		head   *sqlmock.Rows
		insert bool
		moved  bool
	}{
		"the signer fails":  {fail: true, head: sqlmock.NewRows([]string{"seq", "head_digest", "format"}).AddRow(int64(0), "", ReceiptFormat)},
		"a foreign format":  {head: sqlmock.NewRows([]string{"seq", "head_digest", "format"}).AddRow(int64(0), "", "receipt.v6")},
		"a head that moved": {head: sqlmock.NewRows([]string{"seq", "head_digest", "format"}).AddRow(int64(0), "", ReceiptFormat), insert: true, moved: true},
	} {
		fail.Store(test.fail)
		mock.ExpectBegin()
		mock.ExpectQuery(`UPDATE authority_effect_attempts`).WillReturnRows(decisionRows("DENIED", 2))
		mock.ExpectExec(`INSERT INTO authority_receipt_chains`).WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery(`SELECT seq, head_digest, format FROM authority_receipt_chains`).WillReturnRows(test.head)
		if test.insert {
			mock.ExpectExec(`INSERT INTO authority_receipts`).WillReturnResult(sqlmock.NewResult(0, 1))
		}
		if test.moved {
			mock.ExpectExec(`UPDATE authority_receipt_chains SET seq`).WillReturnResult(sqlmock.NewResult(0, 0))
		}
		mock.ExpectRollback()
		tx, err := db.BeginTx(ctx, nil)
		must(t, err)
		if err := svc.recordDecision(ctx, tx, write); err == nil {
			t.Errorf("%s: the decision was recorded", name)
		}
		must(t, tx.Rollback())
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// TestReceiptFenceIsADeferredCheckOnEveryDecisionWrite: migration 15 holds
// the ledger fence, a deferred constraint trigger on every insert into and
// every state change into ADMITTED, DENIED or ESCALATED, requiring the
// receipt of that attempt version at commit. This is the shape a run without
// PostgreSQL can check; TestPostgresADecisionWithoutItsReceiptFailsAtCommit
// proves the behaviour (CTL-059).
func TestReceiptFenceIsADeferredCheckOnEveryDecisionWrite(t *testing.T) {
	var ddl string
	for _, m := range migrations {
		if m.version == 15 {
			var err error
			ddl, err = m.ddl()
			must(t, err)
		}
	}
	normalized := strings.Join(strings.Fields(ddl), " ")
	for _, want := range []string{
		"CREATE CONSTRAINT TRIGGER authority_decision_receipt_insert AFTER INSERT ON authority_effect_attempts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.state IN ('ADMITTED', 'DENIED', 'ESCALATED')) EXECUTE FUNCTION authority_require_decision_receipt();",
		"CREATE CONSTRAINT TRIGGER authority_decision_receipt_update AFTER UPDATE OF state ON authority_effect_attempts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.state IN ('ADMITTED', 'DENIED', 'ESCALATED') AND OLD.state IS DISTINCT FROM NEW.state) EXECUTE FUNCTION authority_require_decision_receipt();",
		"WHERE tenant_id = NEW.tenant_id AND attempt_id = NEW.attempt_id AND attempt_version = NEW.version ) THEN RAISE EXCEPTION 'decision_receipt_missing'",
	} {
		if !strings.Contains(normalized, want) {
			t.Errorf("migration 15 lacks the ledger fence clause %q", want)
		}
	}
}

// BenchmarkSealDecisionReceipt is the per-decision signing cost a decision
// transaction pays while it holds its workspace's chain row: build the
// receipt and its binding, sign, verify the stored bytes and hash them.
func BenchmarkSealDecisionReceipt(b *testing.B) {
	d := sampleDecision()
	b.ReportAllocs()
	for b.Loop() {
		r, _, err := buildDecisionReceipt(d, "0190a5b4-0000-7000-8000-0000000000cc", 7, sampleHead)
		if err != nil {
			b.Fatal(err)
		}
		if _, _, err := sealReceipt(testReceiptSigner, r); err != nil {
			b.Fatal(err)
		}
	}
}
