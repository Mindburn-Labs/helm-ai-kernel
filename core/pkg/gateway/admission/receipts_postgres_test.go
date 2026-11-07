package admission

// CTL-059 against real PostgreSQL 16 (listed in scripts/ci/postgres-proofs.txt):
// every decision admission records commits with its signed receipt, chained
// per (tenant, workspace), and the stored bytes verify offline under the
// gateway's public key alone.
//
// quantum_posture: verifies classical Ed25519 test receipts and recomputes
// SHA-256 digests; no post-quantum claim.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

// storedReceipt is one authority_receipts row.
type storedReceipt struct {
	seq                                                  int64
	receiptID, prev, digest, attemptID, state, keyID, ws string
	version                                              int64
	envelope, binding                                    []byte
}

// chainRows reads a chain's receipts as the owner, in sequence order.
func (f *fixture) chainRows(tenant, ws string) []storedReceipt {
	f.t.Helper()
	var out []storedReceipt
	f.ownerTx(tenant, func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT seq, receipt_id::text, prev_digest, digest, attempt_id::text, state, key_id, workspace_id,
				attempt_version, envelope, binding
			FROM authority_receipts WHERE tenant_id = $1 AND chain_id = $2 ORDER BY seq`, tenant, receiptChainID(tenant, ws))
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var r storedReceipt
			if err := rows.Scan(&r.seq, &r.receiptID, &r.prev, &r.digest, &r.attemptID, &r.state, &r.keyID, &r.ws,
				&r.version, &r.envelope, &r.binding); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out
}

// chainHead reads a chain row as the owner; seq -1 when there is none.
func (f *fixture) chainHead(tenant, ws string) (int64, string) {
	f.t.Helper()
	seq, head := int64(-1), ""
	f.ownerTx(tenant, func(tx *sql.Tx) error {
		err := tx.QueryRow(`SELECT seq, head_digest FROM authority_receipt_chains WHERE tenant_id = $1 AND chain_id = $2`,
			tenant, receiptChainID(tenant, ws)).Scan(&seq, &head)
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	})
	return seq, head
}

// bundleOf is the receipts.json an operator exports: the stored envelopes in
// chain order, as one JSON array.
func bundleOf(t *testing.T, rows []storedReceipt) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, r := range rows {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(r.envelope)
	}
	buf.WriteByte(']')
	return buf.Bytes()
}

func verifyBundle(t *testing.T, raw []byte, trust receiptverify.TrustRoot) receiptverify.Result {
	t.Helper()
	bundle, err := receiptverify.ParseBundle(raw)
	if err != nil {
		return receiptverify.Result{Errors: []string{err.Error()}}
	}
	return receiptverify.VerifyBundle(bundle, trust)
}

// wantContiguousChain checks a chain links from genesis, its head is its last
// receipt, every receipt is signed by the test key and binds its stored row.
func (f *fixture) wantContiguousChain(tenant, ws string, n int) []storedReceipt {
	f.t.Helper()
	rows := f.chainRows(tenant, ws)
	if len(rows) != n {
		f.t.Fatalf("chain %s/%s holds %d receipts, want %d", tenant, ws, len(rows), n)
	}
	prev := ""
	for i, r := range rows {
		if r.seq != int64(i+1) || r.prev != prev || r.ws != ws || r.keyID != testReceiptSigner.GetKeyID() {
			f.t.Fatalf("receipt %d: seq %d prev %q ws %q key %q, want seq %d prev %q", i, r.seq, r.prev, r.ws, r.keyID, i+1, prev)
		}
		bundle, err := receiptverify.ParseBundle(r.envelope)
		must(f.t, err)
		receipt := bundle.Receipts[0]
		digest, err := contracts.ReceiptChainHash(receipt)
		must(f.t, err)
		output := sha256.Sum256(r.binding)
		if digest != r.digest || receipt.OutputHash != hex.EncodeToString(output[:]) || receipt.PrevHash != r.prev ||
			receipt.LamportClock != uint64(r.seq) || receipt.Status != r.state || receipt.ReceiptID != r.receiptID ||
			receipt.DecisionID != fmt.Sprintf("%s:%d", r.attemptID, r.version) || receipt.SessionID != receiptChainID(tenant, ws) {
			f.t.Fatalf("receipt %d does not describe its row: %+v", i, receipt)
		}
		var binding receiptBinding
		decoder := json.NewDecoder(bytes.NewReader(r.binding))
		decoder.DisallowUnknownFields()
		must(f.t, decoder.Decode(&binding))
		if binding.BindingVersion != ReceiptBindingVersion || binding.AttemptID != r.attemptID || binding.AttemptVersion != r.version ||
			binding.State != r.state || binding.TenantID != tenant || binding.Seq != uint64(r.seq) || binding.PolicyHash != receipt.PolicyHash {
			f.t.Fatalf("binding %d does not describe its row: %+v", i, binding)
		}
		prev = r.digest
	}
	if seq, head := f.chainHead(tenant, ws); seq != int64(n) || head != prev {
		f.t.Fatalf("chain head %d %q, want %d %q", seq, head, n, prev)
	}
	if n > 0 {
		if result := verifyBundle(f.t, bundleOf(f.t, rows), trustTestKey()); !result.Valid {
			f.t.Fatalf("the stored chain does not verify offline: %+v", result)
		}
	}
	return rows
}

func TestPostgresDecisionsCommitWithSignedChainedReceipts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	admitted := f.propose(human, note("receipt-note"))
	wantState(t, "note", admitted, "ADMITTED", "")
	denied := f.propose(human, proposal("receipt-off-list", effectargs.GitHubBranchCreateFromChanges, "github.com/Mindburn-Labs/other", branchArgs("helm/x")))
	wantState(t, "off the allowlist", denied, "DENIED", contracts.ReasonEffectOutOfScope)
	escalated := f.escalated("receipt-draft")
	approved, _, err := f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(escalated, "ship it"))
	must(t, err)
	wantState(t, "approved", approved, "ADMITTED", "")

	// The read model carries each decision's receipt, oldest first.
	for _, test := range []struct {
		a      Attempt
		states []string
	}{
		{admitted, []string{"ADMITTED"}},
		{denied, []string{"DENIED"}},
		{approved, []string{"ESCALATED", "ADMITTED"}},
	} {
		got, err := f.svc.Get(ctx, human, test.a.ID)
		must(t, err)
		if len(got.Receipts) != len(test.states) {
			t.Fatalf("%s carries %d receipts, want %d", got.ID, len(got.Receipts), len(test.states))
		}
		for i, ref := range got.Receipts {
			if ref.State != test.states[i] || ref.ChainID != receiptChainID(tenantA, workspace) || ref.KeyID != testReceiptSigner.GetKeyID() ||
				ref.Format != ReceiptFormat || len(ref.Digest) != 64 || ref.Seq == 0 {
				t.Fatalf("%s receipt %d = %+v", got.ID, i, ref)
			}
		}
		if last := got.Receipts[len(got.Receipts)-1]; last.AttemptVersion != got.Version {
			t.Fatalf("%s: last receipt describes version %d, the attempt is at %d", got.ID, last.AttemptVersion, got.Version)
		}
	}
	// The branch the draft was over was admitted too: five decisions.
	rows := f.wantContiguousChain(tenantA, workspace, 5)
	var readmission receiptBinding
	must(t, json.Unmarshal(rows[4].binding, &readmission))
	if readmission.FromState != "ESCALATED" || readmission.ApproverPrincipalID != "human-b" || readmission.PermitID == "" ||
		readmission.ApprovalDigest != hex.EncodeToString(escalated.ApprovalDigest) {
		t.Fatalf("the re-admission binding = %+v", readmission)
	}

	// An idempotent replay records nothing new; another tenant's workspace of
	// the same name is a chain of its own.
	if _, existing, err := f.svc.Propose(ctx, human, note("receipt-note")); err != nil || !existing {
		t.Fatalf("replay: existing=%v err=%v", existing, err)
	}
	f.rootMandate(tenantB, "human-a", skeletonTerms(f.now))
	other := f.propose(Caller{TenantID: tenantB, WorkspaceID: workspace, PrincipalID: "human-a", ActorID: actor}, note("receipt-note"))
	wantState(t, "tenant b", other, "ADMITTED", "")
	f.wantContiguousChain(tenantA, workspace, 5)
	f.wantContiguousChain(tenantB, workspace, 1)
}

func TestPostgresReceiptChainStaysContiguousUnderConcurrentProposals(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	wsB := Caller{TenantID: tenantA, WorkspaceID: "ws-b", PrincipalID: "human-a", ActorID: actor}
	const perWorkspace = 12
	var wg sync.WaitGroup
	errs := make(chan error, 2*perWorkspace)
	for i := range perWorkspace {
		for _, caller := range []Caller{human, wsB} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				in := note(fmt.Sprintf("concurrent-%s-%d", caller.WorkspaceID, i))
				if i%3 == 0 {
					// Denied decisions are receipted too.
					in = proposal(fmt.Sprintf("concurrent-%s-%d", caller.WorkspaceID, i), effectargs.GitHubBranchCreateFromChanges,
						"github.com/Mindburn-Labs/other", branchArgs("helm/x"))
				}
				if _, _, err := f.svc.Propose(ctx, caller, in); err != nil {
					errs <- err
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	for _, ws := range []string{workspace, "ws-b"} {
		rows := f.wantContiguousChain(tenantA, ws, perWorkspace)
		seen := map[string]bool{}
		for _, r := range rows {
			if seen[r.attemptID] {
				t.Fatalf("attempt %s has two receipts in %s", r.attemptID, ws)
			}
			seen[r.attemptID] = true
		}
	}
}

func TestPostgresSigningFailureCommitsNoDecision(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var fail atomic.Bool
	svc, err := New(f.runtime, Config{ReceiptSigner: switchSigner{testReceiptSigner, &fail}})
	must(t, err)

	// A proposal whose receipt cannot be signed leaves no attempt, no content
	// and no chain row behind.
	fail.Store(true)
	if _, _, err := svc.Propose(ctx, human, note("unsigned-1")); err == nil {
		t.Fatal("a decision committed without its receipt")
	}
	if n := f.count(tenantA, `SELECT count(*) FROM authority_effect_attempts WHERE idempotency_key = 'unsigned-1'`); n != 0 {
		t.Fatalf("%d attempts committed without a receipt", n)
	}
	if seq, _ := f.chainHead(tenantA, workspace); seq != -1 {
		t.Fatalf("the chain row committed at %d without a receipt", seq)
	}

	// The same key proposes once the signer recovers: the first attempt left
	// nothing for the idempotency check to find.
	fail.Store(false)
	a, existing, err := svc.Propose(ctx, human, note("unsigned-1"))
	must(t, err)
	if existing || a.State != "ADMITTED" || len(a.Receipts) != 1 || a.Receipts[0].Seq != 1 {
		t.Fatalf("after recovery: existing=%v attempt=%+v", existing, a)
	}

	// An approval whose re-admission cannot be signed leaves the attempt
	// ESCALATED, with no approval recorded and its decide token unspent.
	escalated := f.escalated("unsigned-draft")
	fail.Store(true)
	token := decideToken("helm.gateway.decide")
	if _, _, err := svc.Approve(ctx, approverB, token, approval(escalated, "ship it")); err == nil {
		t.Fatal("an approval committed without its receipt")
	}
	still, err := f.svc.Get(ctx, human, escalated.ID)
	must(t, err)
	if still.State != "ESCALATED" || still.Approval != nil || len(still.Receipts) != 1 || still.Version != escalated.Version {
		t.Fatalf("after a failed approval: %+v", still)
	}
	if n := f.count(tenantA, `SELECT count(*) FROM authority_token_replay WHERE jti = $1`, token.ID); n != 0 {
		t.Fatal("the decide token was spent by a rolled-back approval")
	}
	fail.Store(false)
	f.wantContiguousChain(tenantA, workspace, 3)
}

func TestPostgresReceiptRowsAreAppendOnlyForTheRuntimeRole(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.propose(human, note("append-only"))
	wantState(t, "note", a, "ADMITTED", "")
	rows := f.wantContiguousChain(tenantA, workspace, 1)

	asRuntime := func(tenant, statement string, args ...any) error {
		tx, err := f.runtime.BeginTx(ctx, nil)
		must(t, err)
		defer func() { _ = tx.Rollback() }()
		_, err = tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenant)
		must(t, err)
		_, err = tx.Exec(statement, args...)
		return err
	}
	for _, statement := range []string{
		`UPDATE authority_receipts SET state = 'DENIED'`,
		`UPDATE authority_receipts SET envelope = envelope`,
		`DELETE FROM authority_receipts`,
		`TRUNCATE authority_receipts`,
		`DELETE FROM authority_receipt_chains`,
	} {
		if err := asRuntime(tenantA, statement); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("runtime role %q: err = %v, want permission denied", statement, err)
		}
	}
	// Row security: another tenant's binding sees none of these receipts and
	// cannot write a receipt into tenant A.
	var visible int
	tx, err := f.runtime.BeginTx(ctx, nil)
	must(t, err)
	_, err = tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenantB)
	must(t, err)
	must(t, tx.QueryRow(`SELECT count(*) FROM authority_receipts`).Scan(&visible))
	_ = tx.Rollback()
	if visible != 0 {
		t.Fatalf("tenant B sees %d of tenant A's receipts", visible)
	}
	r := rows[0]
	err = asRuntime(tenantB, `INSERT INTO authority_receipts (tenant_id, chain_id, seq, receipt_id, format, prev_digest, digest,
			attempt_id, attempt_version, workspace_id, state, key_id, envelope, binding)
		VALUES ($1, $2, 2, gen_random_uuid(), 'receipt.v5', $3, $3, $4, 9, $5, 'DENIED', 'k', '\x01', '\x01')`,
		tenantA, receiptChainID(tenantA, workspace), r.digest, r.attemptID, workspace)
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Fatalf("a cross-tenant receipt insert: err = %v, want a row-level security refusal", err)
	}
	// A chain cannot fork: in one transaction, a well-formed successor is
	// accepted, and a second receipt on the same predecessor, a second genesis
	// or a reused sequence number is refused by the ledger itself.
	tx, err = f.runtime.BeginTx(ctx, nil)
	must(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenantA)
	must(t, err)
	insert := func(seq int64, prev, digest string, version int64) error {
		_, err := tx.Exec(`SAVEPOINT probe`)
		must(t, err)
		_, err = tx.Exec(`INSERT INTO authority_receipts (tenant_id, chain_id, seq, receipt_id, format, prev_digest, digest,
				attempt_id, attempt_version, workspace_id, state, key_id, envelope, binding)
			VALUES ($1, $2, $3, gen_random_uuid(), 'receipt.v5', $4, $5, $6, $7, $8, 'DENIED', 'k', '\x01', '\x01')`,
			tenantA, receiptChainID(tenantA, workspace), seq, prev, digest, r.attemptID, version, workspace)
		if err != nil {
			_, rollbackErr := tx.Exec(`ROLLBACK TO SAVEPOINT probe`)
			must(t, rollbackErr)
		}
		return err
	}
	if err := insert(2, r.digest, strings.Repeat("e", 64), 90); err != nil {
		t.Fatalf("a well-formed successor: %v", err)
	}
	for name, probe := range map[string]struct {
		seq     int64
		prev    string
		version int64
	}{
		"a fork":           {3, r.digest, 91},
		"a second genesis": {1, "", 92},
		"a reused seq":     {2, strings.Repeat("e", 64), 93},
	} {
		if err := insert(probe.seq, probe.prev, strings.Repeat("f", 64), probe.version); err == nil || !strings.Contains(err.Error(), "duplicate key") {
			t.Fatalf("%s: err = %v, want a uniqueness refusal", name, err)
		}
	}
}

func TestPostgresStoredReceiptsVerifyOfflineWithTheGatewayKey(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.propose(human, note("offline-1"))
	f.propose(human, proposal("offline-2", effectargs.GitHubBranchCreateFromChanges, "github.com/Mindburn-Labs/other", branchArgs("helm/x")))
	escalated := f.escalated("offline-draft")
	_, _, err := f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(escalated, "ok"))
	must(t, err)
	rows := f.wantContiguousChain(tenantA, workspace, 5)
	raw := bundleOf(t, rows)
	trust := trustTestKey()

	// Known good: the whole chain, and each receipt on its own (an attempt's
	// receipts are not adjacent in its workspace's chain).
	result := verifyBundle(t, raw, trust)
	checks := map[receiptverify.CheckName]receiptverify.Status{}
	for _, c := range result.Checks {
		checks[c.Name] = c.Status
	}
	if !result.Valid || checks[receiptverify.CheckIdentity] != receiptverify.StatusPass || checks[receiptverify.CheckClosure] != receiptverify.StatusPass ||
		result.PreimageVersion != contracts.ReceiptSignatureV5 || result.KeyID != testReceiptSigner.GetKeyID() {
		t.Fatalf("the exported chain: %+v", result)
	}
	for _, r := range rows {
		if result := verifyBundle(t, r.envelope, trust); !result.Valid {
			t.Fatalf("receipt %d alone: %+v", r.seq, result)
		}
	}

	// Known bad: a rewritten verdict, a reordered chain, a dropped receipt and
	// a key that is not the gateway's.
	tampered := bytes.Replace(raw, []byte(`"verdict":"DENY"`), []byte(`"verdict":"ALLOW"`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("the exported chain carries no DENY verdict to tamper with")
	}
	reordered := append([]storedReceipt{rows[1], rows[0]}, rows[2:]...)
	dropped := append(append([]storedReceipt{}, rows[:2]...), rows[3:]...)
	other := otherSigner(t, testReceiptSigner.GetKeyID())
	for name, test := range map[string]struct {
		raw   []byte
		trust receiptverify.TrustRoot
	}{
		"tampered":  {tampered, trust},
		"reordered": {bundleOf(t, reordered), trust},
		"dropped":   {bundleOf(t, dropped), trust},
		"wrong key": {raw, receiptverify.TrustRoot{Keys: map[string]string{other.GetKeyID(): other.PublicKey()}}},
		"no key":    {raw, receiptverify.TrustRoot{}},
	} {
		if result := verifyBundle(t, test.raw, test.trust); result.Valid {
			t.Errorf("%s: the chain verified", name)
		}
	}
	// The binding a receipt commits to cannot be swapped for another.
	if sum := sha256.Sum256(rows[1].binding); hex.EncodeToString(sum[:]) == mustReceipt(t, rows[0].envelope).OutputHash {
		t.Fatal("two decisions share an output_hash")
	}
}

func mustReceipt(t *testing.T, envelope []byte) *contracts.Receipt {
	t.Helper()
	bundle, err := receiptverify.ParseBundle(envelope)
	must(t, err)
	return bundle.Receipts[0]
}

func TestPostgresReceiptSchemaUpgradesFrom14(t *testing.T) {
	f := newFixtureAtVersionWithoutReceipts(t, 14)
	ctx := context.Background()
	// A decision an installed schema-14 binary recorded, without a receipt.
	legacy := "0190a5b4-0000-7000-8000-00000000014a"
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO authority_effect_attempts (tenant_id, attempt_id, workspace_id, idempotency_key, request_digest,
				requester_principal_id, effect_type, target, target_digest, argument_digest, state, reason_code, version)
			VALUES ($1, $2, $3, 'legacy-14', $4, 'human-a', $5, 'ops', $4, $4, 'DENIED', 'EFFECT_OUT_OF_SCOPE', 2)`,
			tenantA, legacy, workspace, sum256("legacy"), noteType)
		return err
	})
	var exists bool
	must(t, f.owner.QueryRow(`SELECT to_regclass('authority_receipts') IS NOT NULL`).Scan(&exists))
	if exists {
		t.Fatal("schema 14 already has receipt tables")
	}

	must(t, Migrate(ctx, f.owner))
	must(t, Migrate(ctx, f.owner))
	version, err := SchemaVersion(ctx, f.owner)
	must(t, err)
	if version != HeadVersion() || HeadVersion() != 15 {
		t.Fatalf("schema at %d after migrating, head %d", version, HeadVersion())
	}
	for _, table := range []string{"authority_receipt_chains", "authority_receipts"} {
		var enabled, forced bool
		must(t, f.owner.QueryRow(`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = to_regclass($1)`, table).Scan(&enabled, &forced))
		if !enabled || !forced {
			t.Fatalf("%s: row security %v, forced %v", table, enabled, forced)
		}
	}
	// The ledger fence arrives with the tables: a schema-14 binary still
	// serving after this point cannot commit a decision without a receipt.
	var fences int
	must(t, f.owner.QueryRow(`SELECT count(*) FROM pg_trigger WHERE tgrelid = to_regclass('authority_effect_attempts')
		AND tgname IN ('authority_decision_receipt_insert', 'authority_decision_receipt_update') AND tgdeferrable AND tginitdeferred`).Scan(&fences))
	if fences != 2 {
		t.Fatalf("%d deferred receipt fences after the upgrade, want 2", fences)
	}
	// The chart's grant step runs after every migrate.
	var schema string
	must(t, f.owner.QueryRow(`SELECT current_schema()`).Scan(&schema))
	grantRuntime(t, f.owner, schema, f.role)

	// The legacy decision stays as it was, without a receipt; the next
	// decision starts the workspace's chain at genesis.
	old, err := f.svc.Get(ctx, human, legacy)
	must(t, err)
	if old.State != "DENIED" || len(old.Receipts) != 0 {
		t.Fatalf("the legacy decision after the upgrade: %+v", old)
	}
	next := f.propose(human, note("after-upgrade"))
	if next.State != "ADMITTED" || len(next.Receipts) != 1 || next.Receipts[0].Seq != 1 {
		t.Fatalf("the first decision after the upgrade: %+v", next)
	}
	f.wantContiguousChain(tenantA, workspace, 1)
	tx, err := f.runtime.BeginTx(ctx, nil)
	must(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenantA)
	must(t, err)
	if _, err := tx.Exec(`UPDATE authority_receipts SET state = state`); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("the runtime role updated a receipt after the upgrade: %v", err)
	}
}

// TestPostgresLiftAndModelCallDecisionsCarryReceipts: a stop's lift, its
// stepped-up approval and a model call's admission are receipted like any
// other decision, and the re-admission binds the approver's workload and the
// step-up proof it used up.
func TestPostgresLiftAndModelCallDecisionsCarryReceipts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// A model call, proposed by an agent under its model mandate.
	f.modelFixture(1_000_000)
	call, _, err := f.svc.Propose(ctx, worker, modelProposal("receipt-model", modelRoute, 1000))
	must(t, err)
	wantState(t, "the model call", call, "ADMITTED", "")
	if len(call.Receipts) != 1 || call.Receipts[0].State != "ADMITTED" || call.Receipts[0].AttemptVersion != call.Version {
		t.Fatalf("the model call carries receipts %+v", call.Receipts)
	}

	// A stop's lift, escalated, and its stepped-up approval.
	must(t, f.rows.CreateEffectType(ctx, tenantA, effectargs.AuthorityLift, authorityrows.RiskLow))
	liftMandate := f.rootMandate(tenantA, "human-c", authorityrows.Terms{
		EffectTypes: []string{effectargs.AuthorityLift}, ValidFrom: f.now.Add(-time.Hour), ValidUntil: f.now.Add(24 * time.Hour),
	})
	stop, _, err := f.svc.Stop(ctx, operator, stopToken(), tenantStop("receipt-stop"))
	must(t, err)
	lift, _, err := f.svc.Lift(ctx, operator, stopToken(), LiftInput{IdempotencyKey: "receipt-lift", StopID: stop.ID, MandateID: liftMandate.ID.String()})
	must(t, err)
	wantState(t, "the lift", lift, "ESCALATED", contracts.ReasonApprovalRequired)
	proof := stepUpProof()
	lifted, _, err := f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), withProof(approval(lift, "lift it"), proof))
	must(t, err)
	wantState(t, "the approved lift", lifted, "ADMITTED", "")
	if len(lifted.Receipts) != 2 || lifted.Receipts[0].State != "ESCALATED" || lifted.Receipts[1].State != "ADMITTED" {
		t.Fatalf("the lift's receipts = %+v", lifted.Receipts)
	}

	rows := f.wantContiguousChain(tenantA, workspace, 3)
	var model receiptBinding
	must(t, json.Unmarshal(rows[0].binding, &model))
	if model.EffectType != effectargs.ModelInference || model.RequesterPrincipalID != worker.PrincipalID || model.State != "ADMITTED" ||
		model.PermitID == "" || model.StepUpJTI != "" {
		t.Fatalf("the model call's binding = %+v", model)
	}
	var readmission receiptBinding
	must(t, json.Unmarshal(rows[2].binding, &readmission))
	if readmission.EffectType != effectargs.AuthorityLift || readmission.FromState != "ESCALATED" ||
		readmission.ApproverPrincipalID != approverB.PrincipalID || readmission.ApproverActorID != approverB.ActorID ||
		readmission.StepUpIssuer != proof.Token.Issuer || readmission.StepUpJTI != proof.Token.ID {
		t.Fatalf("the lift's re-admission binding = %+v", readmission)
	}
}

// TestPostgresADecisionWithoutItsReceiptFailsAtCommit: the ledger itself
// refuses a decision that commits without its receipt, whoever writes it:
// the statement a schema-14 gateway runs during an upgrade, or the owner. A
// transition that is not a decision needs none.
func TestPostgresADecisionWithoutItsReceiptFailsAtCommit(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	inTx := func(db *sql.DB, fn func(*sql.Tx) error) error {
		tx, err := db.BeginTx(ctx, nil)
		must(t, err)
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenantA); err != nil {
			return err
		}
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit()
	}
	// A proposed attempt, inserted the way Propose inserts it.
	propose := func(key string) string {
		var id string
		must(t, inTx(f.owner, func(tx *sql.Tx) error {
			return tx.QueryRow(`INSERT INTO authority_effect_attempts (tenant_id, attempt_id, workspace_id, idempotency_key, request_digest,
					requester_principal_id, effect_type, target, target_digest, argument_digest, state)
				VALUES ($1, gen_random_uuid(), $2, $3, $4, 'human-a', $5, 'ops', $4, $4, 'PROPOSED') RETURNING attempt_id`,
				tenantA, workspace, key, sum256(key), noteType).Scan(&id)
		}))
		return id
	}
	// The exact statement the schema-14 recordDecision ran.
	legacyDecision := func(id, state string) func(*sql.Tx) error {
		return func(tx *sql.Tx) error {
			_, err := tx.Exec(`UPDATE authority_effect_attempts
				SET state = $3, reason_code = $4, mandate_id = $5, risk_class = $6,
				    approval_digest = CASE WHEN $9 = 'PROPOSED' THEN $7 ELSE approval_digest END,
				    approval_expires_at = CASE WHEN $9 = 'PROPOSED' THEN $8 ELSE approval_expires_at END,
				    version = version + 1, updated_at = now()
				WHERE tenant_id = $1 AND attempt_id = $2 AND state = $9`,
				tenantA, id, state, "", nil, "low", nil, nil, "PROPOSED")
			return err
		}
	}
	for _, state := range []string{"ADMITTED", "DENIED"} {
		id := propose("unreceipted-" + state)
		for name, db := range map[string]*sql.DB{"the runtime role": f.runtime, "the owner": f.owner} {
			err := inTx(db, legacyDecision(id, state))
			if err == nil || !strings.Contains(err.Error(), "decision_receipt_missing") {
				t.Fatalf("%s wrote %s without a receipt: err = %v", name, state, err)
			}
		}
		var stored string
		f.ownerTx(tenantA, func(tx *sql.Tx) error {
			return tx.QueryRow(`SELECT state FROM authority_effect_attempts WHERE attempt_id = $1`, id).Scan(&stored)
		})
		if stored != "PROPOSED" {
			t.Fatalf("an unreceipted %s committed: the attempt is %s", state, stored)
		}
	}
	// An attempt inserted already decided is refused the same way.
	err := inTx(f.owner, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO authority_effect_attempts (tenant_id, attempt_id, workspace_id, idempotency_key, request_digest,
				requester_principal_id, effect_type, target, target_digest, argument_digest, state)
			VALUES ($1, gen_random_uuid(), $2, 'born-denied', $3, 'human-a', $4, 'ops', $3, $3, 'DENIED')`,
			tenantA, workspace, sum256("born-denied"), noteType)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "decision_receipt_missing") {
		t.Fatalf("an attempt inserted DENIED without a receipt: err = %v", err)
	}

	// Known good: the gateway's own decision, and a later transition that is
	// not a decision (a cancellation), commit.
	a := f.propose(human, note("receipted"))
	wantState(t, "a receipted decision", a, "ADMITTED", "")
	cancelled, _, err := f.svc.Cancel(ctx, human, Token{Scope: scopePropose}, a.ID)
	must(t, err)
	if cancelled.State != "CANCELLED" || len(cancelled.Receipts) != 1 {
		t.Fatalf("a cancellation: %+v", cancelled)
	}
}
