package admission

// quantum_posture: decision and outcome receipts are signed with classical
// Ed25519 under the receipt.v5 preimage and chained with SHA-256
// (contracts.ReceiptChainHash). A signer that declares any other profile or
// algorithm is refused; no hybrid or post-quantum protection is provided or
// claimed.
//
// Every decision admission records (ADMITTED, DENIED, ESCALATED, including the
// re-admission of an approved escalation) appends one signed receipt to its
// workspace's chain in the decision's own transaction (helm-tracker#276), and
// so does every outcome of an admitted effect (OBSERVED, RECONCILED, SETTLED;
// outcomes.go), in the transaction that records it:
//
//   - the receipt is a contracts.Receipt signed under receipt.v5 (one signing
//     envelope, R4); the gateway's own facts are committed through its
//     output_hash, the SHA-256 of a closed binding document
//     (helm.gateway.receipt-binding.v1) encoded with JCS;
//   - one chain per (tenant, workspace), named by a length-framed chain id in
//     session_id; lamport_clock is the sequence number and prev_hash the
//     predecessor's contracts.ReceiptChainHash, empty at genesis;
//   - the chain row is locked FOR UPDATE as the last row lock the transaction
//     takes on a pre-existing row, so a workspace's decisions serialize on it
//     until they commit; the exact envelope and binding bytes are stored with
//     the digest the next receipt links to. Any failure rolls the decision or
//     the outcome back, and the deferred fences of migrations 15 and 16
//     refuse at commit any decision or outcome written without its receipt
//     (an older binary's, during an upgrade);
//   - args_hash is the hex SHA-256 of the exact argument bytes the attempt
//     stored (its argument_digest), not of a JCS re-encoding of them;
//   - the receipt's timestamp is outside the receipt.v5 preimage, but the next
//     receipt's prev_hash covers it; decided_at (a decision) or settled_at (an
//     outcome) is signed through the binding.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

const (
	// ReceiptFormat is the signed envelope of every receipt this binary
	// writes: contracts.Receipt under the receipt.v5 signing preimage.
	ReceiptFormat = contracts.ReceiptSignatureV5
	// ReceiptBindingVersion names the closed binding document whose SHA-256 a
	// receipt signs as output_hash. Its JSON schema is
	// protocols/json-schemas/gateway/receipt-binding.v1.schema.json.
	ReceiptBindingVersion = "helm.gateway.receipt-binding.v1"
	// authoritySnapshotSchema names the document whose SHA-256 a receipt signs
	// as policy_hash: the versions of the authority rows the decision locked.
	authoritySnapshotSchema = "helm.gateway.authority-snapshot.v1"

	receiptProfileClassical = "classical"
	receiptAlgorithmEd25519 = "ed25519"
)

// ReceiptSigner signs the gateway's decision receipts. The key lives in the
// gateway process and nowhere else (R8); core/pkg/crypto's Ed25519Signer
// satisfies it. PublicKey is the hex Ed25519 public key a verifier trusts
// under GetKeyID.
type ReceiptSigner interface {
	SignReceipt(r *contracts.Receipt) error
	PublicKey() string
	GetKeyID() string
}

// ReceiptRef is one stored receipt of an attempt: where it sits in its chain
// and the digest the next receipt links to. The signed bytes stay in the
// ledger; a reader verifies them against the gateway's published key.
type ReceiptRef struct {
	ReceiptID      string
	ChainID        string
	Seq            uint64
	Digest         string
	KeyID          string
	Format         string
	State          string
	AttemptVersion int64
}

var receiptKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

// CheckReceiptSigner refuses a signer the gateway cannot record receipts
// with: a key id a verifier cannot name (receipt_verify takes
// --key "<key_id>=<hex>"), a public key that is not a 32-byte Ed25519 key, or
// a signer whose signature is not classical Ed25519 over receipt.v5 that
// verifies offline under that public key. It signs one probe receipt.
func CheckReceiptSigner(signer ReceiptSigner) error {
	if signer == nil {
		return errors.New("a receipt signer is required: every decision is recorded with a signed receipt")
	}
	if !receiptKeyIDPattern.MatchString(signer.GetKeyID()) {
		return fmt.Errorf("receipt key id %q must be 1 to 128 characters of letters, digits and . _ : / - starting with a letter or digit", signer.GetKeyID())
	}
	if public, err := hex.DecodeString(signer.PublicKey()); err != nil || len(public) != 32 {
		return errors.New("the receipt signer's public key must be a hex-encoded 32-byte Ed25519 key")
	}
	probe := &contracts.Receipt{
		ReceiptID: "00000000-0000-7000-8000-000000000000", DecisionID: "probe:1", EffectID: "probe",
		Status: "DENIED", Verdict: string(contracts.VerdictDeny), LamportClock: 1,
		SessionID: receiptChainID("probe", "probe"), Timestamp: time.Unix(0, 0).UTC(),
	}
	_, _, err := sealReceipt(signer, probe)
	return err
}

// receiptChainID names the chain of a (tenant, workspace): each part is
// prefixed by its byte length, so no two pairs share an id whatever they
// contain.
func receiptChainID(tenantID, workspaceID string) string {
	return "helm-gateway:" + strconv.Itoa(len(tenantID)) + ":" + tenantID + ":" + strconv.Itoa(len(workspaceID)) + ":" + workspaceID
}

// storedDecision is the attempt row a decision wrote, as UPDATE ... RETURNING
// gave it back, with what the transaction decided it under.
type storedDecision struct {
	TenantID, WorkspaceID, AttemptID string
	Version                          int64
	FromState, State, ReasonCode     string
	EffectType                       string
	RequesterPrincipalID             string
	RequesterActorID                 string
	MandateID, RiskClass             string
	RequestDigest, TargetDigest      []byte
	ArgumentDigest, ApprovalDigest   []byte
	ApprovalExpiresAt                *time.Time
	Quote                            []Amount
	EpisodeID, OrganizationVersionID string
	PermitID, ApproverPrincipalID    string
	ApproverActorID                  string
	StepUpIssuer, StepUpJTI          string
	AuthorityVersions                []AuthorityVersion
	DecidedAt                        time.Time
}

// storedOutcome is the attempt row an outcome write left, as UPDATE ...
// RETURNING gave it back. The row facts it shares with a decision are in the
// embedded storedDecision, whose decision-only members stay empty (no
// approver, no step-up proof, no decision time); PermitID and
// AuthorityVersions are the permit the effect was dispatched under. The
// observation is the one the outcome rests on, as stored.
type storedOutcome struct {
	storedDecision
	Outcome, OutcomeBasis string
	Observation           boundObservation
	SettledAt             time.Time
}

// boundObservation is the stored observation an outcome receipt binds.
type boundObservation struct {
	ID                    int64
	Source, TrustClass    string
	Outcome               string
	EvidenceDigest        []byte
	ResultKind, ResultRef string
	ObservedAt            time.Time
}

// receiptSubject is a stored attempt version a receipt describes: a decision
// (storedDecision) or an outcome (storedOutcome).
type receiptSubject interface {
	row() *storedDecision
	build(receiptID string, seq uint64, prevDigest string) (*contracts.Receipt, []byte, error)
}

func (d storedDecision) row() *storedDecision { return &d }

func (d storedDecision) build(receiptID string, seq uint64, prevDigest string) (*contracts.Receipt, []byte, error) {
	return buildDecisionReceipt(d, receiptID, seq, prevDigest)
}

func (o storedOutcome) row() *storedDecision { return &o.storedDecision }

func (o storedOutcome) build(receiptID string, seq uint64, prevDigest string) (*contracts.Receipt, []byte, error) {
	return buildOutcomeReceipt(o, receiptID, seq, prevDigest)
}

// receiptBinding is helm.gateway.receipt-binding.v1. Every member is always
// present: an empty string (or observation_id 0) is a signed value, never an
// omitted field. A decision receipt leaves the outcome members empty; an
// outcome receipt leaves verdict, decided_at and the approval's approver and
// step-up members empty. Amounts are decimal strings so the document stays
// inside the number range every RFC 8785 implementation reproduces.
type receiptBinding struct {
	BindingVersion        string                    `json:"binding_version"`
	ChainID               string                    `json:"chain_id"`
	Seq                   uint64                    `json:"seq"`
	TenantID              string                    `json:"tenant_id"`
	WorkspaceID           string                    `json:"workspace_id"`
	AttemptID             string                    `json:"attempt_id"`
	AttemptVersion        int64                     `json:"attempt_version"`
	FromState             string                    `json:"from_state"`
	State                 string                    `json:"state"`
	Verdict               string                    `json:"verdict"`
	ReasonCode            string                    `json:"reason_code"`
	EffectType            string                    `json:"effect_type"`
	RequesterPrincipalID  string                    `json:"requester_principal_id"`
	RequesterActorID      string                    `json:"requester_actor_id"`
	MandateID             string                    `json:"mandate_id"`
	RiskClass             string                    `json:"risk_class"`
	RequestDigest         string                    `json:"request_digest"`
	TargetDigest          string                    `json:"target_digest"`
	ArgumentDigest        string                    `json:"argument_digest"`
	Quote                 []bindingAmount           `json:"quote"`
	ApprovalDigest        string                    `json:"approval_digest"`
	ApprovalExpiresAt     string                    `json:"approval_expires_at"`
	ApproverPrincipalID   string                    `json:"approver_principal_id"`
	ApproverActorID       string                    `json:"approver_actor_id"`
	StepUpIssuer          string                    `json:"step_up_issuer"`
	StepUpJTI             string                    `json:"step_up_jti"`
	PermitID              string                    `json:"permit_id"`
	AuthorityVersions     []bindingAuthorityVersion `json:"authority_versions"`
	PolicyHash            string                    `json:"policy_hash"`
	EpisodeID             string                    `json:"episode_id"`
	OrganizationVersionID string                    `json:"organization_version_id"`
	DecidedAt             string                    `json:"decided_at"`
	Outcome               string                    `json:"outcome"`
	OutcomeBasis          string                    `json:"outcome_basis"`
	ObservationID         int64                     `json:"observation_id"`
	ObservationSource     string                    `json:"observation_source"`
	ObservationTrustClass string                    `json:"observation_trust_class"`
	ObservationOutcome    string                    `json:"observation_outcome"`
	EvidenceDigest        string                    `json:"evidence_digest"`
	ResultKind            string                    `json:"result_kind"`
	ResultRef             string                    `json:"result_ref"`
	ObservedAt            string                    `json:"observed_at"`
	SettledAt             string                    `json:"settled_at"`
}

type bindingAmount struct {
	Unit   string `json:"unit"`
	Amount string `json:"amount"`
}

type bindingAuthorityVersion struct {
	Kind    string `json:"kind"`
	Key     string `json:"key"`
	Version int64  `json:"version"`
}

// authoritySnapshot is helm.gateway.authority-snapshot.v1, in the order the
// decision locked the rows (the permit records the same list).
type authoritySnapshot struct {
	Schema   string                    `json:"schema"`
	Versions []bindingAuthorityVersion `json:"versions"`
}

func bindingVersions(versions []AuthorityVersion) []bindingAuthorityVersion {
	out := make([]bindingAuthorityVersion, 0, len(versions))
	for _, v := range versions {
		out = append(out, bindingAuthorityVersion{Kind: v.Kind, Key: v.Key, Version: v.Version})
	}
	return out
}

// authoritySnapshotHash is a receipt's policy_hash: hex SHA-256 of the JCS
// bytes of the authority snapshot.
func authoritySnapshotHash(versions []AuthorityVersion) (string, error) {
	canonical, err := canonicalize.InteroperableJCS(authoritySnapshot{Schema: authoritySnapshotSchema, Versions: bindingVersions(versions)})
	if err != nil {
		return "", fmt.Errorf("authority snapshot: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// receiptVerdict is a decision state's verdict. An outcome state (outcome
// true) has none: its receipt's verdict is empty.
func receiptVerdict(state string) (verdict contracts.Verdict, outcome bool, err error) {
	switch state {
	case "ADMITTED":
		return contracts.VerdictAllow, false, nil
	case "DENIED":
		return contracts.VerdictDeny, false, nil
	case "ESCALATED":
		return contracts.VerdictEscalate, false, nil
	case "OBSERVED", "RECONCILED", "SETTLED":
		return "", true, nil
	}
	return "", false, fmt.Errorf("state %q is neither a decision nor an outcome a receipt records", state)
}

func digestHex(name string, digest []byte, optional bool) (string, error) {
	if optional && len(digest) == 0 {
		return "", nil
	}
	if len(digest) != sha256.Size {
		return "", fmt.Errorf("%s must be %d bytes, got %d", name, sha256.Size, len(digest))
	}
	return hex.EncodeToString(digest), nil
}

func isChainDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// buildDecisionReceipt maps a stored decision to its unsigned receipt and the
// exact binding bytes the receipt commits to. It is pure: the receipt id, the
// sequence number and the predecessor digest come from the caller.
func buildDecisionReceipt(d storedDecision, receiptID string, seq uint64, prevDigest string) (*contracts.Receipt, []byte, error) {
	verdict, outcome, err := receiptVerdict(d.State)
	if err != nil {
		return nil, nil, err
	}
	if outcome {
		return nil, nil, fmt.Errorf("state %q is an outcome, not a decision", d.State)
	}
	if d.DecidedAt.IsZero() {
		return nil, nil, errors.New("a decision receipt needs the decision time")
	}
	doc := receiptBinding{Verdict: string(verdict), ApproverPrincipalID: d.ApproverPrincipalID, ApproverActorID: d.ApproverActorID,
		StepUpIssuer: d.StepUpIssuer, StepUpJTI: d.StepUpJTI, DecidedAt: d.DecidedAt.UTC().Format(time.RFC3339Nano)}
	return buildReceipt(d, doc, d.DecidedAt, receiptID, seq, prevDigest)
}

// buildOutcomeReceipt maps a stored outcome to its unsigned receipt and the
// exact binding bytes the receipt commits to: the row the outcome write
// returned, the permit the effect was dispatched under and the observation
// the outcome rests on. Its verdict is empty and its status the outcome
// state. It is pure, like buildDecisionReceipt.
func buildOutcomeReceipt(o storedOutcome, receiptID string, seq uint64, prevDigest string) (*contracts.Receipt, []byte, error) {
	_, outcome, err := receiptVerdict(o.State)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case !outcome:
		return nil, nil, fmt.Errorf("state %q is a decision, not an outcome", o.State)
	case o.Outcome != string(adapters.OutcomeSucceeded) && o.Outcome != string(adapters.OutcomeFailed):
		return nil, nil, fmt.Errorf("an outcome receipt records SUCCEEDED or FAILED, not %q", o.Outcome)
	case o.OutcomeBasis != "OBSERVED" && o.OutcomeBasis != "RECONCILED",
		o.State != "SETTLED" && o.State != o.OutcomeBasis:
		return nil, nil, fmt.Errorf("state %s cannot rest on outcome basis %q", o.State, o.OutcomeBasis)
	case o.SettledAt.IsZero() || o.PermitID == "":
		return nil, nil, errors.New("an outcome receipt needs the settlement time and the permit the effect was dispatched under")
	case o.ApproverPrincipalID != "" || o.ApproverActorID != "" || o.StepUpIssuer != "" || o.StepUpJTI != "" || !o.DecidedAt.IsZero():
		return nil, nil, errors.New("an outcome receipt carries no approver, step-up proof or decision time")
	case o.Observation.ID <= 0 || o.Observation.Source == "" || o.Observation.TrustClass == "" || o.Observation.ObservedAt.IsZero():
		return nil, nil, errors.New("an outcome receipt needs the stored observation it rests on")
	}
	evidence, err := digestHex("evidence_digest", o.Observation.EvidenceDigest, true)
	if err != nil {
		return nil, nil, err
	}
	doc := receiptBinding{Outcome: o.Outcome, OutcomeBasis: o.OutcomeBasis,
		ObservationID: o.Observation.ID, ObservationSource: o.Observation.Source, ObservationTrustClass: o.Observation.TrustClass,
		ObservationOutcome: o.Observation.Outcome, EvidenceDigest: evidence,
		ResultKind: o.Observation.ResultKind, ResultRef: o.Observation.ResultRef,
		ObservedAt: o.Observation.ObservedAt.UTC().Format(time.RFC3339Nano), SettledAt: o.SettledAt.UTC().Format(time.RFC3339Nano)}
	return buildReceipt(o.storedDecision, doc, o.SettledAt, receiptID, seq, prevDigest)
}

// buildReceipt completes doc, the members only a decision or only an outcome
// sets, with the members every gateway receipt binds from the stored row, and
// returns the unsigned receipt.v5 over it with the binding's exact bytes. The
// receipt's timestamp is at, the database time of the transaction.
func buildReceipt(d storedDecision, doc receiptBinding, at time.Time, receiptID string, seq uint64, prevDigest string) (*contracts.Receipt, []byte, error) {
	if seq == 0 || (seq == 1) != (prevDigest == "") || (prevDigest != "" && !isChainDigest(prevDigest)) {
		return nil, nil, fmt.Errorf("receipt %d of a chain cannot link to %q", seq, prevDigest)
	}
	if d.TenantID == "" || d.WorkspaceID == "" || d.AttemptID == "" || d.Version <= 0 {
		return nil, nil, errors.New("a receipt needs the stored tenant, workspace, attempt and version")
	}
	request, err := digestHex("request_digest", d.RequestDigest, false)
	if err != nil {
		return nil, nil, err
	}
	target, err := digestHex("target_digest", d.TargetDigest, false)
	if err != nil {
		return nil, nil, err
	}
	argument, err := digestHex("argument_digest", d.ArgumentDigest, false)
	if err != nil {
		return nil, nil, err
	}
	approval, err := digestHex("approval_digest", d.ApprovalDigest, true)
	if err != nil {
		return nil, nil, err
	}
	policyHash, err := authoritySnapshotHash(d.AuthorityVersions)
	if err != nil {
		return nil, nil, err
	}
	chain := receiptChainID(d.TenantID, d.WorkspaceID)
	quote := make([]bindingAmount, 0, len(d.Quote))
	for _, q := range d.Quote {
		quote = append(quote, bindingAmount{Unit: q.Unit, Amount: strconv.FormatInt(q.Amount, 10)})
	}
	var expires string
	if d.ApprovalExpiresAt != nil {
		expires = d.ApprovalExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	doc.BindingVersion, doc.ChainID, doc.Seq = ReceiptBindingVersion, chain, seq
	doc.TenantID, doc.WorkspaceID, doc.AttemptID, doc.AttemptVersion = d.TenantID, d.WorkspaceID, d.AttemptID, d.Version
	doc.FromState, doc.State, doc.ReasonCode = d.FromState, d.State, d.ReasonCode
	doc.EffectType, doc.RequesterPrincipalID, doc.RequesterActorID = d.EffectType, d.RequesterPrincipalID, d.RequesterActorID
	doc.MandateID, doc.RiskClass = d.MandateID, d.RiskClass
	doc.RequestDigest, doc.TargetDigest, doc.ArgumentDigest, doc.Quote = request, target, argument, quote
	doc.ApprovalDigest, doc.ApprovalExpiresAt = approval, expires
	doc.PermitID, doc.AuthorityVersions, doc.PolicyHash = d.PermitID, bindingVersions(d.AuthorityVersions), policyHash
	doc.EpisodeID, doc.OrganizationVersionID = d.EpisodeID, d.OrganizationVersionID
	binding, err := canonicalize.InteroperableJCS(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("receipt binding: %w", err)
	}
	output := sha256.Sum256(binding)
	return &contracts.Receipt{
		ReceiptID:    receiptID,
		DecisionID:   d.AttemptID + ":" + strconv.FormatInt(d.Version, 10),
		EffectID:     d.AttemptID,
		Status:       d.State,
		OutputHash:   hex.EncodeToString(output[:]),
		Timestamp:    at.UTC(),
		PrevHash:     prevDigest,
		LamportClock: seq,
		ArgsHash:     argument,
		Verdict:      doc.Verdict,
		ReasonCode:   d.ReasonCode,
		PolicyHash:   policyHash,
		SessionID:    chain,
	}, binding, nil
}

// sealReceipt signs r and returns the exact envelope bytes to store and the
// chain digest of those bytes. It refuses anything but classical Ed25519 over
// receipt.v5 by the signer's own key id, and it verifies the stored bytes
// offline, the way receipt_verify will, before they are written.
func sealReceipt(signer ReceiptSigner, r *contracts.Receipt) ([]byte, string, error) {
	if signer == nil {
		return nil, "", errors.New("no receipt signer")
	}
	if err := signer.SignReceipt(r); err != nil {
		return nil, "", fmt.Errorf("sign receipt: %w", err)
	}
	if r.SignatureProfile != receiptProfileClassical || r.SignatureAlgorithm != receiptAlgorithmEd25519 {
		return nil, "", fmt.Errorf("the receipt signer produced signature profile %q and algorithm %q; the gateway records classical/ed25519 receipts only",
			r.SignatureProfile, r.SignatureAlgorithm)
	}
	if r.SignatureVersion != ReceiptFormat || r.KeyID != signer.GetKeyID() || r.Signature == "" {
		return nil, "", fmt.Errorf("the receipt signer produced %q under key %q; want a %s signature under %q",
			r.SignatureVersion, r.KeyID, ReceiptFormat, signer.GetKeyID())
	}
	envelope, err := json.Marshal(r)
	if err != nil {
		return nil, "", err
	}
	stored, err := receiptverify.ParseBundle(envelope)
	if err != nil || len(stored.Receipts) != 1 {
		return nil, "", fmt.Errorf("the signed receipt does not parse as a receipt: %v", err)
	}
	result := receiptverify.Verify(stored.Receipts, receiptverify.TrustRoot{Keys: map[string]string{signer.GetKeyID(): signer.PublicKey()}})
	if !result.Valid {
		return nil, "", fmt.Errorf("the signed receipt does not verify under key %q: %v %v", signer.GetKeyID(), result.Errors, result.Checks)
	}
	digest, err := contracts.ReceiptChainHash(stored.Receipts[0])
	if err != nil {
		return nil, "", err
	}
	if inMemory, err := contracts.ReceiptChainHash(r); err != nil || inMemory != digest {
		return nil, "", errors.New("the stored receipt bytes do not reproduce the signed receipt's chain hash")
	}
	return envelope, digest, nil
}

// appendReceipt signs the receipt of a decision or an outcome tx has just
// written and appends it to the workspace's chain. The chain row is the last
// row lock the transaction takes on a pre-existing row: every authority,
// counter, exposure and attempt lock is already held, and what may follow in
// the same transaction (an approval record, a lift's token replay row, a
// model call's SETTLED write to the attempt row it holds and that write's own
// receipt) locks nothing new but rows of its own. So the decisions and
// outcomes of one workspace serialize on the chain row until they commit,
// without a lock-order cycle. The head moves by compare-and-set; any error
// rolls the decision or the outcome back with it.
func appendReceipt(ctx context.Context, tx *sql.Tx, signer ReceiptSigner, subject receiptSubject) (ReceiptRef, error) {
	if signer == nil {
		return ReceiptRef{}, errors.New("no receipt signer: a decision or an outcome is never recorded without its receipt")
	}
	d := subject.row()
	chain := receiptChainID(d.TenantID, d.WorkspaceID)
	if _, err := tx.ExecContext(ctx, `INSERT INTO authority_receipt_chains (tenant_id, chain_id, format)
		VALUES ($1, $2, $3) ON CONFLICT (tenant_id, chain_id) DO NOTHING`, d.TenantID, chain, ReceiptFormat); err != nil {
		return ReceiptRef{}, fmt.Errorf("receipt chain: %w", err)
	}
	var seq int64
	var head, format string
	if err := tx.QueryRowContext(ctx, `SELECT seq, head_digest, format FROM authority_receipt_chains
		WHERE tenant_id = $1 AND chain_id = $2 FOR UPDATE`, d.TenantID, chain).Scan(&seq, &head, &format); err != nil {
		return ReceiptRef{}, fmt.Errorf("receipt chain head: %w", err)
	}
	if format != ReceiptFormat {
		return ReceiptRef{}, fmt.Errorf("receipt chain %q is in format %q; this gateway appends %s", chain, format, ReceiptFormat)
	}
	if seq < 0 {
		return ReceiptRef{}, fmt.Errorf("receipt chain %q has sequence %d", chain, seq)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return ReceiptRef{}, err
	}
	next := uint64(seq) + 1
	receipt, binding, err := subject.build(id.String(), next, head)
	if err != nil {
		return ReceiptRef{}, err
	}
	envelope, digest, err := sealReceipt(signer, receipt)
	if err != nil {
		return ReceiptRef{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authority_receipts
			(tenant_id, chain_id, seq, receipt_id, format, prev_digest, digest, attempt_id, attempt_version,
			 workspace_id, state, key_id, envelope, binding)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		d.TenantID, chain, seq+1, receipt.ReceiptID, ReceiptFormat, head, digest, d.AttemptID, d.Version,
		d.WorkspaceID, d.State, receipt.KeyID, envelope, binding); err != nil {
		return ReceiptRef{}, fmt.Errorf("append receipt: %w", err)
	}
	res, err := tx.ExecContext(ctx, `UPDATE authority_receipt_chains SET seq = $3, head_digest = $4, updated_at = now()
		WHERE tenant_id = $1 AND chain_id = $2 AND seq = $5 AND head_digest = $6`,
		d.TenantID, chain, seq+1, digest, seq, head)
	if err != nil {
		return ReceiptRef{}, fmt.Errorf("advance receipt chain: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return ReceiptRef{}, fmt.Errorf("receipt chain %q moved while it was locked (%d rows, %v)", chain, n, err)
	}
	return ReceiptRef{ReceiptID: receipt.ReceiptID, ChainID: chain, Seq: next, Digest: digest, KeyID: receipt.KeyID,
		Format: ReceiptFormat, State: d.State, AttemptVersion: d.Version}, nil
}

// loadReceiptRefs reads the receipts of an attempt, oldest first.
func loadReceiptRefs(ctx context.Context, tx *sql.Tx, tenantID, attemptID string) ([]ReceiptRef, error) {
	rows, err := tx.QueryContext(ctx, `SELECT receipt_id::text, chain_id, seq, digest, key_id, format, state, attempt_version
		FROM authority_receipts WHERE tenant_id = $1 AND attempt_id = $2 ORDER BY attempt_version, seq`, tenantID, attemptID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ReceiptRef
	for rows.Next() {
		var ref ReceiptRef
		var seq int64
		if err := rows.Scan(&ref.ReceiptID, &ref.ChainID, &seq, &ref.Digest, &ref.KeyID, &ref.Format, &ref.State, &ref.AttemptVersion); err != nil {
			return nil, err
		}
		if seq < 1 {
			return nil, fmt.Errorf("stored receipt %s has sequence %d", ref.ReceiptID, seq)
		}
		ref.Seq = uint64(seq)
		out = append(out, ref)
	}
	return out, rows.Err()
}
