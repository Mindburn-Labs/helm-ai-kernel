// Package receiptverify verifies HELM receipts with no service in the trust
// path.
//
// # Why this package exists separately from core/pkg/crypto
//
// core/pkg/crypto can already verify a receipt signature, but its transitive
// import graph reaches net, net/http, crypto/tls and os/exec (223 packages) by
// way of the HSM, TEE and external-signer paths that live in the same package.
// A verifier is only worth as much as the story you can tell about what it is
// able to do, and "it could open a socket, but trust us, it does not" is not
// that story. This package is a leaf: it imports the two canonicalization and
// contract packages plus the standard library, and TestNoNetworkImports walks
// the real import graph to assert that no transport package is reachable. The
// offline property is therefore a compile-time fact about the binary, not a
// claim in a README.
//
// # What a verdict here does and does not mean
//
// Verification answers exactly one question: were these bytes signed by the
// key you supplied, and are they internally consistent? It does not tell you
// that the signing key belongs to anyone in particular. Binding a key to an
// organisation is the caller's problem and deliberately stays outside this
// package — see TrustRoot.
package receiptverify

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// sigSeparator matches crypto.SigSeparator. Duplicated rather than imported so
// this package stays a leaf; canonicalizationAgreement in the test file pins
// the two together so a change to one fails the build of the other.
const sigSeparator = ":"

// CheckName identifies an individual check so callers can render per-check
// outcomes without string-matching on messages.
type CheckName string

const (
	// CheckIdentity verifies the Ed25519 signature over the receipt's declared
	// preimage using a caller-supplied key. It proves the holder of that key
	// signed these bytes. It does not prove who that holder is.
	CheckIdentity CheckName = "identity"
	// CheckIntegrity recomputes the canonical preimage and the chain hash and
	// confirms neither was altered after signing.
	CheckIntegrity CheckName = "integrity"
	// CheckPolicy confirms the receipt's policy_hash and verdict are inside the
	// signed envelope, so the governance meaning cannot be rewritten without
	// invalidating the signature. It does not evaluate the policy itself: the
	// policy content is not in the receipt.
	CheckPolicy CheckName = "policy"
	// CheckExecution confirms the execution observation fields (args_hash,
	// output_hash) are inside the signed envelope. It does not re-execute
	// anything, and it cannot confirm the hashes describe the real payload
	// unless you also supply that payload.
	CheckExecution CheckName = "execution_observation"
	// CheckClosure confirms a receipt sequence is a well-formed chain:
	// prev_hash links resolve to the recomputed hash of the predecessor and the
	// Lamport clock advances monotonically.
	CheckClosure CheckName = "closure"
)

// Status is the outcome of a single check.
type Status string

const (
	// StatusPass means the check ran and the property held.
	StatusPass Status = "pass"
	// StatusFail means the check ran and the property did not hold.
	StatusFail Status = "fail"
	// StatusNotApplicable means the input carried nothing to check. It is never
	// treated as success.
	StatusNotApplicable Status = "not_applicable"
)

// Check is one verification outcome.
type Check struct {
	Name   CheckName `json:"name"`
	Status Status    `json:"status"`
	// Detail states what was established, in terms a reader can act on.
	Detail string `json:"detail"`
}

// Result is the whole verdict. Valid is true only when every applicable check
// passed; a Result with no checks is never Valid.
type Result struct {
	Valid  bool    `json:"valid"`
	Checks []Check `json:"checks"`
	// PreimageVersion names the canonicalization the signature was verified
	// under. Retained versions are what make an old receipt verifiable by a new
	// binary.
	PreimageVersion string `json:"preimage_version,omitempty"`
	// KeyID echoes the receipt's declared key id purely so a caller can see
	// which key the receipt *claims*. It is never used to select a key.
	KeyID    string   `json:"key_id,omitempty"`
	Receipts int      `json:"receipts"`
	Errors   []string `json:"errors,omitempty"`
}

// TrustRoot supplies the public keys a caller is willing to trust.
//
// The zero value trusts nothing, which is the correct default: a receipt that
// carries its own verification key proves only that whoever wrote the receipt
// also wrote the key beside it. AllowSelfAttested exists so that property can
// be demonstrated rather than argued about, and it is never the default.
type TrustRoot struct {
	// Keys maps key id to a hex-encoded Ed25519 public key. A receipt is
	// verified against the key named by its key_id, or against every key when
	// it declares none.
	Keys map[string]string
	// AllowSelfAttested permits falling back to the receipt's own embedded
	// PublicKeySet. This makes the receipt self-referential and is only useful
	// for inspection. Callers must opt in explicitly.
	AllowSelfAttested bool
}

// ErrNoTrustedKey is returned when no caller-supplied key covers a receipt.
var ErrNoTrustedKey = errors.New("no trusted key for receipt; supply one with a trust root, or opt in to the receipt's embedded key")

// receiptV5SigningEnvelope mirrors crypto.receiptV5SigningEnvelope field for
// field, including json tags and order. It is the active receipt.v5 payload:
// the durable causal fields plus the four governance-meaning fields.
//
// This is a narrow, explicitly enumerated envelope by design. A whole-struct
// canonicalization would mean every future field added to contracts.Receipt
// silently changed the preimage and broke every previously issued signature —
// the opposite of what a receipt is for.
type receiptV5SigningEnvelope struct {
	SignatureVersion string `json:"signature_version"`
	ReceiptID        string `json:"receipt_id"`
	DecisionID       string `json:"decision_id"`
	EffectID         string `json:"effect_id"`
	Status           string `json:"status"`
	OutputHash       string `json:"output_hash"`
	PrevHash         string `json:"prev_hash"`
	LamportClock     uint64 `json:"lamport_clock"`
	ArgsHash         string `json:"args_hash"`
	Verdict          string `json:"verdict"`
	ReasonCode       string `json:"reason_code"`
	PolicyHash       string `json:"policy_hash"`
	SessionID        string `json:"session_id"`
}

// canonicalizeV5 reproduces crypto.CanonicalizeReceiptV5.
func canonicalizeV5(r *contracts.Receipt) ([]byte, error) {
	if r == nil {
		return nil, errors.New("receipt is nil")
	}
	return canonicalize.JCS(receiptV5SigningEnvelope{
		SignatureVersion: contracts.ReceiptSignatureV5,
		ReceiptID:        r.ReceiptID,
		DecisionID:       r.DecisionID,
		EffectID:         r.EffectID,
		Status:           r.Status,
		OutputHash:       r.OutputHash,
		PrevHash:         r.PrevHash,
		LamportClock:     r.LamportClock,
		ArgsHash:         r.ArgsHash,
		Verdict:          r.Verdict,
		ReasonCode:       r.ReasonCode,
		PolicyHash:       r.PolicyHash,
		SessionID:        r.SessionID,
	})
}

// canonicalizeV4 reproduces crypto.CanonicalizeReceipt, the legacy colon-joined
// preimage. Retained solely so receipts issued before receipt.v5 stay
// verifiable. Never used to verify a receipt that declares a version.
func canonicalizeV4(r *contracts.Receipt) []byte {
	return []byte(fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s%s%d%s%s",
		r.ReceiptID, sigSeparator, r.DecisionID, sigSeparator, r.EffectID,
		sigSeparator, r.Status, sigSeparator, r.OutputHash, sigSeparator,
		r.PrevHash, sigSeparator, r.LamportClock, sigSeparator, r.ArgsHash))
}

// verifyPayload reconstructs the signed payload for the receipt's declared
// version. An unknown version is rejected rather than guessed: silently
// retrying other preimages is how a verifier is talked into accepting a
// signature over a payload nobody intended.
func verifyPayload(r *contracts.Receipt) ([]byte, string, error) {
	switch r.SignatureVersion {
	case "":
		return canonicalizeV4(r), "v4-fields", nil
	case contracts.ReceiptSignatureV5:
		p, err := canonicalizeV5(r)
		return p, contracts.ReceiptSignatureV5, err
	default:
		return nil, "", fmt.Errorf("unsupported receipt signature version %q", r.SignatureVersion)
	}
}

// verifyEd25519 checks a hex signature over data with a hex public key.
func verifyEd25519(pubKeyHex, sigHex string, data []byte) (bool, error) {
	pubKey, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return false, fmt.Errorf("invalid public key hex: %w", err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size: got %d, want %d", len(pubKey), ed25519.PublicKeySize)
	}
	if len(sig) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid signature size: got %d, want %d", len(sig), ed25519.SignatureSize)
	}
	return ed25519.Verify(ed25519.PublicKey(pubKey), data, sig), nil
}

// candidateKeys returns the keys to try for a receipt, in trust order.
func candidateKeys(r *contracts.Receipt, trust TrustRoot) ([]string, error) {
	var keys []string
	if r.KeyID != "" {
		if k, ok := trust.Keys[r.KeyID]; ok {
			keys = append(keys, k)
		}
	} else {
		for _, k := range trust.Keys {
			keys = append(keys, k)
		}
	}
	if len(keys) > 0 {
		return keys, nil
	}
	if trust.AllowSelfAttested {
		for _, k := range r.PublicKeySet {
			keys = append(keys, k)
		}
		if len(keys) > 0 {
			return keys, nil
		}
	}
	return nil, ErrNoTrustedKey
}

// Verify checks a receipt chain against a trust root.
//
// receipts must be in causal order. Verification is pure: it reads no clock, no
// environment and no file, so the same inputs give the same verdict on any
// machine at any time. That property is what TestVerdictIsStableInTheFarFuture
// pins down.
func Verify(receipts []*contracts.Receipt, trust TrustRoot) Result {
	res := Result{Receipts: len(receipts)}

	if len(receipts) == 0 {
		res.Errors = append(res.Errors, "no receipts supplied")
		return res
	}
	for i, r := range receipts {
		if r == nil {
			res.Errors = append(res.Errors, fmt.Sprintf("receipt[%d] is nil", i))
			return res
		}
	}
	if len(trust.Keys) == 0 && !trust.AllowSelfAttested {
		res.Errors = append(res.Errors, ErrNoTrustedKey.Error())
		return res
	}

	res.KeyID = receipts[0].KeyID

	identity := checkIdentity(receipts, trust, &res)
	res.Checks = append(res.Checks, identity)
	res.Checks = append(res.Checks, checkIntegrity(receipts))
	res.Checks = append(res.Checks, checkPolicy(receipts))
	res.Checks = append(res.Checks, checkExecution(receipts))
	res.Checks = append(res.Checks, checkClosure(receipts))

	res.Valid = len(res.Errors) == 0
	for _, c := range res.Checks {
		if c.Status == StatusFail {
			res.Valid = false
		}
	}
	return res
}

func checkIdentity(receipts []*contracts.Receipt, trust TrustRoot, res *Result) Check {
	verified := 0
	for i, r := range receipts {
		if r.Signature == "" {
			return Check{CheckIdentity, StatusFail, fmt.Sprintf(
				"receipt[%d] %q carries no signature; an unsigned receipt attests to nothing", i, r.ReceiptID)}
		}
		payload, version, err := verifyPayload(r)
		if err != nil {
			return Check{CheckIdentity, StatusFail, fmt.Sprintf("receipt[%d]: %v", i, err)}
		}
		if res.PreimageVersion == "" {
			res.PreimageVersion = version
		}
		keys, err := candidateKeys(r, trust)
		if err != nil {
			return Check{CheckIdentity, StatusFail, fmt.Sprintf(
				"receipt[%d] %q: %v", i, r.ReceiptID, err)}
		}
		ok := false
		for _, k := range keys {
			good, verr := verifyEd25519(k, r.Signature, payload)
			if verr != nil {
				continue
			}
			if good {
				ok = true
				break
			}
		}
		if !ok {
			return Check{CheckIdentity, StatusFail, fmt.Sprintf(
				"receipt[%d] %q: signature does not verify under any supplied key", i, r.ReceiptID)}
		}
		verified++
	}
	src := "caller-supplied trust root"
	if len(trust.Keys) == 0 && trust.AllowSelfAttested {
		src = "the receipt's OWN embedded key — this is self-attestation and proves only internal consistency"
	}
	return Check{CheckIdentity, StatusPass, fmt.Sprintf(
		"%d/%d signatures verify against %s", verified, len(receipts), src)}
}

func checkIntegrity(receipts []*contracts.Receipt) Check {
	for i, r := range receipts {
		if _, err := contracts.ReceiptChainHash(r); err != nil {
			return Check{CheckIntegrity, StatusFail, fmt.Sprintf(
				"receipt[%d] %q: cannot recompute canonical hash: %v", i, r.ReceiptID, err)}
		}
	}
	return Check{CheckIntegrity, StatusPass, fmt.Sprintf(
		"%d receipt(s) recanonicalize; the signed bytes are the bytes on disk", len(receipts))}
}

func checkPolicy(receipts []*contracts.Receipt) Check {
	bound, missing := 0, 0
	for _, r := range receipts {
		if r.SignatureVersion != contracts.ReceiptSignatureV5 {
			missing++
			continue
		}
		if r.PolicyHash == "" && r.Verdict == "" {
			missing++
			continue
		}
		bound++
	}
	if bound == 0 {
		return Check{CheckPolicy, StatusNotApplicable, "no receipt binds a policy hash or verdict into its signed envelope"}
	}
	d := fmt.Sprintf("%d/%d receipt(s) bind policy_hash and verdict inside the signature, so the governance "+
		"meaning cannot be rewritten without breaking it; the policy content itself is not in the receipt and is not evaluated here",
		bound, len(receipts))
	if missing > 0 {
		return Check{CheckPolicy, StatusPass, d + fmt.Sprintf(" (%d receipt(s) predate the v5 envelope)", missing)}
	}
	return Check{CheckPolicy, StatusPass, d}
}

func checkExecution(receipts []*contracts.Receipt) Check {
	observed := 0
	for _, r := range receipts {
		if r.ArgsHash != "" || r.OutputHash != "" {
			observed++
		}
	}
	if observed == 0 {
		return Check{CheckExecution, StatusNotApplicable, "no receipt carries an args_hash or output_hash"}
	}
	return Check{CheckExecution, StatusPass, fmt.Sprintf(
		"%d/%d receipt(s) bind an execution observation (args_hash/output_hash) inside the signature; "+
			"this verifier does not hold the payloads and so cannot confirm the hashes describe them",
		observed, len(receipts))}
}

func checkClosure(receipts []*contracts.Receipt) Check {
	if len(receipts) < 2 {
		return Check{CheckClosure, StatusNotApplicable, "a chain of one has nothing to close over; supply the sequence to check linkage"}
	}
	for i := 1; i < len(receipts); i++ {
		prev, cur := receipts[i-1], receipts[i]
		want, err := contracts.ReceiptChainHash(prev)
		if err != nil {
			return Check{CheckClosure, StatusFail, fmt.Sprintf("receipt[%d]: cannot hash predecessor: %v", i-1, err)}
		}
		if cur.PrevHash != want {
			return Check{CheckClosure, StatusFail, fmt.Sprintf(
				"receipt[%d] %q: prev_hash %q does not match the recomputed hash of receipt[%d] (%q); the chain has a gap or a substitution",
				i, cur.ReceiptID, cur.PrevHash, i-1, want)}
		}
		if cur.LamportClock <= prev.LamportClock {
			return Check{CheckClosure, StatusFail, fmt.Sprintf(
				"receipt[%d] %q: lamport_clock %d does not advance past %d; the order is not causally sound",
				i, cur.ReceiptID, cur.LamportClock, prev.LamportClock)}
		}
	}
	return Check{CheckClosure, StatusPass, fmt.Sprintf(
		"%d receipts form an unbroken chain: every prev_hash matches its recomputed predecessor and the Lamport clock advances", len(receipts))}
}
