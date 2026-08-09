// quantum_posture: these tests exercise classical Ed25519 verification only.
package receiptverify

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// ---------------------------------------------------------------------------
// The offline property
// ---------------------------------------------------------------------------

// transportPackages are the standard-library packages through which a process
// can reach the network or hand the job to something that can. os/exec is on
// the list because "no network imports" is worthless if the verifier can shell
// out to curl.
//
// net/url is deliberately absent: it is a pure string parser with no I/O
// surface, and contracts reaches it. That is the single stated deviation, and
// it is stated rather than hidden.
var transportPackages = []string{
	"net",
	"net/http",
	"crypto/tls",
	"os/exec",
}

// TestNoTransportPackageIsReachable is the whole argument of this package,
// expressed as a test.
//
// It shells out to `go list -deps` — which is why the test binary itself
// imports os/exec, and why that is not a contradiction. The assertion is about
// the import graph of the non-test package, which is what actually ships inside
// receipt_verify. If someone adds a dependency that drags in an HTTP client,
// this fails and names the package.
func TestNoTransportPackageIsReachable(t *testing.T) {
	for _, target := range []string{
		"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify",
		"github.com/Mindburn-Labs/helm-ai-kernel/core/cmd/receipt_verify",
	} {
		t.Run(target, func(t *testing.T) {
			cmd := exec.Command("go", "list", "-deps", target)
			cmd.Env = append(os.Environ(), "GOWORK=off")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("go list -deps %s: %v", target, err)
			}
			deps := make(map[string]bool)
			for _, line := range strings.Split(string(out), "\n") {
				deps[strings.TrimSpace(line)] = true
			}
			for _, banned := range transportPackages {
				if deps[banned] {
					t.Errorf("%s transitively imports %q.\n"+
						"This binary's entire claim is that a counterparty can verify a receipt "+
						"without a service in the trust path. A reachable transport package "+
						"forfeits that claim whether or not it is called.", target, banned)
				}
			}
			if len(deps) == 0 {
				t.Fatal("go list returned no dependencies; the test is not actually checking anything")
			}
			t.Logf("%s: %d packages reachable, none of %v", target, len(deps), transportPackages)
		})
	}
}

// TestVerificationReadsNoClock guards the other half of the offline property.
//
// A verifier that consults the wall clock has an expiry, and an expiry means a
// receipt stops being verifiable on a date nobody chose deliberately. This
// walks this package's own AST and fails on any clock read. The frozen-fixture
// test below would not catch a clock read on its own — it would keep passing
// until the day it suddenly did not.
func TestVerificationReadsNoClock(t *testing.T) {
	banned := map[string]bool{"Now": true, "Since": true, "Until": true}

	entries, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, path := range entries {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		checked++
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != "time" {
				return true
			}
			if banned[sel.Sel.Name] {
				t.Errorf("%s:%d calls time.%s. Verification must be a pure function of its "+
					"inputs: a receipt signed today has to verify in 2036 without the verifier "+
					"having an opinion about what year it is.",
					path, fset.Position(sel.Pos()).Line, sel.Sel.Name)
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no non-test source files found; the test is not actually checking anything")
	}
}

// ---------------------------------------------------------------------------
// The 2036 test
// ---------------------------------------------------------------------------

type frozenFixture struct {
	PublicKeyHex string               `json:"public_key_hex"`
	KeyID        string               `json:"key_id"`
	Receipts     []*contracts.Receipt `json:"receipts"`
}

func loadFrozen(t *testing.T) frozenFixture {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "frozen-chain-2026.json"))
	if err != nil {
		t.Fatalf("read frozen fixture: %v", err)
	}
	var fx frozenFixture
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatalf("parse frozen fixture: %v", err)
	}
	if len(fx.Receipts) != 3 {
		t.Fatalf("fixture should hold a 3-receipt chain, got %d", len(fx.Receipts))
	}
	return fx
}

func (fx frozenFixture) trust() TrustRoot {
	return TrustRoot{Keys: map[string]string{fx.KeyID: fx.PublicKeyHex}}
}

// TestFrozenReceiptStillVerifies is the 2036 test.
//
// The fixture was signed once, in August 2026, and committed with its signature
// bytes. Nothing regenerates it. That is what gives the test teeth: it is not
// checking that the verifier agrees with itself, it is checking that the
// verifier still agrees with a signature produced by code that no longer runs.
//
// Three distinct things have to stay true for this to pass, and each is a way
// the 2036 property can be broken:
//
//  1. No expiry in the verification path — nothing consults a clock, so the
//     verdict does not depend on the year (also pinned by
//     TestVerificationReadsNoClock).
//  2. No key fetch — the key travels with the fixture and is passed in by the
//     caller; there is nowhere to look one up even if the code wanted to.
//  3. Versioned canonicalization retained — the fixture declares receipt.v5,
//     and if that preimage is ever redefined instead of superseded by a new
//     version, these committed signature bytes stop verifying and this fails.
func TestFrozenReceiptStillVerifies(t *testing.T) {
	fx := loadFrozen(t)

	res := Verify(fx.Receipts, fx.trust())
	if !res.Valid {
		t.Fatalf("a receipt chain frozen in 2026 no longer verifies: %+v", res)
	}
	if res.PreimageVersion != contracts.ReceiptSignatureV5 {
		t.Errorf("preimage version = %q, want %q; a retained version must not be silently reassigned",
			res.PreimageVersion, contracts.ReceiptSignatureV5)
	}
	for _, c := range res.Checks {
		if c.Status == StatusFail {
			t.Errorf("check %s failed: %s", c.Name, c.Detail)
		}
	}
}

// TestFrozenFixtureFailsWhenCanonicalizationDrifts proves the previous test can
// actually fail. A test that only ever passes is decoration.
//
// It mutates one byte of governance meaning — the field set receipt.v5 exists
// to bind — and asserts the frozen signature rejects it. If someone widened or
// narrowed the v5 envelope, the mutation would stop being covered and this
// would catch it.
func TestFrozenFixtureFailsWhenCanonicalizationDrifts(t *testing.T) {
	for _, tc := range []struct {
		field  string
		mutate func(*contracts.Receipt)
	}{
		{"verdict", func(r *contracts.Receipt) { r.Verdict = "DENY" }},
		{"policy_hash", func(r *contracts.Receipt) { r.PolicyHash = "sha256:some-other-policy" }},
		{"reason_code", func(r *contracts.Receipt) { r.ReasonCode = "OVERRIDDEN" }},
		{"session_id", func(r *contracts.Receipt) { r.SessionID = "sess-attacker" }},
		{"output_hash", func(r *contracts.Receipt) { r.OutputHash = "sha256:different-output" }},
		{"args_hash", func(r *contracts.Receipt) { r.ArgsHash = "sha256:different-args" }},
		{"status", func(r *contracts.Receipt) { r.Status = "FAILED" }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			fx := loadFrozen(t)
			tc.mutate(fx.Receipts[0])

			res := Verify(fx.Receipts, fx.trust())
			if res.Valid {
				t.Fatalf("rewriting %s left the chain valid; that field is not bound by the signature", tc.field)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Pinning the duplicated canonicalization
// ---------------------------------------------------------------------------

// TestCanonicalizationAgreesWithCrypto pins this package's reimplemented
// preimages to the ones the kernel signs with.
//
// This package deliberately does not import core/pkg/crypto — that is the whole
// point — so the preimage logic exists twice. Duplication without a test is
// drift waiting to happen: the kernel would sign one payload and the public
// verifier would check another, and the first anyone would hear of it is a
// counterparty reporting that a genuine receipt does not verify. The test
// imports crypto (test binaries ship to nobody) and compares bytes.
func TestCanonicalizationAgreesWithCrypto(t *testing.T) {
	fx := loadFrozen(t)
	for i, r := range fx.Receipts {
		mine, err := canonicalizeV5(r)
		if err != nil {
			t.Fatalf("receipt[%d]: %v", i, err)
		}
		theirs, err := crypto.CanonicalizeReceiptV5(r)
		if err != nil {
			t.Fatalf("receipt[%d]: %v", i, err)
		}
		if string(mine) != string(theirs) {
			t.Fatalf("receipt[%d] v5 preimage drifted from crypto.CanonicalizeReceiptV5:\n mine:   %s\n theirs: %s", i, mine, theirs)
		}

		legacy := canonicalizeV4(r)
		theirsV4 := crypto.ReceiptPreimageV4(r)
		if string(legacy) != string(theirsV4) {
			t.Fatalf("receipt[%d] v4 preimage drifted:\n mine:   %s\n theirs: %s", i, legacy, theirsV4)
		}
	}
}

// ---------------------------------------------------------------------------
// Trust-root behaviour
// ---------------------------------------------------------------------------

// TestSelfAttestedKeyIsRefusedByDefault is the "referee cannot be a player"
// case expressed as a test. A receipt carrying its own verification key proves
// only that whoever wrote the receipt also wrote the key beside it.
// A single receipt is used rather than the whole chain because attaching a
// PublicKeySet changes the receipt's canonical hash, which legitimately breaks
// the successor's prev_hash link — the closure check catching that is correct
// behaviour and would mask the property under test here.
func TestSelfAttestedKeyIsRefusedByDefault(t *testing.T) {
	fx := loadFrozen(t)
	r := fx.Receipts[0]
	r.PublicKeySet = map[string]string{fx.KeyID: fx.PublicKeyHex}
	chain := []*contracts.Receipt{r}

	res := Verify(chain, TrustRoot{})
	if res.Valid {
		t.Fatal("a receipt that supplies its own verification key was accepted with an empty trust root")
	}

	// The same bytes must verify once the caller opts in, which proves the
	// refusal above was about the trust root and not something incidental.
	res = Verify(chain, TrustRoot{AllowSelfAttested: true})
	if !res.Valid {
		t.Fatalf("the same receipt did not verify under AllowSelfAttested, so the default refusal "+
			"was not really about the trust root: %+v", res)
	}
	var identity Check
	for _, c := range res.Checks {
		if c.Name == CheckIdentity {
			identity = c
		}
	}
	if !strings.Contains(identity.Detail, "self-attestation") {
		t.Errorf("a self-attested pass must say so in the verdict; got %q", identity.Detail)
	}
}

func TestWrongKeyIsRejected(t *testing.T) {
	fx := loadFrozen(t)
	_, other, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherPub := hex.EncodeToString(other.Public().(ed25519.PublicKey))

	res := Verify(fx.Receipts, TrustRoot{Keys: map[string]string{fx.KeyID: otherPub}})
	if res.Valid {
		t.Fatal("chain verified under a key that did not sign it")
	}
}

func TestUnknownSignatureVersionIsRefusedNotGuessed(t *testing.T) {
	fx := loadFrozen(t)
	fx.Receipts[0].SignatureVersion = "receipt.v9-from-the-future"

	res := Verify(fx.Receipts, fx.trust())
	if res.Valid {
		t.Fatal("a receipt declaring an unknown preimage version was accepted")
	}
	found := false
	for _, c := range res.Checks {
		if c.Name == CheckIdentity && strings.Contains(c.Detail, "unsupported receipt signature version") {
			found = true
		}
	}
	if !found {
		t.Errorf("an unknown version must be refused by name, not retried against other preimages: %+v", res.Checks)
	}
}

func TestEmptyTrustRootVerifiesNothing(t *testing.T) {
	fx := loadFrozen(t)
	res := Verify(fx.Receipts, TrustRoot{})
	if res.Valid {
		t.Fatal("an empty trust root produced a valid verdict")
	}
	if len(res.Errors) == 0 {
		t.Error("an empty trust root must say why it refused")
	}
}

func TestNoReceiptsIsNotSuccess(t *testing.T) {
	if res := Verify(nil, TrustRoot{AllowSelfAttested: true}); res.Valid {
		t.Fatal("verifying nothing reported valid; absence of evidence is not evidence")
	}
}

// ---------------------------------------------------------------------------
// Chain closure
// ---------------------------------------------------------------------------

func TestBrokenChainLinkIsCaught(t *testing.T) {
	fx := loadFrozen(t)
	// Re-sign receipt[1] over a forged prev_hash so the signature is genuine and
	// only the linkage is wrong. Otherwise this would just retest the signature.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	fx.Receipts[1].PrevHash = "sha256:not-the-predecessor"
	payload, err := crypto.ReceiptSigningPayload(fx.Receipts[1])
	if err != nil {
		t.Fatal(err)
	}
	fx.Receipts[1].Signature = hex.EncodeToString(ed25519.Sign(priv, payload))

	res := Verify(fx.Receipts, fx.trust())
	if res.Valid {
		t.Fatal("a chain whose prev_hash does not resolve was accepted")
	}
	var closure Check
	for _, c := range res.Checks {
		if c.Name == CheckClosure {
			closure = c
		}
	}
	if closure.Status != StatusFail {
		t.Errorf("closure check should have failed, got %s: %s", closure.Status, closure.Detail)
	}
}

func TestNonAdvancingLamportClockIsCaught(t *testing.T) {
	fx := loadFrozen(t)
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	// Rebuild a two-receipt chain where the clock goes backwards but every
	// hash link and signature is honest.
	first := fx.Receipts[0]
	second := fx.Receipts[1]
	h, err := contracts.ReceiptChainHash(first)
	if err != nil {
		t.Fatal(err)
	}
	second.PrevHash = h
	second.LamportClock = first.LamportClock
	payload, err := crypto.ReceiptSigningPayload(second)
	if err != nil {
		t.Fatal(err)
	}
	second.Signature = hex.EncodeToString(ed25519.Sign(priv, payload))

	res := Verify([]*contracts.Receipt{first, second}, fx.trust())
	if res.Valid {
		t.Fatal("a chain whose Lamport clock does not advance was accepted")
	}
}

func TestSingleReceiptReportsClosureNotApplicable(t *testing.T) {
	fx := loadFrozen(t)
	res := Verify(fx.Receipts[:1], fx.trust())
	if !res.Valid {
		t.Fatalf("a single signed receipt should verify: %+v", res)
	}
	for _, c := range res.Checks {
		if c.Name == CheckClosure && c.Status != StatusNotApplicable {
			t.Errorf("closure over one receipt should be not_applicable, got %s", c.Status)
		}
	}
}

// TestNotApplicableIsNeverSilentlySuccess guards the failure mode where a
// verifier reports a green verdict because it checked nothing.
func TestNotApplicableIsNeverSilentlySuccess(t *testing.T) {
	fx := loadFrozen(t)
	res := Verify(fx.Receipts[:1], fx.trust())
	for _, c := range res.Checks {
		if c.Status == StatusNotApplicable && !strings.Contains(strings.ToLower(c.Detail), "no ") &&
			!strings.Contains(strings.ToLower(c.Detail), "nothing") {
			t.Errorf("check %s is not_applicable but does not say what was absent: %q", c.Name, c.Detail)
		}
	}
}
