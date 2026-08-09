// quantum_posture: test-only. Ed25519 appears here solely to obtain a signer
// for the round trip. These tests assert that the protobuf wire form of an
// EffectPermit is sufficient to reconstruct the exact signed preimage; they add
// no production cryptographic control and no post-quantum assurance. The permit
// preimage itself stays algorithm-neutral (see effect_permit.go), so a future
// ML-DSA signer satisfies these tests unchanged.
package crypto

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
)

// These tests answer the question the sibling permit_wire_parity_test.go cannot:
// does the wire form actually carry the signed bytes across a hop?
//
// That test compares the signed envelope against the .proto as TEXT — it proves
// a signed field has a wire home by name. This one proves the home works: it
// encodes a signed permit into real protobuf wire bytes, hands nothing but those
// bytes to a verifier, and requires the reconstructed preimage to verify against
// the signature produced before any encoding existed. A test that mutates a Go
// struct in place (as the sibling negative case does) never exercises the codec
// and would pass just as happily with no wire field at all.
//
// WHY protowire AND NOT THE GENERATED TYPE: core must not import sdk/go. That
// module is the published client SDK, so the dependency would point from the
// kernel to its own client and drag the SDK into core's manifest. protowire is
// the same wire codec the generated code is built on, and driving it from the
// field numbers parsed out of the authoritative .proto binds this test to the
// contract rather than to a hand-copied constant: delete field 16 from the
// contract and the encoder has nowhere to put evidence_bindings.
//
// WHAT THIS IS NOT: production has no Go-to-proto permit hop yet, so this is the
// contract a cross-process dispatch must use, proven sufficient in advance — not
// a mirror of a shipping code path. The mapping helpers below are consequently
// the only executable statement of that contract in the repo; see
// TestEffectTypeEnumMappingIsPinned for the part of it that is still unpublished.

// permitWireContract is the EffectPermit field numbering, read from the .proto
// rather than copied, so the test fails when the contract and the signed
// envelope drift apart.
type permitWireContract struct {
	num map[string]protowire.Number
}

func loadPermitWireContract(t *testing.T) permitWireContract {
	t.Helper()
	source, err := os.ReadFile("../../../protocols/proto/helm/effects/v1/effects.proto")
	if err != nil {
		t.Fatalf("read permit wire contract: %v", err)
	}
	block := regexp.MustCompile(`(?s)message EffectPermit \{(.*?)\n\}`).FindSubmatch(source)
	if block == nil {
		t.Fatal("message EffectPermit not found in the wire contract")
	}
	c := permitWireContract{num: map[string]protowire.Number{}}
	for _, m := range regexp.MustCompile(`(?m)^\s*(?:map<[^>]+>|[\w.]+)\s+(\w+)\s*=\s*(\d+);`).FindAllSubmatch(block[1], -1) {
		// Parse at the wire's own width and range-check before narrowing. A
		// protobuf field number is an int32 limited to [1, 2^29-1], so a value
		// outside that must fail loudly rather than wrap into a plausible tag
		// and silently encode the permit against the wrong field.
		n, err := strconv.ParseInt(string(m[2]), 10, 32)
		if err != nil {
			t.Fatalf("field %q has an unparseable number %q: %v", m[1], m[2], err)
		}
		num := protowire.Number(n)
		if num < protowire.MinValidNumber || num > protowire.MaxValidNumber {
			t.Fatalf("field %q has out-of-range wire number %d", m[1], n)
		}
		c.num[string(m[1])] = num
	}
	if len(c.num) == 0 {
		t.Fatal("parsed no fields from message EffectPermit")
	}
	return c
}

// field returns the wire number for name, failing the test when the contract has
// no home for a field the signature covers. This is the assertion that makes the
// whole file a regression guard: removing evidence_bindings from the .proto stops
// the encoder here with an explicit diagnosis instead of silently omitting it.
func (c permitWireContract) field(t *testing.T, name string) protowire.Number {
	t.Helper()
	n, ok := c.num[name]
	if !ok {
		t.Fatalf("effect_permit.v1 signs %q but message EffectPermit has no such field: "+
			"a transport built from this contract cannot carry it, so the permit "+
			"cannot verify on the far side", name)
	}
	return n
}

// effectTypeEnum is the EffectType string-to-enum mapping a cross-process peer
// needs. It is duplicated knowledge, and deliberately so: the Go type is a
// string ("WRITE"), the wire type is an enum (EFFECT_TYPE_WRITE = 2), the signed
// preimage covers the string, and nothing in the repository converts between
// them. See TestEffectTypeEnumMappingIsPinned.
var effectTypeEnum = map[effects.EffectType]uint64{
	"":                        0, // EFFECT_TYPE_UNSPECIFIED
	effects.EffectTypeRead:    1,
	effects.EffectTypeWrite:   2,
	effects.EffectTypeDelete:  3,
	effects.EffectTypeExecute: 4,
	effects.EffectTypeNetwork: 5,
	effects.EffectTypeFinance: 6,
}

func effectTypeFromEnum(v uint64) (effects.EffectType, error) {
	for name, n := range effectTypeEnum {
		if n == v {
			return name, nil
		}
	}
	return "", fmt.Errorf("unknown EffectType enum value %d", v)
}

func appendString(dst []byte, num protowire.Number, s string) []byte {
	dst = protowire.AppendTag(dst, num, protowire.BytesType)
	return protowire.AppendString(dst, s)
}

func appendSubMessage(dst []byte, num protowire.Number, sub []byte) []byte {
	dst = protowire.AppendTag(dst, num, protowire.BytesType)
	return protowire.AppendBytes(dst, sub)
}

func appendVarintField(dst []byte, num protowire.Number, v uint64) []byte {
	dst = protowire.AppendTag(dst, num, protowire.VarintType)
	return protowire.AppendVarint(dst, v)
}

// encodeTimestamp renders a google.protobuf.Timestamp submessage
// (seconds = 1, nanos = 2).
func encodeTimestamp(ts time.Time) []byte {
	utc := ts.UTC()
	var b []byte
	b = appendVarintField(b, 1, uint64(utc.Unix()))
	if n := utc.Nanosecond(); n != 0 {
		b = appendVarintField(b, 2, uint64(n))
	}
	return b
}

func decodeTimestamp(b []byte) (time.Time, error) {
	var seconds, nanos int64
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return time.Time{}, protowire.ParseError(n)
		}
		b = b[n:]
		if typ != protowire.VarintType {
			skip := protowire.ConsumeFieldValue(num, typ, b)
			if skip < 0 {
				return time.Time{}, protowire.ParseError(skip)
			}
			b = b[skip:]
			continue
		}
		v, n := protowire.ConsumeVarint(b)
		if n < 0 {
			return time.Time{}, protowire.ParseError(n)
		}
		b = b[n:]
		switch num {
		case 1:
			seconds = int64(v)
		case 2:
			nanos = int64(v)
		}
	}
	return time.Unix(seconds, nanos).UTC(), nil
}

// encodeScope renders an EffectScope submessage (allowed_action = 1,
// allowed_params = 2, deny_patterns = 3).
func encodeScope(s effects.EffectScope) []byte {
	var b []byte
	if s.AllowedAction != "" {
		b = appendString(b, 1, s.AllowedAction)
	}
	for _, p := range s.AllowedParams {
		b = appendString(b, 2, p)
	}
	for _, d := range s.DenyPatterns {
		b = appendString(b, 3, d)
	}
	return b
}

func decodeScope(b []byte) (effects.EffectScope, error) {
	var s effects.EffectScope
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return s, protowire.ParseError(n)
		}
		b = b[n:]
		if typ != protowire.BytesType {
			skip := protowire.ConsumeFieldValue(num, typ, b)
			if skip < 0 {
				return s, protowire.ParseError(skip)
			}
			b = b[skip:]
			continue
		}
		v, n := protowire.ConsumeString(b)
		if n < 0 {
			return s, protowire.ParseError(n)
		}
		b = b[n:]
		switch num {
		case 1:
			s.AllowedAction = v
		case 2:
			s.AllowedParams = append(s.AllowedParams, v)
		case 3:
			s.DenyPatterns = append(s.DenyPatterns, v)
		}
	}
	return s, nil
}

// encodePermit renders p as helm.effects.v1.EffectPermit wire bytes.
//
// Proto3 omits zero values, and this encoder does the same, so the round trip
// exercises the real hazard: a far side that cannot tell "field absent" from
// "field empty" must still rebuild the preimage the signer used.
//
// Map entries are emitted in sorted key order. Protobuf map ordering is
// unspecified, which is exactly why the preimage canonicalizes rather than
// trusting wire order.
func encodePermit(t *testing.T, c permitWireContract, p *effects.EffectPermit) []byte {
	t.Helper()
	var b []byte
	if p.PermitID != "" {
		b = appendString(b, c.field(t, "permit_id"), p.PermitID)
	}
	if p.IntentHash != "" {
		b = appendString(b, c.field(t, "intent_hash"), p.IntentHash)
	}
	if p.VerdictHash != "" {
		b = appendString(b, c.field(t, "verdict_hash"), p.VerdictHash)
	}
	if p.PlanHash != "" {
		b = appendString(b, c.field(t, "plan_hash"), p.PlanHash)
	}
	if p.PolicyHash != "" {
		b = appendString(b, c.field(t, "policy_hash"), p.PolicyHash)
	}
	enum, ok := effectTypeEnum[p.EffectType]
	if !ok {
		t.Fatalf("effect type %q has no wire enum value", p.EffectType)
	}
	if enum != 0 {
		b = appendVarintField(b, c.field(t, "effect_type"), enum)
	}
	if p.ConnectorID != "" {
		b = appendString(b, c.field(t, "connector_id"), p.ConnectorID)
	}
	b = appendSubMessage(b, c.field(t, "scope"), encodeScope(p.Scope))
	if p.ResourceRef != "" {
		b = appendString(b, c.field(t, "resource_ref"), p.ResourceRef)
	}
	if !p.ExpiresAt.IsZero() {
		b = appendSubMessage(b, c.field(t, "expires_at"), encodeTimestamp(p.ExpiresAt))
	}
	if p.SingleUse {
		b = appendVarintField(b, c.field(t, "single_use"), 1)
	}
	if p.Nonce != "" {
		b = appendString(b, c.field(t, "nonce"), p.Nonce)
	}
	if !p.IssuedAt.IsZero() {
		b = appendSubMessage(b, c.field(t, "issued_at"), encodeTimestamp(p.IssuedAt))
	}
	if p.IssuerID != "" {
		b = appendString(b, c.field(t, "issuer_id"), p.IssuerID)
	}
	if p.Signature != "" {
		b = appendString(b, c.field(t, "signature"), p.Signature)
	}
	keys := make([]string, 0, len(p.EvidenceBindings))
	for k := range p.EvidenceBindings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	bindings := c.field(t, "evidence_bindings")
	for _, k := range keys {
		var entry []byte
		entry = appendString(entry, 1, k)
		entry = appendString(entry, 2, p.EvidenceBindings[k])
		b = appendSubMessage(b, bindings, entry)
	}
	return b
}

// decodePermit rebuilds a permit from wire bytes alone. It is the far side of
// the hop: it receives no Go value, only the encoded contract.
func decodePermit(c permitWireContract, wire []byte) (*effects.EffectPermit, error) {
	p := &effects.EffectPermit{}
	b := wire
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		b = b[n:]

		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			b = b[n:]
			switch num {
			case c.num["effect_type"]:
				et, err := effectTypeFromEnum(v)
				if err != nil {
					return nil, err
				}
				p.EffectType = et
			case c.num["single_use"]:
				p.SingleUse = v != 0
			}
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			b = b[n:]
			switch num {
			case c.num["permit_id"]:
				p.PermitID = string(v)
			case c.num["intent_hash"]:
				p.IntentHash = string(v)
			case c.num["verdict_hash"]:
				p.VerdictHash = string(v)
			case c.num["plan_hash"]:
				p.PlanHash = string(v)
			case c.num["policy_hash"]:
				p.PolicyHash = string(v)
			case c.num["connector_id"]:
				p.ConnectorID = string(v)
			case c.num["resource_ref"]:
				p.ResourceRef = string(v)
			case c.num["nonce"]:
				p.Nonce = string(v)
			case c.num["issuer_id"]:
				p.IssuerID = string(v)
			case c.num["signature"]:
				p.Signature = string(v)
			case c.num["scope"]:
				s, err := decodeScope(v)
				if err != nil {
					return nil, err
				}
				p.Scope = s
			case c.num["expires_at"]:
				ts, err := decodeTimestamp(v)
				if err != nil {
					return nil, err
				}
				p.ExpiresAt = ts
			case c.num["issued_at"]:
				ts, err := decodeTimestamp(v)
				if err != nil {
					return nil, err
				}
				p.IssuedAt = ts
			case c.num["evidence_bindings"]:
				k, val, err := decodeMapEntry(v)
				if err != nil {
					return nil, err
				}
				if p.EvidenceBindings == nil {
					p.EvidenceBindings = map[string]string{}
				}
				p.EvidenceBindings[k] = val
			}
		default:
			skip := protowire.ConsumeFieldValue(num, typ, b)
			if skip < 0 {
				return nil, protowire.ParseError(skip)
			}
			b = b[skip:]
		}
	}
	return p, nil
}

func decodeMapEntry(b []byte) (string, string, error) {
	var key, value string
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return "", "", protowire.ParseError(n)
		}
		b = b[n:]
		if typ != protowire.BytesType {
			skip := protowire.ConsumeFieldValue(num, typ, b)
			if skip < 0 {
				return "", "", protowire.ParseError(skip)
			}
			b = b[skip:]
			continue
		}
		v, n := protowire.ConsumeString(b)
		if n < 0 {
			return "", "", protowire.ParseError(n)
		}
		b = b[n:]
		switch num {
		case 1:
			key = v
		case 2:
			value = v
		}
	}
	return key, value, nil
}

// stripWireField removes every record carrying num, simulating a peer built
// against a contract that predates the field. This is what "the transport
// dropped it" looks like in bytes, as opposed to nilling a Go struct field.
func stripWireField(wire []byte, num protowire.Number) ([]byte, error) {
	var out []byte
	b := wire
	for len(b) > 0 {
		fieldNum, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		valueLen := protowire.ConsumeFieldValue(fieldNum, typ, b[n:])
		if valueLen < 0 {
			return nil, protowire.ParseError(valueLen)
		}
		record := b[:n+valueLen]
		if fieldNum != num {
			out = append(out, record...)
		}
		b = b[n+valueLen:]
	}
	return out, nil
}

// A signed permit must survive the wire hop and verify from the bytes alone.
func TestPermitSurvivesTheProtoWireHopAndStillVerifies(t *testing.T) {
	contract := loadPermitWireContract(t)
	signer, err := NewEd25519SignerFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize), "cross-process")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	origin := fullyPopulatedPermit()
	if len(origin.EvidenceBindings) == 0 {
		t.Fatal("fixture must carry evidence bindings for this test to mean anything")
	}
	if err := SignPermit(signer, origin); err != nil {
		t.Fatalf("sign: %v", err)
	}
	signedPayload, err := EffectPermitSigningPayload(origin)
	if err != nil {
		t.Fatalf("canonicalize origin: %v", err)
	}

	// The hop. Everything past this point sees only bytes.
	wire := encodePermit(t, contract, origin)
	farSide, err := decodePermit(contract, wire)
	if err != nil {
		t.Fatalf("decode permit from wire: %v", err)
	}

	if len(farSide.EvidenceBindings) != len(origin.EvidenceBindings) {
		t.Fatalf("evidence bindings did not survive the hop: got %v, want %v",
			farSide.EvidenceBindings, origin.EvidenceBindings)
	}
	for k, want := range origin.EvidenceBindings {
		if got := farSide.EvidenceBindings[k]; got != want {
			t.Fatalf("evidence binding %q crossed the wire as %q, want %q", k, got, want)
		}
	}

	farPayload, err := EffectPermitSigningPayload(farSide)
	if err != nil {
		t.Fatalf("canonicalize far side: %v", err)
	}
	if !bytes.Equal(signedPayload, farPayload) {
		t.Fatalf("preimage differs across the wire hop:\n origin: %s\n farside: %s",
			signedPayload, farPayload)
	}

	ok, err := VerifyPermit(signer.PublicKey(), farSide)
	if err != nil {
		t.Fatalf("verify on the far side: %v", err)
	}
	if !ok {
		t.Fatal("signature did not verify on the far side of the wire hop")
	}
}

// The positive case above is only meaningful if a wire that drops the binding
// actually fails. Strip field 16 from the encoded bytes — a peer predating the
// field emits exactly this — and require verification to refuse.
func TestPermitFailsVerificationWhenTheWireDropsEvidenceBindings(t *testing.T) {
	contract := loadPermitWireContract(t)
	signer, err := NewEd25519SignerFromSeed(bytes.Repeat([]byte{0x34}, ed25519.SeedSize), "cross-process-drop")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	origin := fullyPopulatedPermit()
	if err := SignPermit(signer, origin); err != nil {
		t.Fatalf("sign: %v", err)
	}

	wire := encodePermit(t, contract, origin)
	stripped, err := stripWireField(wire, contract.field(t, "evidence_bindings"))
	if err != nil {
		t.Fatalf("strip evidence bindings: %v", err)
	}
	if len(stripped) >= len(wire) {
		t.Fatal("stripping evidence_bindings removed no bytes; the fixture is not exercising the field")
	}

	farSide, err := decodePermit(contract, stripped)
	if err != nil {
		t.Fatalf("decode stripped permit: %v", err)
	}
	if len(farSide.EvidenceBindings) != 0 {
		t.Fatalf("expected the stripped wire to carry no bindings, got %v", farSide.EvidenceBindings)
	}

	// Require a signature mismatch specifically. VerifyPermit returns
	// (false, nil) for that, and an error only for malformed inputs — so
	// asserting "not ok, no error" keeps this from passing vacuously if some
	// unrelated failure ever started short-circuiting verification.
	ok, err := VerifyPermit(signer.PublicKey(), farSide)
	if err != nil {
		t.Fatalf("expected a signature mismatch, got an error instead: %v", err)
	}
	if ok {
		t.Fatal("a permit whose evidence bindings were dropped in transit still verified: " +
			"the signature does not cover the evidence obligation")
	}
}

// Proto3 cannot distinguish an absent string from an empty one, and the signed
// envelope deliberately carries empty values rather than omitting them. Prove
// that costs nothing: a permit with no bindings and an empty plan_hash must
// still verify across the hop, so the guard above is catching real loss rather
// than a canonicalization artefact.
func TestPermitWithEmptyOptionalFieldsSurvivesTheWireHop(t *testing.T) {
	contract := loadPermitWireContract(t)
	signer, err := NewEd25519SignerFromSeed(bytes.Repeat([]byte{0x35}, ed25519.SeedSize), "cross-process-empty")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	origin := fullyPopulatedPermit()
	origin.PlanHash = ""
	origin.PolicyHash = ""
	origin.EvidenceBindings = nil
	origin.Scope.AllowedParams = nil
	origin.Scope.DenyPatterns = nil
	if err := SignPermit(signer, origin); err != nil {
		t.Fatalf("sign: %v", err)
	}

	farSide, err := decodePermit(contract, encodePermit(t, contract, origin))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	ok, err := VerifyPermit(signer.PublicKey(), farSide)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("a permit with empty optional fields failed to verify across the wire hop")
	}
}

// The signed preimage covers effect_type as the Go string ("WRITE"); the wire
// carries it as an enum (EFFECT_TYPE_WRITE = 2). Nothing in the repository
// converts between the two, so a far-side verifier has to guess — and guessing
// "EFFECT_TYPE_WRITE" instead of "WRITE" produces a different preimage and a
// failed verification for a permit that is perfectly valid.
//
// This test pins the mapping against the .proto so the two cannot drift, and
// stands as the executable record of a convention that still belongs in a
// published spec. See the PR discussion: the enum-to-string rule is a
// cross-process requirement with no home outside this file.
func TestEffectTypeEnumMappingIsPinned(t *testing.T) {
	source, err := os.ReadFile("../../../protocols/proto/helm/effects/v1/effects.proto")
	if err != nil {
		t.Fatalf("read wire contract: %v", err)
	}
	block := regexp.MustCompile(`(?s)enum EffectType \{(.*?)\n\}`).FindSubmatch(source)
	if block == nil {
		t.Fatal("enum EffectType not found in the wire contract")
	}

	wire := map[string]uint64{}
	for _, m := range regexp.MustCompile(`(?m)^\s*EFFECT_TYPE_(\w+)\s*=\s*(\d+);`).FindAllSubmatch(block[1], -1) {
		n, err := strconv.ParseUint(string(m[2]), 10, 64)
		if err != nil {
			t.Fatalf("enum value %q unparseable: %v", m[2], err)
		}
		wire[string(m[1])] = n
	}
	if len(wire) == 0 {
		t.Fatal("parsed no values from enum EffectType")
	}

	for name, num := range wire {
		if name == "UNSPECIFIED" {
			if got := effectTypeEnum[""]; got != num {
				t.Fatalf("EFFECT_TYPE_UNSPECIFIED is %d on the wire, mapped to %d", num, got)
			}
			continue
		}
		got, ok := effectTypeEnum[effects.EffectType(name)]
		if !ok {
			t.Fatalf("wire enum EFFECT_TYPE_%s has no Go EffectType mapping: a far-side "+
				"verifier cannot reconstruct the signed effect_type string", name)
		}
		if got != num {
			t.Fatalf("EFFECT_TYPE_%s is %d on the wire but mapped to %d", name, num, got)
		}
	}

	// And the reverse: every Go effect type must have a wire value, or a permit
	// carrying it cannot cross a hop at all.
	for goName := range effectTypeEnum {
		if goName == "" {
			continue
		}
		if _, ok := wire[string(goName)]; !ok {
			t.Fatalf("Go EffectType %q has no EFFECT_TYPE_%s on the wire", goName, goName)
		}
	}
}
