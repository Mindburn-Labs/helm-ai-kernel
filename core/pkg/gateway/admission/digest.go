package admission

// quantum_posture: SHA-256 content digests for idempotency and approval
// binding; nothing here signs or verifies, and no post-quantum claim is made.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"time"
)

// Amount is one quote entry: a non-negative integer amount of one unit.
type Amount struct {
	Unit   string `json:"unit"`
	Amount int64  `json:"amount"`
}

// DistinctValue is a value a distinct-value limit counts, as a digest.
type DistinctValue struct {
	Unit   string
	Digest []byte
}

// ApprovalDigestV1 is the approval digest of docs/architecture/
// gateway-effect-api.md: SHA-256 over the domain tag, the attempt id, the
// target and argument digests, the quote (entry count, then each entry sorted
// by unit bytes) and expires_at as RFC 3339 UTC text in whole seconds.
// field(b) is a big-endian uint64 length and b; amounts are big-endian uint64.
func ApprovalDigestV1(attemptID string, targetDigest, argumentDigest []byte, quote []Amount, expiresAt time.Time) []byte {
	var m bytes.Buffer
	field(&m, []byte("helm.gateway.v1.approval-digest.v1"))
	field(&m, []byte(attemptID))
	field(&m, targetDigest)
	field(&m, argumentDigest)
	ordered := append([]Amount(nil), quote...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Unit < ordered[j].Unit })
	u64(&m, uint64(len(ordered)))
	for _, q := range ordered {
		field(&m, []byte(q.Unit))
		u64(&m, uint64(q.Amount)) // #nosec G115 -- quote amounts are validated non-negative
	}
	field(&m, []byte(expiresAt.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")))
	sum := sha256.Sum256(m.Bytes())
	return sum[:]
}

// requestDigest is the R6 idempotency digest: every ProposeRequest field but
// the key, and the authenticated principal and workspace, in one
// length-prefixed encoding. Quote and distinct entries are sorted, so their
// order does not make two equal requests differ.
func requestDigest(caller Caller, in ProposeInput) []byte {
	var m bytes.Buffer
	field(&m, []byte("helm.gateway.v1.request-digest.v1"))
	field(&m, []byte(caller.PrincipalID))
	field(&m, []byte(caller.WorkspaceID))
	field(&m, []byte(in.MandateID))
	field(&m, []byte(in.CommitmentID))
	field(&m, []byte(in.CaseID))
	field(&m, []byte(in.EffectType))
	field(&m, []byte(in.Target))
	field(&m, in.Arguments)
	quote := append([]Amount(nil), in.Quote...)
	sort.Slice(quote, func(i, j int) bool { return quote[i].Unit < quote[j].Unit })
	u64(&m, uint64(len(quote)))
	for _, q := range quote {
		field(&m, []byte(q.Unit))
		u64(&m, uint64(q.Amount)) // #nosec G115 -- validated non-negative
	}
	distinct := append([]DistinctValue(nil), in.Distinct...)
	sort.Slice(distinct, func(i, j int) bool { return distinct[i].Unit < distinct[j].Unit })
	u64(&m, uint64(len(distinct)))
	for _, d := range distinct {
		field(&m, []byte(d.Unit))
		field(&m, d.Digest)
	}
	expires := ""
	if in.ApprovalExpiresAt != nil {
		expires = in.ApprovalExpiresAt.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
	}
	field(&m, []byte(expires))
	sum := sha256.Sum256(m.Bytes())
	return sum[:]
}

func field(m *bytes.Buffer, b []byte) {
	u64(m, uint64(len(b)))
	m.Write(b)
}

func u64(m *bytes.Buffer, n uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	m.Write(b[:])
}
