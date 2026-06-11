package audit

// Agent Audit Trail (AAT) export mode.
//
// Implements the record structure of the IETF draft
// draft-sharif-agent-audit-trail: JSON records with mandatory fields,
// a mandatory tamper-evident SHA-256 hash chain, and optional digital
// signatures for non-repudiation of every agent action.
//
// Records are canonicalized with JCS (RFC 8785) before hashing so the
// chain verifies identically on every platform. Output is JSON Lines
// (one canonical record per line) and is byte-deterministic for a given
// input sequence.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

const (
	// AATVersion identifies the draft revision this export targets.
	AATVersion = "draft-sharif-agent-audit-trail-00"

	// AATGenesisHash is the previous_record_hash of the first record in a chain.
	AATGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	// ErrAATChainBroken is returned when hash-chain verification fails.
	ErrAATChainBroken = errors.New("audit: aat hash chain broken")
	// ErrAATBadSignature is returned when a record signature does not verify.
	ErrAATBadSignature = errors.New("audit: aat record signature invalid")
	// ErrAATEmptyAgentID is returned when the exporting agent identity is empty.
	ErrAATEmptyAgentID = errors.New("audit: aat agent_id must not be empty")
)

// AATSignature is the optional non-repudiation envelope on a record.
type AATSignature struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	Value     string `json:"value"`
}

// AATRecord is a single AAT-conformant audit record. Mandatory fields per
// the draft: aat_version, record_id, sequence, timestamp, agent_id,
// action_type, action, resource, payload_hash, previous_record_hash,
// record_hash. signature is optional.
type AATRecord struct {
	AATVersion         string            `json:"aat_version"`
	RecordID           string            `json:"record_id"`
	Sequence           uint64            `json:"sequence"`
	Timestamp          string            `json:"timestamp"`
	AgentID            string            `json:"agent_id"`
	ActionType         string            `json:"action_type"`
	Action             string            `json:"action"`
	Resource           string            `json:"resource"`
	PayloadHash        string            `json:"payload_hash"`
	Metadata           map[string]string `json:"metadata,omitempty"`
	PreviousRecordHash string            `json:"previous_record_hash"`
	RecordHash         string            `json:"record_hash"`
	Signature          *AATSignature     `json:"signature,omitempty"`
}

// AATSigner signs record hashes. The draft permits ECDSA; HELM's native
// deterministic implementation is Ed25519. Any algorithm satisfying this
// interface may be plugged in.
type AATSigner interface {
	Algorithm() string
	PublicKey() []byte
	Sign(digest []byte) ([]byte, error)
}

// Ed25519AATSigner signs AAT records with an Ed25519 private key.
// Ed25519 signatures are deterministic, preserving byte-identical exports.
type Ed25519AATSigner struct {
	key ed25519.PrivateKey
}

// NewEd25519AATSigner wraps an Ed25519 private key as an AATSigner.
func NewEd25519AATSigner(key ed25519.PrivateKey) (*Ed25519AATSigner, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("audit: invalid ed25519 private key size %d", len(key))
	}
	return &Ed25519AATSigner{key: key}, nil
}

func (s *Ed25519AATSigner) Algorithm() string { return "Ed25519" }

func (s *Ed25519AATSigner) PublicKey() []byte {
	return s.key.Public().(ed25519.PublicKey)
}

func (s *Ed25519AATSigner) Sign(digest []byte) ([]byte, error) {
	return ed25519.Sign(s.key, digest), nil
}

// hashableView returns the record with record_hash and signature cleared,
// which is the form covered by the SHA-256 hash chain.
func (r AATRecord) hashableView() AATRecord {
	r.RecordHash = ""
	r.Signature = nil
	return r
}

func computeAATRecordHash(r AATRecord) (string, error) {
	view := r.hashableView()
	canonical, err := canonicalize.JCS(view)
	if err != nil {
		return "", fmt.Errorf("audit: aat canonicalization failed: %w", err)
	}
	return canonicalize.HashBytes(canonical), nil
}

// ConvertEntriesToAAT converts append-only audit store entries into an
// AAT-conformant record chain. Entries are processed in the given order;
// the chain is rooted at AATGenesisHash. When signer is non-nil every
// record hash is signed for non-repudiation.
func ConvertEntriesToAAT(entries []*store.AuditEntry, agentID string, signer AATSigner) ([]AATRecord, error) {
	if agentID == "" {
		return nil, ErrAATEmptyAgentID
	}
	records := make([]AATRecord, 0, len(entries))
	previous := AATGenesisHash
	for i, entry := range entries {
		if entry == nil {
			return nil, fmt.Errorf("audit: aat input entry %d is nil", i)
		}
		record := AATRecord{
			AATVersion:         AATVersion,
			RecordID:           entry.EntryID,
			Sequence:           entry.Sequence,
			Timestamp:          entry.Timestamp.UTC().Format(time.RFC3339Nano),
			AgentID:            agentID,
			ActionType:         string(entry.EntryType),
			Action:             entry.Action,
			Resource:           entry.Subject,
			PayloadHash:        "sha256:" + entry.PayloadHash,
			Metadata:           entry.Metadata,
			PreviousRecordHash: previous,
		}
		hash, err := computeAATRecordHash(record)
		if err != nil {
			return nil, err
		}
		record.RecordHash = hash
		if signer != nil {
			digest, err := hex.DecodeString(hash)
			if err != nil {
				return nil, fmt.Errorf("audit: aat record hash decode: %w", err)
			}
			sig, err := signer.Sign(digest)
			if err != nil {
				return nil, fmt.Errorf("audit: aat signing failed: %w", err)
			}
			record.Signature = &AATSignature{
				Algorithm: signer.Algorithm(),
				PublicKey: base64.StdEncoding.EncodeToString(signer.PublicKey()),
				Value:     base64.StdEncoding.EncodeToString(sig),
			}
		}
		records = append(records, record)
		previous = hash
	}
	return records, nil
}

// MarshalAATJSONL serializes records as JSON Lines, one JCS-canonical
// record per line. Output is byte-deterministic for identical input.
func MarshalAATJSONL(records []AATRecord) ([]byte, error) {
	var b strings.Builder
	for i, record := range records {
		canonical, err := canonicalize.JCS(record)
		if err != nil {
			return nil, fmt.Errorf("audit: aat record %d serialization failed: %w", i, err)
		}
		b.Write(canonical)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// VerifyAATChain re-derives every record hash, checks the SHA-256 chain
// from AATGenesisHash, and verifies Ed25519 signatures where present.
func VerifyAATChain(records []AATRecord) error {
	previous := AATGenesisHash
	for i, record := range records {
		if record.PreviousRecordHash != previous {
			return fmt.Errorf("%w: record %d previous_record_hash mismatch", ErrAATChainBroken, i)
		}
		expected, err := computeAATRecordHash(record)
		if err != nil {
			return err
		}
		if record.RecordHash != expected {
			return fmt.Errorf("%w: record %d record_hash mismatch", ErrAATChainBroken, i)
		}
		if record.Signature != nil && record.Signature.Algorithm == "Ed25519" {
			pub, err := base64.StdEncoding.DecodeString(record.Signature.PublicKey)
			if err != nil || len(pub) != ed25519.PublicKeySize {
				return fmt.Errorf("%w: record %d public key malformed", ErrAATBadSignature, i)
			}
			sig, err := base64.StdEncoding.DecodeString(record.Signature.Value)
			if err != nil {
				return fmt.Errorf("%w: record %d signature malformed", ErrAATBadSignature, i)
			}
			digest, err := hex.DecodeString(record.RecordHash)
			if err != nil {
				return fmt.Errorf("%w: record %d record_hash malformed", ErrAATBadSignature, i)
			}
			if !ed25519.Verify(ed25519.PublicKey(pub), digest, sig) {
				return fmt.Errorf("%w: record %d", ErrAATBadSignature, i)
			}
		}
		previous = record.RecordHash
	}
	return nil
}

// GenerateAAT exports the requested audit window as an AAT-conformant
// JSON Lines document. Fail-closed: requires a configured store.
func (e *Exporter) GenerateAAT(ctx context.Context, req ExportRequest, agentID string, signer AATSigner) ([]byte, error) {
	if req.TenantID == "" {
		return nil, ErrEmptyTenantID
	}
	if !req.StartTime.IsZero() && !req.EndTime.IsZero() && req.StartTime.After(req.EndTime) {
		return nil, ErrInvalidTimeRange
	}
	if e.store == nil {
		return nil, ErrStoreNotConfigured
	}
	filter := store.QueryFilter{
		EntryType: store.EntryTypeAudit,
		Subject:   "tenant:" + req.TenantID,
	}
	if !req.StartTime.IsZero() {
		filter.StartTime = &req.StartTime
	}
	if !req.EndTime.IsZero() {
		filter.EndTime = &req.EndTime
	}
	entries := e.store.Query(filter)
	records, err := ConvertEntriesToAAT(entries, agentID, signer)
	if err != nil {
		return nil, err
	}
	return MarshalAATJSONL(records)
}
