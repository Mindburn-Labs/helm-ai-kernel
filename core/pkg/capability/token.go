package capability

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

// Token schema version (capability-token/v1, see
// protocols/json-schemas/capability/capability_token.v1.json and
// docs/governance/task-capability-tokens.md).
//
// Scope honesty: chunk 2 implements mint/verify with an in-memory store.
// Durable storage, cross-process revocation propagation, and permit-ceremony
// minting are follow-up work.
const TokenSchemaVersion = "capability-token/v1"

// TokenStatus is the dynamic lifecycle state of a capability token. Terminal
// states are fail-closed: Guardian refuses a dispatch that presents one.
type TokenStatus string

const (
	TokenStatusActive  TokenStatus = "active"
	TokenStatusUsedUp  TokenStatus = "used_up"
	TokenStatusExpired TokenStatus = "expired"
	TokenStatusRevoked TokenStatus = "revoked"
)

var validTokenStatuses = map[TokenStatus]bool{
	TokenStatusActive: true, TokenStatusUsedUp: true, TokenStatusExpired: true, TokenStatusRevoked: true,
}

// Terminal reports whether the status refuses dispatch.
func (s TokenStatus) Terminal() bool {
	return s == TokenStatusUsedUp || s == TokenStatusExpired || s == TokenStatusRevoked
}

// DefaultTokenTTL is the recommended default grant window
// (task-capability-tokens.md: min(task end, 15 minutes)).
const DefaultTokenTTL = 15 * time.Minute

var tokenIDPattern = regexp.MustCompile(`^tok_[A-Za-z0-9_-]{8,64}$`)
var tokenDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// TokenSubject binds a token to an agent (optionally session/device).
type TokenSubject struct {
	AgentID   string `json:"agent_id"`
	SessionID string `json:"session_id,omitempty"`
	DeviceID  string `json:"device_id,omitempty"`
}

// TokenCapabilityRef pins the exact manifest revision granted.
type TokenCapabilityRef struct {
	CapabilityID string `json:"capability_id"`
	Version      string `json:"version"`
	ManifestHash string `json:"manifest_hash"`
}

// TokenConstraints narrow a grant further than the manifest allows.
type TokenConstraints struct {
	ArgsDigest          string `json:"args_digest,omitempty"`
	DataBoundaryCeiling string `json:"data_boundary_ceiling,omitempty"`
}

// TokenGrant is the validity window and usage bounds.
type TokenGrant struct {
	IssuedAt    time.Time        `json:"issued_at"`
	ExpiresAt   time.Time        `json:"expires_at"`
	MaxUses     int              `json:"max_uses,omitempty"`
	Constraints TokenConstraints `json:"constraints,omitempty"`
}

// Token is a task-bound, TTL-limited, manifest-hash-pinned capability grant.
// Status, RevocationReceiptRef, and Signature are NOT part of the signed
// payload: status transitions and revocation happen after minting.
type Token struct {
	SchemaVersion        string             `json:"schema_version"`
	TokenID              string             `json:"token_id"`
	TaskID               string             `json:"task_id"`
	Subject              TokenSubject       `json:"subject"`
	CapabilityRef        TokenCapabilityRef `json:"capability_ref"`
	Grant                TokenGrant         `json:"grant"`
	Status               TokenStatus        `json:"status"`
	RevocationReceiptRef string             `json:"revocation_receipt_ref,omitempty"`
	Signature            string             `json:"signature,omitempty"`
}

// signedPayload returns the token view covered by the authority signature.
func (t *Token) signedPayload() Token {
	out := *t
	out.Status = ""
	out.RevocationReceiptRef = ""
	out.Signature = ""
	return out
}

// ValidateShape enforces the capability-token/v1 structural rules for a
// presented token, including the schema-required detached signature.
func (t *Token) ValidateShape() error {
	return t.validateShape(true)
}

// validateShape permits the mint path to validate a complete unsigned payload
// immediately before attaching its detached signature.
func (t *Token) validateShape(requireSignature bool) error {
	if t.SchemaVersion != TokenSchemaVersion {
		return fmt.Errorf("schema_version must be %q, got %q", TokenSchemaVersion, t.SchemaVersion)
	}
	if !tokenIDPattern.MatchString(t.TokenID) {
		return fmt.Errorf("token_id %q does not match required pattern", t.TokenID)
	}
	if t.TaskID == "" {
		return fmt.Errorf("task_id is required")
	}
	if t.Subject.AgentID == "" {
		return fmt.Errorf("subject.agent_id is required")
	}
	if t.CapabilityRef.CapabilityID == "" || !capabilityIDPattern.MatchString(t.CapabilityRef.CapabilityID) {
		return fmt.Errorf("capability_ref.capability_id %q invalid", t.CapabilityRef.CapabilityID)
	}
	if !semverPattern.MatchString(t.CapabilityRef.Version) {
		return fmt.Errorf("capability_ref.version %q is not valid semver", t.CapabilityRef.Version)
	}
	if !tokenDigestPattern.MatchString(t.CapabilityRef.ManifestHash) {
		return fmt.Errorf("capability_ref.manifest_hash must be a sha256 digest")
	}
	if t.Grant.IssuedAt.IsZero() || t.Grant.ExpiresAt.IsZero() {
		return fmt.Errorf("grant.issued_at and grant.expires_at are required")
	}
	if !t.Grant.ExpiresAt.After(t.Grant.IssuedAt) {
		return fmt.Errorf("grant.expires_at must be after grant.issued_at")
	}
	if t.Grant.MaxUses < 0 {
		return fmt.Errorf("grant.max_uses must be >= 0")
	}
	if t.Grant.Constraints.ArgsDigest != "" && !tokenDigestPattern.MatchString(t.Grant.Constraints.ArgsDigest) {
		return fmt.Errorf("constraints.args_digest must be a sha256 digest")
	}
	if t.Grant.Constraints.DataBoundaryCeiling != "" &&
		!validBoundaries[DataBoundary(t.Grant.Constraints.DataBoundaryCeiling)] {
		return fmt.Errorf("constraints.data_boundary_ceiling %q invalid", t.Grant.Constraints.DataBoundaryCeiling)
	}
	if !validTokenStatuses[t.Status] {
		return fmt.Errorf("status %q is invalid", t.Status)
	}
	if requireSignature && t.Signature == "" {
		return fmt.Errorf("signature is required")
	}
	return nil
}

// boundaryRank orders data boundaries so a grant ceiling can be compared
// against a manifest's boundary: local_only < device < org < external.
func boundaryRank(b DataBoundary) int {
	switch b {
	case BoundaryLocalOnly:
		return 0
	case BoundaryDevice:
		return 1
	case BoundaryOrg:
		return 2
	case BoundaryExternal:
		return 3
	}
	return -1
}

// DecodeToken strictly decodes a token from a context value: a JSON string or
// an already-decoded map (e.g. from a JSON request body). It rejects unknown
// fields and concatenated JSON values to preserve the closed token schema.
func DecodeToken(v interface{}) (*Token, error) {
	var raw []byte
	switch value := v.(type) {
	case string:
		raw = []byte(value)
	case map[string]interface{}:
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("re-encode token map: %w", err)
		}
		raw = encoded
	default:
		return nil, fmt.Errorf("unsupported token context type %T", v)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var token Token
	if err := dec.Decode(&token); err != nil {
		return nil, fmt.Errorf("decode token: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode token: trailing JSON value")
	}
	return &token, nil
}
