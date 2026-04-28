// did_payload.go — DID-qualified agent identifiers in A2A envelopes.
//
// Workstream D extends the A2A protocol to accept W3C DIDs in the
// `origin_agent_id` and `target_agent_id` fields of an Envelope. The
// existing string fields are preserved on the wire to keep the protobuf
// schema unchanged; the helpers below enforce the additional invariant
// that, when a DID-shaped value is supplied, it parses as a valid DID URI.
//
// Backwards compatibility:
//   - Legacy opaque IDs (no `did:` prefix) continue to be accepted.
//   - When the consumer enables DID enforcement (CanonicalizeDIDFields),
//     non-DID identifiers are logged at INFO with a deprecation message
//     and accepted unchanged so existing deployments do not break.
//
// Field shape on the wire stays identical: `origin_agent_id` and
// `target_agent_id` remain strings. Protobuf regen is therefore not
// required for this change. Future protobuf schemas may add explicit
// `origin_did` / `target_did` fields; see docs/architecture/portable-identity.md
// for the migration plan.

package a2a

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity/did"
)

// IsDID returns true if the supplied agent identifier is a W3C DID URI.
func IsDID(id string) bool {
	return strings.HasPrefix(id, "did:") && parseDID(id) == nil
}

// parseDID returns nil when id is a structurally valid DID URI.
func parseDID(id string) error {
	if _, _, err := did.ParseDID(id); err != nil {
		return err
	}
	return nil
}

// ValidateAgentIdentifier accepts either a DID URI or a legacy opaque
// string. When the value carries a `did:` prefix, it must parse cleanly;
// otherwise, the value is accepted unchanged so existing deployments are
// not broken.
//
// The deprecationLogger argument is invoked at INFO level the first time a
// non-DID identifier is observed for a given Envelope; pass slog.Default()
// in production paths.
func ValidateAgentIdentifier(field, id string, deprecationLogger *slog.Logger) error {
	if id == "" {
		return fmt.Errorf("a2a: %s is empty", field)
	}
	if strings.HasPrefix(id, "did:") {
		if err := parseDID(id); err != nil {
			return fmt.Errorf("a2a: %s is malformed DID %q: %w", field, id, err)
		}
		return nil
	}
	if deprecationLogger != nil {
		deprecationLogger.Info("a2a: legacy opaque agent identifier accepted; DID-qualified IDs preferred",
			slog.String("field", field), slog.String("agent_id", id))
	}
	return nil
}

// CanonicalizeDIDFields validates the envelope's origin_agent_id and
// target_agent_id. Pass slog.Default() (or a structured logger of choice)
// to receive deprecation notices for legacy IDs.
//
// Returns the first validation error encountered, or nil on success.
func CanonicalizeDIDFields(env *Envelope, logger *slog.Logger) error {
	if env == nil {
		return fmt.Errorf("a2a: nil envelope")
	}
	if err := ValidateAgentIdentifier("origin_agent_id", env.OriginAgentID, logger); err != nil {
		return err
	}
	if err := ValidateAgentIdentifier("target_agent_id", env.TargetAgentID, logger); err != nil {
		return err
	}
	return nil
}

// EnvelopeIdentifierKind classifies an envelope's agent identifiers as a
// pair of (origin, target) classifications: "did", "legacy", or "missing".
// Useful for telemetry counters that track DID adoption.
func EnvelopeIdentifierKind(env *Envelope) (origin, target string) {
	return classify(env.OriginAgentID), classify(env.TargetAgentID)
}

func classify(id string) string {
	switch {
	case id == "":
		return "missing"
	case IsDID(id):
		return "did"
	default:
		return "legacy"
	}
}
