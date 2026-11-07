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

import ()
