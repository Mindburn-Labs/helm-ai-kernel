// narrative.go implements a business-readable projection of an evidence pack
// (MIN-442). An EvidencePack is a content-addressed, tamper-evident archive of
// receipts, policy decisions, and tool transcripts (see manifest.go / builder.go).
// Read raw, it requires Kernel internals knowledge to interpret.
//
// BusinessNarrative answers, in plain language, the questions a business
// approver, buyer, auditor, or department leader asks of any action:
//
//   - Who proposed the action?      -> Manifest.ActorDID + Manifest.IntentID
//   - Who approved or denied it?    -> the signed DecisionRecord(s) under policy/
//   - Which policy rule applied?    -> decision verdict + reason + policy version/hash
//   - Which data/connector records? -> effect / transcript / connector / diff entries
//   - What happened?                -> the ordered set of effects recorded in the pack
//   - What proves it?               -> the manifest hash + per-claim content hashes
//
// Design invariants (mirroring summary.go):
//
//   - DERIVED, never authored: every field is projected from the signed manifest
//     and entry content. The narrative is NOT a second source of truth; it links
//     back to the cryptographic proof chain via ProofRefs and ManifestHash.
//   - Tamper-evident: NarrativeHash binds the projection; Verify() recomputes it
//     AND re-checks that every cited proof ref still matches a manifest entry by
//     content hash. A business view that drifts from the signed pack fails Verify.
//   - No new proof universe: the narrative cites existing manifest entries and the
//     ProofGraph node types already inferred by summary.go. It adds readability,
//     not authority.
package evidencepack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// NarrativeVersion is the schema version of the business narrative projection.
const NarrativeVersion = "narrative.v1"

// VerdictUnknown is used when no policy decision in the pack records a verdict.
const VerdictUnknown = "UNKNOWN"

// ProofRef links one human-readable claim back to a specific entry in the signed
// pack. ContentHash is copied from the manifest entry, so a verifier can confirm
// the cited artifact is exactly the one that was signed.
type ProofRef struct {
	// Claim is the business question this artifact answers, e.g. "approval".
	Claim string `json:"claim"`
	// Path is the manifest entry path, e.g. "policy/gate-1.json".
	Path string `json:"path"`
	// ContentHash is the entry's content hash from the manifest (sha256:hex).
	ContentHash string `json:"content_hash"`
	// NodeType is the ProofGraph node type the entry maps to (may be empty).
	NodeType string `json:"node_type,omitempty"`
}

// ApprovalRecord is the business-readable view of a single signed policy decision
// (contracts.DecisionRecord) found in the pack. It captures who/what/why without
// requiring the reader to parse the raw decision JSON, while ProofPath links back
// to the signed record.
type ApprovalRecord struct {
	// Verdict is the canonical decision: ALLOW, DENY, ESCALATE (or UNKNOWN).
	Verdict string `json:"verdict"`
	// Subject is the principal the decision was made about (DecisionRecord.SubjectID).
	Subject string `json:"subject,omitempty"`
	// Action is the requested action (DecisionRecord.Action).
	Action string `json:"action,omitempty"`
	// Resource is the target resource (DecisionRecord.Resource).
	Resource string `json:"resource,omitempty"`
	// Reason is the human-readable explanation recorded on the decision.
	Reason string `json:"reason,omitempty"`
	// ReasonCode is the machine-readable registry code, if present.
	ReasonCode string `json:"reason_code,omitempty"`
	// PolicyRule identifies the governing policy: version preferred, else content hash.
	PolicyRule string `json:"policy_rule,omitempty"`
	// Signed reports whether the underlying decision carried a signature.
	Signed bool `json:"signed"`
	// DecidedAt is the decision timestamp, if recorded.
	DecidedAt time.Time `json:"decided_at,omitempty"`
	// ProofPath is the manifest entry path of the signed decision.
	ProofPath string `json:"proof_path"`
}

// BusinessNarrative is the business-readable projection of an evidence pack.
// It is a derived view: GenerateNarrative builds it from a manifest and the pack
// content map, and Verify re-checks it against the signed pack.
//
//nolint:govet // fieldalignment: layout is grouped for human readability.
type BusinessNarrative struct {
	Version      string `json:"version"`
	PackID       string `json:"pack_id"`
	ManifestHash string `json:"manifest_hash"`

	// Title is a one-line summary an approver can read at a glance.
	Title string `json:"title"`
	// Summary is a multi-sentence plain-language account of the action story.
	Summary string `json:"summary"`

	// --- The five business questions ---

	// ProposedBy answers "who proposed the action?" (actor identity).
	ProposedBy string `json:"proposed_by"`
	// IntentID is the proposing intent the pack was built for.
	IntentID string `json:"intent_id"`
	// Approvals answers "who approved/denied it, under which rule?".
	Approvals []ApprovalRecord `json:"approvals"`
	// Outcome is the rolled-up verdict across all approvals (worst-case wins:
	// DENY > ESCALATE > ALLOW), so a leader sees the gating decision immediately.
	Outcome string `json:"outcome"`
	// DataSources answers "which data/connector records were used?".
	DataSources []string `json:"data_sources"`
	// WhatHappened answers "what happened?" — the recorded effects, plainly named.
	WhatHappened []string `json:"what_happened"`

	// --- The proof linkage ("what proves it?") ---

	// ProofRefs cites every artifact backing a claim, each bound by content hash.
	ProofRefs []ProofRef `json:"proof_refs"`
	// NodeTypes is the ProofGraph node-type coverage of the pack (from the summary).
	NodeTypes []string `json:"node_types"`
	// GeneratedAt is when this projection was produced.
	GeneratedAt time.Time `json:"generated_at"`
	// NarrativeHash binds all fields above; see Verify.
	NarrativeHash string `json:"narrative_hash"`
}

// decisionView is the subset of contracts.DecisionRecord the narrative reads.
// It is declared locally so the evidencepack package keeps zero dependency on the
// contracts package (the pack stores decisions as opaque JSON entries).
//
//nolint:govet // fieldalignment: mirrors the decision JSON field order.
type decisionView struct {
	SubjectID         string    `json:"subject_id"`
	Action            string    `json:"action"`
	Resource          string    `json:"resource"`
	Verdict           string    `json:"verdict"`
	Reason            string    `json:"reason"`
	ReasonCode        string    `json:"reason_code"`
	PolicyVersion     string    `json:"policy_version"`
	PolicyContentHash string    `json:"policy_content_hash"`
	Signature         string    `json:"signature"`
	Timestamp         time.Time `json:"timestamp"`
}

// GenerateNarrative builds a business-readable narrative from a manifest and the
// pack content map (as returned by Builder.Build). The content map is used only
// to read already-signed policy decisions; if it is nil, the narrative is still
// produced from manifest metadata, but approvals are reported as UNKNOWN.
func GenerateNarrative(manifest *Manifest, content map[string][]byte) (*BusinessNarrative, error) {
	if manifest == nil {
		return nil, fmt.Errorf("manifest is nil")
	}

	n := &BusinessNarrative{
		Version:      NarrativeVersion,
		PackID:       manifest.PackID,
		ManifestHash: manifest.ManifestHash,
		ProposedBy:   actorLabel(manifest.ActorDID),
		IntentID:     manifest.IntentID,
		GeneratedAt:  time.Now().UTC(),
	}

	// Walk manifest entries in deterministic (sorted) order so the narrative and
	// its hash are stable regardless of builder insertion order.
	entries := make([]ManifestEntry, len(manifest.Entries))
	copy(entries, manifest.Entries)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	nodeTypeSet := make(map[string]struct{})
	for _, e := range entries {
		nodeType := inferNodeType(e.Path, e.ContentType)
		if nodeType != "" {
			nodeTypeSet[nodeType] = struct{}{}
		}

		switch {
		case strings.HasPrefix(e.Path, "policy/"):
			ar := buildApproval(e, content)
			n.Approvals = append(n.Approvals, ar)
			n.ProofRefs = append(n.ProofRefs, ProofRef{
				Claim: "approval", Path: e.Path, ContentHash: e.ContentHash, NodeType: nodeType,
			})
		case strings.HasPrefix(e.Path, "receipts/"):
			n.WhatHappened = append(n.WhatHappened, fmt.Sprintf("Receipt recorded: %s", entryLabel(e.Path, "receipts/")))
			n.ProofRefs = append(n.ProofRefs, ProofRef{
				Claim: "attestation", Path: e.Path, ContentHash: e.ContentHash, NodeType: nodeType,
			})
		case strings.HasPrefix(e.Path, "transcripts/"):
			n.DataSources = append(n.DataSources, fmt.Sprintf("Tool transcript: %s", entryLabel(e.Path, "transcripts/")))
			n.WhatHappened = append(n.WhatHappened, fmt.Sprintf("Tool executed: %s", entryLabel(e.Path, "transcripts/")))
			n.ProofRefs = append(n.ProofRefs, ProofRef{
				Claim: "effect", Path: e.Path, ContentHash: e.ContentHash, NodeType: nodeType,
			})
		case strings.HasPrefix(e.Path, "network/"):
			n.DataSources = append(n.DataSources, fmt.Sprintf("Network egress log: %s", entryLabel(e.Path, "network/")))
			n.ProofRefs = append(n.ProofRefs, ProofRef{
				Claim: "effect", Path: e.Path, ContentHash: e.ContentHash, NodeType: nodeType,
			})
		case strings.HasPrefix(e.Path, "diffs/"):
			n.WhatHappened = append(n.WhatHappened, fmt.Sprintf("Workspace change: %s", entryLabel(e.Path, "diffs/")))
			n.ProofRefs = append(n.ProofRefs, ProofRef{
				Claim: "effect", Path: e.Path, ContentHash: e.ContentHash, NodeType: nodeType,
			})
		case strings.HasPrefix(e.Path, "host_evidence/"):
			n.DataSources = append(n.DataSources, fmt.Sprintf("Host evidence: %s", strings.TrimPrefix(e.Path, "host_evidence/")))
			n.ProofRefs = append(n.ProofRefs, ProofRef{
				Claim: "data_source", Path: e.Path, ContentHash: e.ContentHash, NodeType: nodeType,
			})
		case strings.HasPrefix(e.Path, "secrets/"):
			n.DataSources = append(n.DataSources, fmt.Sprintf("Secret access log: %s", entryLabel(e.Path, "secrets/")))
			n.ProofRefs = append(n.ProofRefs, ProofRef{
				Claim: "data_source", Path: e.Path, ContentHash: e.ContentHash, NodeType: nodeType,
			})
		}
	}

	n.NodeTypes = sortedKeys(nodeTypeSet)
	n.Outcome = rollupOutcome(n.Approvals)
	n.Title = buildTitle(n)
	n.Summary = buildSummary(n)

	hash, err := computeNarrativeHash(n)
	if err != nil {
		return nil, fmt.Errorf("compute narrative hash: %w", err)
	}
	n.NarrativeHash = hash
	return n, nil
}

// buildApproval projects one signed policy decision into an ApprovalRecord.
// If the decision content is unavailable or unparseable, the record still cites
// the proof path but reports an UNKNOWN verdict, so the business view never
// silently fabricates an approval that the signed pack does not support.
func buildApproval(e ManifestEntry, content map[string][]byte) ApprovalRecord {
	ar := ApprovalRecord{Verdict: VerdictUnknown, ProofPath: e.Path}
	if content == nil {
		return ar
	}
	raw, ok := content[e.Path]
	if !ok {
		return ar
	}
	var dv decisionView
	if err := json.Unmarshal(raw, &dv); err != nil {
		return ar
	}
	if dv.Verdict != "" {
		ar.Verdict = dv.Verdict
	}
	ar.Subject = dv.SubjectID
	ar.Action = dv.Action
	ar.Resource = dv.Resource
	ar.Reason = dv.Reason
	ar.ReasonCode = dv.ReasonCode
	ar.PolicyRule = firstNonEmpty(dv.PolicyVersion, dv.PolicyContentHash)
	ar.Signed = dv.Signature != ""
	ar.DecidedAt = dv.Timestamp
	return ar
}

// rollupOutcome reduces all approvals to a single gating verdict an approver can
// act on. A single DENY gates the whole action; otherwise any ESCALATE wins over
// ALLOW. With no decisions, the outcome is UNKNOWN (the pack proves no approval).
func rollupOutcome(approvals []ApprovalRecord) string {
	if len(approvals) == 0 {
		return VerdictUnknown
	}
	outcome := "ALLOW"
	sawKnown := false
	for _, a := range approvals {
		switch a.Verdict {
		case "DENY":
			return "DENY"
		case "ESCALATE":
			outcome = "ESCALATE"
			sawKnown = true
		case "ALLOW":
			sawKnown = true
		}
	}
	if !sawKnown {
		return VerdictUnknown
	}
	return outcome
}

func buildTitle(n *BusinessNarrative) string {
	switch n.Outcome {
	case "ALLOW":
		return fmt.Sprintf("Approved action proposed by %s", n.ProposedBy)
	case "DENY":
		return fmt.Sprintf("Denied action proposed by %s", n.ProposedBy)
	case "ESCALATE":
		return fmt.Sprintf("Escalated action proposed by %s", n.ProposedBy)
	default:
		return fmt.Sprintf("Action record proposed by %s", n.ProposedBy)
	}
}

// buildSummary renders the plain-language action story. It is deterministic and
// references only values already projected onto the narrative.
func buildSummary(n *BusinessNarrative) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s proposed intent %s. ", n.ProposedBy, shortID(n.IntentID))

	switch {
	case len(n.Approvals) == 0:
		b.WriteString("No policy decision is recorded in this pack. ")
	case len(n.Approvals) == 1:
		a := n.Approvals[0]
		fmt.Fprintf(&b, "The policy engine returned %s", a.Verdict)
		if a.PolicyRule != "" {
			fmt.Fprintf(&b, " under rule %s", a.PolicyRule)
		}
		if a.Reason != "" {
			fmt.Fprintf(&b, " (%s)", a.Reason)
		}
		b.WriteString(". ")
	default:
		fmt.Fprintf(&b, "The policy engine recorded %d decisions, rolling up to %s. ", len(n.Approvals), n.Outcome)
	}

	if len(n.DataSources) > 0 {
		fmt.Fprintf(&b, "It used %d data/connector record(s). ", len(n.DataSources))
	}
	if len(n.WhatHappened) > 0 {
		fmt.Fprintf(&b, "%d effect(s) were recorded and attested. ", len(n.WhatHappened))
	} else {
		b.WriteString("No effects were recorded. ")
	}
	fmt.Fprintf(&b, "Every statement above is backed by a signed entry in pack %s (manifest %s).",
		n.PackID, shortHash(n.ManifestHash))
	return b.String()
}

// Verify confirms the narrative is a faithful, untampered projection of the
// signed pack. It (1) recomputes the narrative hash, and (2) re-checks that every
// cited proof ref still corresponds to a manifest entry with the same content
// hash. This is the consistency guarantee MIN-442 requires: the business view is
// derived from, and provably consistent with, the signed pack.
func (n *BusinessNarrative) Verify(manifest *Manifest) error {
	if n.NarrativeHash == "" {
		return fmt.Errorf("narrative hash is empty")
	}
	expected, err := computeNarrativeHash(n)
	if err != nil {
		return fmt.Errorf("recompute narrative hash: %w", err)
	}
	if n.NarrativeHash != expected {
		return fmt.Errorf("narrative hash mismatch: stored %s, computed %s", n.NarrativeHash, expected)
	}
	if manifest == nil {
		return fmt.Errorf("manifest is nil")
	}
	if n.ManifestHash != manifest.ManifestHash {
		return fmt.Errorf("narrative bound to manifest %s but verified against %s", n.ManifestHash, manifest.ManifestHash)
	}
	index := make(map[string]string, len(manifest.Entries))
	for _, e := range manifest.Entries {
		index[e.Path] = e.ContentHash
	}
	for _, ref := range n.ProofRefs {
		got, ok := index[ref.Path]
		if !ok {
			return fmt.Errorf("proof ref %q (%s) not present in manifest", ref.Path, ref.Claim)
		}
		if got != ref.ContentHash {
			return fmt.Errorf("proof ref %q content hash mismatch: narrative %s, manifest %s", ref.Path, ref.ContentHash, got)
		}
	}
	return nil
}

// computeNarrativeHash hashes every field except NarrativeHash itself, via JCS.
func computeNarrativeHash(n *BusinessNarrative) (string, error) {
	hashable := struct {
		Version      string           `json:"version"`
		PackID       string           `json:"pack_id"`
		ManifestHash string           `json:"manifest_hash"`
		Title        string           `json:"title"`
		Summary      string           `json:"summary"`
		ProposedBy   string           `json:"proposed_by"`
		IntentID     string           `json:"intent_id"`
		Approvals    []ApprovalRecord `json:"approvals"`
		Outcome      string           `json:"outcome"`
		DataSources  []string         `json:"data_sources"`
		WhatHappened []string         `json:"what_happened"`
		ProofRefs    []ProofRef       `json:"proof_refs"`
		NodeTypes    []string         `json:"node_types"`
		GeneratedAt  time.Time        `json:"generated_at"`
	}{
		Version:      n.Version,
		PackID:       n.PackID,
		ManifestHash: n.ManifestHash,
		Title:        n.Title,
		Summary:      n.Summary,
		ProposedBy:   n.ProposedBy,
		IntentID:     n.IntentID,
		Approvals:    n.Approvals,
		Outcome:      n.Outcome,
		DataSources:  n.DataSources,
		WhatHappened: n.WhatHappened,
		ProofRefs:    n.ProofRefs,
		NodeTypes:    n.NodeTypes,
		GeneratedAt:  n.GeneratedAt,
	}
	data, err := canonicalize.JCS(hashable)
	if err != nil {
		return "", fmt.Errorf("canonicalize narrative: %w", err)
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// --- small projection helpers ---

func actorLabel(did string) string {
	if did == "" {
		return "an unidentified actor"
	}
	return did
}

func entryLabel(path, prefix string) string {
	name := strings.TrimPrefix(path, prefix)
	name = strings.TrimSuffix(name, ".json")
	name = strings.TrimSuffix(name, ".log")
	name = strings.TrimSuffix(name, ".diff")
	return name
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func shortID(id string) string {
	if id == "" {
		return "(none)"
	}
	if len(id) > 16 {
		return id[:16] + "…"
	}
	return id
}

func shortHash(hash string) string {
	h := strings.TrimPrefix(hash, "sha256:")
	if len(h) > 12 {
		return h[:12] + "…"
	}
	return h
}
