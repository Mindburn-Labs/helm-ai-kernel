// quantum_posture: hook decision receipts are signed with the classical
// Ed25519 workstation seed resolved via workstation_signing.go; no
// post-quantum or hybrid primitives are used in this file.

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/actioninbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

// decideHookCall decides every effect of one call before it writes any
// receipt. A call with a denied effect leaves only its denials on disk, so no
// ALLOW receipt stands for a call that never ran. Every receipt of the call
// carries, in its signed bytes, the call's identifier, how many receipts the
// call wrote, the call's verdict and a digest of the tool input.
func decideHookCall(opts hookOptions, payload preToolPayload, classifications []hookClassification, stdout, stderr io.Writer) int {
	decider, err := newHookDecider(opts)
	if err != nil {
		return failHookDecision(opts, payload, classifications[0], err, stdout, stderr)
	}
	call, err := newHookCallBinding(payload, classifications)
	if err != nil {
		return failHookDecision(opts, payload, classifications[0], err, stdout, stderr)
	}
	// The verdict of each effect is settled first; the receipts that are kept
	// are then signed with the outcome of the whole call in them.
	verdicts := make([]string, len(classifications))
	callVerdict := contracts.WorkstationVerdictAllow
	for i, classification := range classifications {
		receipt, err := decider.decide(payload, classification, nil)
		if err != nil {
			return failHookDecision(opts, payload, classification, err, stdout, stderr)
		}
		verdicts[i] = receipt.Verdict
		if receipt.Verdict == contracts.WorkstationVerdictDeny {
			callVerdict = contracts.WorkstationVerdictDeny
		}
	}
	var kept []int
	for i := range classifications {
		if callVerdict == contracts.WorkstationVerdictAllow || verdicts[i] == contracts.WorkstationVerdictDeny {
			kept = append(kept, i)
		}
	}
	binding := call.metadata(len(kept), callVerdict)
	receipts := make([]*contracts.WorkstationPolicyDecisionReceipt, 0, len(kept))
	for _, i := range kept {
		receipt, err := decider.decide(payload, classifications[i], binding)
		if err == nil && receipt.Verdict != verdicts[i] {
			err = fmt.Errorf("decision for %s changed between evaluations", classifications[i].Action)
		}
		if err != nil {
			return failHookDecision(opts, payload, classifications[i], err, stdout, stderr)
		}
		receipts = append(receipts, receipt)
	}
	written := make([]string, 0, len(receipts))
	for k, receipt := range receipts {
		receiptPath, err := hookWriteReceipt("", filepath.Join(opts.DataDir, "receipts", "hooks"), receipt)
		if err != nil {
			// The call is refused. An ALLOW receipt already written for it
			// would stand for a call that never ran, so it is removed, as far
			// as removal works. A denial already written records a refusal
			// that did happen and stays. Either way call_receipts tells a
			// reader the set is incomplete.
			for i, path := range written {
				if receipts[i].Verdict == contracts.WorkstationVerdictAllow {
					_ = os.Remove(path)
				}
			}
			fmt.Fprintf(stderr, "hook pre-tool: write receipt: %v\n", err)
			tripped, run := recordHookDoomLoopOutcome(opts, payload, classifications[kept[k]], true, stderr)
			return emitHookDenyOrFail(stdout, stderr, opts.Client, withDoomLoopSteering(tripped, classifications[kept[k]], run, failClosedSteeringText(
				"HELM denied operation: receipt persistence is unavailable",
				actioninbox.ReasonReceiptPersistence,
				"HELM cannot persist the signed decision receipt, so the operation fails closed.",
				"Do not retry until receipt storage is fixed; check the data directory is writable.",
				"Escalate to the human operator; storage repair is an operator action, not an agent action.",
			)))
		}
		written = append(written, receiptPath)
	}
	if callVerdict == contracts.WorkstationVerdictDeny {
		// The receipts have already been persisted. The breaker only enriches
		// the denial text after repeated identical failures; it never
		// decides the effect or bypasses receipt generation.
		decision, receipt := classifications[kept[0]], receipts[0]
		tripped, run := recordHookDoomLoopOutcome(opts, payload, decision, true, stderr)
		feedback := actioninbox.DenyFeedbackFor(receipt.ReasonCode, receipt.CreatedAt)
		return emitHookDenyOrFail(stdout, stderr, opts.Client, withDoomLoopSteering(tripped, decision, run,
			fmt.Sprintf("HELM denied %s: %s (receipt: %s) %s",
				decision.Reason, receipt.ReasonCode, written[0], actioninbox.RenderSteeringText(feedback))))
	}
	// A fully allowed multi-effect call is successful progress only after
	// every classification has produced a signed, persisted receipt.
	recordHookDoomLoopOutcome(opts, payload, hookClassification{}, false, stderr)
	return 0
}

// failHookDecision refuses a call whose decision could not be made: the
// policy profile or the signer is unavailable. Nothing is written.
func failHookDecision(opts hookOptions, payload preToolPayload, decision hookClassification, err error, stdout, stderr io.Writer) int {
	fmt.Fprintf(stderr, "hook pre-tool: %v\n", err)
	tripped, run := recordHookDoomLoopOutcome(opts, payload, decision, true, stderr)
	if errors.Is(err, errHookPolicyProfile) {
		return emitHookDenyOrFail(stdout, stderr, opts.Client, withDoomLoopSteering(tripped, decision, run, failClosedSteeringText(
			"HELM denied operation: policy profile is unavailable",
			actioninbox.ReasonPolicyProfileUnavailable,
			"HELM cannot load or verify the selected workstation policy profile, so the operation fails closed.",
			"Do not retry until the policy profile and its approved digest are restored.",
			"Escalate to the human operator; policy profile repair is an operator action.",
		)))
	}
	return emitHookDenyOrFail(stdout, stderr, opts.Client, withDoomLoopSteering(tripped, decision, run, failClosedSteeringText(
		"HELM denied operation: local receipt signer is unavailable",
		actioninbox.ReasonSignerUnavailable,
		"HELM cannot sign a local decision receipt, so the operation fails closed.",
		"Do not retry until the signer is fixed. Run helm-ai-kernel doctor or helm-ai-kernel setup, or pass --signing-seed-file.",
		"Escalate to the human operator; signer repair is an operator action, not an agent action.",
	)))
}

// hookCallBinding is what every receipt of one call records about the call:
// an identifier shared by its receipts and a digest of its input.
type hookCallBinding struct {
	id string
	// inputBinding names what inputSHA is the digest of: the canonical tool
	// input (jcs-sha256) or, for a payload over the input limit, the bytes
	// the hook read of it (payload-prefix-sha256), inputBytes of them.
	inputBinding string
	inputSHA     string
	inputBytes   int
}

// Input bindings of a hook receipt.
const (
	hookInputBindingJCS           = "jcs-sha256"
	hookInputBindingPayloadPrefix = "payload-prefix-sha256"
)

func newHookCallBinding(payload preToolPayload, classifications []hookClassification) (hookCallBinding, error) {
	id, err := newHookRandomID("hookcall_")
	if err != nil {
		return hookCallBinding{}, fmt.Errorf("generate hook call ID: %w", err)
	}
	call := hookCallBinding{id: id}
	for _, classification := range classifications {
		if classification.InputTooLarge {
			// The tool input was not read in full; what was read is bound.
			if read := classification.InputRead; read != nil {
				call.inputBinding, call.inputSHA, call.inputBytes = hookInputBindingPayloadPrefix, read.sha256, read.bytes
			}
			return call, nil
		}
	}
	canonicalInput, err := canonicalize.JCS(payload.ToolInput)
	if err != nil {
		return hookCallBinding{}, fmt.Errorf("canonicalize tool input: %w", err)
	}
	call.inputBinding, call.inputSHA = hookInputBindingJCS, canonicalize.ComputeArtifactHash(canonicalInput)
	return call, nil
}

// metadata is the call binding as receipt metadata, for a call that writes
// receipts receipts and whose overall verdict is verdict.
func (c hookCallBinding) metadata(receipts int, verdict string) map[string]string {
	metadata := map[string]string{
		"call_id":       c.id,
		"call_receipts": strconv.Itoa(receipts),
		"call_verdict":  verdict,
	}
	if c.inputBinding != "" {
		metadata["tool_input_binding"] = c.inputBinding
		metadata["tool_input_sha256"] = c.inputSHA
	}
	if c.inputBinding == hookInputBindingPayloadPrefix {
		metadata["tool_input_bytes_read"] = strconv.Itoa(c.inputBytes)
	}
	return metadata
}

// hookDecider holds what every decision of one call is made with: the policy
// profile, its digest and the signing seed, each loaded once per call.
type hookDecider struct {
	opts          hookOptions
	profile       contracts.WorkstationPolicyProfile
	profileDigest string
	seed          []byte
}

func newHookDecider(opts hookOptions) (*hookDecider, error) {
	profile, profileDigest, err := workstation.LoadPolicyProfileFileWithDigest(opts.PolicyProfile)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errHookPolicyProfile, err)
	}
	if strings.TrimSpace(opts.PolicyProfile) != "" {
		approvedDigest := strings.TrimSpace(opts.PolicyProfileSHA256)
		if approvedDigest == "" {
			return nil, fmt.Errorf("%w: custom policy profile has no approved digest", errHookPolicyProfile)
		}
		if approvedDigest != profileDigest {
			return nil, fmt.Errorf("%w: custom policy profile digest does not match installed configuration", errHookPolicyProfile)
		}
	}
	seed, err := resolveWorkstationSigningSeed(opts.DataDir, "", opts.SigningSeedFile)
	if err != nil {
		return nil, fmt.Errorf("load workstation signing key: %w", err)
	}
	return &hookDecider{opts: opts, profile: profile, profileDigest: profileDigest, seed: seed}, nil
}

// Target bindings name what request.target is the SHA-256 of. A network
// receipt's target is the destination, scheme://host[:port]; receipts written
// before this release hashed the whole URL under hookTargetBindingText, so the
// destination has a binding of its own.
const (
	hookTargetBindingText        = "sha256:utf-8"
	hookTargetBindingDestination = "sha256:utf-8:network-destination"
)

// decide signs one decision. callMetadata, when given, binds the receipt to
// its call and is part of the signed bytes.
func (d *hookDecider) decide(payload preToolPayload, classification hookClassification, callMetadata map[string]string) (*contracts.WorkstationPolicyDecisionReceipt, error) {
	effectType, effectMode, defaultAction, defaultTool := workstation.EffectDefaults(classification.Class)
	action := firstNonEmptyString(classification.Action, defaultAction)
	toolID := firstNonEmptyString(classification.ToolID, payload.ToolName, defaultTool)
	targetFingerprint := fingerprintHookTarget(classification.Target)
	requestID, err := newHookRandomID("hook_")
	if err != nil {
		return nil, fmt.Errorf("generate hook request ID: %w", err)
	}
	req := contracts.WorkstationDecisionRequest{
		RequestID:    requestID,
		RunID:        firstNonEmptyString(payload.SessionID, "hook-pre-tool"),
		ActorID:      "agent.local",
		WorkspaceID:  firstNonEmptyString(payload.CWD, "local-workstation"),
		AgentSurface: d.opts.Client,
		ToolID:       toolID,
		Action:       action,
		EffectType:   effectType,
		EffectMode:   effectMode,
		Target:       classification.Target,
		OccurredAt:   hookNow(),
		Metadata: map[string]string{
			"client": d.opts.Client,
			"tool":   payload.ToolName,
		},
	}
	for key, value := range classification.Metadata {
		req.Metadata[key] = value
	}
	persistedMetadata := map[string]string{
		"target_binding": hookTargetBindingText,
	}
	if effectType == contracts.EffectTypeWorkstationNetworkEgress {
		persistedMetadata["target_binding"] = hookTargetBindingDestination
	}
	if d.profileDigest != "" {
		persistedMetadata["policy_profile_sha256"] = d.profileDigest
	}
	if effectType == contracts.EffectTypeWorkstationMCPToolCall && !classification.InputTooLarge {
		canonicalInput, err := canonicalize.JCS(payload.ToolInput)
		if err != nil {
			return nil, fmt.Errorf("canonicalize MCP tool input: %w", err)
		}
		persistedMetadata["mcp_input_binding"] = "jcs-sha256"
		persistedMetadata["mcp_input_sha256"] = canonicalize.ComputeArtifactHash(canonicalInput)
	}
	for key, value := range callMetadata {
		persistedMetadata[key] = value
	}
	return workstation.Decide(d.profile, req, workstation.DecisionOptions{
		SigningSeed:       d.seed,
		PersistedTarget:   targetFingerprint,
		PersistedMetadata: persistedMetadata,
		TrustMaterial:     classification.TrustMaterial,
		InputTooLarge:     classification.InputTooLarge,
	})
}

// newHookRandomID returns prefix followed by 16 random bytes in hex.
func newHookRandomID(prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value[:]), nil
}

func fingerprintHookTarget(target string) string {
	sum := sha256.Sum256([]byte(target))
	return "sha256:" + hex.EncodeToString(sum[:])
}
