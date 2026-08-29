// quantum_posture: this wiring consumes a classical Ed25519 seed only to key
// the bridge's permit signer; it implements no cryptography itself and claims
// no hybrid or post-quantum protection. Signing and verification are delegated
// to the bridge and core/pkg/crypto, whose posture governs.

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtimeadapters"
	rtmcp "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtimeadapters/mcp"
)

// Environment contract for governed GitHub dispatch on the local MCP runtime.
//
// HELM_GITHUB_TOKEN arms the github.* tools: the runtime constructs the real
// GitHub connector and hands it to a GovernedBridge whose permit signer is
// keyed from the same root seed that signs receipts (data-dir root.key). Unset,
// the tools are not registered and the handler refuses with a structured
// reason — there is no mode where a github tool call is "allowed but not
// dispatched" or dispatched under an unverifiable permit.
const (
	githubEffectsTokenEnv   = "HELM_GITHUB_TOKEN"
	githubEffectsBaseURLEnv = "HELM_GITHUB_API_URL"
	githubEffectsServerID   = "helm-github-effects"
	githubEffectsDefaultURL = "https://api.github.com"
)

// githubEffectsRuntime is the shipped wiring of the governed effects stack:
// a real connector bound to a GovernedBridge that signs every minted
// EffectPermit and verifies the signature at dispatch (PERMIT_UNVERIFIED
// denial on failure). Reads dispatch under single-use permits; writes stay
// fail-closed behind the approval ceremony (no ApprovalStore is configured
// here, so bounded writes always escalate and never dispatch).
type githubEffectsRuntime struct {
	bridge      *rtmcp.GovernedBridge
	otel        *effects.EffectsOTelInstrumentation
	destination string
}

// newGitHubEffectsRuntimeFromEnv builds the governed GitHub dispatch runtime,
// or returns (nil, nil) when HELM_GITHUB_TOKEN is unset. A set token with an
// unusable permit signing seed is a hard error, never a silent downgrade to
// unsigned permits: the bridge's dispatch gate is deliberately a no-op without
// a signer, so arming dispatch without one would make the tamper check
// vacuously pass.
func newGitHubEffectsRuntimeFromEnv(dataDir string) (*githubEffectsRuntime, error) {
	token := strings.TrimSpace(os.Getenv(githubEffectsTokenEnv))
	if token == "" {
		return nil, nil
	}
	seed, err := localPermitSigningSeed(dataDir)
	if err != nil {
		return nil, fmt.Errorf("github effects: %w", err)
	}
	return newGitHubEffectsRuntime(token, strings.TrimSpace(os.Getenv(githubEffectsBaseURLEnv)), seed)
}

// newGitHubEffectsRuntime constructs the governed dispatch runtime from
// explicit inputs. It refuses a seed that yields no permit signer: the bridge's
// dispatch gate is a no-op without a signer, so arming dispatch without one
// would make the permit-tamper check pass vacuously — the one failure mode this
// wiring exists to prevent.
func newGitHubEffectsRuntime(token, baseURL string, seed []byte) (*githubEffectsRuntime, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("github effects: token is required")
	}
	connector := github.NewConnector(github.Config{Token: token, BaseURL: baseURL})
	bridge := rtmcp.NewGovernedBridge(rtmcp.BridgeConfig{
		ServerID:    githubEffectsServerID,
		Profile:     githubEffectsProfile(),
		SigningSeed: seed,
		Connector:   connector,
	})
	if bridge.PermitSigningPublicKey() == "" {
		return nil, fmt.Errorf("github effects: permit signer unavailable; a valid Ed25519 signing seed is required")
	}
	instrumentation, _ := effects.NewEffectsOTelInstrumentation()
	return &githubEffectsRuntime{
		bridge:      bridge,
		otel:        instrumentation,
		destination: githubEffectsDestination(baseURL),
	}, nil
}

func githubEffectsDestination(baseURL string) string {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = githubEffectsDefaultURL
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// localPermitSigningSeed reads the Ed25519 seed the local runtime already uses
// for receipt signing (data-dir root.key, hex-encoded). The bridge reuses it
// so a permit and the decision receipt that authorized it trace to one key.
func localPermitSigningSeed(dataDir string) ([]byte, error) {
	if dataDir == "" {
		dataDir = "data"
	}
	keyPath := filepath.Join(dataDir, "root.key")
	keyHex, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read permit signing seed: %w", err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(keyHex)))
	if err != nil {
		return nil, fmt.Errorf("permit signing seed at %s is not hex: %w", keyPath, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("permit signing seed at %s has %d bytes, need %d", keyPath, len(seed), ed25519.SeedSize)
	}
	return seed, nil
}

// githubEffectsProfile authorizes operate-class MCP tool calls for this
// bridge. Scope below this profile is enforced by the connector's declared
// permit contract (exact tool, exact params) and the permit signature gate;
// above it, the serve-policy Guardian gate stays deny-all unless --policy
// explicitly allows each github tool. This profile never ships as a default
// for anything else.
func githubEffectsProfile() contracts.WorkstationPolicyProfile {
	return contracts.WorkstationPolicyProfile{
		ID:      "workstation.github.effects.v1",
		Mode:    "operate",
		Operate: contracts.WorkstationOperatePolicy{Permissions: []string{contracts.WorkstationPermissionMCPMutate}},
	}
}

// toolRefs returns the catalog entries for the governed GitHub tools. Schemas
// mirror the connector's declared permit scope exactly; the connector refuses
// unknown params by name, so the schemas refuse them too.
func (r *githubEffectsRuntime) toolRefs() []mcppkg.ToolRef {
	repoProp := map[string]any{"type": "string", "description": "owner/name"}
	return []mcppkg.ToolRef{
		{
			Name:        "github.list_prs",
			Title:       "List GitHub pull requests",
			Description: "Lists pull requests in a repository. Dispatches under a signed EffectPermit verified at dispatch.",
			ServerID:    githubEffectsServerID,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"repo":  repoProp,
					"state": map[string]any{"type": "string", "enum": []string{"open", "closed", "all"}},
				},
				"required":             []string{"repo"},
				"additionalProperties": false,
			},
			EffectClass:               "E0",
			RiskTier:                  contracts.RiskTierLow,
			EgressDestinationRequired: true,
			EgressDestination:         r.destination,
		},
		{
			Name:        "github.read_pr",
			Title:       "Read a GitHub pull request",
			Description: "Reads one pull request. Dispatches under a signed EffectPermit verified at dispatch.",
			ServerID:    githubEffectsServerID,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"repo":   repoProp,
					"number": map[string]any{"type": "integer"},
				},
				"required":             []string{"repo", "number"},
				"additionalProperties": false,
			},
			EffectClass:               "E0",
			RiskTier:                  contracts.RiskTierLow,
			EgressDestinationRequired: true,
			EgressDestination:         r.destination,
		},
		{
			Name:        "github.create_issue",
			Title:       "Create a GitHub issue",
			Description: "Bounded write: requires human approval evidence before dispatch; without it the call escalates and nothing is sent.",
			ServerID:    githubEffectsServerID,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"repo":      repoProp,
					"title":     map[string]any{"type": "string"},
					"body":      map[string]any{"type": "string"},
					"labels":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"assignees": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				},
				"required":             []string{"repo", "title"},
				"additionalProperties": false,
			},
			EffectClass:               "E4",
			RiskTier:                  contracts.RiskTierHigh,
			EgressDestinationRequired: true,
			EgressDestination:         r.destination,
		},
		{
			Name:        "github.add_comment",
			Title:       "Comment on a GitHub issue",
			Description: "Bounded write: requires human approval evidence before dispatch; without it the call escalates and nothing is sent.",
			ServerID:    githubEffectsServerID,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"repo":         repoProp,
					"issue_number": map[string]any{"type": "integer"},
					"body":         map[string]any{"type": "string"},
				},
				"required":             []string{"repo", "issue_number", "body"},
				"additionalProperties": false,
			},
			EffectClass:               "E3",
			RiskTier:                  contracts.RiskTierHigh,
			EgressDestinationRequired: true,
			EgressDestination:         r.destination,
		},
	}
}

// execute routes a github.* tool call through the governed bridge and returns
// the outcome as a machine document: verdict, dispatch state, the signed
// permit, and a canonical receipt bundle for offline receipt_verify use.
func (r *githubEffectsRuntime) execute(ctx context.Context, req mcppkg.ToolExecutionRequest) (mcppkg.ToolExecutionResponse, error) {
	effectType := effects.EffectTypeRead
	if strings.HasPrefix(req.ToolName, "github.create_") || req.ToolName == "github.add_comment" {
		effectType = effects.EffectTypeWrite
	}
	started := time.Now()
	ctx, span := r.otel.StartExecution(ctx, effectType, "github")
	succeeded := false
	defer func() {
		r.otel.MarkSuccess(span, succeeded)
		r.otel.RecordExecution(ctx, effectType, "github", succeeded, time.Since(started))
		r.otel.EndSpan(span)
	}()

	adapted := &runtimeadapters.AdaptedRequest{
		RuntimeType:         "mcp",
		ToolName:            req.ToolName,
		Arguments:           req.Arguments,
		PrincipalID:         firstNonEmpty(req.SessionID, "workstation-local"),
		SessionID:           req.SessionID,
		DelegationSessionID: req.DelegationSessionID,
	}
	inputHash, err := canonicalize.CanonicalHash(adapted)
	if err != nil {
		return mcppkg.ToolExecutionResponse{}, fmt.Errorf("github effects: input hash: %w", err)
	}
	outcome := r.bridge.Govern(ctx, adapted, inputHash)

	doc := map[string]any{
		"verdict":           string(outcome.Verdict),
		"dispatch_state":    outcome.DispatchState,
		"decision_id":       outcome.DecisionID,
		"receipt_hash":      outcome.ReceiptHash,
		"input_hash":        inputHash,
		"permit":            outcome.Permit,
		"permit_public_key": r.bridge.PermitSigningPublicKey(),
	}
	if outcome.Verdict == contracts.VerdictAllow {
		if outcome.Permit == nil || outcome.ExecutionReceipt == nil || outcome.ExecutionReceiptHash == "" {
			return mcppkg.ToolExecutionResponse{}, fmt.Errorf("github effects: dispatched call produced no canonical execution receipt")
		}
		if outcome.ExecutionReceipt.EffectID != outcome.Permit.PermitID {
			return mcppkg.ToolExecutionResponse{}, fmt.Errorf("github effects: execution receipt does not bind the dispatched permit")
		}
		doc["result"] = outcome.Output
		doc["output_hash"] = outcome.OutputHash
		doc["execution_receipt_hash"] = outcome.ExecutionReceiptHash
		doc["receipt_bundle"] = map[string]any{
			"receipts": []any{outcome.ExecutionReceipt},
			"permits":  []any{outcome.Permit},
		}
		doc["next_steps"] = []string{
			"save receipt_bundle as bundle.json and run receipt_verify --receipt bundle.json --key-file <caller-trusted-root-key-file>",
			"after verification, require receipts[0].effect_id to equal permits[0].permit_id",
		}
		resp, err := structuredLocalMCPResponse(doc)
		if err != nil {
			return resp, err
		}
		attachGovernedOutcome(&resp, outcome)
		succeeded = true
		return resp, nil
	}

	doc["reason_code"] = outcome.ReasonCode
	doc["reason"] = outcome.Reason
	doc["denied_by"] = "governed-bridge"
	if outcome.Verdict == contracts.VerdictEscalate {
		doc["next_steps"] = []string{"obtain human approval evidence for this exact request, then retry"}
	} else {
		doc["next_steps"] = []string{"do not retry the same call; modify scope or fix the configuration named in reason"}
	}
	resp, err := structuredLocalMCPResponse(doc)
	if err != nil {
		return resp, err
	}
	resp.IsError = true
	return resp, nil
}

// attachGovernedOutcome keeps authoritative dispatch evidence inside the
// runtime response until the shared MCP firewall projects it. The fields on
// ToolExecutionResponse are json:"-" so this bridge never adds receipt or
// approval material to the public MCP response shape.
func attachGovernedOutcome(resp *mcppkg.ToolExecutionResponse, outcome rtmcp.GovernedOutcome) {
	if resp == nil {
		return
	}
	resp.ExecutionReceipt = outcome.ExecutionReceipt
	resp.DispatchState = outcome.DispatchState
	if outcome.Approval == nil {
		return
	}
	resp.ApprovalHash = outcome.Approval.ApprovalHash
	resp.ApproverID = outcome.Approval.ApproverID
	if outcome.Approval.DispatchAdmission != nil {
		resp.DispatchAdmissionExpiry = outcome.Approval.DispatchAdmission.Admission.ExpiresAt
	}
}
