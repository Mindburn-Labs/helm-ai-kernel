package runtimeadapters

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
)

const (
	BrowserSplitRuntimeType = "browser_split"

	ReasonCognitiveFirewallDomainDeny        = "COGNITIVE_FIREWALL_DOMAIN_DENY"
	ReasonCognitiveFirewallInvalidURL        = "COGNITIVE_FIREWALL_INVALID_URL"
	ReasonCognitiveFirewallSentinelDeny      = "COGNITIVE_FIREWALL_SENTINEL_DENY"
	ReasonCognitiveFirewallPlannerRefMissing = "COGNITIVE_FIREWALL_PLANNER_REF_REQUIRED"
)

// BrowserSplitPolicy configures the split-compute guard for browser agents.
type BrowserSplitPolicy struct {
	AllowedDomains                  []string `json:"allowed_domains,omitempty"`
	BlockedDomains                  []string `json:"blocked_domains,omitempty"`
	MaxSentinelRisk                 int      `json:"max_sentinel_risk"`
	RequirePlannerRefForSideEffects bool     `json:"require_planner_ref_for_side_effects"`
}

// BrowserSplitObservation is the local Sentinel output. It contains hashes and
// risk signals, not full page contents, so raw browser data can stay client-side.
type BrowserSplitObservation struct {
	URL              string   `json:"url"`
	DOMHash          string   `json:"dom_hash,omitempty"`
	VisualTextHash   string   `json:"visual_text_hash,omitempty"`
	SentinelRisk     int      `json:"sentinel_risk"`
	SentinelFindings []string `json:"sentinel_findings,omitempty"`
}

// BrowserSplitPlan is the cloud planner output that the deterministic guard
// checks before any side-effecting browser tool is allowed.
type BrowserSplitPlan struct {
	ToolName    string         `json:"tool_name"`
	Arguments   map[string]any `json:"arguments,omitempty"`
	PlannerRef  string         `json:"planner_ref,omitempty"`
	SideEffect  bool           `json:"side_effect"`
	Destination string         `json:"destination,omitempty"`
}

// BrowserSplitRequest binds the local Sentinel output to the planner's tool
// intent at the deterministic Guard boundary.
type BrowserSplitRequest struct {
	PrincipalID string                  `json:"principal_id"`
	SessionID   string                  `json:"session_id,omitempty"`
	Observation BrowserSplitObservation `json:"observation"`
	Plan        BrowserSplitPlan        `json:"plan"`
}

// BrowserSplitAdapter prototypes the Cognitive Firewall split-compute pattern:
// local Sentinel signals + planner intent + deterministic side-effect guard.
type BrowserSplitAdapter struct {
	graph  *proofgraph.Graph
	policy BrowserSplitPolicy
	logger *slog.Logger
}

type BrowserSplitConfig struct {
	Graph  *proofgraph.Graph
	Policy BrowserSplitPolicy
	Logger *slog.Logger
}

// NewBrowserSplitAdapter creates a browser split-compute adapter.
func NewBrowserSplitAdapter(cfg BrowserSplitConfig) (*BrowserSplitAdapter, error) {
	if cfg.Graph == nil {
		return nil, fmt.Errorf("runtimeadapters/browser_split: ProofGraph is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &BrowserSplitAdapter{
		graph:  cfg.Graph,
		policy: withBrowserSplitDefaults(cfg.Policy),
		logger: logger,
	}, nil
}

func (a *BrowserSplitAdapter) ID() string {
	return "browser-split-adapter-v1"
}

// Intercept adapts a generic browser_split request into the structured
// split-compute guard. Metadata keys:
//   - browser.url
//   - browser.dom_hash
//   - browser.visual_text_hash
//   - browser.sentinel_risk
//   - browser.sentinel_findings_csv
//   - browser.planner_ref
//   - browser.side_effect
//   - browser.destination
func (a *BrowserSplitAdapter) Intercept(ctx context.Context, req *AdaptedRequest) (*AdaptedResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("runtimeadapters/browser_split: nil request")
	}

	meta := req.Metadata
	if meta == nil {
		meta = map[string]string{}
	}

	splitReq := &BrowserSplitRequest{
		PrincipalID: req.PrincipalID,
		SessionID:   req.SessionID,
		Observation: BrowserSplitObservation{
			URL:              firstNonEmpty(meta["browser.url"], stringArg(req.Arguments, "url")),
			DOMHash:          meta["browser.dom_hash"],
			VisualTextHash:   meta["browser.visual_text_hash"],
			SentinelRisk:     intMeta(meta, "browser.sentinel_risk"),
			SentinelFindings: csvMeta(meta, "browser.sentinel_findings_csv"),
		},
		Plan: BrowserSplitPlan{
			ToolName:    req.ToolName,
			Arguments:   req.Arguments,
			PlannerRef:  meta["browser.planner_ref"],
			SideEffect:  boolMeta(meta, "browser.side_effect"),
			Destination: firstNonEmpty(meta["browser.destination"], stringArg(req.Arguments, "destination")),
		},
	}

	return a.InterceptBrowserAction(ctx, splitReq)
}

// InterceptBrowserAction evaluates the structured split-compute browser action.
func (a *BrowserSplitAdapter) InterceptBrowserAction(ctx context.Context, req *BrowserSplitRequest) (*AdaptedResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("runtimeadapters/browser_split: nil request")
	}
	if req.Plan.ToolName == "" {
		return nil, fmt.Errorf("runtimeadapters/browser_split: missing tool name")
	}

	inputHash, err := canonicalize.CanonicalHash(req)
	if err != nil {
		return nil, fmt.Errorf("runtimeadapters/browser_split: input hash failed: %w", err)
	}

	nodeHash, err := a.appendProofNode(req, inputHash)
	if err != nil {
		return nil, err
	}

	if deny := a.evaluatePolicy(req); deny != nil {
		a.logger.WarnContext(ctx, "browser split-compute action denied",
			"tool", req.Plan.ToolName,
			"principal", req.PrincipalID,
			"reason", deny.Code,
			"proof_node", nodeHash,
		)
		return &AdaptedResponse{
			Allowed:        false,
			DenyReason:     deny,
			ReceiptID:      nodeHash,
			DecisionID:     nodeHash,
			ProofGraphNode: nodeHash,
		}, nil
	}

	a.logger.InfoContext(ctx, "browser split-compute action allowed",
		"tool", req.Plan.ToolName,
		"principal", req.PrincipalID,
		"proof_node", nodeHash,
	)
	return &AdaptedResponse{
		Allowed:        true,
		Result:         map[string]any{"planner_ref": req.Plan.PlannerRef, "tool_name": req.Plan.ToolName},
		ReceiptID:      nodeHash,
		DecisionID:     nodeHash,
		ProofGraphNode: nodeHash,
	}, nil
}

func (a *BrowserSplitAdapter) appendProofNode(req *BrowserSplitRequest, inputHash string) (string, error) {
	payload, err := json.Marshal(browserSplitProofPayload{
		AdapterID:   a.ID(),
		RuntimeType: BrowserSplitRuntimeType,
		InputHash:   inputHash,
		Request:     req,
		Policy:      a.policy,
	})
	if err != nil {
		return "", fmt.Errorf("runtimeadapters/browser_split: payload marshal failed: %w", err)
	}

	node, err := a.graph.Append(proofgraph.NodeTypeIntent, payload, req.PrincipalID, 0)
	if err != nil {
		return "", fmt.Errorf("runtimeadapters/browser_split: proofgraph append failed: %w", err)
	}
	return node.NodeHash, nil
}

func (a *BrowserSplitAdapter) evaluatePolicy(req *BrowserSplitRequest) *DenyReason {
	destination := firstNonEmpty(req.Plan.Destination, req.Observation.URL)
	if destination != "" {
		allowed, invalid := domainAllowed(destination, a.policy)
		if invalid {
			return &DenyReason{
				Code:       ReasonCognitiveFirewallInvalidURL,
				Message:    "browser split-compute guard received an invalid destination URL",
				Actionable: "modify_scope",
			}
		}
		if !allowed {
			return &DenyReason{
				Code:       ReasonCognitiveFirewallDomainDeny,
				Message:    "browser split-compute guard blocked a destination outside policy scope",
				Actionable: "modify_scope",
			}
		}
	}

	if req.Plan.SideEffect && req.Observation.SentinelRisk >= a.policy.MaxSentinelRisk {
		return &DenyReason{
			Code:       ReasonCognitiveFirewallSentinelDeny,
			Message:    "local Sentinel risk is too high for a side-effecting browser action",
			Actionable: "request_approval",
		}
	}

	if req.Plan.SideEffect && a.policy.RequirePlannerRefForSideEffects && req.Plan.PlannerRef == "" {
		return &DenyReason{
			Code:       ReasonCognitiveFirewallPlannerRefMissing,
			Message:    "side-effecting browser actions require a planner reference",
			Actionable: "request_approval",
		}
	}

	return nil
}

func withBrowserSplitDefaults(policy BrowserSplitPolicy) BrowserSplitPolicy {
	if policy.MaxSentinelRisk <= 0 {
		policy.MaxSentinelRisk = 70
	}
	if !policy.RequirePlannerRefForSideEffects {
		policy.RequirePlannerRefForSideEffects = true
	}
	return policy
}

func domainAllowed(raw string, policy BrowserSplitPolicy) (allowed bool, invalid bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return false, true
	}
	host := strings.ToLower(parsed.Hostname())
	if domainMatches(host, policy.BlockedDomains) {
		return false, false
	}
	if len(policy.AllowedDomains) == 0 {
		return true, false
	}
	return domainMatches(host, policy.AllowedDomains), false
}

func domainMatches(host string, domains []string) bool {
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func stringArg(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	value, _ := args[key].(string)
	return value
}

func intMeta(meta map[string]string, key string) int {
	value, err := strconv.Atoi(strings.TrimSpace(meta[key]))
	if err != nil {
		return 0
	}
	return value
}

func boolMeta(meta map[string]string, key string) bool {
	value, err := strconv.ParseBool(strings.TrimSpace(meta[key]))
	if err != nil {
		return false
	}
	return value
}

func csvMeta(meta map[string]string, key string) []string {
	raw := strings.TrimSpace(meta[key])
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

type browserSplitProofPayload struct {
	AdapterID   string               `json:"adapter_id"`
	RuntimeType string               `json:"runtime_type"`
	InputHash   string               `json:"input_hash"`
	Request     *BrowserSplitRequest `json:"request"`
	Policy      BrowserSplitPolicy   `json:"policy"`
}
