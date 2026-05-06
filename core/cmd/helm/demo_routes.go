package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/api"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
)

const demoPolicyID = "agent_tool_call_boundary"
const demoSandboxLabel = "HELM OSS public sandbox - no external side effects"

type demoActionMode string

const (
	demoModeAllow    demoActionMode = "allow"
	demoModeDeny     demoActionMode = "deny"
	demoModeEscalate demoActionMode = "escalate"
)

type demoAction struct {
	ID          string
	Label       string
	Description string
	Action      string
	Resource    string
	Mode        demoActionMode
	RiskTier    string
}

type demoRunRequest struct {
	ActionID string         `json:"action_id"`
	PolicyID string         `json:"policy_id"`
	Args     map[string]any `json:"args,omitempty"`
}

type demoVerifyRequest struct {
	Receipt contracts.Receipt `json:"receipt"`
}

type demoTamperRequest struct {
	Receipt  contracts.Receipt `json:"receipt"`
	Mutation string            `json:"mutation"`
}

var demoActions = map[string]demoAction{
	"read_ticket": {
		ID: "read_ticket", Label: "Read support ticket", Description: "Read-only support context.", Action: "demo.read_ticket", Resource: "ticket:T-1042", Mode: demoModeAllow, RiskTier: "T1",
	},
	"draft_reply": {
		ID: "draft_reply", Label: "Draft customer reply", Description: "Draft-only work with no external send.", Action: "demo.draft_reply", Resource: "ticket:T-1042/draft", Mode: demoModeAllow, RiskTier: "T1",
	},
	"small_refund": {
		ID: "small_refund", Label: "Small refund", Description: "Low-risk write within sample policy ceiling.", Action: "demo.small_refund", Resource: "refund:25-usd", Mode: demoModeAllow, RiskTier: "T2",
	},
	"large_refund": {
		ID: "large_refund", Label: "Large refund", Description: "High-value customer-impacting write.", Action: "demo.large_refund", Resource: "refund:2500-usd", Mode: demoModeEscalate, RiskTier: "T3",
	},
	"dangerous_shell": {
		ID: "dangerous_shell", Label: "Dangerous shell command", Description: "Destructive command request.", Action: "demo.dangerous_shell", Resource: "shell:rm-rf", Mode: demoModeDeny, RiskTier: "T3",
	},
	"export_customer_list": {
		ID: "export_customer_list", Label: "Export customer list", Description: "Sensitive bulk data egress.", Action: "demo.export_customer_list", Resource: "customer-list:all", Mode: demoModeDeny, RiskTier: "T3",
	},
	"modify_policy": {
		ID: "modify_policy", Label: "Modify policy", Description: "Policy/IAM-like authority change.", Action: "demo.modify_policy", Resource: "policy:agent_tool_call_boundary", Mode: demoModeEscalate, RiskTier: "T3",
	},
}

func registerDemoRoutes(mux *http.ServeMux, svc *Services) {
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeJSON(w, map[string]any{
			"version":          displayVersion(),
			"commit":           displayCommit(),
			"helm_oss_version": displayVersion(),
			"status":           "ok",
			"build_time":       displayBuildTime(),
			"git_sha":          displayCommit(),
			"deployment_id":    envOrDefault("HELM_DEPLOYMENT_ID", "local"),
		})
	})

	mux.HandleFunc("/api/demo/run", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req demoRunRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16_384)).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid JSON body")
			return
		}
		if req.PolicyID == "" {
			req.PolicyID = demoPolicyID
		}
		if req.PolicyID != demoPolicyID {
			api.WriteError(w, http.StatusBadRequest, "Unknown demo policy", "policy_id must be agent_tool_call_boundary")
			return
		}
		action, ok := demoActions[req.ActionID]
		if !ok {
			api.WriteError(w, http.StatusBadRequest, "Unknown demo action", "action_id is not in the Agent Tool Call Boundary scenario")
			return
		}
		if svc == nil || svc.ReceiptStore == nil || svc.ReceiptSigner == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Demo unavailable", "receipt store or signer not initialized")
			return
		}

		guard, err := demoGuardian(svc, action)
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		context := demoDecisionContext(action, req.Args)
		decision, err := guard.EvaluateDecision(r.Context(), guardian.DecisionRequest{
			Principal: "demo.agent@helm-oss",
			Action:    action.Action,
			Resource:  action.Resource,
			Context:   context,
		})
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		bodyBytes, _ := json.Marshal(map[string]any{"action_id": action.ID, "policy_id": req.PolicyID, "args": req.Args})
		if err := persistDecisionReceipt(r.Context(), svc, decision, "demo.agent@helm-oss", bodyBytes, map[string]any{
			"source":                 "public.demo",
			"policy_id":              demoPolicyID,
			"action_id":              action.ID,
			"action_label":           action.Label,
			"sandbox_label":          demoSandboxLabel,
			"side_effect_dispatched": false,
			"truth_label":            "OSS-BACKED SANDBOX SAMPLE POLICY",
		}); err != nil {
			api.WriteInternal(w, err)
			return
		}
		receipt, err := svc.ReceiptStore.GetByReceiptID(r.Context(), "rcpt_"+decision.ID)
		if err != nil {
			api.WriteInternal(w, fmt.Errorf("load persisted demo receipt: %w", err))
			return
		}
		receiptHash, _ := contracts.ReceiptChainHash(receipt)
		writeJSON(w, map[string]any{
			"action_id":         action.ID,
			"selected_action":   action.Label,
			"active_policy":     demoPolicySnapshot(),
			"verdict":           decision.Verdict,
			"reason_code":       publicReasonCode(decision),
			"reason":            decision.Reason,
			"receipt":           receipt,
			"proof_refs":        map[string]string{"decision_id": decision.ID, "receipt_id": receipt.ReceiptID, "receipt_hash": receiptHash},
			"verification_hint": "/api/demo/verify",
			"sandbox_label":     demoSandboxLabel,
			"helm_oss_version":  displayVersion(),
		})
	})

	mux.HandleFunc("/api/demo/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req demoVerifyRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16_384)).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid JSON body")
			return
		}
		result := verifyDemoReceipt(svc, &req.Receipt)
		writeJSON(w, result)
	})

	mux.HandleFunc("/api/demo/tamper", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req demoTamperRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16_384)).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid JSON body")
			return
		}
		originalHash, _ := contracts.ReceiptChainHash(&req.Receipt)
		tampered := req.Receipt
		switch strings.TrimSpace(req.Mutation) {
		case "", "flip_verdict", "flip_status":
			if tampered.Status == string(contracts.VerdictDeny) {
				tampered.Status = string(contracts.VerdictAllow)
			} else {
				tampered.Status = string(contracts.VerdictDeny)
			}
		case "change_action":
			tampered.EffectID = tampered.EffectID + ".tampered"
		default:
			api.WriteError(w, http.StatusBadRequest, "Unknown tamper mutation", "supported mutations: flip_verdict, change_action")
			return
		}
		result := verifyDemoReceipt(svc, &tampered)
		tamperedHash, _ := contracts.ReceiptChainHash(&tampered)
		result["original_hash"] = originalHash
		result["tampered_hash"] = tamperedHash
		writeJSON(w, result)
	})
}

func demoGuardian(svc *Services, action demoAction) (*guardian.Guardian, error) {
	graph := prg.NewGraph()
	for _, item := range demoActions {
		set := prg.RequirementSet{ID: demoPolicyID + ":" + item.ID, Logic: prg.AND}
		if item.Mode == demoModeDeny {
			set.Requirements = []prg.Requirement{{
				ID:          set.ID + ":deny",
				Description: "Sample policy blocks this risk class.",
				Expression:  "false",
			}}
		}
		if err := graph.AddRule(item.Action, set); err != nil {
			return nil, err
		}
	}
	opts := []guardian.GuardianOption{}
	if action.Mode == demoModeEscalate {
		clock := demoClock{}
		tg := guardian.NewTemporalGuardian(guardian.EscalationPolicy{
			WindowSize: time.Second,
			Thresholds: []guardian.EscalationThreshold{{
				Level:        guardian.ResponseInterrupt,
				MaxRate:      0,
				SustainedFor: 0,
			}},
		}, clock)
		_ = tg.Evaluate(context.Background())
		opts = append(opts, guardian.WithTemporalGuardian(tg))
	}
	return guardian.NewGuardian(svc.ReceiptSigner, graph, nil, opts...), nil
}

type demoClock struct{}

func (demoClock) Now() time.Time { return time.Now().UTC() }

func demoDecisionContext(action demoAction, args map[string]any) map[string]any {
	if args == nil {
		args = map[string]any{}
	}
	return map[string]any{
		"policy_id":              demoPolicyID,
		"sample_policy":          true,
		"risk_tier":              action.RiskTier,
		"sandbox_label":          demoSandboxLabel,
		"connector_contract":     "demo.connector.v1",
		"mcp_approval_state":     "sample",
		"side_effect_dispatched": false,
		"args":                   args,
	}
}

func demoPolicySnapshot() map[string]any {
	return map[string]any{
		"policy_id": demoPolicyID,
		"labels":    []string{"LIVE", "OSS-BACKED", "SANDBOX", "SAMPLE POLICY"},
		"rules": []map[string]string{
			{"action_id": "read_ticket", "verdict": "ALLOW", "reason": "read-only context"},
			{"action_id": "draft_reply", "verdict": "ALLOW", "reason": "draft-only work"},
			{"action_id": "small_refund", "verdict": "ALLOW", "reason": "within sample ceiling"},
			{"action_id": "large_refund", "verdict": "ESCALATE", "reason": "high-value customer impact"},
			{"action_id": "dangerous_shell", "verdict": "DENY", "reason": "destructive command"},
			{"action_id": "export_customer_list", "verdict": "DENY", "reason": "sensitive data egress"},
			{"action_id": "modify_policy", "verdict": "ESCALATE", "reason": "authority change"},
		},
	}
}

func publicReasonCode(decision *contracts.DecisionRecord) string {
	if decision == nil {
		return "UNKNOWN"
	}
	if decision.ReasonCode != "" {
		return decision.ReasonCode
	}
	if decision.Verdict == string(contracts.VerdictAllow) {
		return "ALLOW_BY_SAMPLE_POLICY"
	}
	return "UNSPECIFIED"
}

func verifyDemoReceipt(svc *Services, receipt *contracts.Receipt) map[string]any {
	receiptHash, hashErr := contracts.ReceiptChainHash(receipt)
	if svc == nil || svc.ReceiptSigner == nil {
		return map[string]any{"valid": false, "reason": "receipt signer unavailable", "receipt_hash": receiptHash}
	}
	verifier, ok := svc.ReceiptSigner.(interface {
		VerifyReceipt(*contracts.Receipt) (bool, error)
	})
	if !ok {
		return map[string]any{"valid": false, "reason": "receipt signer cannot verify receipts", "receipt_hash": receiptHash}
	}
	valid, verifyErr := verifier.VerifyReceipt(receipt)
	reason := "signature verified"
	if hashErr != nil {
		valid = false
		reason = "receipt hash failed: " + hashErr.Error()
	} else if verifyErr != nil {
		valid = false
		reason = "signature verification failed: " + verifyErr.Error()
	} else if !valid {
		reason = "signature verification failed"
	}
	return map[string]any{
		"valid":           valid,
		"reason":          reason,
		"verified_fields": []string{"receipt_id", "decision_id", "effect_id", "status", "output_hash", "prev_hash", "lamport_clock", "args_hash", "signature"},
		"receipt_hash":    receiptHash,
	}
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}
