package workstation

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type OperatorView struct {
	Runs              []OperatorRunSummary `json:"runs"`
	DeniedTimeline    []DeniedTimelineItem `json:"denied_timeline"`
	MemoryReviewQueue []MemoryReviewItem   `json:"memory_review_queue"`
	RecurringLoops    []RecurringLoopItem  `json:"recurring_loops"`
}

type OperatorRunSummary struct {
	RunID             string    `json:"run_id"`
	ReceiptID         string    `json:"receipt_id,omitempty"`
	DecisionID        string    `json:"decision_id,omitempty"`
	Goal              string    `json:"goal,omitempty"`
	AgentSurface      string    `json:"agent_surface,omitempty"`
	PolicyProfile     string    `json:"policy_profile"`
	Verdict           string    `json:"verdict,omitempty"`
	ToolActions       int       `json:"tool_actions,omitempty"`
	ChangedFiles      int       `json:"changed_files,omitempty"`
	ValidationResults int       `json:"validation_results,omitempty"`
	MemoryEffects     int       `json:"memory_effects,omitempty"`
	RecurringLoops    int       `json:"recurring_loops,omitempty"`
	DeniedEffects     int       `json:"denied_effects,omitempty"`
	ReceiptHash       string    `json:"receipt_hash"`
	CreatedAt         time.Time `json:"created_at"`
}

type DeniedTimelineItem struct {
	RunID    string    `json:"run_id,omitempty"`
	EffectID string    `json:"effect_id,omitempty"`
	Effect   string    `json:"effect"`
	ToolID   string    `json:"tool_id,omitempty"`
	Action   string    `json:"action,omitempty"`
	Target   string    `json:"target,omitempty"`
	Reason   string    `json:"reason_code"`
	Receipt  string    `json:"receipt"`
	Occurred time.Time `json:"occurred_at"`
	Source   string    `json:"source"`
}

type MemoryReviewItem struct {
	RunID       string    `json:"run_id"`
	EffectID    string    `json:"effect_id"`
	MemoryClass string    `json:"memory_class"`
	DataClass   string    `json:"data_class"`
	Sensitivity string    `json:"sensitivity"`
	TTLDays     uint32    `json:"ttl_days"`
	ReviewState string    `json:"review_state,omitempty"`
	Verdict     string    `json:"verdict"`
	Receipt     string    `json:"receipt"`
	ObservedAt  time.Time `json:"observed_at"`
}

type RecurringLoopItem struct {
	RunID      string    `json:"run_id"`
	EffectID   string    `json:"effect_id"`
	Schedule   string    `json:"schedule"`
	MaxRuntime string    `json:"max_runtime"`
	ToolScope  []string  `json:"tool_scope"`
	ExpiresAt  time.Time `json:"expires_at"`
	Verdict    string    `json:"verdict"`
	Receipt    string    `json:"receipt"`
}

func BuildOperatorView(paths ...string) (OperatorView, error) {
	files, err := expandJSONInputs(paths)
	if err != nil {
		return OperatorView{}, err
	}
	view := OperatorView{}
	for _, file := range files {
		receipt, decision, err := loadWorkstationReceipt(file)
		if err != nil {
			return OperatorView{}, err
		}
		if receipt != nil {
			appendAgentRunReceipt(&view, receipt)
		}
		if decision != nil {
			appendDecisionReceipt(&view, decision)
		}
	}
	sortOperatorView(&view)
	return view, nil
}

func appendAgentRunReceipt(view *OperatorView, receipt *contracts.AgentRunReceipt) {
	view.Runs = append(view.Runs, OperatorRunSummary{
		RunID:             receipt.RunID,
		ReceiptID:         receipt.ReceiptID,
		Goal:              receipt.Goal,
		AgentSurface:      receipt.AgentSurface,
		PolicyProfile:     receipt.PolicyProfile,
		ToolActions:       len(receipt.ToolActions),
		ChangedFiles:      len(receipt.ChangedFiles),
		ValidationResults: len(receipt.ValidationResults),
		MemoryEffects:     len(receipt.MemoryEffects),
		RecurringLoops:    len(receipt.RecurringLoopEffects),
		DeniedEffects:     len(receipt.DeniedEffects),
		ReceiptHash:       receipt.ReceiptHash,
		CreatedAt:         receipt.CreatedAt,
	})
	for _, denied := range receipt.DeniedEffects {
		view.DeniedTimeline = append(view.DeniedTimeline, DeniedTimelineItem{
			RunID:    receipt.RunID,
			EffectID: denied.EffectID,
			Effect:   denied.EffectType,
			ToolID:   denied.ToolID,
			Action:   denied.Action,
			Reason:   denied.ReasonCode,
			Receipt:  receipt.ReceiptID,
			Occurred: denied.OccurredAt,
			Source:   "agent_run_receipt",
		})
	}
	for _, memory := range receipt.MemoryEffects {
		view.MemoryReviewQueue = append(view.MemoryReviewQueue, MemoryReviewItem{
			RunID:       receipt.RunID,
			EffectID:    memory.EffectID,
			MemoryClass: memory.MemoryClass,
			DataClass:   memory.DataClass,
			Sensitivity: memory.Sensitivity,
			TTLDays:     memory.TTLDays,
			ReviewState: memory.ReviewState,
			Verdict:     memory.Verdict,
			Receipt:     receipt.ReceiptID,
			ObservedAt:  receipt.CreatedAt,
		})
	}
	for _, loop := range receipt.RecurringLoopEffects {
		view.RecurringLoops = append(view.RecurringLoops, RecurringLoopItem{
			RunID:      receipt.RunID,
			EffectID:   loop.EffectID,
			Schedule:   loop.Schedule,
			MaxRuntime: loop.MaxRuntime,
			ToolScope:  loop.ToolScope,
			ExpiresAt:  loop.ExpiresAt,
			Verdict:    loop.Verdict,
			Receipt:    receipt.ReceiptID,
		})
	}
}

func appendDecisionReceipt(view *OperatorView, receipt *contracts.WorkstationPolicyDecisionReceipt) {
	view.Runs = append(view.Runs, OperatorRunSummary{
		RunID:         receipt.Request.RunID,
		DecisionID:    receipt.DecisionID,
		AgentSurface:  receipt.Request.AgentSurface,
		PolicyProfile: receipt.PolicyProfile,
		Verdict:       receipt.Verdict,
		DeniedEffects: boolCount(receipt.Verdict == contracts.WorkstationVerdictDeny),
		ReceiptHash:   receipt.ReceiptHash,
		CreatedAt:     receipt.CreatedAt,
	})
	if receipt.Verdict == contracts.WorkstationVerdictDeny {
		view.DeniedTimeline = append(view.DeniedTimeline, DeniedTimelineItem{
			RunID:    receipt.Request.RunID,
			EffectID: receipt.Request.RequestID,
			Effect:   receipt.Request.EffectType,
			ToolID:   receipt.Request.ToolID,
			Action:   receipt.Request.Action,
			Target:   receipt.Request.Target,
			Reason:   receipt.ReasonCode,
			Receipt:  receipt.DecisionID,
			Occurred: receipt.Request.OccurredAt,
			Source:   "policy_decision_receipt",
		})
	}
}

func loadWorkstationReceipt(path string) (*contracts.AgentRunReceipt, *contracts.WorkstationPolicyDecisionReceipt, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var result ImportResult
	if err := json.Unmarshal(data, &result); err == nil && result.Receipt != nil && result.Receipt.ReceiptID != "" {
		return result.Receipt, nil, nil
	}
	var agentReceipt contracts.AgentRunReceipt
	if err := json.Unmarshal(data, &agentReceipt); err == nil && agentReceipt.ReceiptID != "" {
		return &agentReceipt, nil, nil
	}
	var decision contracts.WorkstationPolicyDecisionReceipt
	if err := json.Unmarshal(data, &decision); err == nil && decision.DecisionID != "" {
		return nil, &decision, nil
	}
	return nil, nil, fmt.Errorf("%s: unsupported workstation receipt JSON", path)
}

func expandJSONInputs(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, errors.New("at least one receipt path or directory is required")
	}
	var files []string
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			files = append(files, path)
			continue
		}
		matches, err := filepath.Glob(filepath.Join(path, "*.json"))
		if err != nil {
			return nil, err
		}
		files = append(files, matches...)
	}
	sort.Strings(files)
	return files, nil
}

func sortOperatorView(view *OperatorView) {
	sort.SliceStable(view.Runs, func(i, j int) bool {
		return view.Runs[i].CreatedAt.Before(view.Runs[j].CreatedAt)
	})
	sort.SliceStable(view.DeniedTimeline, func(i, j int) bool {
		return view.DeniedTimeline[i].Occurred.Before(view.DeniedTimeline[j].Occurred)
	})
	sort.SliceStable(view.MemoryReviewQueue, func(i, j int) bool {
		return strings.Compare(view.MemoryReviewQueue[i].EffectID, view.MemoryReviewQueue[j].EffectID) < 0
	})
	sort.SliceStable(view.RecurringLoops, func(i, j int) bool {
		return strings.Compare(view.RecurringLoops[i].EffectID, view.RecurringLoops[j].EffectID) < 0
	})
}

func boolCount(ok bool) int {
	if ok {
		return 1
	}
	return 0
}
