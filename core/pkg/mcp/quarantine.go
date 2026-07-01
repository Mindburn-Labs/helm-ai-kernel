package mcp

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type QuarantineState string

const (
	QuarantineDiscovered  QuarantineState = "discovered"
	QuarantineQuarantined QuarantineState = "quarantined"
	QuarantineApproved    QuarantineState = "approved"
	QuarantineRevoked     QuarantineState = "revoked"
	QuarantineExpired     QuarantineState = "expired"
)

type ServerRisk string

const (
	ServerRiskUnknown  ServerRisk = "unknown"
	ServerRiskLow      ServerRisk = "low"
	ServerRiskMedium   ServerRisk = "medium"
	ServerRiskHigh     ServerRisk = "high"
	ServerRiskCritical ServerRisk = "critical"
)

// ServerQuarantineRecord tracks the local-first lifecycle for a discovered MCP
// server. Unknown servers are not executable until an approval ceremony emits a
// receipt and the registry transitions the record to approved.
type ServerQuarantineRecord struct {
	ServerID              string          `json:"server_id"`
	Name                  string          `json:"name,omitempty"`
	Transport             string          `json:"transport,omitempty"`
	Endpoint              string          `json:"endpoint,omitempty"`
	ToolNames             []string        `json:"tool_names,omitempty"`
	ApprovedToolNames     []string        `json:"approved_tool_names,omitempty"`
	ApprovedEffects       []string        `json:"approved_effects,omitempty"`
	Risk                  ServerRisk      `json:"risk"`
	State                 QuarantineState `json:"state"`
	DiscoveredAt          time.Time       `json:"discovered_at"`
	ApprovedAt            time.Time       `json:"approved_at,omitempty"`
	ApprovedBy            string          `json:"approved_by,omitempty"`
	ApprovalReceiptID     string          `json:"approval_receipt_id,omitempty"`
	ApprovalReceiptPath   string          `json:"approval_receipt_path,omitempty"`
	RevokedAt             time.Time       `json:"revoked_at,omitempty"`
	RevocationReceiptPath string          `json:"revocation_receipt_path,omitempty"`
	ExpiresAt             time.Time       `json:"expires_at,omitempty"`
	Reason                string          `json:"reason,omitempty"`
}

type DiscoverServerRequest struct {
	ServerID     string
	Name         string
	Transport    string
	Endpoint     string
	ToolNames    []string
	Risk         ServerRisk
	DiscoveredAt time.Time
	ExpiresAt    time.Time
	Reason       string
}

type ApprovalDecision struct {
	ServerID          string
	ApproverID        string
	ApprovalReceiptID string
	ApprovedAt        time.Time
	ExpiresAt         time.Time
	Reason            string
	ToolNames         []string
	Effects           []string
}

type QuarantineRegistry struct {
	mu      sync.RWMutex
	records map[string]ServerQuarantineRecord
}

func NewQuarantineRegistry() *QuarantineRegistry {
	return &QuarantineRegistry{records: make(map[string]ServerQuarantineRecord)}
}

func (r *QuarantineRegistry) Discover(ctx context.Context, req DiscoverServerRequest) (ServerQuarantineRecord, error) {
	if req.ServerID == "" {
		return ServerQuarantineRecord{}, fmt.Errorf("server id is required")
	}
	now := req.DiscoveredAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	risk := req.Risk
	if risk == "" {
		risk = ServerRiskUnknown
	}
	tools := append([]string(nil), req.ToolNames...)
	sort.Strings(tools)

	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.records[req.ServerID]; ok {
		if existing.State == QuarantineApproved {
			return existing, nil
		}
		existing.ToolNames = tools
		existing.Risk = risk
		existing.Reason = req.Reason
		existing.State = QuarantineQuarantined
		r.records[req.ServerID] = existing
		return existing, nil
	}

	record := ServerQuarantineRecord{
		ServerID:     req.ServerID,
		Name:         req.Name,
		Transport:    req.Transport,
		Endpoint:     req.Endpoint,
		ToolNames:    tools,
		Risk:         risk,
		State:        QuarantineQuarantined,
		DiscoveredAt: now,
		ExpiresAt:    req.ExpiresAt,
		Reason:       req.Reason,
	}
	r.records[req.ServerID] = record
	return record, nil
}

func (r *QuarantineRegistry) Approve(ctx context.Context, decision ApprovalDecision) (ServerQuarantineRecord, error) {
	if decision.ServerID == "" {
		return ServerQuarantineRecord{}, fmt.Errorf("server id is required")
	}
	if decision.ApproverID == "" {
		return ServerQuarantineRecord{}, fmt.Errorf("approver id is required")
	}
	if decision.ApprovalReceiptID == "" {
		return ServerQuarantineRecord{}, fmt.Errorf("approval receipt id is required")
	}
	tools, err := normalizeApprovalScope(decision.ToolNames, "tool")
	if err != nil {
		return ServerQuarantineRecord{}, err
	}
	effects, err := normalizeApprovalScope(decision.Effects, "effect")
	if err != nil {
		return ServerQuarantineRecord{}, err
	}
	if len(effects) == 0 {
		effects = []string{"read"}
	}
	if decision.Reason == "" {
		return ServerQuarantineRecord{}, fmt.Errorf("approval reason is required")
	}
	now := decision.ApprovedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.records[decision.ServerID]
	if !ok {
		return ServerQuarantineRecord{}, fmt.Errorf("server %q is not discovered", decision.ServerID)
	}
	if record.State == QuarantineRevoked {
		return ServerQuarantineRecord{}, fmt.Errorf("server %q is revoked", decision.ServerID)
	}
	record.State = QuarantineApproved
	record.ApprovedAt = now
	record.ApprovedBy = decision.ApproverID
	record.ApprovalReceiptID = decision.ApprovalReceiptID
	record.ExpiresAt = decision.ExpiresAt
	record.Reason = decision.Reason
	record.ApprovedToolNames = tools
	record.ApprovedEffects = effects
	r.records[decision.ServerID] = record
	return record, nil
}

func (r *QuarantineRegistry) Revoke(ctx context.Context, serverID, reason string, at time.Time) (ServerQuarantineRecord, error) {
	if serverID == "" {
		return ServerQuarantineRecord{}, fmt.Errorf("server id is required")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.records[serverID]
	if !ok {
		return ServerQuarantineRecord{}, fmt.Errorf("server %q is not discovered", serverID)
	}
	record.State = QuarantineRevoked
	record.RevokedAt = at
	record.Reason = reason
	r.records[serverID] = record
	return record, nil
}

func (r *QuarantineRegistry) Get(ctx context.Context, serverID string) (ServerQuarantineRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, ok := r.records[serverID]
	return record, ok
}

func (r *QuarantineRegistry) List(ctx context.Context) []ServerQuarantineRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	records := make([]ServerQuarantineRecord, 0, len(r.records))
	for _, record := range r.records {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].ServerID < records[j].ServerID
	})
	return records
}

func (r *QuarantineRegistry) RequireApproved(ctx context.Context, serverID string, now time.Time) error {
	return r.RequireApprovedTool(ctx, serverID, "", "", now)
}

func (r *QuarantineRegistry) RequireApprovedTool(ctx context.Context, serverID, toolName, effect string, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.records[serverID]
	if !ok {
		return fmt.Errorf("server %q is not discovered", serverID)
	}
	if !record.ExpiresAt.IsZero() && now.After(record.ExpiresAt) {
		record.State = QuarantineExpired
		record.Reason = "approval expired"
		r.records[serverID] = record
		return fmt.Errorf("server %q approval expired", serverID)
	}
	if record.State != QuarantineApproved {
		return fmt.Errorf("server %q is %s", serverID, record.State)
	}
	if toolName != "" && !scopeAllows(record.ApprovedToolNames, toolName) {
		return fmt.Errorf("server %q approval does not include tool %q", serverID, toolName)
	}
	if effect != "" && !scopeAllows(record.ApprovedEffects, effect) {
		return fmt.Errorf("server %q approval does not include effect %q", serverID, effect)
	}
	return nil
}

func normalizeApprovalScope(values []string, label string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if value == "*" {
			return nil, fmt.Errorf("%s wildcard approval is not allowed", label)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	if label == "tool" && len(out) == 0 {
		return nil, fmt.Errorf("approval tools are required")
	}
	return out, nil
}

func scopeAllows(allowed []string, value string) bool {
	for _, item := range allowed {
		if item == value {
			return true
		}
	}
	return false
}
