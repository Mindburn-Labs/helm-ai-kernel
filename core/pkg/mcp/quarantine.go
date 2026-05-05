package mcp

import (
	"context"
	"fmt"
	"sort"
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
	ServerID          string          `json:"server_id"`
	Name              string          `json:"name,omitempty"`
	Transport         string          `json:"transport,omitempty"`
	Endpoint          string          `json:"endpoint,omitempty"`
	ToolNames         []string        `json:"tool_names,omitempty"`
	Risk              ServerRisk      `json:"risk"`
	State             QuarantineState `json:"state"`
	DiscoveredAt      time.Time       `json:"discovered_at"`
	ApprovedAt        time.Time       `json:"approved_at,omitempty"`
	ApprovedBy        string          `json:"approved_by,omitempty"`
	ApprovalReceiptID string          `json:"approval_receipt_id,omitempty"`
	RevokedAt         time.Time       `json:"revoked_at,omitempty"`
	ExpiresAt         time.Time       `json:"expires_at,omitempty"`
	Reason            string          `json:"reason,omitempty"`
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
	return nil
}
