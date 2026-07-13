package mcp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ErrApprovalVerificationUnavailable prevents opaque caller-supplied approval
// fields from becoming executable MCP authority.
var ErrApprovalVerificationUnavailable = errors.New("MCP approval verification unavailable")

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
// server. Unknown servers are not executable until a credential-verifying
// approval integration records an approved state.
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

// FailClosedUnverifiedApproval removes opaque persisted approval metadata.
// A credential-verifying integration must own any future transition to
// QuarantineApproved; the local surface registry must never expose or restore
// caller-supplied approval fields as executable authority.
func FailClosedUnverifiedApproval(record ServerQuarantineRecord) ServerQuarantineRecord {
	if record.State != QuarantineApproved {
		return record
	}
	record.State = QuarantineQuarantined
	record.ApprovedToolNames = nil
	record.ApprovedEffects = nil
	record.ApprovedAt = time.Time{}
	record.ApprovedBy = ""
	record.ApprovalReceiptID = ""
	record.ApprovalReceiptPath = ""
	record.ExpiresAt = time.Time{}
	record.Reason = ErrApprovalVerificationUnavailable.Error()
	return record
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

func (r *QuarantineRegistry) Approve(_ context.Context, _ ApprovalDecision) (ServerQuarantineRecord, error) {
	return ServerQuarantineRecord{}, ErrApprovalVerificationUnavailable
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

func scopeAllows(allowed []string, value string) bool {
	for _, item := range allowed {
		if item == value {
			return true
		}
	}
	return false
}
