// Package workforce provides the virtual employee model for HELM-governed
// AI agents. Each virtual employee operates within a bounded execution
// envelope defined by tool scope, budget limits, and manager oversight.
package workforce

import "time"

// ExecutionMode defines how much autonomy a virtual employee has.
type ExecutionMode string

const (
	ModeAutonomous ExecutionMode = "AUTONOMOUS"
	ModeSupervised ExecutionMode = "SUPERVISED"
	ModeManual     ExecutionMode = "MANUAL"
)

// VirtualEmployee represents an AI agent operating under HELM governance.
type VirtualEmployee struct {
	EmployeeID     string          `json:"employee_id"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	ManagerID      string          `json:"manager_id"`
	RoleID         string          `json:"role_id"`
	ToolScope      ToolScope       `json:"tool_scope"`
	BudgetEnvelope BudgetEnvelope  `json:"budget_envelope"`
	ExecutionMode  ExecutionMode   `json:"execution_mode"`
	Presence       []PresenceBinding `json:"presence,omitempty"`
	Status         string          `json:"status"` // ACTIVE, SUSPENDED, TERMINATED
	CreatedAt      time.Time       `json:"created_at"`
	ContentHash    string          `json:"content_hash"`
}

// ToolScope restricts which tools a virtual employee may invoke.
type ToolScope struct {
	AllowedTools         []string `json:"allowed_tools,omitempty"`
	BlockedTools         []string `json:"blocked_tools,omitempty"`
	MaxRiskClass         string   `json:"max_risk_class"`
	RequiresApprovalAbove string  `json:"requires_approval_above"`
}

// BudgetEnvelope defines spend limits for a virtual employee.
type BudgetEnvelope struct {
	TenantID       string `json:"tenant_id"`
	DailyCentsCap  int64  `json:"daily_cents_cap"`
	MonthlyCentsCap int64 `json:"monthly_cents_cap"`
	ToolCallCap    int64  `json:"tool_call_cap"`
}

// PresenceBinding maps a virtual employee to a communication channel.
type PresenceBinding struct {
	ChannelType string `json:"channel_type"`
	ChannelID   string `json:"channel_id"`
	DisplayName string `json:"display_name"`
	Active      bool   `json:"active"`
}

// ManagerAssignment records the assignment of a manager to an employee.
type ManagerAssignment struct {
	AssignmentID string    `json:"assignment_id"`
	EmployeeID   string    `json:"employee_id"`
	ManagerID    string    `json:"manager_id"`
	AssignedAt   time.Time `json:"assigned_at"`
	Scope        string    `json:"scope"` // full, approval_only, oversight
}
