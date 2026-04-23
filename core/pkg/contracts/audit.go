// Receipts and Audit Types
package contracts

import "time"

// AuditEntry records a security or operational event.
type AuditEntry struct {
	ID        string    `json:"id"`
	Action    string    `json:"action"`
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor,omitempty"`
	Details   string    `json:"details,omitempty"`
}
