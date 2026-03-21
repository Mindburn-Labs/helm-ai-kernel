// Package actuators — Wallet, Message, FileMovement, Physical actuator contracts.
//
// Per HELM 2030 Spec §5.6:
//
//	Every actuator produces a typed ReceiptFragment. These contracts
//	define the interface and receipt schema for actuators beyond sandbox.
//
// Resolves: GAP-24, GAP-25, GAP-26, GAP-27, GAP-28, GAP-29, GAP-30, GAP-31.
package actuators

import "time"

// ReceiptFragment is defined in sandbox.go and reused by all actuators.
// GAP-31: typed transcripts for all actuators use the existing ReceiptFragment.

// ── GAP-24: Wallet Actuator ──────────────────────────────────────

// WalletOp defines wallet/financial operations.
type WalletOp string

const (
	WalletOpBalance   WalletOp = "BALANCE"
	WalletOpAuthorize WalletOp = "AUTHORIZE"
	WalletOpCapture   WalletOp = "CAPTURE"
	WalletOpRefund    WalletOp = "REFUND"
	WalletOpTransfer  WalletOp = "TRANSFER"
)

// WalletRequest is a governed financial operation request.
type WalletRequest struct {
	Operation   WalletOp `json:"operation"`
	AccountID   string   `json:"account_id"`
	AmountCents int64    `json:"amount_cents,omitempty"`
	Currency    string   `json:"currency,omitempty"`
	Reference   string   `json:"reference"`
	IdempotencyKey string `json:"idempotency_key"`
}

// WalletResponse is the result of a wallet operation.
type WalletResponse struct {
	TransactionID string          `json:"transaction_id"`
	Status        string          `json:"status"`
	BalanceCents  int64           `json:"balance_cents,omitempty"`
	Receipt       ReceiptFragment `json:"receipt"`
}

// WalletActuator is the interface for financial actuators.
type WalletActuator interface {
	Execute(req WalletRequest) (*WalletResponse, error)
}

// ── GAP-25: Procurement Actuator ─────────────────────────────────

// ProcurementActuator handles governed procurement operations.
type ProcurementActuator interface {
	InitiatePurchase(vendorID string, items []PurchaseItem) (*ProcurementResult, error)
	CheckStatus(purchaseID string) (*ProcurementResult, error)
	CancelPurchase(purchaseID, reason string) (*ReceiptFragment, error)
}

// PurchaseItem is an item in a procurement request.
type PurchaseItem struct {
	Description string `json:"description"`
	Quantity    int    `json:"quantity"`
	UnitCostCents int64 `json:"unit_cost_cents"`
	Category    string `json:"category"`
}

// ProcurementResult is the outcome of a procurement operation.
type ProcurementResult struct {
	PurchaseID string          `json:"purchase_id"`
	Status     string          `json:"status"`
	TotalCents int64           `json:"total_cents"`
	Receipt    ReceiptFragment `json:"receipt"`
}

// ── GAP-26: Message Actuator ─────────────────────────────────────

// MessageActuator handles governed messaging operations.
type MessageActuator interface {
	Send(req MessageRequest) (*MessageResult, error)
	Template(templateID string, vars map[string]string) (*MessageRequest, error)
	Schedule(req MessageRequest, at time.Time) (*MessageResult, error)
}

// MessageRequest is a governed messaging request.
type MessageRequest struct {
	Channel     string            `json:"channel"` // "EMAIL", "SMS", "SLACK", "WEBHOOK"
	To          []string          `json:"to"`
	Subject     string            `json:"subject,omitempty"`
	Body        string            `json:"body"`
	TemplateID  string            `json:"template_id,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// MessageResult is the outcome of a messaging operation.
type MessageResult struct {
	MessageID string          `json:"message_id"`
	Status    string          `json:"status"`
	Receipt   ReceiptFragment `json:"receipt"`
}

// ── GAP-27: File/Data Movement Actuator ──────────────────────────

// FileMovementActuator handles governed file and data operations.
type FileMovementActuator interface {
	Copy(src, dst string, opts FileOpts) (*FileResult, error)
	Move(src, dst string, opts FileOpts) (*FileResult, error)
	Archive(paths []string, archivePath string) (*FileResult, error)
	Sync(src, dst string, opts FileOpts) (*FileResult, error)
}

// FileOpts configures file movement.
type FileOpts struct {
	Recursive     bool   `json:"recursive"`
	Overwrite     bool   `json:"overwrite"`
	Checksum      bool   `json:"checksum_verify"`
	EncryptAtRest bool   `json:"encrypt_at_rest"`
	MaxSizeBytes  int64  `json:"max_size_bytes,omitempty"`
}

// FileResult is the outcome of a file movement operation.
type FileResult struct {
	OperationID string          `json:"operation_id"`
	FilesAffected int           `json:"files_affected"`
	BytesMoved  int64           `json:"bytes_moved"`
	Receipt     ReceiptFragment `json:"receipt"`
}

// ── GAP-28, 29, 30: Physical-World Actuators ─────────────────────

// RobotActuator governs physical robot actions.
type RobotActuator interface {
	Execute(cmd RobotCommand) (*RobotResult, error)
	EmergencyStop(robotID, reason string) (*ReceiptFragment, error)
	Status(robotID string) (*RobotStatus, error)
}

// RobotCommand is a governed robot instruction.
type RobotCommand struct {
	RobotID      string            `json:"robot_id"`
	Action       string            `json:"action"`
	Parameters   map[string]string `json:"parameters,omitempty"`
	SafetyLevel  string            `json:"safety_level"` // "STANDARD", "ELEVATED", "CRITICAL"
	TimeoutSecs  int               `json:"timeout_seconds"`
}

// RobotResult is the outcome of a robot operation.
type RobotResult struct {
	CommandID string          `json:"command_id"`
	Status    string          `json:"status"`
	Receipt   ReceiptFragment `json:"receipt"`
}

// RobotStatus reports the current state of a robot.
type RobotStatus struct {
	RobotID    string `json:"robot_id"`
	State      string `json:"state"` // "IDLE", "EXECUTING", "STOPPED", "ERROR"
	BatterPct  int    `json:"battery_pct,omitempty"`
	Location   string `json:"location,omitempty"`
	Interlocks []string `json:"active_interlocks"`
}

// DeviceActuator governs IoT and device actions.
type DeviceActuator interface {
	Send(deviceID string, cmd DeviceCommand) (*ReceiptFragment, error)
	Read(deviceID string, sensor string) (*SensorReading, error)
	Configure(deviceID string, config map[string]string) (*ReceiptFragment, error)
}

// DeviceCommand is a governed device instruction.
type DeviceCommand struct {
	Action    string            `json:"action"`
	Params    map[string]string `json:"params,omitempty"`
	SafeMode  bool              `json:"safe_mode"`
}

// SensorReading is a timestamped sensor value.
type SensorReading struct {
	DeviceID  string    `json:"device_id"`
	Sensor    string    `json:"sensor"`
	Value     float64   `json:"value"`
	Unit      string    `json:"unit"`
	Timestamp time.Time `json:"timestamp"`
}

// FacilityActuator governs physical facility systems.
type FacilityActuator interface {
	Control(facilityID string, system string, cmd FacilityCommand) (*ReceiptFragment, error)
	Status(facilityID string) (*FacilityStatus, error)
	Lockdown(facilityID, reason string) (*ReceiptFragment, error)
}

// FacilityCommand is a governed facility instruction.
type FacilityCommand struct {
	System    string `json:"system"` // "HVAC", "LIGHTING", "ACCESS", "SECURITY"
	Action    string `json:"action"`
	Zone      string `json:"zone,omitempty"`
	SafeMode  bool   `json:"safe_mode"`
}

// FacilityStatus reports the state of a facility.
type FacilityStatus struct {
	FacilityID string            `json:"facility_id"`
	Systems    map[string]string `json:"system_states"` // system → state
	Occupancy  int               `json:"occupancy"`
	Alerts     []string          `json:"alerts,omitempty"`
}

// ── GAP-A10: Browser Actuator ────────────────────────────────────
//
// Per §5.6: "browser actuators MUST support domain constraints,
// pre-submit checkpoints, and receipt capture"
// Per §6.1.9: DOM/screenshot receipt hooks, checkout interception,
// disclosure policy hooks.

// BrowserActuator governs browser-based execution.
type BrowserActuator interface {
	Navigate(req BrowserNavRequest) (*BrowserResult, error)
	Click(pageID, selector string) (*BrowserResult, error)
	Fill(pageID, selector, value string) (*BrowserResult, error)
	Submit(pageID string, checkpoint PreSubmitCheckpoint) (*BrowserResult, error)
	CaptureDOM(pageID string) (*DOMReceipt, error)
	CaptureScreenshot(pageID string) (*ScreenshotCapture, error)
}

// BrowserNavRequest is a governed browser navigation request.
type BrowserNavRequest struct {
	URL             string   `json:"url"`
	AllowedDomains  []string `json:"allowed_domains"`
	BlockedDomains  []string `json:"blocked_domains,omitempty"`
	TimeoutSecs     int      `json:"timeout_seconds"`
	CaptureReceipt  bool     `json:"capture_receipt"`
}

// BrowserResult is the outcome of a browser operation.
type BrowserResult struct {
	PageID     string          `json:"page_id"`
	URL        string          `json:"url"`
	StatusCode int             `json:"status_code"`
	Title      string          `json:"title,omitempty"`
	Receipt    ReceiptFragment `json:"receipt"`
}

// PreSubmitCheckpoint is a policy gate before form submission.
type PreSubmitCheckpoint struct {
	FormID         string            `json:"form_id"`
	FieldValues    map[string]string `json:"field_values"`
	DisclosureOK   bool              `json:"disclosure_acknowledged"`
	CheckoutIntent *CheckoutInterception `json:"checkout_intent,omitempty"`
}

// DOMReceipt captures the DOM state as evidence.
type DOMReceipt struct {
	PageID      string    `json:"page_id"`
	URL         string    `json:"url"`
	DOMHash     string    `json:"dom_hash"`     // SHA-256 of serialized DOM
	ElementCount int      `json:"element_count"`
	CapturedAt  time.Time `json:"captured_at"`
	ContentHash string    `json:"content_hash"`
}

// ScreenshotCapture captures a visual screenshot as evidence.
type ScreenshotCapture struct {
	PageID      string    `json:"page_id"`
	Format      string    `json:"format"` // "PNG", "WEBP"
	Width       int       `json:"width"`
	Height      int       `json:"height"`
	DataHash    string    `json:"data_hash"` // SHA-256 of image bytes
	CapturedAt  time.Time `json:"captured_at"`
}

// CheckoutInterception intercepts e-commerce checkout flows.
type CheckoutInterception struct {
	MerchantID    string `json:"merchant_id"`
	TotalCents    int64  `json:"total_cents"`
	Currency      string `json:"currency"`
	ItemCount     int    `json:"item_count"`
	RequiresApproval bool `json:"requires_approval"`
}

// DisclosurePolicyBinding governs information disclosure in browser contexts.
type DisclosurePolicyBinding struct {
	PolicyID       string   `json:"policy_id"`
	AllowedFields  []string `json:"allowed_fields"`
	BlockedFields  []string `json:"blocked_fields"`
	RequireConsent bool     `json:"require_consent"`
	AuditRequired  bool     `json:"audit_required"`
}

// ── GAP-A11: Identity Actuator ───────────────────────────────────

// IdentityActuator governs identity lifecycle operations.
type IdentityActuator interface {
	CreateIdentity(req IdentityCreateRequest) (*IdentityResult, error)
	VerifyIdentity(identityID string, evidence []byte) (*IdentityResult, error)
	RevokeCredential(identityID, credentialID, reason string) (*ReceiptFragment, error)
	DelegateAuthority(from, to string, scope DelegationScope) (*ReceiptFragment, error)
}

// IdentityCreateRequest is a governed identity creation request.
type IdentityCreateRequest struct {
	ActorType   string            `json:"actor_type"` // "HUMAN", "AGENT", "SERVICE", "DEVICE"
	DisplayName string            `json:"display_name"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	TrustLevel  string            `json:"trust_level"` // "UNTRUSTED", "BASIC", "VERIFIED", "HIGH"
}

// IdentityResult is the outcome of an identity operation.
type IdentityResult struct {
	IdentityID string          `json:"identity_id"`
	Status     string          `json:"status"`
	Receipt    ReceiptFragment `json:"receipt"`
}

// DelegationScope defines the scope of an authority delegation.
type DelegationScope struct {
	Actions     []string  `json:"actions"`
	Resources   []string  `json:"resources"`
	MaxDepth    int       `json:"max_depth"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// ── GAP-A12: Webhook, Queue, and Event Actuators ─────────────────

// WebhookActuator governs outbound webhook delivery.
type WebhookActuator interface {
	Send(req WebhookRequest) (*WebhookResult, error)
	Register(endpoint WebhookEndpoint) (*ReceiptFragment, error)
	Verify(deliveryID string) (*WebhookResult, error)
}

// WebhookRequest is a governed webhook call.
type WebhookRequest struct {
	EndpointURL    string            `json:"endpoint_url"`
	Method         string            `json:"method"` // "POST", "PUT"
	Headers        map[string]string `json:"headers,omitempty"`
	Payload        []byte            `json:"payload"`
	SignatureScheme string           `json:"signature_scheme"` // "HMAC-SHA256", "ED25519"
	TimeoutSecs    int               `json:"timeout_seconds"`
	RetryPolicy    string            `json:"retry_policy"` // "NONE", "LINEAR", "EXPONENTIAL"
}

// WebhookEndpoint is a registered webhook destination.
type WebhookEndpoint struct {
	EndpointID  string   `json:"endpoint_id"`
	URL         string   `json:"url"`
	Events      []string `json:"events"`
	Secret      string   `json:"secret,omitempty"`
	Active      bool     `json:"active"`
}

// WebhookResult is the outcome of a webhook delivery.
type WebhookResult struct {
	DeliveryID   string          `json:"delivery_id"`
	StatusCode   int             `json:"status_code"`
	ResponseHash string          `json:"response_hash,omitempty"`
	Attempts     int             `json:"attempts"`
	Receipt      ReceiptFragment `json:"receipt"`
}

// QueueActuator governs message queue operations.
type QueueActuator interface {
	Publish(queue string, msg QueueMessage) (*QueueResult, error)
	Acknowledge(queue, messageID string) (*ReceiptFragment, error)
}

// QueueMessage is a governed queue message.
type QueueMessage struct {
	MessageID   string            `json:"message_id"`
	ContentType string            `json:"content_type"`
	Payload     []byte            `json:"payload"`
	Headers     map[string]string `json:"headers,omitempty"`
	Priority    int               `json:"priority"`
	DelaySecs   int               `json:"delay_seconds,omitempty"`
}

// QueueResult is the outcome of a queue operation.
type QueueResult struct {
	MessageID string          `json:"message_id"`
	Queue     string          `json:"queue"`
	Status    string          `json:"status"`
	Receipt   ReceiptFragment `json:"receipt"`
}

// EventActuator governs event emission and subscription.
type EventActuator interface {
	Emit(event EventPayload) (*ReceiptFragment, error)
	ListenOnce(topic string, timeoutSecs int) (*EventPayload, error)
}

// EventPayload is a governed event.
type EventPayload struct {
	EventID   string            `json:"event_id"`
	Topic     string            `json:"topic"`
	EventType string            `json:"event_type"`
	Source    string            `json:"source"`
	Data      map[string]any    `json:"data"`
	Timestamp time.Time         `json:"timestamp"`
}

// ── GAP-A13: Human Approval Actuator ─────────────────────────────

// HumanApprovalActuator governs human-in-the-loop approval workflows.
type HumanApprovalActuator interface {
	RequestApproval(req ApprovalRequest) (*ApprovalResult, error)
	CheckStatus(approvalID string) (*ApprovalResult, error)
	EscalateTimeout(approvalID, escalateTo, reason string) (*ReceiptFragment, error)
}

// ApprovalRequest is a governed request for human approval.
type ApprovalRequest struct {
	RequestID    string            `json:"request_id"`
	Requester    string            `json:"requester"`
	Approvers    []string          `json:"approvers"`
	Subject      string            `json:"subject"`
	Description  string            `json:"description"`
	EffectClass  string            `json:"effect_class"`
	AmountCents  int64             `json:"amount_cents,omitempty"`
	Deadline     time.Time         `json:"deadline"`
	EscalationChain []string       `json:"escalation_chain,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// ApprovalResult is the outcome of a human approval request.
type ApprovalResult struct {
	ApprovalID  string          `json:"approval_id"`
	Status      string          `json:"status"` // "PENDING", "APPROVED", "DENIED", "ESCALATED", "EXPIRED"
	ApprovedBy  string          `json:"approved_by,omitempty"`
	DeniedBy    string          `json:"denied_by,omitempty"`
	Rationale   string          `json:"rationale,omitempty"`
	Receipt     ReceiptFragment `json:"receipt"`
}
