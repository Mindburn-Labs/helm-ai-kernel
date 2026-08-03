package actioninbox

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// InMemoryInboxStore implements Inbox using an in-memory map.
// Thread-safe via RWMutex.
type InMemoryInboxStore struct {
	mu                sync.RWMutex
	items             map[string]*InboxItem
	cascadeIdentities map[string]string
}

// NewInMemoryInboxStore creates a new in-memory inbox store.
func NewInMemoryInboxStore() *InMemoryInboxStore {
	return &InMemoryInboxStore{
		items:             make(map[string]*InboxItem),
		cascadeIdentities: make(map[string]string),
	}
}

func canonicalContentHash(item *InboxItem) (string, error) {
	if item == nil {
		return "", fmt.Errorf("actioninbox: item must not be nil")
	}
	contextWithoutSession := make(map[string]any, len(item.Context))
	for key, value := range item.Context {
		if key != SessionContextKey {
			contextWithoutSession[key] = value
		}
	}
	identity, err := canonicalize.CanonicalHash(struct {
		ProposalID  string         `json:"proposal_id"`
		Title       string         `json:"title"`
		Summary     string         `json:"summary"`
		RiskClass   string         `json:"risk_class"`
		EffectTypes []string       `json:"effect_types"`
		Context     map[string]any `json:"context"`
	}{
		ProposalID:  item.ProposalID,
		Title:       item.Title,
		Summary:     item.Summary,
		RiskClass:   item.RiskClass,
		EffectTypes: item.EffectTypes,
		Context:     contextWithoutSession,
	})
	if err != nil {
		return "", fmt.Errorf("actioninbox: canonicalize content identity: %w", err)
	}
	return identity, nil
}

func cascadeIdentity(item *InboxItem, contentIdentity string) string {
	if item == nil || contentIdentity == "" || item.SessionID() == "" || !item.HasApprovalDomain() {
		return ""
	}
	identity, err := canonicalize.CanonicalHash(struct {
		ContentHash string        `json:"content_hash"`
		SessionID   string        `json:"session_id"`
		EmployeeID  string        `json:"employee_id"`
		ManagerID   string        `json:"manager_id"`
		Route       ApprovalRoute `json:"route"`
	}{
		ContentHash: contentIdentity,
		SessionID:   item.SessionID(),
		EmployeeID:  item.EmployeeID,
		ManagerID:   item.ManagerID,
		Route:       item.Route,
	})
	if err != nil {
		return ""
	}
	return identity
}

// copyItem deep-copies an inbox item: the structured denial record, the
// context map (including nested map/slice values), the approval-route
// approver slices, the effect-type slice, and the escalation record.
// Anything less would let callers mutate stored approval evidence —
// denial records, session scoping, approver lists, or escalation data —
// through aliased references obtained via Enqueue arguments or Get /
// ListPending results.
func copyItem(item *InboxItem) *InboxItem {
	val := *item
	if item.Denial != nil {
		d := *item.Denial
		val.Denial = &d
	}
	if item.Escalation != nil {
		e := *item.Escalation
		val.Escalation = &e
	}
	if item.Context != nil {
		val.Context = copyContextValue(item.Context).(map[string]any)
	}
	val.Route.ApproverIDs = slices.Clone(item.Route.ApproverIDs)
	val.Route.ApproverRoles = slices.Clone(item.Route.ApproverRoles)
	val.EffectTypes = slices.Clone(item.EffectTypes)
	return &val
}

// copyContextValue recursively copies mutable context containers while
// preserving cycles. Context accepts typed containers, not just
// map[string]any and []any.
func copyContextValue(v any) any {
	type visit struct {
		typ reflect.Type
		ptr uintptr
		len int
		cap int
	}
	seen := make(map[visit]reflect.Value)

	var clone func(reflect.Value) reflect.Value
	clone = func(src reflect.Value) reflect.Value {
		if !src.IsValid() {
			return src
		}
		if src.Kind() == reflect.Interface {
			if src.IsNil() {
				return reflect.Zero(src.Type())
			}
			dst := reflect.New(src.Type()).Elem()
			dst.Set(clone(src.Elem()))
			return dst
		}

		switch src.Kind() {
		case reflect.Map:
			if src.IsNil() {
				return reflect.Zero(src.Type())
			}
			key := visit{typ: src.Type(), ptr: src.Pointer()}
			if dst, ok := seen[key]; ok {
				return dst
			}
			dst := reflect.MakeMapWithSize(src.Type(), src.Len())
			seen[key] = dst
			iter := src.MapRange()
			for iter.Next() {
				dst.SetMapIndex(clone(iter.Key()), clone(iter.Value()))
			}
			return dst
		case reflect.Slice:
			if src.IsNil() {
				return reflect.Zero(src.Type())
			}
			key := visit{typ: src.Type(), ptr: src.Pointer(), len: src.Len(), cap: src.Cap()}
			if dst, ok := seen[key]; ok {
				return dst
			}
			dst := reflect.MakeSlice(src.Type(), src.Len(), src.Len())
			seen[key] = dst
			for i := range src.Len() {
				dst.Index(i).Set(clone(src.Index(i)))
			}
			return dst
		case reflect.Pointer:
			if src.IsNil() {
				return reflect.Zero(src.Type())
			}
			key := visit{typ: src.Type(), ptr: src.Pointer()}
			if dst, ok := seen[key]; ok {
				return dst
			}
			dst := reflect.New(src.Type().Elem())
			seen[key] = dst
			dst.Elem().Set(clone(src.Elem()))
			return dst
		case reflect.Array:
			dst := reflect.New(src.Type()).Elem()
			for i := range src.Len() {
				dst.Index(i).Set(clone(src.Index(i)))
			}
			return dst
		case reflect.Struct:
			// Preserve unexported value fields, then replace every exported
			// field with its recursively cloned value.
			dst := reflect.New(src.Type()).Elem()
			dst.Set(src)
			for i := range src.NumField() {
				if src.Type().Field(i).PkgPath == "" {
					dst.Field(i).Set(clone(src.Field(i)))
				}
			}
			return dst
		default:
			return src
		}
	}

	return clone(reflect.ValueOf(v)).Interface()
}

func (s *InMemoryInboxStore) Enqueue(ctx context.Context, item *InboxItem) error {
	if item == nil {
		return fmt.Errorf("actioninbox: item must not be nil")
	}
	if item.ItemID == "" {
		return fmt.Errorf("actioninbox: item_id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.items[item.ItemID]; exists {
		return fmt.Errorf("actioninbox: item %q already exists", item.ItemID)
	}

	// Store a copy to prevent external mutation. A freshly enqueued item
	// is PENDING: strip any caller-supplied denial record so forged
	// denial evidence can never ride in on a pending item.
	val := copyItem(item)
	val.Status = StatusPending
	val.Denial = nil
	contentIdentity, err := canonicalContentHash(val)
	if err != nil {
		return err
	}
	s.items[item.ItemID] = val
	s.cascadeIdentities[item.ItemID] = cascadeIdentity(val, contentIdentity)
	return nil
}

func (s *InMemoryInboxStore) Get(ctx context.Context, itemID string) (*InboxItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[itemID]
	if !ok {
		return nil, fmt.Errorf("actioninbox: item %q not found", itemID)
	}

	// Check expiry on read.
	if item.Status == StatusPending && !item.ExpiresAt.IsZero() && time.Now().After(item.ExpiresAt) {
		item.Status = StatusExpired
	}

	return copyItem(item), nil
}

func (s *InMemoryInboxStore) ListPending(ctx context.Context, managerID string, limit int) ([]*InboxItem, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*InboxItem
	for _, item := range s.items {
		if item.ManagerID == managerID && item.Status == StatusPending {
			// Check expiry.
			if !item.ExpiresAt.IsZero() && time.Now().After(item.ExpiresAt) {
				continue
			}
			result = append(result, copyItem(item))
			if limit > 0 && len(result) >= limit {
				break
			}
		}
	}
	return result, nil
}

func (s *InMemoryInboxStore) Approve(ctx context.Context, itemID string, approverID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[itemID]
	if !ok {
		return fmt.Errorf("actioninbox: item %q not found", itemID)
	}
	if item.Status != StatusPending {
		return fmt.Errorf("actioninbox: item %q is not pending (status=%s)", itemID, item.Status)
	}

	item.Status = StatusApproved
	return nil
}

func (s *InMemoryInboxStore) Deny(ctx context.Context, itemID string, reason string, principalID string) error {
	return s.DenyWithFeedback(ctx, itemID, reason, ReasonHumanRejected, principalID)
}

// DenyWithFeedback marks an item as denied and attaches a structured,
// model-actionable denial record (reject-with-feedback): the human's
// steering text is preserved on the item so the requesting agent can
// retrieve it and self-correct instead of retrying blind.
func (s *InMemoryInboxStore) DenyWithFeedback(ctx context.Context, itemID string, feedback string, reasonCode string, principalID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[itemID]
	if !ok {
		return fmt.Errorf("actioninbox: item %q not found", itemID)
	}
	if item.Status != StatusPending {
		return fmt.Errorf("actioninbox: item %q is not pending (status=%s)", itemID, item.Status)
	}
	if strings.TrimSpace(reasonCode) == "" {
		reasonCode = ReasonHumanRejected
	}
	reasonCode = strings.TrimSpace(reasonCode)

	item.Status = StatusDenied
	item.Denial = newHumanDenialRecord(feedback, reasonCode, principalID, time.Now().UTC())
	return nil
}

func newHumanDenialRecord(feedback, reasonCode, principalID string, decidedAt time.Time) *DenialRecord {
	return &DenialRecord{
		SchemaVersion: DenyFeedbackSchemaVersion,
		ReasonCode:    reasonCode,
		Explanation:   "The requested action was reviewed and rejected by the approving principal.",
		Feedback:      feedback,
		Remediation:   "Do not retry the identical request. Adjust the proposal according to the feedback, or abandon it.",
		Escalation:    "If the rejection seems mistaken, escalate to the approving principal with this item's receipt and content hash.",
		PrincipalID:   principalID,
		DecidedAt:     decidedAt,
	}
}

// DenyCascade marks an item as denied with feedback, then cascade-rejects
// every other still-pending item that is an identical same-session ask in
// the same approval domain: same non-empty ContentHash, same non-empty
// session ID, and SameApprovalDomain (same requester, approval authority,
// and route). A logically expired target is rejected (error) and never
// cascades; logically expired duplicates are skipped, not denied; items
// lacking comparable domain fields are never cascaded to (fail-closed).
// Cascaded items are denied, never approved — the cascade only ever
// narrows, preserving fail-closed semantics. It returns the IDs of the
// cascaded items (excluding itemID).
func (s *InMemoryInboxStore) DenyCascade(ctx context.Context, itemID string, feedback string, principalID string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[itemID]
	if !ok {
		return nil, fmt.Errorf("actioninbox: item %q not found", itemID)
	}
	if item.Status != StatusPending {
		return nil, fmt.Errorf("actioninbox: item %q is not pending (status=%s)", itemID, item.Status)
	}
	now := time.Now().UTC()
	if !item.ExpiresAt.IsZero() && now.After(item.ExpiresAt) {
		// A logically expired target is an expired audit record (lazy
		// expiry marks it EXPIRED on read), not a deniable ask: it must
		// not be denied and must not cascade rejection into live matching
		// requests.
		return nil, fmt.Errorf("actioninbox: item %q is expired and cannot be cascade-denied", itemID)
	}

	item.Status = StatusDenied
	item.Denial = newHumanDenialRecord(feedback, ReasonHumanRejected, principalID, now)

	var cascaded []string
	identity := s.cascadeIdentities[itemID]
	if identity == "" {
		// Without a store-derived identity there is no safe proof of an
		// identical ask. This includes missing domain/session fields and
		// context shapes that cannot be canonically hashed.
		return cascaded, nil
	}
	for _, other := range s.items {
		if other.ItemID == itemID || other.Status != StatusPending {
			continue
		}
		// Skip logically expired items: they are expired audit records
		// (lazy expiry marks them EXPIRED on read), not deniable asks —
		// a cascade must never rewrite them as DENIED.
		if !other.ExpiresAt.IsZero() && now.After(other.ExpiresAt) {
			continue
		}
		// Caller-supplied hash/session/domain strings are not authority.
		// Compare the private canonical identity computed at Enqueue.
		if s.cascadeIdentities[other.ItemID] != identity {
			continue
		}
		// Cascade only within the target's approval domain: same
		// requester, same approval authority, same route. A principal
		// denying one ask must never settle asks owned by another
		// manager, employee, or route; items without comparable domain
		// fields are skipped (fail-closed).
		if !item.SameApprovalDomain(other) {
			continue
		}
		other.Status = StatusDenied
		other.Denial = &DenialRecord{
			SchemaVersion: DenyFeedbackSchemaVersion,
			ReasonCode:    ReasonCascadeRejected,
			Explanation:   "An identical pending request in the same session was rejected; this duplicate was cascade-rejected.",
			Feedback:      feedback,
			CascadedFrom:  itemID,
			Remediation:   "Do not re-enqueue the identical request in this session. Adjust the proposal according to the feedback first.",
			Escalation:    "Escalate to the approving principal with the originating item's receipt if the cascade seems mistaken.",
			PrincipalID:   principalID,
			DecidedAt:     now,
		}
		cascaded = append(cascaded, other.ItemID)
	}
	sort.Strings(cascaded)
	return cascaded, nil
}

func (s *InMemoryInboxStore) Defer(ctx context.Context, itemID string, until time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[itemID]
	if !ok {
		return fmt.Errorf("actioninbox: item %q not found", itemID)
	}
	if item.Status != StatusPending {
		return fmt.Errorf("actioninbox: item %q is not pending (status=%s)", itemID, item.Status)
	}

	item.Status = StatusDeferred
	item.ExpiresAt = until
	return nil
}
