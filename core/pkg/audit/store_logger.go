package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/store"
)

type StoreLogger struct {
	store *store.AuditStore
}

func NewStoreLogger(s *store.AuditStore) *StoreLogger {
	return &StoreLogger{store: s}
}

func (l *StoreLogger) Record(ctx context.Context, eventType EventType, action, resource string, metadata map[string]interface{}) error {
	if l.store == nil {
		return fmt.Errorf("fail-closed: audit store not configured")
	}

	principal, _ := auth.GetPrincipal(ctx)
	tenantID := "system"
	actorID := "system"
	if principal != nil {
		tenantID = principal.GetTenantID()
		actorID = principal.GetID()
	}

	evt := Event{
		ID:        uuid.New().String(),
		TenantID:  tenantID,
		ActorID:   actorID,
		Type:      eventType,
		Action:    action,
		Resource:  resource,
		Timestamp: time.Now().UTC(),
		Metadata:  metadata,
	}

	_, err := l.store.Append(store.EntryTypeAudit, "tenant:"+tenantID, action, evt, map[string]string{
		"actor_id":   actorID,
		"event_id":   evt.ID,
		"event_type": string(eventType),
	})
	return err
}
