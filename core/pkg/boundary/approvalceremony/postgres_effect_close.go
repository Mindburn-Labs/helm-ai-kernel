package approvalceremony

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

const effectClosureColumns = `
tenant_id, workspace_id, admission_id, close_id,
acknowledgement_hash, receipt_hash, outcome,
evidence_pack_ref, evidence_pack_hash,
acknowledgement_json, receipt_json,
signature_algorithm, signature, created_at
`

func effectReservationHeadHash(event EffectReservationEvent) (string, error) {
	hash, err := canonicalize.CanonicalHash(event)
	if err != nil {
		return "", fmt.Errorf("hash effect reservation head: %w", err)
	}
	return "sha256:" + hash, nil
}

type effectClosureScanner interface {
	Scan(...any) error
}

func queryEffectReservationAtSequence(
	ctx context.Context,
	tx *sql.Tx,
	tenantID, workspaceID, admissionID string,
	sequence uint64,
) (EffectReservationEvent, error) {
	return scanEffectReservationEvent(tx.QueryRowContext(ctx, `SELECT `+effectReservationColumns+`
		FROM approval_effect_reservation_events
		WHERE tenant_id = $1 AND workspace_id = $2 AND admission_id = $3 AND sequence = $4`,
		tenantID, workspaceID, admissionID, sequence,
	))
}
