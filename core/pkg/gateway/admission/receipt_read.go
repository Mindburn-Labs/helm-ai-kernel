package admission

// quantum_posture: reads stored classical Ed25519 receipt.v5 envelopes and
// their binding bytes back exactly as written and encodes them for offline
// verification; it signs nothing and makes no post-quantum claim.
//
// The receipt reads (helm-tracker#276): a reader gets the exact bytes the
// gateway signed and stored, never a re-encoding, so receipt_verify checks
// what the ledger holds. Both reads run REPEATABLE READ and READ ONLY in the
// caller's tenant (forced row security), and both are held to the caller's
// workspace from the token (R9).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

// MaxExportReceipts bounds one ExportReceiptChain range. A caller pages with
// consecutive ranges.
const MaxExportReceipts = 256

// SignedReceipt is one stored receipt: its place in its chain and the exact
// envelope and binding bytes the gateway wrote.
type SignedReceipt struct {
	Ref      ReceiptRef
	Envelope []byte
	Binding  []byte
}

// ExportInput names a range of the caller's workspace chain. WorkspaceID is
// the caller's statement of its own workspace; it never selects another.
type ExportInput struct {
	WorkspaceID    string
	FromSeq, ToSeq uint64
}

// ChainExport is one contiguous segment of a workspace's receipt chain.
type ChainExport struct {
	ChainID  string
	HeadSeq  uint64
	Receipts []SignedReceipt
	// Bundle is the segment as the document receipt_verify --receipt reads.
	Bundle []byte
}

const signedReceiptColumns = `receipt_id::text, chain_id, seq, digest, key_id, format, state, attempt_version, envelope, binding`

func scanSignedReceipts(rows *sql.Rows) ([]SignedReceipt, error) {
	defer func() { _ = rows.Close() }()
	var out []SignedReceipt
	for rows.Next() {
		var r SignedReceipt
		var seq int64
		if err := rows.Scan(&r.Ref.ReceiptID, &r.Ref.ChainID, &seq, &r.Ref.Digest, &r.Ref.KeyID, &r.Ref.Format,
			&r.Ref.State, &r.Ref.AttemptVersion, &r.Envelope, &r.Binding); err != nil {
			return nil, err
		}
		if seq < 1 {
			return nil, fmt.Errorf("stored receipt %s has sequence %d", r.Ref.ReceiptID, seq)
		}
		r.Ref.Seq = uint64(seq)
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetReceipts returns the signed receipts of an attempt the caller may read,
// oldest first. It reads what Get reads: an attempt of the caller's tenant
// and workspace and, for a caller with an episode claim, only one of its own
// episode proposed by its own principal. Anything else is not found.
// Continuation and reassignment grants do not extend to receipts.
func (s *Service) GetReceipts(ctx context.Context, caller Caller, attemptID string) ([]SignedReceipt, error) {
	if err := checkCaller(caller); err != nil {
		return nil, err
	}
	if err := checkAttemptID(attemptID); err != nil {
		return nil, err
	}
	var out []SignedReceipt
	err := s.inTenantWith(ctx, caller.TenantID, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}, func(tx *sql.Tx) error {
		var visible bool
		err := tx.QueryRowContext(ctx, `SELECT true FROM authority_effect_attempts
			WHERE tenant_id = $1 AND attempt_id = $2 AND workspace_id = $3
				AND ($4 = '' OR (episode_id = $4 AND requester_principal_id = $5))`,
			caller.TenantID, attemptID, caller.WorkspaceID, episodeScope(caller), caller.PrincipalID).Scan(&visible)
		if errors.Is(err, sql.ErrNoRows) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT `+signedReceiptColumns+` FROM authority_receipts
			WHERE tenant_id = $1 AND attempt_id = $2 AND workspace_id = $3 ORDER BY attempt_version, seq`,
			caller.TenantID, attemptID, caller.WorkspaceID)
		if err != nil {
			return err
		}
		out, err = scanSignedReceipts(rows)
		return err
	})
	return out, err
}

// ExportReceiptChain exports receipts FromSeq..ToSeq of the receipt chain of
// the caller's tenant and workspace, in chain order, with the document
// receipt_verify checks offline. It refuses a workspace other than the
// caller's own and a caller with an episode claim, whose view is its own
// episode while the chain holds the whole workspace's decisions. A ToSeq past
// the chain's head reads up to the head, which the export names; a FromSeq
// past it is not found. A segment the ledger cannot return whole and
// contiguous is an error, never a partial export.
func (s *Service) ExportReceiptChain(ctx context.Context, caller Caller, in ExportInput) (ChainExport, error) {
	if err := checkCaller(caller); err != nil {
		return ChainExport{}, err
	}
	if caller.Episode != nil {
		return ChainExport{}, refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege,
			"an episode token cannot export its workspace's receipt chain")
	}
	if in.WorkspaceID == "" {
		return ChainExport{}, refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation, "workspace_id is required")
	}
	if in.WorkspaceID != caller.WorkspaceID {
		return ChainExport{}, refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege,
			"the token reads the receipt chain of its own workspace only")
	}
	if in.FromSeq < 1 || in.ToSeq < in.FromSeq || in.ToSeq-in.FromSeq >= MaxExportReceipts {
		return ChainExport{}, refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation,
			"from_seq must be at least 1 and to_seq at least from_seq, for at most %d receipts", MaxExportReceipts)
	}
	out := ChainExport{ChainID: receiptChainID(caller.TenantID, caller.WorkspaceID)}
	err := s.inTenantWith(ctx, caller.TenantID, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}, func(tx *sql.Tx) error {
		var head int64
		err := tx.QueryRowContext(ctx, `SELECT seq FROM authority_receipt_chains WHERE tenant_id = $1 AND chain_id = $2`,
			caller.TenantID, out.ChainID).Scan(&head)
		if errors.Is(err, sql.ErrNoRows) {
			return refuse(CodeNotFound, "", "the workspace has no receipt chain")
		}
		if err != nil {
			return err
		}
		if head < 0 || in.FromSeq > uint64(head) {
			return refuse(CodeNotFound, "", "the workspace's receipt chain ends at sequence %d", head)
		}
		out.HeadSeq = uint64(head)
		in.ToSeq = min(in.ToSeq, out.HeadSeq)
		rows, err := tx.QueryContext(ctx, `SELECT `+signedReceiptColumns+` FROM authority_receipts
			WHERE tenant_id = $1 AND chain_id = $2 AND workspace_id = $3 AND seq BETWEEN $4 AND $5 ORDER BY seq`,
			caller.TenantID, out.ChainID, caller.WorkspaceID, in.FromSeq, in.ToSeq)
		if err != nil {
			return err
		}
		out.Receipts, err = scanSignedReceipts(rows)
		return err
	})
	if err != nil {
		return ChainExport{}, err
	}
	stored := make([]receiptverify.GatewayReceipt, 0, len(out.Receipts))
	for i, r := range out.Receipts {
		if r.Ref.Seq != in.FromSeq+uint64(i) || r.Ref.ChainID != out.ChainID {
			return ChainExport{}, fmt.Errorf("receipt chain %q: sequence %d is missing from the ledger", out.ChainID, in.FromSeq+uint64(i))
		}
		stored = append(stored, receiptverify.GatewayReceipt{ReceiptID: r.Ref.ReceiptID, Envelope: r.Envelope, Binding: r.Binding})
	}
	if uint64(len(out.Receipts)) != in.ToSeq-in.FromSeq+1 {
		return ChainExport{}, fmt.Errorf("receipt chain %q: %d of %d receipts are in the ledger", out.ChainID, len(out.Receipts), in.ToSeq-in.FromSeq+1)
	}
	if out.Bundle, err = receiptverify.EncodeGatewayBundle(stored); err != nil {
		return ChainExport{}, fmt.Errorf("receipt chain %q: %w", out.ChainID, err)
	}
	return out, nil
}
