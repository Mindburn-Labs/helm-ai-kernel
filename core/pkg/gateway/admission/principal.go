package admission

import (
	"context"
	"database/sql"
	"errors"
)

// PrincipalEffects is what the MCP tool list reads about a caller: who it is
// and which effect types its mandates name. It grants nothing: every call is
// decided again from the locked rows (R3), so a list that is stale, or read by
// a caller whose mandates changed since, makes a tool the caller cannot use
// visible and never one it can use invisible to admission.
type PrincipalEffects struct {
	// Kind is the principal's kind (human, agent or service); empty when the
	// tenant has no such principal.
	Kind string
	// Active is whether the principal is active.
	Active bool
	// EffectTypes are the effect types named by some active mandate of the
	// principal whose every link, the parents included, is active and inside its
	// validity window now: the effect types the principal may propose. Sorted.
	// Empty for a principal that is not active.
	EffectTypes []string
}

// effectTypesSQL is the union of the effect types of the principal's leaf
// mandates whose whole chain is live. The chain is walked upwards from each
// leaf in one statement, so the answer needs no bound on how many mandates a
// seat holds, and a parent that was revoked or has expired removes every leaf
// under it.
const effectTypesSQL = `
WITH RECURSIVE chain AS (
	SELECT mandate_id AS leaf, parent_id, status, valid_from, valid_until
	FROM authority_mandates WHERE tenant_id = $1 AND holder_id = $2 AND status = 'active'
	UNION ALL
	SELECT c.leaf, m.parent_id, m.status, m.valid_from, m.valid_until
	FROM chain c JOIN authority_mandates m ON m.tenant_id = $1 AND m.mandate_id = c.parent_id)
SELECT DISTINCT e FROM authority_mandates l CROSS JOIN LATERAL unnest(l.effect_types) AS e
WHERE l.tenant_id = $1 AND l.mandate_id IN (
	SELECT leaf FROM chain GROUP BY leaf
	HAVING bool_and(status = 'active' AND valid_from <= now() AND now() < valid_until))
ORDER BY e`

// PrincipalEffects reads the caller's principal row and the effect types of its
// live mandates, in one transaction.
func (s *Service) PrincipalEffects(ctx context.Context, caller Caller) (PrincipalEffects, error) {
	if err := checkCaller(caller); err != nil {
		return PrincipalEffects{}, err
	}
	var out PrincipalEffects
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		var status string
		err := tx.QueryRowContext(ctx, `SELECT kind, status FROM authority_principals WHERE tenant_id = $1 AND principal_id = $2`,
			caller.TenantID, caller.PrincipalID).Scan(&out.Kind, &status)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if out.Active = status == "active"; !out.Active {
			return nil
		}
		rows, err := tx.QueryContext(ctx, effectTypesSQL, caller.TenantID, caller.PrincipalID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var effectType string
			if err := rows.Scan(&effectType); err != nil {
				return err
			}
			out.EffectTypes = append(out.EffectTypes, effectType)
		}
		return rows.Err()
	})
	return out, err
}
