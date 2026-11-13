package provision

// quantum_posture: stores classical ECDSA P-256 and Ed25519 public keys of
// human principals' passkeys; nothing here signs or verifies, and no
// post-quantum claim is made.

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// GenesisProof is the owner's self-signed enrolment of its passkey at the
// tenant's genesis, which the gateway verified and keeps so that it can be
// verified again offline.
type GenesisProof struct {
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
	// SignCount is the counter the enrolment assertion carried.
	SignCount uint32
}

// EnrollGenesisCredential records the owner's passkey of a tenant this
// transaction creates, with its verified genesis proof
// (authority_principal_credentials, helm-tracker#334). A tenant has one
// genesis credential: a second is refused by the schema.
func EnrollGenesisCredential(ctx context.Context, tx *sql.Tx, tenantID, principalID string, c effectargs.Credential, proof GenesisProof) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO authority_principal_credentials
			(tenant_id, credential_id, principal_id, alg, public_key_spki, rp_id, sign_count, enrolled_by,
			 genesis_authenticator_data, genesis_client_data_json, genesis_signature)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'genesis', $8, $9, $10)`,
		tenantID, c.ID, principalID, c.Alg, c.PublicKeySPKI, c.RPID, int64(proof.SignCount),
		proof.AuthenticatorData, proof.ClientDataJSON, proof.Signature)
	return err
}

// enrollPlanCredential records a passkey an approved provision plan enrolls for
// a human. The same passkey of the same human again changes nothing; a
// credential id the tenant already has for another principal or key is an
// identity conflict, and the plan applies nothing.
func enrollPlanCredential(ctx context.Context, tx *sql.Tx, tenantID, principalID, attemptID string, c effectargs.Credential) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO authority_principal_credentials
			(tenant_id, credential_id, principal_id, alg, public_key_spki, rp_id, enrolled_by, enrolled_attempt_id)
		VALUES ($1, $2, $3, $4, $5, $6, 'plan', $7)
		ON CONFLICT (tenant_id, credential_id) DO NOTHING`,
		tenantID, c.ID, principalID, c.Alg, c.PublicKeySPKI, c.RPID, attemptID); err != nil {
		return err
	}
	stored, _, err := LoadCredential(ctx, tx, tenantID, c.ID, false)
	if err != nil {
		return err
	}
	if stored.PrincipalID != principalID || !stored.Same(c) {
		return adapters.Refuse(contracts.ReasonIdentityIsolationViolation,
			"the tenant already has this credential id for another principal or key")
	}
	return nil
}

// EnrolledCredential is a stored passkey and the principal it belongs to.
type EnrolledCredential struct {
	effectargs.Credential
	PrincipalID string
	// Genesis: the owner enrolled it at the tenant's genesis.
	Genesis bool
}

// Same reports whether c is this passkey: the same id, algorithm, key and
// relying party.
func (e EnrolledCredential) Same(c effectargs.Credential) bool {
	return bytes.Equal(e.ID, c.ID) && e.Alg == c.Alg && e.RPID == c.RPID && bytes.Equal(e.PublicKeySPKI, c.PublicKeySPKI)
}

// ErrNoCredential reports a credential id the tenant has not enrolled.
var ErrNoCredential = errors.New("the tenant has no passkey with this credential id")

// LoadCredential reads an enrolled passkey and its signature counter in tx,
// bound to the tenant; with lock the row is locked FOR UPDATE, for an approval
// that will record a new counter.
func LoadCredential(ctx context.Context, tx *sql.Tx, tenantID string, id []byte, lock bool) (EnrolledCredential, uint32, error) {
	query := `SELECT principal_id, alg, public_key_spki, rp_id, sign_count, enrolled_by = 'genesis' FROM authority_principal_credentials
		WHERE tenant_id = $1 AND credential_id = $2`
	if lock {
		query += ` FOR UPDATE`
	}
	out := EnrolledCredential{Credential: effectargs.Credential{ID: append([]byte(nil), id...)}}
	var count int64
	err := tx.QueryRowContext(ctx, query, tenantID, id).Scan(&out.PrincipalID, &out.Alg, &out.PublicKeySPKI, &out.RPID, &count, &out.Genesis)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrolledCredential{}, 0, ErrNoCredential
	}
	if err != nil {
		return EnrolledCredential{}, 0, err
	}
	if count < 0 || count > 1<<32-1 {
		return EnrolledCredential{}, 0, fmt.Errorf("authority_principal_credentials.sign_count %d is out of range", count)
	}
	return out, uint32(count), nil
}

// SetSignCount records the counter an approval's verified assertion carried.
// The schema refuses a counter that goes backwards.
func SetSignCount(ctx context.Context, tx *sql.Tx, tenantID string, id []byte, count uint32) error {
	res, err := tx.ExecContext(ctx, `UPDATE authority_principal_credentials SET sign_count = $3
		WHERE tenant_id = $1 AND credential_id = $2`, tenantID, id, int64(count))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return errors.New("the credential's counter was not recorded")
	}
	return nil
}
