package mcpserver

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

// A direct MCP call cannot turn a forbidden default-branch write or a
// control-plane operation into a provider effect.
func TestPostgresDefaultBranchAndAuthorityToolsFailClosed(t *testing.T) {
	e := newEnv(t)
	// The G0 mandate makes the repository's default branch a prohibited head.
	// Narrow the fixture's otherwise unconstrained branch mandate before the
	// client calls the tool.
	var mandateIDText string
	must(t, e.owner.QueryRow(`SELECT mandate_id::text FROM authority_mandates WHERE tenant_id = $1 AND holder_id = 'agt:seat-1'`, tenantA).Scan(&mandateIDText))
	mandateID, err := uuid.Parse(mandateIDText)
	must(t, err)
	var mandate authorityrows.Mandate
	must(t, e.rows.InTenant(context.Background(), tenantA, func(tx *authorityrows.Tx) error {
		var loadErr error
		mandate, loadErr = tx.Mandate(context.Background(), mandateID)
		return loadErr
	}))
	terms := mandate.Terms
	terms.Condition = `input.effect_type == "github.repository.get" || input.args.head.startsWith("helm/")`
	_, err = e.rows.Narrow(context.Background(), tenantA, mandateID, terms)
	must(t, err)

	beforeAttempts := e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`)
	content, isError := e.callTool(t, tokenSeat1Ep1, "default-head", "github_branch_create_from_changes", branchCall(repoA, "main")).structured(t)
	if !isError || content["status"] != "denied" || content["reason_code"] != "MISSING_REQUIREMENT" {
		t.Fatalf("default-branch write was not denied with its prerequisite: %v isError=%t", content, isError)
	}
	attempt := e.attempt(tenantA, content["attempt_id"].(string))
	if attempt.State != "DENIED" || attempt.Permit != nil || e.adapter.dispatched.Load() != 0 ||
		e.count(tenantA, `SELECT count(*) FROM authority_permits`) != 0 ||
		e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`) != beforeAttempts+1 {
		t.Fatalf("default-branch denial leaked authority or provider I/O: %+v", attempt)
	}

	names := toolNames(t, e.modern(t, tokenSeat1Ep1, "list", "tools/list", nil))
	for _, forbidden := range []string{"helm_authority_provision", "model_inference", "helm_approve", "helm_decide"} {
		for _, offered := range names {
			if offered == forbidden {
				t.Fatalf("control-plane operation %q offered to worker", forbidden)
			}
		}
		e.callTool(t, tokenSeat1Ep1, forbidden, forbidden, map[string]any{}).rpcError(t, http.StatusOK, codeInvalidParams)
	}
	if e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`) != beforeAttempts+1 || e.adapter.dispatched.Load() != 0 {
		t.Fatal("unknown authority tools created an attempt or reached the provider")
	}

	allowed, isError := e.callTool(t, tokenSeat1Ep1, "allowed-control", "github_repository_get", getArgs(repoA)).structured(t)
	if isError || allowed["status"] != "succeeded" || e.adapter.dispatched.Load() != 1 {
		t.Fatalf("an in-mandate control call did not dispatch exactly once: %v isError=%t", allowed, isError)
	}
}
