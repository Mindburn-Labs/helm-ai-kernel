package conformance

import (
	"context"
	"testing"
	"time"
)

func TestOWASPFirewallSchemaAndNoSchemaBranches(t *testing.T) {
	firewall := newOWASPFirewall()
	firewall.AllowTool("with-schema", `{"type":"object","required":["target","mode"]}`)

	if !firewall.allowedTools["with-schema"] || firewall.schemas["with-schema"] == "" {
		t.Fatalf("AllowTool did not record non-empty schema")
	}
	if _, err := firewall.CallTool("with-schema", map[string]any{"target": "repo", "mode": "read"}); err != nil {
		t.Fatalf("schema-valid tool call failed: %v", err)
	}

	firewall.AllowTool("without-schema", "")
	if _, err := firewall.CallTool("without-schema", map[string]any{"anything": true}); err != nil {
		t.Fatalf("schema-less tool call failed: %v", err)
	}
	if err := firewall.validateParams("without-required", `{"type":"object"}`, map[string]any{}); err != nil {
		t.Fatalf("schema without required fields should validate: %v", err)
	}
	if fields := extractRequiredFields(`{"type":"object"}`); fields != nil {
		t.Fatalf("schema without required returned fields: %+v", fields)
	}
	if fields := extractRequiredFields(`{"required":"not-an-array"}`); fields != nil {
		t.Fatalf("malformed required declaration returned fields: %+v", fields)
	}
}

func TestOWASPDelegationReDelegateErrorBranches(t *testing.T) {
	ctx := context.Background()
	dm := newOWASPDelegationManager()

	if _, err := dm.ReDelegate(ctx, "missing", owaspDelegationRequest{}); err == nil {
		t.Fatal("missing parent grant should fail")
	}

	dm.grants["revoked"] = &owaspDelegationGrant{
		GrantID:       "revoked",
		Capabilities:  []string{"read"},
		MaxChainDepth: 2,
		ExpiresAt:     time.Now().Add(time.Hour),
		Revoked:       true,
	}
	if _, err := dm.ReDelegate(ctx, "revoked", owaspDelegationRequest{Capabilities: []string{"read"}}); err == nil {
		t.Fatal("revoked parent grant should fail")
	}

	dm.grants["expired"] = &owaspDelegationGrant{
		GrantID:       "expired",
		Capabilities:  []string{"read"},
		MaxChainDepth: 2,
		ExpiresAt:     time.Now().Add(-time.Minute),
	}
	if _, err := dm.ReDelegate(ctx, "expired", owaspDelegationRequest{Capabilities: []string{"read"}}); err == nil {
		t.Fatal("expired parent grant should fail")
	}

	dm.grants["max-depth"] = &owaspDelegationGrant{
		GrantID:       "max-depth",
		Capabilities:  []string{"read"},
		MaxChainDepth: 1,
		ChainDepth:    1,
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	if _, err := dm.ReDelegate(ctx, "max-depth", owaspDelegationRequest{Capabilities: []string{"read"}}); err == nil {
		t.Fatal("max-depth parent grant should fail")
	}

	dm.grants["attenuated"] = &owaspDelegationGrant{
		GrantID:       "attenuated",
		Capabilities:  []string{"read"},
		MaxChainDepth: 2,
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	if _, err := dm.ReDelegate(ctx, "attenuated", owaspDelegationRequest{Capabilities: []string{"write"}}); err == nil {
		t.Fatal("capability expansion should fail")
	}
}
