package server

// This wire proof uses a real PostgreSQL schema, forced RLS, a restricted
// gateway role, and signed read-scope tokens. It makes no provider request.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/provision"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

func TestPostgresTeamCounterAuthenticatedExactRead(t *testing.T) {
	w := newAdminWire(t)
	ctx := context.Background()
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		_, err := w.ensure(tenant, serviceSpec(adminProvision), serviceSpec("svc:other-reader"), humanSpec(adminOwner, adminOwner))
		must(t, err)
	}
	var plan map[string]any
	must(t, json.Unmarshal(adminPlan(t, "", "counter-v1", time.Now()), &plan))
	plan["limits"] = []any{
		map[string]any{"node": adminOrg, "unit": "effects", "measure": "count", "window": "none", "span": 1, "value": 100000},
		map[string]any{"node": adminTeam, "unit": "effects", "measure": "count", "window": "none", "span": 1, "value": 1000},
	}
	raw, err := json.Marshal(plan)
	must(t, err)
	w.apply("tenant-a", raw)
	read := w.token("tenant-a", adminProvision, ScopeRead)
	provisioning, err := w.client.GetProvisioning(ctx, withToken(&gatewayv1.GetProvisioningRequest{OrgRef: adminOrg}, read))
	must(t, err)
	applied := provisioning.Msg.GetProvisioning()
	team := applied.GetNodes()[1]
	teamLimit := team.GetLimits()[0]
	parentLimit := applied.GetNodes()[0].GetLimits()[0]
	binding := provision.TeamCounterBinding{
		OrgRef: applied.GetOrgRef(), VersionRef: applied.GetVersionRef(), PlanDigest: applied.GetPlanDigest(),
		Revision: applied.GetRevision(), TeamNode: team.GetNode(), MandateID: team.GetMandateId(),
		LimitID: teamLimit.GetLimitId(), LimitVersion: teamLimit.GetVersion(), Unit: teamLimit.GetUnit(),
		Measure: teamLimit.GetMeasure(), Window: teamLimit.GetWindow(), Span: int(teamLimit.GetSpan()),
	}
	body, err := json.Marshal(map[string]any{"binding": binding})
	must(t, err)
	readAt := func(token string, payload []byte) (int, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.baseURL+"/v1/authority/team-counter:read", bytes.NewReader(payload))
		must(t, err)
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := w.httpClient.Do(req)
		must(t, err)
		defer resp.Body.Close()
		content, err := io.ReadAll(resp.Body)
		must(t, err)
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("counter response is cacheable")
		}
		return resp.StatusCode, content
	}
	if status, _ := readAt("", body); status != http.StatusUnauthorized {
		t.Fatalf("anonymous read status = %d", status)
	}
	if status, _ := readAt(w.token("tenant-a", adminProvision, ScopePropose), body); status != http.StatusForbidden {
		t.Fatalf("propose-scope read status = %d", status)
	}
	withTenant := append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"tenant_id":"tenant-b"}`)...)
	if status, _ := readAt(read, withTenant); status != http.StatusBadRequest {
		t.Fatalf("caller-supplied tenant status = %d", status)
	}
	if status, reply := readAt(read, body); status != http.StatusPreconditionFailed || !bytes.Contains(reply, []byte("counter_not_materialized")) {
		t.Fatalf("unmaterialized counter = %d %s", status, reply)
	}
	// The parent has a different counter; selecting it by aggregation would
	// overstate the team's usage. The read must touch the team limit alone.
	must(t, w.rows.InTenant(ctx, "tenant-a", func(tx *authorityrows.Tx) error {
		for _, row := range []struct {
			limit          string
			used, reserved int
		}{{teamLimit.GetLimitId(), 12, 3}, {parentLimit.GetLimitId(), 120, 20}} {
			if _, err := tx.SQL().ExecContext(ctx, `INSERT INTO authority_counters
				(tenant_id, limit_id, bucket_start, used, reserved) VALUES ($1, $2, $3, $4, $5)`,
				"tenant-a", row.limit, time.Unix(0, 0).UTC(), row.used, row.reserved); err != nil {
				return err
			}
		}
		return nil
	}))
	if status, reply := readAt(read, body); status != http.StatusOK {
		t.Fatalf("team read = %d %s", status, reply)
	} else {
		var snapshot provision.TeamCounterSnapshot
		must(t, json.Unmarshal(reply, &snapshot))
		if snapshot.Binding != binding || snapshot.Cap != 1000 || snapshot.Used != 12 || snapshot.Reserved != 3 ||
			!snapshot.WithinCap || snapshot.ObservedAt.IsZero() || snapshot.SnapshotID == "" || len(snapshot.Buckets) != 1 ||
			snapshot.Buckets[0].Used != 12 || snapshot.Buckets[0].Reserved != 3 || !snapshot.Buckets[0].Start.Equal(time.Unix(0, 0).UTC()) {
			t.Fatalf("team counter = %+v", snapshot)
		}
		if !bytes.Contains(reply, []byte(`"used":"12"`)) || !bytes.Contains(reply, []byte(`"cap":"1000"`)) {
			t.Fatalf("wire amounts are not decimal strings: %s", reply)
		}
	}
	if status, reply := readAt(w.token("tenant-a", adminTeam, ScopeRead), body); status != http.StatusOK {
		t.Fatalf("team principal read = %d %s", status, reply)
	}
	if status, _ := readAt(w.token("tenant-a", "svc:other-reader", ScopeRead), body); status != http.StatusForbidden {
		t.Fatalf("unrelated service principal read = %d", status)
	}
	wrongWorkspace := w.iss.token(t, testAudience, "tenant-a", adminProvision, ScopeRead, func(c *tokenClaims) { c.WorkspaceID = "ws-b" })
	foreignStatus, foreignBody := readAt(wrongWorkspace, body)
	if foreignStatus != http.StatusNotFound || strings.Contains(string(foreignBody), adminTeam) {
		t.Fatalf("foreign workspace read = %d %s", foreignStatus, foreignBody)
	}
	if status, reply := readAt(w.token("tenant-b", adminProvision, ScopeRead), body); status != foreignStatus || !bytes.Equal(reply, foreignBody) {
		t.Fatalf("foreign tenant read differs from workspace refusal: %d %s", status, reply)
	}
	stale := binding
	stale.LimitVersion++
	staleBody, err := json.Marshal(map[string]any{"binding": stale})
	must(t, err)
	if status, _ := readAt(read, staleBody); status != http.StatusPreconditionFailed {
		t.Fatalf("stale limit read status = %d", status)
	}
	other := binding
	other.LimitID = parentLimit.GetLimitId()
	other.LimitVersion = parentLimit.GetVersion()
	otherBody, err := json.Marshal(map[string]any{"binding": other})
	must(t, err)
	if status, _ := readAt(read, otherBody); status != http.StatusPreconditionFailed {
		t.Fatalf("parent limit accepted as the team counter: %d", status)
	}
	var counters, postings int
	must(t, w.rows.ReadInTenant(ctx, "tenant-a", func(tx *authorityrows.Tx) error {
		return tx.SQL().QueryRowContext(ctx, `SELECT
			(SELECT count(*) FROM authority_counters), (SELECT count(*) FROM authority_postings)`).Scan(&counters, &postings)
	}))
	if counters != 2 || postings != 0 {
		t.Fatalf("counter reads mutated ledger: counters=%d postings=%d", counters, postings)
	}
	must(t, w.rows.InTenant(ctx, "tenant-a", func(tx *authorityrows.Tx) error {
		_, err := tx.SQL().ExecContext(ctx, `UPDATE authority_counters SET used=1000 WHERE tenant_id=$1 AND limit_id=$2`,
			"tenant-a", teamLimit.GetLimitId())
		return err
	}))
	if status, reply := readAt(read, body); status != http.StatusOK {
		t.Fatalf("over-cap counter read = %d %s", status, reply)
	} else {
		var snapshot provision.TeamCounterSnapshot
		must(t, json.Unmarshal(reply, &snapshot))
		if snapshot.WithinCap || snapshot.Used != 1000 || snapshot.Reserved != 3 {
			t.Fatalf("the over-cap counter was hidden: %+v", snapshot)
		}
	}
	must(t, w.rows.InTenant(ctx, "tenant-a", func(tx *authorityrows.Tx) error {
		_, err := tx.SQL().ExecContext(ctx, `UPDATE authority_provisions
			SET nodes = nodes || jsonb_build_array(nodes->1) WHERE tenant_id=$1 AND org_ref=$2`, "tenant-a", adminOrg)
		return err
	}))
	if status, _ := readAt(read, body); status != http.StatusPreconditionFailed {
		t.Fatalf("ambiguous team node read = %d", status)
	}
}
