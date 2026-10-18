package provision_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/provision"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

func TestPostgresTeamCounterReadsOnlyCurrentTeamWindow(t *testing.T) {
	f := newProvisionFixture(t)
	applied, err := provision.GetProvisioning(f.ctx, f.rows, provisionTenant, provisionOrg)
	provisionMust(t, err)
	var team, parent authorityrows.Limit
	var teamMandate string
	for i, node := range applied.Nodes {
		for _, limit := range applied.Status[i].Limits {
			if limit.Spec.Unit != "usd_micros" {
				continue
			}
			if node.Node == provisionChild {
				team, teamMandate = limit, node.MandateID
			} else if node.Node == provisionOrg {
				parent = limit
			}
		}
	}
	if team.ID.String() == "00000000-0000-0000-0000-000000000000" || parent.ID.String() == "00000000-0000-0000-0000-000000000000" {
		t.Fatal("the plan did not produce a parent and team limit")
	}
	b := provision.TeamCounterBinding{
		OrgRef: applied.OrgRef, VersionRef: applied.VersionRef, PlanDigest: applied.Digest,
		Revision: applied.Revision, TeamNode: provisionChild, MandateID: teamMandate,
		LimitID: team.ID.String(), LimitVersion: team.Version, Unit: team.Spec.Unit,
		Measure: team.Spec.Measure, Window: team.Spec.Window, Span: team.Spec.Span,
	}
	read := func(binding provision.TeamCounterBinding, workspace string) (*provision.TeamCounterSnapshot, error) {
		return provision.GetTeamCounter(f.ctx, f.rows, provisionTenant, workspace, provisioner, binding)
	}
	if _, err := read(b, "workspace-provision"); !errors.Is(err, provision.ErrTeamCounterAbsent) {
		t.Fatalf("unmaterialized buckets: %v", err)
	}
	current := time.Date(time.Now().UTC().Year(), time.Now().UTC().Month(), time.Now().UTC().Day(), 0, 0, 0, 0, time.UTC)
	previous := current.AddDate(0, 0, -1)
	provisionMust(t, f.rows.InTenant(f.ctx, provisionTenant, func(tx *authorityrows.Tx) error {
		for _, row := range []struct {
			limit          string
			start          time.Time
			used, reserved int
		}{
			{team.ID.String(), current, 4, 1},
			{team.ID.String(), previous, 5, 2},
			{parent.ID.String(), current, 40, 10},
			{parent.ID.String(), previous, 50, 20},
		} {
			if _, err := tx.SQL().ExecContext(context.Background(), `INSERT INTO authority_counters
				(tenant_id, limit_id, bucket_start, used, reserved) VALUES ($1, $2, $3, $4, $5)`,
				provisionTenant, row.limit, row.start, row.used, row.reserved); err != nil {
				return err
			}
		}
		return nil
	}))
	snapshot, err := read(b, "workspace-provision")
	provisionMust(t, err)
	if snapshot.Cap != 80 || snapshot.Used != 9 || snapshot.Reserved != 3 || !snapshot.WithinCap ||
		len(snapshot.Buckets) != 2 || !snapshot.Buckets[0].Start.Equal(current) || !snapshot.Buckets[1].Start.Equal(previous) ||
		snapshot.SnapshotID == "" || snapshot.ObservedAt.IsZero() {
		t.Fatalf("rolling team counter: %+v", snapshot)
	}
	if _, err := read(b, "other-workspace"); !errors.Is(err, provision.ErrNotProvisioned) {
		t.Fatalf("foreign workspace: %v", err)
	}
	stale := b
	stale.Revision++
	if _, err := read(stale, "workspace-provision"); !errors.Is(err, provision.ErrTeamCounterBinding) {
		t.Fatalf("stale applied revision: %v", err)
	}
	stale = b
	stale.Unit = "effects"
	if _, err := read(stale, "workspace-provision"); !errors.Is(err, provision.ErrTeamCounterBinding) {
		t.Fatalf("wrong unit: %v", err)
	}
}
