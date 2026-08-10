package store

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// receiptFilterFixture seeds one tenant with receipts that vary across every
// filter dimension so a single query can assert an exact slice of the ledger.
type receiptFilterFixture struct {
	receiptID string
	sessionID string
	verdict   string
	reason    string
	executor  string
	effect    string
	issuedAt  time.Time
}

func seedTenantFilterReceipts(t *testing.T, s *SQLiteReceiptStore, tenantID string, rows []receiptFilterFixture) {
	t.Helper()
	ctx := context.Background()
	for _, row := range rows {
		row := row
		if err := s.AppendCausalScoped(ctx, tenantID, row.sessionID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
			return &contracts.Receipt{
				ReceiptID:        row.receiptID,
				DecisionID:       "decision-" + row.receiptID,
				EffectID:         row.effect,
				Status:           row.verdict,
				Timestamp:        row.issuedAt,
				OutputHash:       "output-" + row.receiptID,
				DecisionHash:     "decision-hash-" + row.receiptID,
				ArgsHash:         "args-" + row.receiptID,
				SignatureVersion: contracts.ReceiptSignatureV5,
				SessionID:        row.sessionID,
				ExecutorID:       row.executor,
				Verdict:          row.verdict,
				ReasonCode:       row.reason,
				PrevHash:         prevHash,
				LamportClock:     lamport,
			}, nil
		}); err != nil {
			t.Fatalf("seed receipt %s: %v", row.receiptID, err)
		}
	}
}

func receiptIDsOf(receipts []*contracts.Receipt) []string {
	out := make([]string, 0, len(receipts))
	for _, r := range receipts {
		out = append(out, r.ReceiptID)
	}
	return out
}

// TestSQLiteListByTenantCursorFilteredByDimensions is the predicate mutation
// test: it seeds receipts spanning two verdicts, two reason codes, two
// executors, two effects and four timestamps, then asserts each filtered query
// returns exactly the expected receipts in durable append order.
//
// Mutation check (recorded in the PR): making the verdict predicate a no-op in
// appendReceiptFilterPredicatesSQLite makes the Verdict=DENY case return the
// ALLOW receipt too, failing this test; restoring it passes.
func TestSQLiteListByTenantCursorFilteredByDimensions(t *testing.T) {
	receiptStore, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()

	const tenantID = "tenant-a"
	deny := string(contracts.VerdictDeny)
	allow := string(contracts.VerdictAllow)
	t1 := time.Date(2026, 8, 1, 1, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 8, 1, 2, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 8, 1, 3, 0, 0, 0, time.UTC)
	t4 := time.Date(2026, 8, 1, 4, 0, 0, 0, time.UTC)

	seedTenantFilterReceipts(t, receiptStore, tenantID, []receiptFilterFixture{
		{"rcpt-1", "sess-1", deny, "policy.blocked", "agent-1", "fs.write", t1},
		{"rcpt-2", "sess-2", allow, "ok", "agent-1", "fs.read", t2},
		{"rcpt-3", "sess-3", deny, "policy.blocked", "agent-2", "net.egress", t3},
		{"rcpt-4", "sess-4", deny, "rate.limit", "agent-1", "fs.write", t4},
	})

	// A receipt for a different tenant must never leak into tenant-a results,
	// no matter how permissive the filter.
	seedTenantFilterReceipts(t, receiptStore, "tenant-b", []receiptFilterFixture{
		{"rcpt-foreign", "sess-b", deny, "policy.blocked", "agent-1", "fs.write", t1},
	})

	cases := []struct {
		name   string
		filter ReceiptQueryFilter
		want   []string
	}{
		{"no filter returns all tenant receipts", ReceiptQueryFilter{}, []string{"rcpt-1", "rcpt-2", "rcpt-3", "rcpt-4"}},
		{"verdict deny", ReceiptQueryFilter{Verdict: deny}, []string{"rcpt-1", "rcpt-3", "rcpt-4"}},
		{"verdict deny and reason policy.blocked", ReceiptQueryFilter{Verdict: deny, ReasonCode: "policy.blocked"}, []string{"rcpt-1", "rcpt-3"}},
		{"reason rate.limit", ReceiptQueryFilter{ReasonCode: "rate.limit"}, []string{"rcpt-4"}},
		{"executor agent-2", ReceiptQueryFilter{Executor: "agent-2"}, []string{"rcpt-3"}},
		{"effect fs.write", ReceiptQueryFilter{Effect: "fs.write"}, []string{"rcpt-1", "rcpt-4"}},
		{"time window [t2,t4)", ReceiptQueryFilter{From: t2, To: t4}, []string{"rcpt-2", "rcpt-3"}},
		{"deny since t3", ReceiptQueryFilter{Verdict: deny, From: t3}, []string{"rcpt-3", "rcpt-4"}},
		{"denied for reason X in period Y", ReceiptQueryFilter{Verdict: deny, ReasonCode: "policy.blocked", From: t1, To: t3}, []string{"rcpt-1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := receiptStore.ListByTenantCursorFiltered(ctx, tenantID, TenantReceiptCursor{}, tc.filter, 100)
			if err != nil {
				t.Fatalf("filtered list: %v", err)
			}
			if ids := receiptIDsOf(got); !reflect.DeepEqual(ids, tc.want) {
				t.Fatalf("filter %+v returned %v, want %v", tc.filter, ids, tc.want)
			}
		})
	}
}

// TestSQLiteListByTenantSessionFilteredByVerdict covers the session-scoped
// filtered path over a single signed causal chain.
func TestSQLiteListByTenantSessionFilteredByVerdict(t *testing.T) {
	receiptStore, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()

	const tenantID = "tenant-a"
	const sessionID = "sess-chain"
	deny := string(contracts.VerdictDeny)
	allow := string(contracts.VerdictAllow)
	base := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)

	seedTenantFilterReceipts(t, receiptStore, tenantID, []receiptFilterFixture{
		{"chain-1", sessionID, deny, "policy.blocked", "agent-1", "fs.write", base},
		{"chain-2", sessionID, allow, "ok", "agent-1", "fs.read", base.Add(time.Second)},
		{"chain-3", sessionID, deny, "rate.limit", "agent-1", "net.egress", base.Add(2 * time.Second)},
	})

	got, err := receiptStore.ListByTenantSessionFiltered(ctx, tenantID, sessionID, 0, ReceiptQueryFilter{Verdict: deny}, 100)
	if err != nil {
		t.Fatalf("filtered session list: %v", err)
	}
	if ids := receiptIDsOf(got); !reflect.DeepEqual(ids, []string{"chain-1", "chain-3"}) {
		t.Fatalf("session verdict filter returned %v, want [chain-1 chain-3]", ids)
	}

	all, err := receiptStore.ListByTenantSession(ctx, tenantID, sessionID, 0, 100)
	if err != nil || len(all) != 3 {
		t.Fatalf("unfiltered session list = %d receipts err=%v, want 3", len(all), err)
	}
}

func TestSQLiteReceiptTimeFilterOrdersFractionalRFC3339Chronologically(t *testing.T) {
	receiptStore, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()

	const tenantID = "tenant-fractional-time"
	base := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	seedTenantFilterReceipts(t, receiptStore, tenantID, []receiptFilterFixture{
		{"at-second", "session-second", string(contracts.VerdictAllow), "ok", "agent", "read", base},
		{"after-second", "session-fractional", string(contracts.VerdictAllow), "ok", "agent", "read", base.Add(500 * time.Millisecond)},
	})

	got, err := receiptStore.ListByTenantCursorFiltered(ctx, tenantID, TenantReceiptCursor{}, ReceiptQueryFilter{From: base}, 10)
	if err != nil {
		t.Fatalf("filter from whole second: %v", err)
	}
	if ids := receiptIDsOf(got); !reflect.DeepEqual(ids, []string{"at-second", "after-second"}) {
		t.Fatalf("fractional timestamp ordering returned %v", ids)
	}
}

func TestPostgresListByTenantCursorFilteredBuildsScopedPredicates(t *testing.T) {
	ctx := context.Background()
	db, mock, cleanup := newStoreCoverageSQLMock(t)
	defer cleanup()
	receiptStore := NewPostgresReceiptStore(db)

	const tenantID = "tenant-filtered"
	prefix := causalReceiptTenantScopePrefix(tenantID)
	from := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	receipt := storeCoverageReceipt("receipt-filtered", "decision-filtered", "session-filtered", 1, from)

	mock.ExpectQuery(`left\(causal_session_id, char_length\(\$2\)\) = \$2[\s\S]*verdict = \$3[\s\S]*reason_code = \$4[\s\S]*executor_id = \$5[\s\S]*effect_id = \$6[\s\S]*timestamp >= \$7[\s\S]*timestamp < \$8[\s\S]*ORDER BY append_sequence ASC LIMIT \$9`).
		WithArgs(contracts.ReceiptSignatureV5, prefix, "DENY", "policy.blocked", "agent-1", "fs.write", from, to, 10).
		WillReturnRows(storePostgresReceiptRows(receipt, nil))

	got, err := receiptStore.ListByTenantCursorFiltered(ctx, tenantID, TenantReceiptCursor{}, ReceiptQueryFilter{
		Verdict:    "DENY",
		ReasonCode: "policy.blocked",
		Executor:   "agent-1",
		Effect:     "fs.write",
		From:       from,
		To:         to,
	}, 10)
	if err != nil || len(got) != 1 || got[0].ReceiptID != receipt.ReceiptID {
		t.Fatalf("Postgres filtered tenant receipts = %+v err=%v", got, err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Postgres filtered query contract: %v", err)
	}
}
