package activitytrail

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

const (
	repository = "github.com/Acme/widget"
	shaA       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaB       = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	shaC       = "cccccccccccccccccccccccccccccccccccccccc"
)

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

type fakeGitHub struct {
	mu            sync.Mutex
	head          string
	commits       []string
	aheadOverride int
	events        []repositoryEvent
	comparePages  []int
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer read-only" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/repos/Acme/widget":
		_, _ = w.Write([]byte(`{"full_name":"Acme/widget","default_branch":"main"}`))
	case r.URL.Path == "/repos/Acme/widget/git/ref/heads/main":
		_, _ = fmt.Fprintf(w, `{"ref":"refs/heads/main","object":{"sha":%q,"type":"commit"}}`, f.head)
	case strings.HasPrefix(r.URL.Path, "/repos/Acme/widget/compare/"):
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			http.Error(w, "bad page", 400)
			return
		}
		f.comparePages = append(f.comparePages, page)
		base := strings.TrimPrefix(r.URL.Path, "/repos/Acme/widget/compare/")
		before, after, ok := strings.Cut(base, "...")
		if !ok || after != f.head {
			http.Error(w, "bad comparison", 400)
			return
		}
		start := (page - 1) * 100
		if start > len(f.commits) {
			start = len(f.commits)
		}
		end := start + 100
		if end > len(f.commits) {
			end = len(f.commits)
		}
		commits := make([]map[string]string, 0, end-start)
		for _, sha := range f.commits[start:end] {
			commits = append(commits, map[string]string{"sha": sha})
		}
		ahead := len(f.commits)
		if f.aheadOverride > 0 {
			ahead = f.aheadOverride
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ahead", "ahead_by": ahead, "base_commit": map[string]string{"sha": before}, "commits": commits})
	case r.URL.Path == "/repos/Acme/widget/events":
		w.Header().Set("X-Poll-Interval", "60")
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			http.Error(w, "bad page", 400)
			return
		}
		start := (page - 1) * 100
		if start > len(f.events) {
			start = len(f.events)
		}
		end := start + 100
		if end > len(f.events) {
			end = len(f.events)
		}
		_ = json.NewEncoder(w).Encode(f.events[start:end])
	default:
		http.NotFound(w, r)
	}
}

type pgFixture struct {
	t              *testing.T
	owner, runtime *sql.DB
	svc            *Service
	provider       *fakeGitHub
	server         *httptest.Server
	scope          Scope
}

func testDSN(t *testing.T, raw, schema, role string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	if role != "" {
		u.User = url.UserPassword(role, "activity-probe")
	}
	return u.String()
}

func newPGFixture(t *testing.T) *pgFixture {
	t.Helper()
	base := os.Getenv("HELM_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL for real PostgreSQL activity proofs")
	}
	admin, err := sql.Open("postgres", base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	schema := fmt.Sprintf("helm_activity_%d", time.Now().UnixNano())
	role := schema + "_runtime"
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		_, _ = admin.Exec(`DROP ROLE IF EXISTS ` + role)
	})
	owner, err := sql.Open("postgres", testDSN(t, base, schema, ""))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	ctx := context.Background()
	if err := admission.Migrate(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, owner); err != nil {
		t.Fatalf("migration retry: %v", err)
	}
	rows, err := authorityrows.New(owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		if err := rows.CreateTenant(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	statements := []string{
		`CREATE ROLE ` + role + ` LOGIN PASSWORD 'activity-probe' NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB`,
		`GRANT USAGE ON SCHEMA ` + schema + ` TO ` + role,
		`GRANT SELECT,INSERT,UPDATE ON ` + strings.Join(Tables, ",") + ` TO ` + role,
	}
	for _, q := range statements {
		if _, err := owner.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	runtime, err := sql.Open("postgres", testDSN(t, base, schema, role))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	provider := &fakeGitHub{head: shaA}
	server := httptest.NewServer(http.HandlerFunc(provider.serve))
	t.Cleanup(server.Close)
	svc, err := New(runtime, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &pgFixture{t: t, owner: owner, runtime: runtime, svc: svc, provider: provider, server: server,
		scope: Scope{TenantID: "tenant-a", WorkspaceID: "ws-a", Repository: repository}}
}

func (f *pgFixture) enable() {
	f.t.Helper()
	coverage, err := f.svc.Enable(context.Background(), f.scope, staticToken("read-only"))
	if err != nil {
		f.t.Fatal(err)
	}
	if coverage.Class != CoverageObservedOnly || coverage.HeadSHA != shaA {
		f.t.Fatalf("baseline coverage: %+v", coverage)
	}
	if coverage.AttributionComplete {
		f.t.Fatal("baseline falsely claimed attribution before either provider poll")
	}
}

func (f *pgFixture) count(table string) int {
	f.t.Helper()
	ctx := context.Background()
	var n int
	err := f.svc.inTenant(ctx, f.scope.TenantID, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM `+table+` WHERE tenant_id=$1 AND workspace_id=$2`, f.scope.TenantID, f.scope.WorkspaceID).Scan(&n)
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestPostgresComparePaginationAndObservedOnlyReads(t *testing.T) {
	f := newPGFixture(t)
	f.enable()
	ctx := context.Background()
	commits := make([]string, 101)
	for i := range commits {
		commits[i] = fmt.Sprintf("%040x", i+1)
	}
	commits[100] = shaB
	f.provider.mu.Lock()
	f.provider.head = shaB
	f.provider.commits = commits
	f.provider.mu.Unlock()
	result, err := f.svc.PollDefaultBranch(ctx, f.scope, staticToken("read-only"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Existing || result.BeforeSHA != shaA || result.AfterSHA != shaB || result.Observation.ActorLogin != "" || result.Observation.ProviderTime != nil {
		t.Fatalf("comparison result: %+v", result)
	}
	f.provider.mu.Lock()
	pages := append([]int{}, f.provider.comparePages...)
	f.provider.mu.Unlock()
	if fmt.Sprint(pages) != "[1 2]" {
		t.Fatalf("comparison pages: %v", pages)
	}
	if got := f.count("gateway_activity_observations"); got != 1 {
		t.Fatalf("observation count %d", got)
	}
	if got := f.count("gateway_activity_evidence"); got != 1 {
		t.Fatalf("evidence count %d", got)
	}
	result, err = f.svc.PollDefaultBranch(ctx, f.scope, staticToken("read-only"))
	if err != nil || result.Changed {
		t.Fatalf("repeat comparison: %+v, %v", result, err)
	}
	coverage, err := f.svc.CoverageMap(ctx, f.scope)
	if err != nil || coverage.Class != CoverageObservedOnly || coverage.UnattributedCount != 1 || coverage.AttributionComplete {
		t.Fatalf("coverage: %+v, %v", coverage, err)
	}
	page, next, err := f.svc.ListOwnerExceptions(ctx, f.scope, Page{Limit: 1})
	if err != nil || len(page) != 1 || page[0].Reason != OutsideHELMReason || page[0].Observation.Governed || next != "" {
		t.Fatalf("exceptions: %+v, %q, %v", page, next, err)
	}
	other := f.scope
	other.TenantID = "tenant-b"
	otherPage, _, err := f.svc.ListObservations(ctx, other, Page{})
	if err != nil || len(otherPage) != 0 {
		t.Fatalf("cross-tenant read: %+v, %v", otherPage, err)
	}
	for _, table := range Tables {
		var forced bool
		if err := f.owner.QueryRow(`SELECT relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&forced); err != nil || !forced {
			t.Fatalf("%s FORCE RLS: %v, %v", table, forced, err)
		}
	}
}

func signedPush(before, after, delivery string) ([]byte, string) {
	raw := []byte(fmt.Sprintf(`{"ref":"refs/heads/main","before":%q,"after":%q,"repository":{"full_name":"Acme/widget"},"sender":{"login":"break-glass"}}`, before, after))
	mac := hmac.New(sha256.New, []byte("test-secret-at-least-sixteen-bytes"))
	_, _ = mac.Write(raw)
	return raw, "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestPostgresSignedPushDeliveryDedupAndEventsEnrichment(t *testing.T) {
	f := newPGFixture(t)
	f.enable()
	ctx := context.Background()
	if result, err := f.svc.PollDefaultBranch(ctx, f.scope, staticToken("read-only")); err != nil || result.Changed {
		t.Fatalf("baseline ref poll: %+v, %v", result, err)
	}
	secret := []byte("test-secret-at-least-sixteen-bytes")
	raw, signature := signedPush(shaA, shaB, "delivery-one")
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	existing := make(chan bool, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, was, err := f.svc.IngestSignedPush(ctx, f.scope, "push", "delivery-one", signature, raw, secret)
			errs <- err
			existing <- was
		}()
	}
	wg.Wait()
	close(errs)
	close(existing)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	newCount := 0
	for was := range existing {
		if !was {
			newCount++
		}
	}
	if newCount != 1 || f.count("gateway_activity_observations") != 1 || f.count("gateway_activity_evidence") != 1 {
		t.Fatalf("parallel delivery new=%d", newCount)
	}
	badRaw, badSig := signedPush(shaB, shaC, "delivery-one")
	_, _, err := f.svc.IngestSignedPush(ctx, f.scope, "push", "delivery-one", badSig, badRaw, secret)
	if !errors.Is(err, ErrDeliveryConflict) {
		t.Fatalf("reused delivery with changed fact: %v", err)
	}
	if f.count("gateway_activity_observations") != 1 {
		t.Fatal("conflicting delivery committed a fact")
	}
	when := time.Now().UTC().Truncate(time.Second)
	event := repositoryEvent{ID: "event-one", Type: "PushEvent", CreatedAt: when}
	event.Actor.Login = "break-glass"
	event.Repo.Name = "Acme/widget"
	event.Payload.Ref = "refs/heads/main"
	event.Payload.Before = shaA
	event.Payload.Head = shaB
	f.provider.mu.Lock()
	f.provider.events = []repositoryEvent{event}
	f.provider.mu.Unlock()
	matched, err := f.svc.PollRepositoryEvents(ctx, f.scope, staticToken("read-only"))
	if err != nil || matched != 1 {
		t.Fatalf("event poll: %d, %v", matched, err)
	}
	observations, _, err := f.svc.ListObservations(ctx, f.scope, Page{})
	if err != nil || len(observations) != 1 || observations[0].ActorLogin != "break-glass" || observations[0].ProviderTime == nil || !observations[0].ProviderTime.Equal(when) {
		t.Fatalf("enriched observation: %+v, %v", observations, err)
	}
	coverage, err := f.svc.CoverageMap(ctx, f.scope)
	if err != nil || !coverage.AttributionComplete {
		t.Fatalf("coverage after event: %+v, %v", coverage, err)
	}
	f.svc.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	matched, err = f.svc.PollRepositoryEvents(ctx, f.scope, staticToken("read-only"))
	if err != nil || matched != 1 || f.count("gateway_activity_observations") != 1 || f.count("gateway_activity_evidence") != 2 {
		t.Fatalf("repeat event: %d, %v", matched, err)
	}
	raw2, sig2 := signedPush(shaB, shaC, "delivery-two")
	_, was, err := f.svc.IngestSignedPush(ctx, f.scope, "push", "delivery-two", sig2, raw2, secret)
	if err != nil || was {
		t.Fatalf("distinct fact: existing=%v, err=%v", was, err)
	}
	page, next, err := f.svc.ListObservations(ctx, f.scope, Page{Limit: 1})
	if err != nil || len(page) != 1 || next == "" {
		t.Fatalf("first page: %+v, %q, %v", page, next, err)
	}
	page2, next2, err := f.svc.ListObservations(ctx, f.scope, Page{Limit: 1, After: next})
	if err != nil || len(page2) != 1 || next2 != "" || page2[0].FactDigest == page[0].FactDigest {
		t.Fatalf("second page: %+v, %q, %v", page2, next2, err)
	}
	other := f.scope
	other.TenantID = "tenant-b"
	if _, _, err := f.svc.ListObservations(ctx, other, Page{After: next}); err == nil {
		t.Fatal("cross-tenant page cursor accepted")
	}
}

func TestPostgresSignedPushRejectsInvalidSignatureAndDisabledSource(t *testing.T) {
	f := newPGFixture(t)
	f.enable()
	ctx := context.Background()
	raw, sig := signedPush(shaA, shaB, "one")
	if _, _, err := f.svc.IngestSignedPush(ctx, f.scope, "push", "one", sig, raw, []byte("wrong-secret-long-enough")); err == nil {
		t.Fatal("invalid signature accepted")
	}
	if f.count("gateway_activity_observations") != 0 {
		t.Fatal("invalid signature persisted")
	}
	if err := f.svc.Disable(ctx, f.scope); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.IngestSignedPush(ctx, f.scope, "push", "one", sig, raw, []byte("test-secret-at-least-sixteen-bytes")); !errors.Is(err, ErrNotEnabled) {
		t.Fatalf("disabled source: %v", err)
	}
	coverage, err := f.svc.CoverageMap(ctx, f.scope)
	if err != nil || coverage.Class != CoverageUnmanaged {
		t.Fatalf("disabled coverage: %+v, %v", coverage, err)
	}
}

func TestPostgresIncompleteComparisonKeepsCursor(t *testing.T) {
	f := newPGFixture(t)
	f.enable()
	ctx := context.Background()
	f.provider.mu.Lock()
	f.provider.head, f.provider.commits, f.provider.aheadOverride = shaB, []string{shaB}, 2
	f.provider.mu.Unlock()
	if _, err := f.svc.PollDefaultBranch(ctx, f.scope, staticToken("read-only")); !errors.Is(err, ErrIncompleteCompare) {
		t.Fatalf("truncated comparison: %v", err)
	}
	coverage, err := f.svc.CoverageMap(ctx, f.scope)
	if err != nil || coverage.HeadSHA != shaA || coverage.LastPollError == "" || f.count("gateway_activity_observations") != 0 {
		t.Fatalf("incomplete compare advanced cursor or lost gap: %+v, %v", coverage, err)
	}
	f.provider.mu.Lock()
	f.provider.aheadOverride = 0
	f.provider.mu.Unlock()
	result, err := f.svc.PollDefaultBranch(ctx, f.scope, staticToken("read-only"))
	if err != nil || !result.Changed || result.BeforeSHA != shaA {
		t.Fatalf("retry comparison: %+v, %v", result, err)
	}
}

func TestPostgresComparisonHeadMismatchKeepsCursor(t *testing.T) {
	f := newPGFixture(t)
	f.enable()
	ctx := context.Background()
	f.provider.mu.Lock()
	f.provider.head, f.provider.commits = shaB, []string{shaC}
	f.provider.mu.Unlock()
	if _, err := f.svc.PollDefaultBranch(ctx, f.scope, staticToken("read-only")); !errors.Is(err, ErrIncompleteCompare) {
		t.Fatalf("comparison did not end at current head: %v", err)
	}
	coverage, err := f.svc.CoverageMap(ctx, f.scope)
	if err != nil || coverage.HeadSHA != shaA || coverage.LastPollError == "" || f.count("gateway_activity_observations") != 0 {
		t.Fatalf("mismatched comparison advanced cursor: %+v, %v", coverage, err)
	}
}

func TestPostgresRepositoryEventsSkipHistoryBeforeEnable(t *testing.T) {
	f := newPGFixture(t)
	f.enable()
	event := repositoryEvent{ID: "old-event", Type: "PushEvent", CreatedAt: time.Now().Add(-time.Hour)}
	event.Actor.Login = "old-actor"
	event.Repo.Name = "Acme/widget"
	event.Payload.Ref, event.Payload.Before, event.Payload.Head = "refs/heads/main", shaA, shaB
	f.provider.mu.Lock()
	f.provider.events = []repositoryEvent{event}
	f.provider.mu.Unlock()
	matched, err := f.svc.PollRepositoryEvents(context.Background(), f.scope, staticToken("read-only"))
	if err != nil || matched != 0 || f.count("gateway_activity_observations") != 0 {
		t.Fatalf("pre-enable event imported: matched=%d, err=%v", matched, err)
	}
}

func TestPostgresReenableRequiresFreshPolls(t *testing.T) {
	f := newPGFixture(t)
	f.enable()
	ctx := context.Background()
	if _, err := f.svc.PollDefaultBranch(ctx, f.scope, staticToken("read-only")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.PollRepositoryEvents(ctx, f.scope, staticToken("read-only")); err != nil {
		t.Fatal(err)
	}
	before, err := f.svc.CoverageMap(ctx, f.scope)
	if err != nil || !before.AttributionComplete {
		t.Fatalf("initial freshness: %+v, %v", before, err)
	}
	if err := f.svc.Disable(ctx, f.scope); err != nil {
		t.Fatal(err)
	}
	after, err := f.svc.Enable(ctx, f.scope, staticToken("read-only"))
	if err != nil || after.LastPollAt != nil || after.LastEventPollAt != nil || after.AttributionComplete {
		t.Fatalf("re-enabled source reused prior poll freshness: %+v, %v", after, err)
	}
}
