package admission

// ListAttempts (HELM-751): the attempts of the caller's tenant and workspace,
// oldest change first, one page at a time. See "ListAttempts" in
// docs/architecture/gateway-effect-api.md.
//
// quantum_posture: a page token carries a SHA-256 digest of the filters it
// belongs to, so a token cannot be replayed under another listing by mistake.
// The digest is an integrity check on the caller's own request, not a
// signature or a secret; no post-quantum claim is made.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const (
	defaultListPageSize = 50
	maxListPageSize     = 200
)

// attemptStates are the states a listing may filter on: the values of the
// state column, which are the proto's EffectAttemptState without its prefix
// and without UNSPECIFIED.
var attemptStates = map[string]bool{
	"PROPOSED": true, "DENIED": true, "ESCALATED": true, "APPROVED": true, "REJECTED": true, "EXPIRED": true,
	"ADMITTED": true, "CANCELLED": true, "DISPATCHING": true, "DISPATCHED": true, "UNKNOWN": true,
	"OBSERVED": true, "RECONCILED": true, "ESCALATED_TO_HUMAN": true, "SETTLED": true, "COMPENSATED": true,
}

// ListInput is a ListAttemptsRequest. Every filter narrows; none reaches
// outside the caller's tenant and workspace.
type ListInput struct {
	// States keeps the attempts in any of these states, named as stored
	// (ESCALATED, ADMITTED, ...). Empty: every state.
	States []string
	// CommitmentID or CaseID keeps the attempts serving that work reference.
	// At most one is set.
	CommitmentID string
	CaseID       string
	// RequesterPrincipalID keeps the attempts that principal proposed.
	RequesterPrincipalID string
	// EffectType keeps the attempts of that effect type.
	EffectType string
	// EpisodeID keeps the attempts proposed in that episode. Like every filter
	// it only narrows: a caller with an episode claim lists its own episode's
	// attempts, the ones its own principal proposed, whatever it sets here.
	EpisodeID string
	// UpdatedAfter keeps the attempts whose updated_at is later, exclusive:
	// the incremental cursor.
	UpdatedAfter *time.Time
	// PageSize is 1 to 200; 0 means 50.
	PageSize int
	// PageToken is the NextPageToken of the previous page, with the same
	// filters. Empty for the first page.
	PageToken string
}

// settledMargin is added to MaxTransaction to make a listing's SettledBefore:
// a cancelled transaction takes a moment to end.
const settledMargin = 30 * time.Second

// ListResult is one page of attempts.
type ListResult struct {
	// Attempts are as Get returns them, oldest change first.
	Attempts []Attempt
	// NextPageToken is set only when more attempts follow.
	NextPageToken string
	// SettledBefore is the safe resume point of an incremental reader, set on
	// every page, empty and last ones too: database time, MaxTransaction and a
	// margin before the first page's transaction began. Continuation pages
	// retain that watermark so a late commit behind an earlier page's cursor
	// is included by the next incremental traversal. An attempt's updated_at is
	// the time the transaction that last changed it began, and no transaction
	// runs that long, so every attempt updated before it was committed or
	// aborted by the time the page was read: none is listed later with an
	// earlier position.
	SettledBefore time.Time
}

// List returns one page of the caller's attempts that match in, ordered by
// (updated_at, attempt_id). It reads only the caller's tenant and workspace,
// whatever the filters say, and refuses a malformed request before it reads
// anything.
func (s *Service) List(ctx context.Context, caller Caller, in ListInput) (ListResult, error) {
	if err := checkCaller(caller); err != nil {
		return ListResult{}, err
	}
	q, err := parseList(caller, in)
	if err != nil {
		return ListResult{}, err
	}
	statement, args := q.statement(caller)
	var page ListResult
	// One snapshot for the whole page. Under READ COMMITTED an attempt that
	// changed between the keyset read and its own read would come back with
	// an updated_at past the position its page token continues from, and a
	// client that keeps the last updated_at it saw would skip the attempts in
	// between.
	err = s.inTenantWith(ctx, caller.TenantID, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}, func(tx *sql.Tx) error {
		// The database's clock, at the transaction's start: the snapshot the
		// page is read from is no earlier, so what began before this and ran
		// no longer than MaxTransaction is in it.
		if err := tx.QueryRowContext(ctx, `SELECT now() - $1::bigint * interval '1 microsecond'`,
			(s.cfg.MaxTransaction + settledMargin).Microseconds()).Scan(&page.SettledBefore); err != nil {
			return err
		}
		page.SettledBefore = page.SettledBefore.UTC()
		if q.settledBefore != nil {
			if q.settledBefore.After(page.SettledBefore) {
				return refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation, "page_token watermark is later than the database's safe resume point")
			}
			page.SettledBefore = *q.settledBefore
		}
		found, err := listPositions(ctx, tx, statement, args)
		if err != nil {
			return err
		}
		// One row past the page says whether more follows.
		more := len(found) > q.pageSize
		if more {
			found = found[:q.pageSize]
		}
		for _, p := range found {
			a, err := loadAttempt(ctx, tx, caller, p.id.String())
			if errors.Is(err, errNotFound) {
				// Not a not_found of the caller's: the snapshot listed it.
				return fmt.Errorf("attempt %s vanished from its own snapshot", p.id)
			}
			if err != nil {
				return err
			}
			page.Attempts = append(page.Attempts, a)
		}
		if more {
			page.NextPageToken = encodePageToken(found[len(found)-1], q.digest, page.SettledBefore)
		}
		return nil
	})
	if err != nil {
		return ListResult{}, err
	}
	return page, nil
}

// listPosition is where an attempt sits in the listing order. updatedAt has
// the microsecond precision of a timestamptz.
type listPosition struct {
	updatedAt time.Time
	id        uuid.UUID
}

func listPositions(ctx context.Context, tx *sql.Tx, statement string, args []any) ([]listPosition, error) {
	rows, err := tx.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var found []listPosition
	for rows.Next() {
		var p listPosition
		if err := rows.Scan(&p.id, &p.updatedAt); err != nil {
			return nil, err
		}
		p.updatedAt = p.updatedAt.UTC()
		found = append(found, p)
	}
	return found, rows.Err()
}

// listQuery is a ListInput that passed validation.
type listQuery struct {
	states       []string // distinct and sorted
	commitmentID string
	caseID       string
	requester    string
	effectType   string
	episodeID    string // the filter
	episodeScope string // the caller's own episode, which restricts it
	// episodePrincipal is the caller's principal, which an episode restricts the
	// listing to as well; set with episodeScope.
	episodePrincipal string
	after            *time.Time // in UTC, truncated to the microsecond
	pageSize         int
	cursor           *listPosition // where the page token continues, if there is one
	settledBefore    *time.Time    // safe resume point captured by the first page
	digest           []byte        // of the filters and the scope a page token belongs to
}

// parseList validates in, before anything is read, and binds its page token
// to its filters.
func parseList(caller Caller, in ListInput) (listQuery, error) {
	bad := func(format string, args ...any) error {
		return refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation, format, args...)
	}
	q := listQuery{commitmentID: in.CommitmentID, caseID: in.CaseID, requester: in.RequesterPrincipalID, effectType: in.EffectType,
		episodeID: in.EpisodeID, episodeScope: episodeScope(caller)}
	if q.episodeScope != "" {
		q.episodePrincipal = caller.PrincipalID
	}
	for _, state := range in.States {
		if !attemptStates[state] {
			return q, bad("states holds a state that is not an attempt state")
		}
	}
	q.states = slices.Clone(in.States)
	slices.Sort(q.states)
	q.states = slices.Compact(q.states)
	switch {
	case in.CommitmentID != "" && in.CaseID != "":
		return q, bad("set one of commitment_id and case_id")
	case !listValueOK(in.CommitmentID) || !listValueOK(in.CaseID):
		return q, bad("commitment_id and case_id are at most %d bytes of UTF-8 without NUL", maxWorkRefBytes)
	case !listValueOK(in.RequesterPrincipalID):
		return q, bad("requester_principal_id is at most %d bytes of UTF-8 without NUL", maxWorkRefBytes)
	case !listValueOK(in.EpisodeID):
		return q, bad("episode_id is at most %d bytes of UTF-8 without NUL", maxWorkRefBytes)
	case in.EffectType != "" && !effectTypePattern.MatchString(in.EffectType):
		return q, bad("effect_type is not an effect type")
	}
	if in.UpdatedAfter != nil {
		t := in.UpdatedAfter.UTC()
		if year := t.Year(); year < 1 || year > 9999 {
			return q, bad("updated_after is not a valid timestamp")
		}
		// updated_at is whole microseconds, so "later than t" is "later than t
		// rounded down": the exclusive bound stays exact, where PostgreSQL
		// would round the parameter to the nearest microsecond.
		t = t.Truncate(time.Microsecond)
		q.after = &t
	}
	switch {
	case in.PageSize < 0 || in.PageSize > maxListPageSize:
		return q, bad("page_size is 1 to %d, or 0 for %d", maxListPageSize, defaultListPageSize)
	case in.PageSize == 0:
		q.pageSize = defaultListPageSize
	default:
		q.pageSize = in.PageSize
	}
	q.digest = listFilterDigest(caller, q)
	if in.PageToken != "" {
		cursor, settled, err := decodePageToken(in.PageToken, q.digest)
		if err != nil {
			return q, err
		}
		q.cursor = &cursor
		q.settledBefore = &settled
	}
	return q, nil
}

// listValueOK reports whether v can be a filter on a stored identifier: at
// most maxWorkRefBytes of UTF-8, and no NUL, which PostgreSQL text cannot
// hold. Empty means no filter.
func listValueOK(v string) bool {
	return len(v) <= maxWorkRefBytes && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
}

// statement is the keyset query: the caller's tenant and workspace, the
// filters, and everything after the cursor, one row past the page. Every value
// is a bound parameter.
//
// ponytail: it is served in order by authority_effect_attempts_by_update
// (migration 1), so a page costs the page. A filter that few attempts match
// is applied to the rows of that index range in order, so it costs the
// workspace's history: about 50 ms per 300,000 attempts measured for a state
// none is in. Upgrade to a partial index on the states that await someone
// (ESCALATED, UNKNOWN, ESCALATED_TO_HUMAN) when the Console's inbox poll
// shows it, and create it while the table is small: migrations run in one
// transaction, which rules out CREATE INDEX CONCURRENTLY.
func (q listQuery) statement(caller Caller) (string, []any) {
	query := `SELECT attempt_id, updated_at FROM authority_effect_attempts WHERE tenant_id = $1 AND workspace_id = $2`
	args := []any{caller.TenantID, caller.WorkspaceID}
	and := func(condition string, value any) {
		args = append(args, value)
		query += fmt.Sprintf(" AND "+condition, len(args))
	}
	if len(q.states) > 0 {
		and("state = ANY($%d)", pq.Array(q.states))
	}
	if q.commitmentID != "" {
		and("commitment_id = $%d", q.commitmentID)
	}
	if q.caseID != "" {
		and("case_id = $%d", q.caseID)
	}
	if q.requester != "" {
		and("requester_principal_id = $%d", q.requester)
	}
	if q.effectType != "" {
		and("effect_type = $%d", q.effectType)
	}
	if q.episodeID != "" {
		and("episode_id = $%d", q.episodeID)
	}
	if q.episodeScope != "" {
		// The caller's own episode, and the attempts its own principal proposed.
		and("episode_id = $%d", q.episodeScope)
		and("requester_principal_id = $%d", q.episodePrincipal)
	}
	if q.after != nil {
		and("updated_at > $%d", *q.after)
	}
	if q.cursor != nil {
		args = append(args, q.cursor.updatedAt, q.cursor.id.String())
		query += fmt.Sprintf(" AND (updated_at, attempt_id) > ($%d::timestamptz, $%d::uuid)", len(args)-1, len(args))
	}
	args = append(args, q.pageSize+1)
	query += fmt.Sprintf(" ORDER BY updated_at, attempt_id LIMIT $%d", len(args))
	return query, args
}

// listFilterDigest is the digest a page token binds to: the caller's tenant
// and workspace and every filter, in one length-prefixed encoding. The states
// are a set, so their order and repeats do not change it, and updated_after
// counts at the microsecond it is compared at. page_size is not a filter: a
// caller may change it between pages.
func listFilterDigest(caller Caller, q listQuery) []byte {
	var m bytes.Buffer
	field(&m, []byte("helm.gateway.v1.list-attempts-filters.v1"))
	field(&m, []byte(caller.TenantID))
	field(&m, []byte(caller.WorkspaceID))
	u64(&m, uint64(len(q.states)))
	for _, state := range q.states {
		field(&m, []byte(state))
	}
	field(&m, []byte(q.commitmentID))
	field(&m, []byte(q.caseID))
	field(&m, []byte(q.requester))
	field(&m, []byte(q.effectType))
	after := ""
	if q.after != nil {
		after = q.after.Format("2006-01-02T15:04:05.000000Z")
	}
	field(&m, []byte(after))
	// The episode filter and the caller's episode, only when there is one, so
	// the digest of every other listing, and the tokens issued for it, are
	// unchanged.
	if q.episodeID != "" || q.episodeScope != "" {
		field(&m, []byte(q.episodeID))
		field(&m, []byte(q.episodeScope))
		field(&m, []byte(q.episodePrincipal))
	}
	sum := sha256.Sum256(m.Bytes())
	return sum[:]
}

// A page token is opaque to callers: base64url of a version byte, the last
// attempt's updated_at as big-endian microseconds since the Unix epoch, its
// attempt_id, the first page's settled_before, and the digest of its filters.
const (
	pageTokenVersion = 2
	pageTokenSize    = 1 + 8 + 16 + 8 + sha256.Size
)

func encodePageToken(last listPosition, filters []byte, settledBefore time.Time) string {
	var raw bytes.Buffer
	raw.WriteByte(pageTokenVersion)
	_ = binary.Write(&raw, binary.BigEndian, last.updatedAt.UnixMicro()) // a bytes.Buffer does not fail
	raw.Write(last.id[:])
	_ = binary.Write(&raw, binary.BigEndian, settledBefore.UnixMicro())
	raw.Write(filters)
	return base64.RawURLEncoding.EncodeToString(raw.Bytes())
}

// decodePageToken returns the position token continues from. A token this
// listing did not issue, one for another set of filters or scope, and a
// malformed one are invalid_argument.
func decodePageToken(token string, filters []byte) (listPosition, time.Time, error) {
	malformed := refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation, "page_token is not a page token of this gateway")
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	// Re-encoding refuses what the decoder tolerates, such as a newline in the
	// middle, so a position has one spelling.
	if err != nil || len(raw) != pageTokenSize || raw[0] != pageTokenVersion || base64.RawURLEncoding.EncodeToString(raw) != token {
		return listPosition{}, time.Time{}, malformed
	}
	if !bytes.Equal(raw[pageTokenSize-sha256.Size:], filters) {
		return listPosition{}, time.Time{}, refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation,
			"page_token belongs to another set of filters: repeat the request without it")
	}
	var micros int64
	_ = binary.Read(bytes.NewReader(raw[1:9]), binary.BigEndian, &micros) // eight bytes are there
	at := time.UnixMicro(micros).UTC()
	if year := at.Year(); year < 1 || year > 9999 {
		return listPosition{}, time.Time{}, malformed
	}
	var watermarkMicros int64
	_ = binary.Read(bytes.NewReader(raw[25:33]), binary.BigEndian, &watermarkMicros)
	watermark := time.UnixMicro(watermarkMicros).UTC()
	if year := watermark.Year(); year < 1 || year > 9999 || watermark.IsZero() {
		return listPosition{}, time.Time{}, malformed
	}
	var last listPosition
	last.updatedAt = at
	copy(last.id[:], raw[9:25])
	return last, watermark, nil
}
