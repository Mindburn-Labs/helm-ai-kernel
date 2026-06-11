package trust

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust/registry"
)

func TestRegisterRoutes(t *testing.T) {
	handler, _ := newTestHandler()
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/trust/state", nil)
	mux.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("registered state route returned %d: %s", resp.Code, resp.Body.String())
	}
}

func TestHandleGetSnapshot(t *testing.T) {
	handler, store := newTestHandler()

	current := doRequest(handler.HandleGetSnapshot, http.MethodGet, "/v1/trust/snapshot", nil)
	if current.Code != http.StatusOK {
		t.Fatalf("current snapshot status = %d body=%s", current.Code, current.Body.String())
	}
	if decodeMap(t, current)["lamport"].(float64) != 0 {
		t.Fatalf("unexpected current snapshot: %s", current.Body.String())
	}

	currentByName := doRequest(handler.HandleGetSnapshot, http.MethodGet, "/v1/trust/snapshot?lamport=current", nil)
	if currentByName.Code != http.StatusOK {
		t.Fatalf("named current snapshot status = %d", currentByName.Code)
	}

	invalid := doRequest(handler.HandleGetSnapshot, http.MethodGet, "/v1/trust/snapshot?lamport=nope", nil)
	if invalid.Code != http.StatusBadRequest || !strings.Contains(invalid.Body.String(), "invalid lamport parameter") {
		t.Fatalf("expected invalid lamport response, got %d %s", invalid.Code, invalid.Body.String())
	}

	handler.registry.State().Lamport = 10
	future := doRequest(handler.HandleGetSnapshot, http.MethodGet, "/v1/trust/snapshot?lamport=10", nil)
	if future.Code != http.StatusOK {
		t.Fatalf("future/current snapshot status = %d body=%s", future.Code, future.Body.String())
	}

	store.events = []*registry.TrustEvent{tenantRegisterEvent("tenant-1")}
	historical := doRequest(handler.HandleGetSnapshot, http.MethodGet, "/v1/trust/snapshot?lamport=1", nil)
	if historical.Code != http.StatusOK {
		t.Fatalf("historical snapshot status = %d body=%s", historical.Code, historical.Body.String())
	}

	store.getUpToErr = errors.New("get up to failed")
	listErr := doRequest(handler.HandleGetSnapshot, http.MethodGet, "/v1/trust/snapshot?lamport=1", nil)
	if listErr.Code != http.StatusInternalServerError || !strings.Contains(listErr.Body.String(), "failed to load events") {
		t.Fatalf("expected list error, got %d %s", listErr.Code, listErr.Body.String())
	}
	store.getUpToErr = nil

	store.events = []*registry.TrustEvent{{ID: "bad", Lamport: 1, EventType: registry.EventTenantSuspend, SubjectID: "tenant-1", Payload: json.RawMessage(`{"tenant_id":"tenant-1"}`)}}
	reduceErr := doRequest(handler.HandleGetSnapshot, http.MethodGet, "/v1/trust/snapshot?lamport=1", nil)
	if reduceErr.Code != http.StatusInternalServerError || !strings.Contains(reduceErr.Body.String(), "failed to reduce state") {
		t.Fatalf("expected reduce error, got %d %s", reduceErr.Code, reduceErr.Body.String())
	}
}

func TestHandleGetSnapshotCreationError(t *testing.T) {
	handler, _ := newTestHandler()
	restore := replaceSnapshotHook()
	defer restore()

	snapshotFromRegistry = func(*registry.Registry) (*registry.TrustSnapshot, error) {
		return nil, errors.New("snapshot failed")
	}

	resp := doRequest(handler.HandleGetSnapshot, http.MethodGet, "/v1/trust/snapshot", nil)
	if resp.Code != http.StatusInternalServerError || !strings.Contains(resp.Body.String(), "snapshot creation failed") {
		t.Fatalf("expected snapshot creation error, got %d %s", resp.Code, resp.Body.String())
	}
}

func TestHandlePostEvent(t *testing.T) {
	handler, store := newTestHandler()

	badJSON := doRequest(handler.HandlePostEvent, http.MethodPost, "/v1/trust/events", strings.NewReader("{"))
	if badJSON.Code != http.StatusBadRequest || !strings.Contains(badJSON.Body.String(), "invalid event payload") {
		t.Fatalf("expected bad json, got %d %s", badJSON.Code, badJSON.Body.String())
	}

	missingType := doJSON(handler.HandlePostEvent, registry.TrustEvent{SubjectID: "tenant-1"})
	if missingType.Code != http.StatusBadRequest || !strings.Contains(missingType.Body.String(), "event_type is required") {
		t.Fatalf("expected missing event type, got %d %s", missingType.Code, missingType.Body.String())
	}

	missingSubject := doJSON(handler.HandlePostEvent, registry.TrustEvent{EventType: registry.EventTenantRegister})
	if missingSubject.Code != http.StatusBadRequest || !strings.Contains(missingSubject.Body.String(), "subject_id is required") {
		t.Fatalf("expected missing subject, got %d %s", missingSubject.Code, missingSubject.Body.String())
	}

	signer, knownKey := trustTestAuthorKey(t, "kid-known")
	handler.registry.State().Keys["kid-known"] = knownKey
	handler.trustedAuthorPublicKeys = map[string]string{"kid-known": signer.PublicKey()}

	unsigned := doJSON(handler.HandlePostEvent, registry.TrustEvent{
		EventType: registry.EventTenantRegister,
		SubjectID: "tenant-unsigned",
		Payload:   json.RawMessage(`{"tenant_id":"tenant-unsigned"}`),
		AuthorKID: "kid-known",
	})
	if unsigned.Code != http.StatusForbidden || !strings.Contains(unsigned.Body.String(), "author_sig is required") {
		t.Fatalf("expected unsigned event rejected, got %d %s", unsigned.Code, unsigned.Body.String())
	}

	unknownAuthor := doJSON(handler.HandlePostEvent, registry.TrustEvent{
		EventType: registry.EventTenantRegister,
		SubjectID: "tenant-1",
		Payload:   json.RawMessage(`{"tenant_id":"tenant-1"}`),
		AuthorKID: "kid-unknown",
		AuthorSig: "sig",
	})
	if unknownAuthor.Code != http.StatusForbidden || !strings.Contains(unknownAuthor.Body.String(), "author key not found") {
		t.Fatalf("expected forbidden unknown key, got %d %s", unknownAuthor.Code, unknownAuthor.Body.String())
	}

	handler.trustedAuthorPublicKeys = nil
	unconfigured := doJSON(handler.HandlePostEvent, signedTrustEvent(t, signer, registry.TrustEvent{
		ID:        "evt-unconfigured",
		EventType: registry.EventTenantRegister,
		SubjectID: "tenant-unconfigured",
		Payload:   json.RawMessage(`{"tenant_id":"tenant-unconfigured"}`),
		AuthorKID: "kid-known",
	}))
	if unconfigured.Code != http.StatusForbidden || !strings.Contains(unconfigured.Body.String(), "not configured") {
		t.Fatalf("expected unconfigured key rejected, got %d %s", unconfigured.Code, unconfigured.Body.String())
	}
	handler.trustedAuthorPublicKeys = map[string]string{"kid-known": signer.PublicKey()}

	otherSigner, _ := trustTestAuthorKey(t, "kid-other")
	handler.trustedAuthorPublicKeys = map[string]string{"kid-known": otherSigner.PublicKey()}
	hashMismatch := doJSON(handler.HandlePostEvent, signedTrustEvent(t, otherSigner, registry.TrustEvent{
		ID:        "evt-hash-mismatch",
		EventType: registry.EventTenantRegister,
		SubjectID: "tenant-hash-mismatch",
		Payload:   json.RawMessage(`{"tenant_id":"tenant-hash-mismatch"}`),
		AuthorKID: "kid-known",
	}))
	if hashMismatch.Code != http.StatusForbidden || !strings.Contains(hashMismatch.Body.String(), "does not match") {
		t.Fatalf("expected key hash mismatch rejected, got %d %s", hashMismatch.Code, hashMismatch.Body.String())
	}
	handler.trustedAuthorPublicKeys = map[string]string{"kid-known": signer.PublicKey()}

	tampered := signedTrustEvent(t, signer, registry.TrustEvent{
		ID:        "evt-tampered",
		EventType: registry.EventTenantRegister,
		SubjectID: "tenant-tampered",
		Payload:   json.RawMessage(`{"tenant_id":"tenant-tampered"}`),
		AuthorKID: "kid-known",
	})
	tampered.Payload = json.RawMessage(`{"tenant_id":"tenant-attacker"}`)
	tamperedResp := doJSON(handler.HandlePostEvent, tampered)
	if tamperedResp.Code != http.StatusForbidden || !strings.Contains(tamperedResp.Body.String(), "signature verification failed") {
		t.Fatalf("expected tampered payload rejected, got %d %s", tamperedResp.Code, tamperedResp.Body.String())
	}

	store.latestErr = errors.New("latest failed")
	appendErr := doJSON(handler.HandlePostEvent, signedTrustEvent(t, signer, registry.TrustEvent{
		ID:        "evt-append-fail",
		EventType: registry.EventTenantRegister,
		SubjectID: "tenant-1",
		Payload:   json.RawMessage(`{"tenant_id":"tenant-1"}`),
		AuthorKID: "kid-known",
	}))
	if appendErr.Code != http.StatusConflict || !strings.Contains(appendErr.Body.String(), "get latest lamport") {
		t.Fatalf("expected append conflict, got %d %s", appendErr.Code, appendErr.Body.String())
	}
	store.latestErr = nil

	success := doJSON(handler.HandlePostEvent, signedTrustEvent(t, signer, registry.TrustEvent{
		ID:          "evt-1",
		EventType:   registry.EventTenantRegister,
		SubjectID:   "tenant-1",
		SubjectType: "tenant",
		Payload:     json.RawMessage(`{"tenant_id":"tenant-1"}`),
		AuthorKID:   "kid-known",
	}))
	if success.Code != http.StatusCreated {
		t.Fatalf("expected created, got %d %s", success.Code, success.Body.String())
	}
	body := decodeMap(t, success)
	if body["lamport"].(float64) != 1 || body["hash"] == "" {
		t.Fatalf("unexpected success body: %v", body)
	}

	bootstrapHandler, _ := newTestHandler()
	bootstrapSigner, _ := trustTestAuthorKey(t, "kid-bootstrap")
	bootstrap := doJSON(bootstrapHandler.HandlePostEvent, signedTrustEvent(t, bootstrapSigner, registry.TrustEvent{
		ID:        "evt-bootstrap",
		EventType: registry.EventTenantRegister,
		SubjectID: "tenant-bootstrap",
		Payload:   json.RawMessage(`{"tenant_id":"tenant-bootstrap"}`),
		AuthorKID: "kid-bootstrap",
	}))
	if bootstrap.Code != http.StatusForbidden || !strings.Contains(bootstrap.Body.String(), "bootstrapped offline") {
		t.Fatalf("expected bootstrap network write rejected, got %d %s", bootstrap.Code, bootstrap.Body.String())
	}
}

func TestHandleGetState(t *testing.T) {
	handler, _ := newTestHandler()
	handler.registry.State().Lamport = 7

	resp := doRequest(handler.HandleGetState, http.MethodGet, "/v1/trust/state", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("state status = %d", resp.Code)
	}
	if decodeMap(t, resp)["lamport"].(float64) != 7 {
		t.Fatalf("unexpected state body: %s", resp.Body.String())
	}
}

func TestHandleListEvents(t *testing.T) {
	handler, store := newTestHandler()
	store.events = []*registry.TrustEvent{
		{ID: "evt-1", Lamport: 1, SubjectID: "subject-1", EventType: registry.EventTenantRegister},
		{ID: "evt-2", Lamport: 2, SubjectID: "subject-2", EventType: registry.EventTenantRegister},
	}
	handler.registry.State().Lamport = 2

	all := doRequest(handler.HandleListEvents, http.MethodGet, "/v1/trust/events", nil)
	if all.Code != http.StatusOK || len(decodeMap(t, all)["events"].([]any)) != 2 {
		t.Fatalf("unexpected all events response: %d %s", all.Code, all.Body.String())
	}

	since := doRequest(handler.HandleListEvents, http.MethodGet, "/v1/trust/events?since=1", nil)
	if since.Code != http.StatusOK || len(decodeMap(t, since)["events"].([]any)) != 1 {
		t.Fatalf("unexpected since response: %d %s", since.Code, since.Body.String())
	}

	invalidSince := doRequest(handler.HandleListEvents, http.MethodGet, "/v1/trust/events?since=nope", nil)
	if invalidSince.Code != http.StatusBadRequest || !strings.Contains(invalidSince.Body.String(), "invalid since parameter") {
		t.Fatalf("expected invalid since, got %d %s", invalidSince.Code, invalidSince.Body.String())
	}

	subject := doRequest(handler.HandleListEvents, http.MethodGet, "/v1/trust/events?subject=subject-1", nil)
	if subject.Code != http.StatusOK || len(decodeMap(t, subject)["events"].([]any)) != 1 {
		t.Fatalf("unexpected subject response: %d %s", subject.Code, subject.Body.String())
	}

	store.bySubjectErr = errors.New("subject failed")
	subjectErr := doRequest(handler.HandleListEvents, http.MethodGet, "/v1/trust/events?subject=subject-1", nil)
	if subjectErr.Code != http.StatusInternalServerError || !strings.Contains(subjectErr.Body.String(), "failed to list events") {
		t.Fatalf("expected subject list error, got %d %s", subjectErr.Code, subjectErr.Body.String())
	}
	store.bySubjectErr = nil

	store.getAllErr = errors.New("all failed")
	allErr := doRequest(handler.HandleListEvents, http.MethodGet, "/v1/trust/events", nil)
	if allErr.Code != http.StatusInternalServerError || !strings.Contains(allErr.Body.String(), "failed to list events") {
		t.Fatalf("expected all list error, got %d %s", allErr.Code, allErr.Body.String())
	}
}

type fakeEventStore struct {
	events       []*registry.TrustEvent
	appendErr    error
	getAllErr    error
	getSinceErr  error
	getUpToErr   error
	bySubjectErr error
	latestErr    error
}

func (s *fakeEventStore) Append(_ context.Context, event *registry.TrustEvent) error {
	if s.appendErr != nil {
		return s.appendErr
	}
	cp := *event
	s.events = append(s.events, &cp)
	return nil
}

func (s *fakeEventStore) GetAll(context.Context) ([]*registry.TrustEvent, error) {
	if s.getAllErr != nil {
		return nil, s.getAllErr
	}
	return cloneEvents(s.events), nil
}

func (s *fakeEventStore) GetSince(_ context.Context, afterLamport uint64) ([]*registry.TrustEvent, error) {
	if s.getSinceErr != nil {
		return nil, s.getSinceErr
	}
	var out []*registry.TrustEvent
	for _, event := range s.events {
		if event.Lamport > afterLamport {
			out = append(out, cloneEvent(event))
		}
	}
	return out, nil
}

func (s *fakeEventStore) GetUpTo(_ context.Context, upToLamport uint64) ([]*registry.TrustEvent, error) {
	if s.getUpToErr != nil {
		return nil, s.getUpToErr
	}
	var out []*registry.TrustEvent
	for _, event := range s.events {
		if event.Lamport <= upToLamport {
			out = append(out, cloneEvent(event))
		}
	}
	return out, nil
}

func (s *fakeEventStore) GetBySubject(_ context.Context, subjectID string) ([]*registry.TrustEvent, error) {
	if s.bySubjectErr != nil {
		return nil, s.bySubjectErr
	}
	var out []*registry.TrustEvent
	for _, event := range s.events {
		if event.SubjectID == subjectID {
			out = append(out, cloneEvent(event))
		}
	}
	return out, nil
}

func (s *fakeEventStore) LatestLamport(context.Context) (uint64, error) {
	if s.latestErr != nil {
		return 0, s.latestErr
	}
	var latest uint64
	for _, event := range s.events {
		if event.Lamport > latest {
			latest = event.Lamport
		}
	}
	return latest, nil
}

func newTestHandler() (*Handler, *fakeEventStore) {
	store := &fakeEventStore{}
	return NewHandler(registry.NewRegistry(store), slog.New(slog.NewTextHandler(io.Discard, nil))), store
}

func doJSON(handler http.HandlerFunc, value any) *httptest.ResponseRecorder {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return doRequest(handler, http.MethodPost, "/v1/trust/events", bytes.NewReader(data))
}

func doRequest(handler http.HandlerFunc, method, target string, body io.Reader) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(method, target, body)
	handler(recorder, req)
	return recorder
}

func decodeMap(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", recorder.Body.String(), err)
	}
	return out
}

func tenantRegisterEvent(tenantID string) *registry.TrustEvent {
	return &registry.TrustEvent{
		ID:          "evt-" + tenantID,
		Lamport:     1,
		EventType:   registry.EventTenantRegister,
		SubjectID:   tenantID,
		SubjectType: "tenant",
		Payload:     json.RawMessage(`{"tenant_id":"` + tenantID + `"}`),
	}
}

func trustTestAuthorKey(t *testing.T, kid string) (*helmcrypto.Ed25519Signer, registry.KeyEntry) {
	t.Helper()
	signer, err := helmcrypto.NewEd25519Signer(kid)
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	return signer, registry.KeyEntry{
		KID:           kid,
		Algorithm:     "ed25519",
		PublicKeyHash: ed25519PublicKeyHash(signer.PublicKey()),
		OwnerDID:      "did:helm:test",
	}
}

func signedTrustEvent(t *testing.T, signer *helmcrypto.Ed25519Signer, event registry.TrustEvent) registry.TrustEvent {
	t.Helper()
	sig, err := signer.Sign(TrustEventAuthorSignatureMaterial(event))
	if err != nil {
		t.Fatalf("sign trust event: %v", err)
	}
	event.AuthorSig = sig
	return event
}

func cloneEvents(events []*registry.TrustEvent) []*registry.TrustEvent {
	out := make([]*registry.TrustEvent, 0, len(events))
	for _, event := range events {
		out = append(out, cloneEvent(event))
	}
	return out
}

func cloneEvent(event *registry.TrustEvent) *registry.TrustEvent {
	if event == nil {
		return nil
	}
	cp := *event
	cp.Payload = append(json.RawMessage(nil), event.Payload...)
	return &cp
}

func replaceSnapshotHook() func() {
	original := snapshotFromRegistry
	return func() { snapshotFromRegistry = original }
}
