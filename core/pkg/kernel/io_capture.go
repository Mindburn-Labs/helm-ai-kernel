// Package kernel provides external I/O capture for deterministic replay.
// Per Section 2.5 - External I/O Capture
package kernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

// IORecord captures a single external I/O interaction.
type IORecord struct {
	RecordID      string    `json:"record_id"`
	OperationType string    `json:"operation_type"` // http_request, http_response, db_query, etc.
	Timestamp     time.Time `json:"timestamp"`

	// Request details
	RequestHash     string            `json:"request_hash"`
	RequestMethod   string            `json:"request_method,omitempty"`
	RequestURL      string            `json:"request_url,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	RequestBodyHash string            `json:"request_body_hash,omitempty"`

	// Response details
	ResponseHash     string            `json:"response_hash,omitempty"`
	ResponseStatus   int               `json:"response_status,omitempty"`
	ResponseHeaders  map[string]string `json:"response_headers,omitempty"`
	ResponseBodyHash string            `json:"response_body_hash,omitempty"`

	// Retry tracking
	RetryAttempt int    `json:"retry_attempt"`
	RetryDelay   string `json:"retry_delay,omitempty"`
	RetryReason  string `json:"retry_reason,omitempty"`

	// Idempotency
	IdempotencyKey string `json:"idempotency_key,omitempty"`

	// Redaction
	RedactedFields      []string `json:"redacted_fields,omitempty"`
	RedactionCommitment string   `json:"redaction_commitment,omitempty"`

	// Correlation
	EffectID string `json:"effect_id,omitempty"`
	LoopID   string `json:"loop_id,omitempty"`

	// Timing
	DurationMs int64 `json:"duration_ms,omitempty"`
}

// IOCaptureStore stores and retrieves I/O records.
type IOCaptureStore interface {
	// Record stores an I/O record.
	Record(ctx context.Context, record *IORecord) error

	// Get retrieves a record by ID.
	Get(ctx context.Context, recordID string) (*IORecord, error)

	// ListByEffect returns all records for an effect.
	ListByEffect(ctx context.Context, effectID string) ([]*IORecord, error)

	// ListByLoop returns all records for a control loop.
	ListByLoop(ctx context.Context, loopID string) ([]*IORecord, error)
}

// InMemoryIOCaptureStore provides in-memory I/O capture.
type InMemoryIOCaptureStore struct {
	mu       sync.RWMutex
	records  map[string]*IORecord
	byEffect map[string][]string // effectID -> recordIDs
	byLoop   map[string][]string // loopID -> recordIDs
}

// NewInMemoryIOCaptureStore creates a new I/O capture store.
func NewInMemoryIOCaptureStore() *InMemoryIOCaptureStore {
	return &InMemoryIOCaptureStore{
		records:  make(map[string]*IORecord),
		byEffect: make(map[string][]string),
		byLoop:   make(map[string][]string),
	}
}

// Record implements IOCaptureStore.
func (s *InMemoryIOCaptureStore) Record(ctx context.Context, record *IORecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records[record.RecordID] = record

	if record.EffectID != "" {
		s.byEffect[record.EffectID] = append(s.byEffect[record.EffectID], record.RecordID)
	}
	if record.LoopID != "" {
		s.byLoop[record.LoopID] = append(s.byLoop[record.LoopID], record.RecordID)
	}

	return nil
}

// Get implements IOCaptureStore.
func (s *InMemoryIOCaptureStore) Get(ctx context.Context, recordID string) (*IORecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if record, ok := s.records[recordID]; ok {
		return record, nil
	}
	return nil, nil
}

// ListByEffect implements IOCaptureStore.
func (s *InMemoryIOCaptureStore) ListByEffect(ctx context.Context, effectID string) ([]*IORecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := s.byEffect[effectID]
	records := make([]*IORecord, 0, len(ids))
	for _, id := range ids {
		if r, ok := s.records[id]; ok {
			records = append(records, r)
		}
	}
	return records, nil
}

// ListByLoop implements IOCaptureStore.
func (s *InMemoryIOCaptureStore) ListByLoop(ctx context.Context, loopID string) ([]*IORecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := s.byLoop[loopID]
	records := make([]*IORecord, 0, len(ids))
	for _, id := range ids {
		if r, ok := s.records[id]; ok {
			records = append(records, r)
		}
	}
	return records, nil
}

// IOInterceptor intercepts and captures external I/O.
type IOInterceptor struct {
	store IOCaptureStore
	log   EventLog
}

// NewIOInterceptor creates a new I/O interceptor.
func NewIOInterceptor(store IOCaptureStore, log EventLog) *IOInterceptor {
	return &IOInterceptor{
		store: store,
		log:   log,
	}
}

// CaptureRequest captures an outgoing request.
func (i *IOInterceptor) CaptureRequest(ctx context.Context, recordID, effectID, loopID string, req *HTTPRequestCapture) (*IORecord, error) {
	record := &IORecord{
		RecordID:        recordID,
		OperationType:   "http_request",
		Timestamp:       time.Now().UTC(),
		RequestHash:     hashData(req),
		RequestMethod:   req.Method,
		RequestURL:      req.URL,
		RequestHeaders:  req.Headers,
		RequestBodyHash: hashBytes(req.Body),
		EffectID:        effectID,
		LoopID:          loopID,
		IdempotencyKey:  req.IdempotencyKey,
	}

	if err := i.store.Record(ctx, record); err != nil {
		return nil, err
	}

	// Log to event log
	if i.log != nil {
		_, _ = i.log.Append(ctx, &EventEnvelope{
			EventID:   "io-" + recordID,
			EventType: "io.request",
			Payload: map[string]interface{}{
				"record_id":       recordID,
				"effect_id":       effectID,
				"request_hash":    record.RequestHash,
				"idempotency_key": req.IdempotencyKey,
			},
		})
	}

	return record, nil
}

// CaptureResponse captures an incoming response.
func (i *IOInterceptor) CaptureResponse(ctx context.Context, record *IORecord, resp *HTTPResponseCapture, durationMs int64) error {
	record.ResponseHash = hashData(resp)
	record.ResponseStatus = resp.StatusCode
	record.ResponseHeaders = resp.Headers
	record.ResponseBodyHash = hashBytes(resp.Body)
	record.DurationMs = durationMs

	if err := i.store.Record(ctx, record); err != nil {
		return err
	}

	// Log to event log
	if i.log != nil {
		_, _ = i.log.Append(ctx, &EventEnvelope{
			EventID:   "io-resp-" + record.RecordID,
			EventType: "io.response",
			Payload: map[string]interface{}{
				"record_id":     record.RecordID,
				"effect_id":     record.EffectID,
				"response_hash": record.ResponseHash,
				"status_code":   resp.StatusCode,
				"duration_ms":   durationMs,
			},
		})
	}

	return nil
}

// CaptureRetry captures a retry attempt.
func (i *IOInterceptor) CaptureRetry(ctx context.Context, record *IORecord, attempt int, delay time.Duration, reason string) error {
	retryRecord := &IORecord{
		RecordID:       record.RecordID + "-retry-" + string(rune('0'+attempt)),
		OperationType:  "http_retry",
		Timestamp:      time.Now().UTC(),
		RequestHash:    record.RequestHash,
		RetryAttempt:   attempt,
		RetryDelay:     delay.String(),
		RetryReason:    reason,
		EffectID:       record.EffectID,
		LoopID:         record.LoopID,
		IdempotencyKey: record.IdempotencyKey,
	}

	if err := i.store.Record(ctx, retryRecord); err != nil {
		return err
	}

	// Log retry to event log
	if i.log != nil {
		_, _ = i.log.Append(ctx, &EventEnvelope{
			EventID:   "io-retry-" + retryRecord.RecordID,
			EventType: "io.retry",
			Payload: map[string]interface{}{
				"record_id": record.RecordID,
				"effect_id": record.EffectID,
				"attempt":   attempt,
				"delay":     delay.String(),
				"reason":    reason,
			},
		})
	}

	return nil
}

// RedactAndCommit redacts sensitive fields and creates a cryptographic commitment.
func (i *IOInterceptor) RedactAndCommit(record *IORecord, fieldsToRedact []string, originalData map[string]interface{}) string {
	record.RedactedFields = fieldsToRedact

	// Create commitment: hash of original data
	originalJSON, _ := json.Marshal(originalData)
	h := sha256.Sum256(originalJSON)
	commitment := hex.EncodeToString(h[:])
	record.RedactionCommitment = commitment

	return commitment
}

// HTTPRequestCapture captures HTTP request details.
type HTTPRequestCapture struct {
	Method         string
	URL            string
	Headers        map[string]string
	Body           []byte
	IdempotencyKey string
}

// HTTPResponseCapture captures HTTP response details.
type HTTPResponseCapture struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

// hashData creates a hash of any data structure.
func hashData(data interface{}) string {
	jsonData, _ := json.Marshal(data)
	h := sha256.Sum256(jsonData)
	return hex.EncodeToString(h[:])
}

// hashBytes creates a hash of raw bytes.
func hashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
