package ledger

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

// FileLedger implements Ledger using a local JSON file (for simple durability).
type FileLedger struct {
	path  string
	mu    sync.RWMutex
	data  map[string]Obligation
	clock func() time.Time // Injectable clock
}

func NewFileLedger(path string) (*FileLedger, error) {
	return NewFileLedgerWithClock(path, time.Now)
}

func NewFileLedgerWithClock(path string, clock func() time.Time) (*FileLedger, error) {
	fl := &FileLedger{
		path:  path,
		data:  make(map[string]Obligation),
		clock: clock,
	}
	if err := fl.load(); err != nil {
		return nil, err
	}
	return fl, nil
}

func (f *FileLedger) load() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, err := os.Stat(f.path); os.IsNotExist(err) {
		return nil // Start empty
	}

	bytes, err := os.ReadFile(f.path)
	if err != nil {
		return err
	}

	return json.Unmarshal(bytes, &f.data)
}

func (f *FileLedger) save() error {
	bytes, err := json.MarshalIndent(f.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(f.path, bytes, 0600)
}

func (f *FileLedger) Create(ctx context.Context, obl Obligation) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, exists := f.data[obl.ID]; exists {
		return errors.New("obligation exists")
	}

	obl.CreatedAt = f.clock()
	obl.UpdatedAt = f.clock()
	obl.State = StatePending

	f.data[obl.ID] = obl
	return f.save()
}

func (f *FileLedger) Get(ctx context.Context, id string) (Obligation, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	obl, exists := f.data[id]
	if !exists {
		return Obligation{}, ErrNotFound
	}
	return obl, nil
}

func (f *FileLedger) AcquireLease(ctx context.Context, id, workerID string, duration time.Duration) (Obligation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	obl, exists := f.data[id]
	if !exists {
		return Obligation{}, ErrNotFound
	}

	now := f.clock()
	if obl.LeasedUntil.After(now) && obl.LeasedBy != workerID {
		return obl, errors.New("locked by another worker")
	}

	obl.LeasedBy = workerID
	obl.LeasedUntil = now.Add(duration)
	obl.UpdatedAt = now
	f.data[id] = obl

	if err := f.save(); err != nil {
		return obl, err
	}
	return obl, nil
}

func (f *FileLedger) UpdateState(ctx context.Context, id string, newState State, details map[string]any) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	obl, exists := f.data[id]
	if !exists {
		return ErrNotFound
	}

	obl.State = newState
	obl.UpdatedAt = f.clock()
	f.data[id] = obl

	return f.save()
}

func (f *FileLedger) ListPending(ctx context.Context) ([]Obligation, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var pending []Obligation
	for _, obl := range f.data {
		// Include PENDING and FAILED (for retry purposes if we auto-retry FAILED)
		// Specifically for DLQ test, we need to pick up PENDING ones.
		// The test sets RetryCount=3 and State=PENDING.
		if obl.State == StatePending {
			pending = append(pending, obl)
		}
	}
	return pending, nil
}

func (f *FileLedger) ListAll(ctx context.Context) ([]Obligation, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	list := make([]Obligation, 0, len(f.data))
	for _, obl := range f.data {
		list = append(list, obl)
	}
	return list, nil
}
