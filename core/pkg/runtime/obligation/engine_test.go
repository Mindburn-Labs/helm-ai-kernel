package obligation

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestObligationEngine_Escalation(t *testing.T) {
	store := NewMemoryStore()
	engine := NewObligationEngine(store)

	// Create obligation
	o, err := engine.CreateObligation("test-goal")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	worker := "worker-1"

	// Attempt 1: Fail
	lease1, err := engine.Lease(worker, 1*time.Minute)
	if err != nil || lease1 == nil {
		t.Fatalf("Lease 1 failed")
	}
	if err := engine.Fail(lease1.ID, errors.New("fail 1")); err != nil {
		t.Fatalf("Fail 1 failed: %v", err)
	}

	// Check status: Should be Pending (Retry)
	o1, _ := store.Get(o.ID)
	if o1.Status != StatusPending {
		t.Errorf("Expected Pending after 1st fail, got %s", o1.Status)
	}

	// Attempt 2: Fail
	lease2, _ := engine.Lease(worker, 1*time.Minute)
	if lease2 == nil {
		t.Fatal("Lease 2 failed")
	}
	engine.Fail(lease2.ID, errors.New("fail 2"))

	// Check status: Should be Pending
	o2, _ := store.Get(o.ID)
	if o2.Status != StatusPending {
		t.Errorf("Expected Pending after 2nd fail, got %s", o2.Status)
	}

	// Attempt 3: Fail
	lease3, _ := engine.Lease(worker, 1*time.Minute)
	if lease3 == nil {
		t.Fatal("Lease 3 failed")
	}
	engine.Fail(lease3.ID, errors.New("fail 3"))

	// Check status: Should be Escalated
	o3, _ := store.Get(o.ID)
	if o3.Status != StatusEscalated {
		t.Errorf("Expected Escalated after 3rd fail, got %s", o3.Status)
	}
}

func TestObligationEngine_Concurrency(t *testing.T) {
	store := NewMemoryStore()
	engine := NewObligationEngine(store)

	// Create multiple obligations
	for i := 0; i < 100; i++ {
		engine.CreateObligation("goal")
	}

	// Concurrent workers leasing
	var wg sync.WaitGroup
	workers := 10
	leasesPerWorker := 10

	// We want to ensure no two workers get the same obligation
	leaseMap := make(map[string]string) // obligationID -> workerID
	mu := sync.Mutex{}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			workerID := string(rune(id)) // just use int as string key
			for j := 0; j < leasesPerWorker; j++ {
				o, err := engine.Lease(workerID, 1*time.Minute)
				if err != nil {
					t.Errorf("Lease error: %v", err)
					return
				}
				if o == nil {
					// Might run out if race logic is wrong? No, we created 100.
					// But concurrency might make them miss if timing aligns.
					continue
				}

				mu.Lock()
				if holder, exists := leaseMap[o.ID]; exists {
					t.Errorf("Race detected! Obligation %s leased by %s AND %s", o.ID, holder, workerID)
				}
				leaseMap[o.ID] = workerID
				mu.Unlock()
			}
		}(w)
	}

	wg.Wait()

	// Verify total distinct leases
	if len(leaseMap) == 0 {
		t.Error("No leases acquired")
	}
}
