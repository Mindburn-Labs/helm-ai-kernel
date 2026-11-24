package budget

import (
	"sync"
)

// MemoryStorage preserves the type of the retired in-memory budget store.
type MemoryStorage struct {
	mu      sync.RWMutex
	budgets map[string]*Budget
	limits  map[string]struct{ d, m int64 }
}
