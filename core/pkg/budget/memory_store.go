package budget

import (
	"sync"
)

// MemoryStorage implements Storage in memory.
// Thread-safe via RWMutex.
type MemoryStorage struct {
	mu      sync.RWMutex
	budgets map[string]*Budget
	limits  map[string]struct{ d, m int64 }
}
