package pack

import (
	"sync"
)

// FSRegistry retains the root directory of the former filesystem pack registry.
type FSRegistry struct {
	rootDir string
	mu      sync.RWMutex
}
