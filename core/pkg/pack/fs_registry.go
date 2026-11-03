package pack

import (
	"sync"
)

// FSRegistry implements PackRegistry using a file system directory.
// Structure: <root>/<pack_id>/<version>/manifest.json
type FSRegistry struct {
	rootDir string
	mu      sync.RWMutex
}
