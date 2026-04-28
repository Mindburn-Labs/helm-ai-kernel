// resolver.go — multi-method DID resolver with TTL cache.
//
// The Resolver dispatches to a registered Method driver by inspecting the
// `did:<method>:<identifier>` prefix. Drivers are pluggable so individual
// methods (web, key, jwk, plc) can be unit-tested in isolation.
//
// Resolved documents are cached in-memory with per-entry TTLs. The cache
// is keyed by full DID string, so two requests for the same DID share the
// same document until the TTL expires. The cache is also persistable via
// an injected Keystore — that lets the kernel survive a restart without
// re-fetching every did:web document from the network.
//
// Concurrency: the resolver is safe for concurrent use. Method drivers are
// expected to be stateless or to manage their own locking.

package did

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Method drives DID resolution for a single DID method.
//
// Implementations live under did/method/{web,key,jwk,plc}/ and never
// reference each other.
type Method interface {
	// Name returns the method-specific name, e.g. "web", "key", "jwk", "plc".
	Name() string

	// Resolve returns the DID Document for the supplied DID. The driver may
	// fetch over the network (did:web, did:plc) or compute the document from
	// the identifier (did:key, did:jwk).
	Resolve(ctx context.Context, did string) (*ResolvedDocument, error)
}

// Keystore is the minimal interface the resolver needs to persist cached
// documents. The kernel keystore (see core/pkg/identity/file_store.go) does
// not currently expose this surface; consumers wire an in-memory or
// project-local store as needed.
type Keystore interface {
	GetDIDDocument(did string) (*ResolvedDocument, time.Time, bool)
	PutDIDDocument(did string, doc *ResolvedDocument, expiresAt time.Time) error
}

// cacheEntry is the in-memory cache representation.
type cacheEntry struct {
	Document  *ResolvedDocument
	ExpiresAt time.Time
}

// Resolver is the multi-method DID resolver.
type Resolver struct {
	mu       sync.RWMutex
	methods  map[string]Method
	cache    map[string]cacheEntry
	keystore Keystore
	ttl      time.Duration
	clock    func() time.Time
}

// ResolverOption configures a Resolver.
type ResolverOption func(*Resolver)

// WithCacheTTL overrides the default cache TTL (5 minutes).
func WithCacheTTL(ttl time.Duration) ResolverOption {
	return func(r *Resolver) { r.ttl = ttl }
}

// WithKeystore wires a persistent keystore for cross-restart caching.
func WithKeystore(ks Keystore) ResolverOption {
	return func(r *Resolver) { r.keystore = ks }
}

// WithClock injects a deterministic clock for testing.
func WithClock(clock func() time.Time) ResolverOption {
	return func(r *Resolver) { r.clock = clock }
}

// NewResolver constructs a resolver with no methods registered. Call
// Register to attach drivers.
func NewResolver(opts ...ResolverOption) *Resolver {
	r := &Resolver{
		methods: make(map[string]Method),
		cache:   make(map[string]cacheEntry),
		ttl:     5 * time.Minute,
		clock:   time.Now,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Register adds a method driver. Re-registering an existing method
// replaces the previous driver.
func (r *Resolver) Register(m Method) {
	if m == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.methods[m.Name()] = m
}

// Methods returns the registered method names in stable order.
func (r *Resolver) Methods() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.methods))
	for name := range r.methods {
		names = append(names, name)
	}
	return names
}

// Resolve returns the DID Document for the given DID, hitting the cache
// first and falling back to the registered method driver.
func (r *Resolver) Resolve(ctx context.Context, didURI string) (*ResolvedDocument, error) {
	if didURI == "" {
		return nil, errors.New("did: empty DID")
	}

	method, _, err := ParseDID(didURI)
	if err != nil {
		return nil, err
	}

	now := r.clock()

	// 1. In-memory cache.
	r.mu.RLock()
	entry, ok := r.cache[didURI]
	r.mu.RUnlock()
	if ok && now.Before(entry.ExpiresAt) {
		return entry.Document, nil
	}

	// 2. Persistent keystore cache.
	if r.keystore != nil {
		if doc, expiresAt, found := r.keystore.GetDIDDocument(didURI); found && now.Before(expiresAt) {
			r.mu.Lock()
			r.cache[didURI] = cacheEntry{Document: doc, ExpiresAt: expiresAt}
			r.mu.Unlock()
			return doc, nil
		}
	}

	// 3. Method-driver dispatch.
	r.mu.RLock()
	driver, ok := r.methods[method]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("did: no driver registered for method %q", method)
	}

	doc, err := driver.Resolve(ctx, didURI)
	if err != nil {
		return nil, fmt.Errorf("did: %s resolver: %w", method, err)
	}
	if doc == nil {
		return nil, fmt.Errorf("did: %s resolver returned nil document", method)
	}

	// 4. Cache write-through.
	expiresAt := now.Add(r.ttl)
	r.mu.Lock()
	r.cache[didURI] = cacheEntry{Document: doc, ExpiresAt: expiresAt}
	r.mu.Unlock()

	if r.keystore != nil {
		// Best-effort: persistence failure must not break resolution.
		_ = r.keystore.PutDIDDocument(didURI, doc, expiresAt)
	}

	return doc, nil
}

// Invalidate drops a cached entry. Intended for rotation flows.
func (r *Resolver) Invalidate(didURI string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.cache, didURI)
}

// ── In-memory keystore (for tests and dev flows) ────────────────

// MemoryKeystore is a Keystore backed by a single map. Useful for tests
// and ephemeral kernels; production deployments should plug a persistent
// store.
type MemoryKeystore struct {
	mu sync.RWMutex
	m  map[string]cacheEntry
}

// NewMemoryKeystore returns a fresh in-memory keystore.
func NewMemoryKeystore() *MemoryKeystore {
	return &MemoryKeystore{m: make(map[string]cacheEntry)}
}

// GetDIDDocument retrieves a cached document.
func (k *MemoryKeystore) GetDIDDocument(did string) (*ResolvedDocument, time.Time, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	e, ok := k.m[did]
	if !ok {
		return nil, time.Time{}, false
	}
	return e.Document, e.ExpiresAt, true
}

// PutDIDDocument writes a document to the cache.
func (k *MemoryKeystore) PutDIDDocument(did string, doc *ResolvedDocument, expiresAt time.Time) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m[did] = cacheEntry{Document: doc, ExpiresAt: expiresAt}
	return nil
}
