package crypto

import (
	"hash"
	"io"
	"sync"
)

const numShards = 32
const maxEntriesPerShard = 1024

type cacheShard struct {
	mu    sync.RWMutex
	items map[[32]byte]bool
}

// ShardedCache implements a lock-minimized, bounded verification cache.
type ShardedCache struct {
	shards [numShards]*cacheShard
}

// NewShardedCache creates a fully initialized ShardedCache.
func NewShardedCache() *ShardedCache {
	c := &ShardedCache{}
	for i := 0; i < numShards; i++ {
		c.shards[i] = &cacheShard{
			items: make(map[[32]byte]bool),
		}
	}
	return c
}

// Lookup queries the cache for a specific key.
func (c *ShardedCache) Lookup(key [32]byte) (bool, bool) {
	shard := c.shards[key[0]%numShards]
	shard.mu.RLock()
	val, ok := shard.items[key]
	shard.mu.RUnlock()
	return val, ok
}

// Store caches a validation result, applying random eviction if maximum capacity is reached.
func (c *ShardedCache) Store(key [32]byte, val bool) {
	shard := c.shards[key[0]%numShards]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if len(shard.items) >= maxEntriesPerShard {
		// Evict 10% of entries to bound memory usage without double-linked list allocations
		evictCount := maxEntriesPerShard / 10
		for k := range shard.items {
			delete(shard.items, k)
			evictCount--
			if evictCount <= 0 {
				break
			}
		}
	}
	shard.items[key] = val
}

// GetHasher returns a SHA-256 hasher from a pool to eliminate heap allocations.
func GetHasher(pool *sync.Pool) hash.Hash {
	hasher := pool.Get().(hash.Hash)
	hasher.Reset()
	return hasher
}

// PutHasher returns a SHA-256 hasher back to the pool.
func PutHasher(pool *sync.Pool, hasher hash.Hash) {
	pool.Put(hasher)
}

// WriteStringToHasher writes strings directly to the hasher avoiding temporary slice allocations.
func WriteStringToHasher(hasher hash.Hash, val string) {
	_, _ = io.WriteString(hasher, val)
}
