package custody

// quantum_posture: provider API keys are opaque bearer strings read from
// mounted files; nothing here signs, verifies or negotiates a key exchange,
// and no post-quantum claim is made.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// maxProviderKeyBytes bounds a key file. Provider API keys are a few hundred
// bytes; a larger file is a mistake, not a key.
const maxProviderKeyBytes = 4096

// ErrNoProviderKey reports a provider the custody holds no usable key for.
var ErrNoProviderKey = errors.New("custody: no usable key for the provider")

// ProviderKeys is the model gateway's connection custody for model providers
// (target architecture §9.6, R8): the only place a provider API key exists.
// Each key is a file the chart mounts into the gateway Pod only. The model
// gateway asks for a provider's key on every upstream call, puts it on that one
// request and keeps nothing.
//
// A key file is read when the custody is built, which refuses a missing,
// empty or malformed one, and again whenever its modification time or size
// changes, so a rotated Secret is picked up without a restart. A read that
// fails after a good one keeps serving the last good key, as the TLS
// certificate reloader does: a Secret update is not atomic to the reader.
type ProviderKeys struct {
	keys map[string]*providerKeyFile
}

type providerKeyFile struct {
	path string

	mu  sync.Mutex
	key string
	sig serveKeySignature
}

type serveKeySignature struct {
	modTime time.Time
	size    int64
}

// NewProviderKeys reads the key file of every provider (provider id to file
// path) and refuses a set with no providers or a file it cannot use. Errors
// name the file and the reason, never the key.
func NewProviderKeys(files map[string]string) (*ProviderKeys, error) {
	if len(files) == 0 {
		return nil, errors.New("custody: no provider key files")
	}
	p := &ProviderKeys{keys: make(map[string]*providerKeyFile, len(files))}
	for id, path := range files {
		f := &providerKeyFile{path: path}
		if err := f.reload(); err != nil {
			return nil, fmt.Errorf("custody: provider %q: %w", id, err)
		}
		p.keys[id] = f
	}
	return p, nil
}

// Key returns the provider's API key. It is for one upstream request and must
// not be logged, stored or returned to a caller.
func (p *ProviderKeys) Key(_ context.Context, providerID string) (string, error) {
	f, ok := p.keys[providerID]
	if !ok {
		return "", fmt.Errorf("%w: %q is not configured", ErrNoProviderKey, providerID)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// A failed re-read keeps the last good key (see the type comment).
	_ = f.reloadIfChanged()
	if f.key == "" {
		return "", fmt.Errorf("%w: %q", ErrNoProviderKey, providerID)
	}
	return f.key, nil
}

func (f *providerKeyFile) reload() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reloadIfChanged()
}

// reloadIfChanged re-reads the file when its signature changed. f.mu is held.
func (f *providerKeyFile) reloadIfChanged() error {
	info, err := os.Stat(f.path)
	if err != nil {
		return fmt.Errorf("stat the key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("the key file is not a regular file")
	}
	sig := serveKeySignature{modTime: info.ModTime(), size: info.Size()}
	if f.key != "" && sig == f.sig {
		return nil
	}
	if info.Size() > maxProviderKeyBytes {
		return fmt.Errorf("the key file is %d bytes, more than %d", info.Size(), maxProviderKeyBytes)
	}
	raw, err := os.ReadFile(f.path) // #nosec G304 -- operator-configured key file path
	if err != nil {
		return fmt.Errorf("read the key file: %w", err)
	}
	key, err := cleanKey(string(raw))
	if err != nil {
		return err
	}
	f.key, f.sig = key, sig
	return nil
}

// cleanKey trims the whitespace a Secret's writer leaves around a key and
// refuses what cannot be one: an empty key, or a value with a control
// character or a space, which would let a key file inject a header.
func cleanKey(raw string) (string, error) {
	start, end := 0, len(raw)
	for start < end && isKeySpace(raw[start]) {
		start++
	}
	for end > start && isKeySpace(raw[end-1]) {
		end--
	}
	key := raw[start:end]
	if key == "" {
		return "", errors.New("the key file is empty")
	}
	for i := 0; i < len(key); i++ {
		if c := key[i]; c <= 0x20 || c == 0x7f {
			return "", errors.New("the key file holds a space or a control character; a key is one token")
		}
	}
	return key, nil
}

func isKeySpace(c byte) bool { return c == ' ' || c == '\n' || c == '\r' || c == '\t' }
