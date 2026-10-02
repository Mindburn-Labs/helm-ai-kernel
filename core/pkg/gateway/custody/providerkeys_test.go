package custody

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeKey(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProviderKeysServeEachProvidersOwnKeyTrimmed(t *testing.T) {
	dir := t.TempDir()
	keys, err := NewProviderKeys(map[string]string{
		"anthropic": writeKey(t, dir, "a", "canary-anthropic-key\n"),
		"openai":    writeKey(t, dir, "o", "  canary-openai-key \r\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for provider, want := range map[string]string{"anthropic": "canary-anthropic-key", "openai": "canary-openai-key"} {
		got, err := keys.Key(context.Background(), provider)
		if err != nil || got != want {
			t.Fatalf("Key(%s) = %q, %v; want %q", provider, got, err, want)
		}
	}
	// An unknown provider has no key, and the error names the provider only.
	_, err = keys.Key(context.Background(), "openrouter")
	if !errors.Is(err, ErrNoProviderKey) || !strings.Contains(err.Error(), "openrouter") || strings.Contains(err.Error(), "canary") {
		t.Fatalf("an unknown provider: %v", err)
	}
}

func TestProviderKeysRefuseWhatCannotBeAKey(t *testing.T) {
	dir := t.TempDir()
	for name, test := range map[string]struct {
		files map[string]string
		want  string
	}{
		"no providers":       {map[string]string{}, "no provider key files"},
		"a missing file":     {map[string]string{"p": filepath.Join(dir, "absent")}, "stat the key file"},
		"an empty file":      {map[string]string{"p": writeKey(t, dir, "empty", "\n \n")}, "empty"},
		"a key with a space": {map[string]string{"p": writeKey(t, dir, "space", "two words")}, "one token"},
		"a header injection": {map[string]string{"p": writeKey(t, dir, "crlf", "key\r\nX-Evil: 1")}, "one token"},
		"a control byte":     {map[string]string{"p": writeKey(t, dir, "ctl", "key\x00")}, "one token"},
		"a directory":        {map[string]string{"p": dir}, "not a regular file"},
		"an oversized file":  {map[string]string{"p": writeKey(t, dir, "big", strings.Repeat("k", maxProviderKeyBytes+1))}, "more than"},
	} {
		_, err := NewProviderKeys(test.files)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: err = %v, want one naming %q", name, err, test.want)
		}
		// Whatever it refused, it never repeats the key.
		if err != nil && strings.Contains(err.Error(), "X-Evil") {
			t.Errorf("%s: the error repeats the file's content: %v", name, err)
		}
	}
}

func TestProviderKeysPickUpARotationAndSurviveATornRead(t *testing.T) {
	dir := t.TempDir()
	path := writeKey(t, dir, "k", "canary-old-key")
	keys, err := NewProviderKeys(map[string]string{"p": path})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := keys.Key(context.Background(), "p"); got != "canary-old-key" {
		t.Fatalf("first key = %q", got)
	}
	// A rotated Secret is served on the next call: a new size and time.
	if err := os.WriteFile(path, []byte("canary-new-key-rotated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if got, _ := keys.Key(context.Background(), "p"); got != "canary-new-key-rotated" {
		t.Fatalf("rotated key = %q", got)
	}
	// A file that goes missing or unusable keeps serving the last good key.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got, err := keys.Key(context.Background(), "p"); err != nil || got != "canary-new-key-rotated" {
		t.Fatalf("after the file vanished: %q, %v", got, err)
	}
	if err := os.WriteFile(path, []byte("bad key with spaces"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := keys.Key(context.Background(), "p"); err != nil || got != "canary-new-key-rotated" {
		t.Fatalf("after a malformed rewrite: %q, %v", got, err)
	}
}

func TestProviderKeysAreSafeForConcurrentUse(t *testing.T) {
	dir := t.TempDir()
	path := writeKey(t, dir, "k", "canary-key")
	keys, err := NewProviderKeys(map[string]string{"p": path})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if got, err := keys.Key(context.Background(), "p"); err != nil || got != "canary-key" {
					t.Errorf("Key = %q, %v", got, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
