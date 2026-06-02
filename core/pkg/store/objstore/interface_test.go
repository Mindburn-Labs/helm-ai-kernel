package objstore

import "testing"

func TestErrNotFoundError(t *testing.T) {
	err := &ErrNotFound{Hash: "sha256:abc"}
	if got := err.Error(); got != "object not found: sha256:abc" {
		t.Fatalf("unexpected error string %q", got)
	}
}
