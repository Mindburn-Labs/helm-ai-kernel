package install

import (
	"testing"
	"time"
)

func TestReceipt_DeterministicHash(t *testing.T) {
	ts := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	r1 := newReceipt("p1", "install", "sha256:abc", "", ts)
	r2 := newReceipt("p1", "install", "sha256:abc", "", ts)
	if r1.Hash != r2.Hash {
		t.Errorf("Hash mismatch for identical inputs: %q vs %q", r1.Hash, r2.Hash)
	}
	if r1.Hash == "" {
		t.Error("Hash is empty")
	}
}

func TestReceipt_Chain(t *testing.T) {
	ts := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	first := newReceipt("p1", "install", "sha256:abc", "", ts)
	second := newReceipt("p1", "uninstall", "sha256:abc", first.Hash, ts.Add(time.Hour))

	if second.PrevReceiptHash != first.Hash {
		t.Errorf("PrevReceiptHash = %q, want %q", second.PrevReceiptHash, first.Hash)
	}
	if second.Hash == first.Hash {
		t.Error("second receipt reused first receipt's hash")
	}
}

func TestReceipt_ActionChangesHash(t *testing.T) {
	ts := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	install := newReceipt("p1", "install", "sha256:abc", "", ts)
	rollback := newReceipt("p1", "rollback", "sha256:abc", "", ts)
	if install.Hash == rollback.Hash {
		t.Error("hash did not change when only the action differed")
	}
}

func TestReceipt_MissingFields(t *testing.T) {
	ts := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		build func() *Receipt
		other func() *Receipt
	}{
		{
			"missing pack_id",
			func() *Receipt { return newReceipt("", "install", "sha256:abc", "", ts) },
			func() *Receipt { return newReceipt("p1", "install", "sha256:abc", "", ts) },
		},
		{
			"missing action",
			func() *Receipt { return newReceipt("p1", "", "sha256:abc", "", ts) },
			func() *Receipt { return newReceipt("p1", "install", "sha256:abc", "", ts) },
		},
		{
			"missing manifest_hash",
			func() *Receipt { return newReceipt("p1", "install", "", "", ts) },
			func() *Receipt { return newReceipt("p1", "install", "sha256:abc", "", ts) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			missing := tc.build()
			populated := tc.other()
			if missing.Hash == "" {
				t.Error("Hash is empty even for missing-field receipt")
			}
			if missing.Hash == populated.Hash {
				t.Error("missing-field receipt hash collides with populated receipt hash")
			}
		})
	}
}
