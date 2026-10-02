package admission

import "testing"

// A duplicate older migration appended by an otherwise conflict-free merge
// made HeadVersion report 6 after migration 7 had just run. Every fresh
// database then refused its own binary as a downgrade. Check the registry
// before the PostgreSQL proofs to keep this failure cheap and explicit.
func TestMigrationVersionsAreUniqueAndOrdered(t *testing.T) {
	if len(migrations) == 0 {
		t.Fatal("gateway migration registry is empty")
	}
	for i, m := range migrations {
		if m.version != i+1 {
			t.Fatalf("migration %q at position %d has version %d; want %d", m.name, i, m.version, i+1)
		}
	}
}
