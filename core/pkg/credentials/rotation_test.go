package credentials

import (
	"testing"
	"time"
)

func TestCredentialIssue(t *testing.T) {
	m := NewRotationManager(RotationPolicy{MaxAge: time.Hour, GracePeriod: 10 * time.Minute})
	cred := m.Issue("tenant-1", "postgres")

	if cred.State != CredentialActive {
		t.Fatal("expected ACTIVE")
	}
	if cred.RotationGen != 1 {
		t.Fatal("expected generation 1")
	}
}

func TestCredentialRotate(t *testing.T) {
	m := NewRotationManager(RotationPolicy{MaxAge: time.Hour})
	old := m.Issue("tenant-1", "redis")

	newCred, err := m.Rotate(old.CredentialID)
	if err != nil {
		t.Fatal(err)
	}

	if newCred.RotationGen != 2 {
		t.Fatal("expected generation 2")
	}

	oldCred, _ := m.Get(old.CredentialID)
	if oldCred.State != CredentialRotated {
		t.Fatal("old should be ROTATED")
	}
}

func TestCredentialIsValid(t *testing.T) {
	m := NewRotationManager(RotationPolicy{MaxAge: time.Hour})
	cred := m.Issue("t", "s")

	if !m.IsValid(cred.CredentialID) {
		t.Fatal("expected valid")
	}
}

func TestCredentialExpiry(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	m := NewRotationManager(RotationPolicy{MaxAge: time.Hour, GracePeriod: 10 * time.Minute}).
		WithClock(func() time.Time { return now })

	m.Issue("t", "s")

	// Move clock to grace period
	m.WithClock(func() time.Time { return now.Add(55 * time.Minute) })
	expiring := m.CheckExpiry()
	if len(expiring) != 1 {
		t.Fatalf("expected 1 expiring, got %d", len(expiring))
	}
}

func TestCredentialRevoke(t *testing.T) {
	m := NewRotationManager(RotationPolicy{MaxAge: time.Hour})
	cred := m.Issue("t", "s")

	m.Revoke(cred.CredentialID)

	if m.IsValid(cred.CredentialID) {
		t.Fatal("should be invalid after revocation")
	}
}

func TestCredentialNotFound(t *testing.T) {
	m := NewRotationManager(RotationPolicy{MaxAge: time.Hour})
	_, err := m.Rotate("nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
}
