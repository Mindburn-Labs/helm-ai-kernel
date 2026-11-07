package registry

import ()

// mockVerifier is a test verifier that always succeeds.
type mockVerifier struct{}

func (m *mockVerifier) VerifyPackSignature(contentHash string, signature *PackSignature) (bool, error) {
	return true, nil
}

// failingVerifier always fails verification.
type failingVerifier struct{}

func (f *failingVerifier) VerifyPackSignature(contentHash string, signature *PackSignature) (bool, error) {
	return false, nil
}
