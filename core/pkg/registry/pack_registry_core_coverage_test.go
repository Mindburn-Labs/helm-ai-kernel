package registry

import (
	"errors"
	"strings"
	"testing"
)

type registryErrorVerifier struct{}

func (registryErrorVerifier) VerifyPackSignature(string, *PackSignature) (bool, error) {
	return false, errors.New("verify failed")
}

func requireRegistryErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want substring %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want substring %q", err, want)
	}
}
