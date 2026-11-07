package executor

import (
	"errors"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type failingPackSigner struct{}

func (failingPackSigner) Sign([]byte) (string, error) {
	return "", errors.New("sign failed")
}

func (failingPackSigner) PublicKey() string { return "test-key" }

func (failingPackSigner) PublicKeyBytes() []byte { return []byte("test-key") }

func (failingPackSigner) SignDecision(*contracts.DecisionRecord) error { return nil }

func (failingPackSigner) SignIntent(*contracts.AuthorizedExecutionIntent) error { return nil }

func (failingPackSigner) SignReceipt(*contracts.Receipt) error { return nil }
