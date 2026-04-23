package actiongraph

import "context"

// ActionExtractor converts a signal into zero or more ActionProposals.
// Implementations are domain-specific and may consult external context
// (entity graphs, policy stores) to produce well-formed proposals.
type ActionExtractor interface {
	Extract(ctx context.Context, signalID, signalClass string, subject map[string]string) ([]*ActionProposal, error)
}
