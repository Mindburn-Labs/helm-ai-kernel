package governance

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSwarmPDPEvaluateBatchPropagatesBaseError(t *testing.T) {
	expectedErr := errors.New("base pdp unavailable")
	swarm := NewSwarmPDP(&swarmErrorPDP{version: "v-error", err: expectedErr}, &SwarmPDPConfig{
		MaxParallelPDPs:     1,
		EnableMetrics:       true,
		DomainDecomposition: true,
		StrictMerge:         true,
	})

	result, err := swarm.EvaluateBatch(context.Background(), []PDPRequest{
		{RequestID: "req-1", Effect: EffectDescriptor{EffectType: "authorize"}},
	})
	require.ErrorIs(t, err, expectedErr)
	require.Nil(t, result)
}

func TestSwarmPDPStreamEvaluateEmitsFullAndRemainderBatches(t *testing.T) {
	swarm := NewSwarmPDP(NewMockPDP("v-stream"), &SwarmPDPConfig{
		MaxParallelPDPs:     2,
		EnableMetrics:       true,
		DomainDecomposition: false,
		StrictMerge:         true,
	})
	requests := make(chan PDPRequest, 3)
	requests <- PDPRequest{RequestID: "req-1", Effect: EffectDescriptor{EffectType: "authorize"}}
	requests <- PDPRequest{RequestID: "req-2", Effect: EffectDescriptor{EffectType: "transfer"}}
	requests <- PDPRequest{RequestID: "req-3", Effect: EffectDescriptor{EffectType: "trade"}}
	close(requests)

	responses, errs := swarm.StreamEvaluate(context.Background(), requests, 2)

	got := collectSwarmStreamResponses(responses)
	require.Len(t, got, 3)
	require.Equal(t, "decision-req-1", got[0].DecisionID)
	require.Equal(t, "decision-req-2", got[1].DecisionID)
	require.Equal(t, "decision-req-3", got[2].DecisionID)
	require.Empty(t, collectSwarmStreamErrors(errs))
}

func TestSwarmPDPStreamEvaluateReportsFullBatchError(t *testing.T) {
	expectedErr := errors.New("full batch failed")
	swarm := NewSwarmPDP(&swarmErrorPDP{version: "v-error", err: expectedErr}, &SwarmPDPConfig{
		MaxParallelPDPs:     1,
		EnableMetrics:       true,
		DomainDecomposition: false,
		StrictMerge:         true,
	})
	requests := make(chan PDPRequest, 1)
	requests <- PDPRequest{RequestID: "req-1", Effect: EffectDescriptor{EffectType: "authorize"}}
	close(requests)

	responses, errs := swarm.StreamEvaluate(context.Background(), requests, 1)

	require.Empty(t, collectSwarmStreamResponses(responses))
	require.ErrorIs(t, firstSwarmStreamError(errs), expectedErr)
}

func TestSwarmPDPStreamEvaluateReportsRemainderBatchError(t *testing.T) {
	expectedErr := errors.New("remainder batch failed")
	swarm := NewSwarmPDP(&swarmErrorPDP{version: "v-error", err: expectedErr}, &SwarmPDPConfig{
		MaxParallelPDPs:     1,
		EnableMetrics:       true,
		DomainDecomposition: false,
		StrictMerge:         true,
	})
	requests := make(chan PDPRequest, 1)
	requests <- PDPRequest{RequestID: "req-1", Effect: EffectDescriptor{EffectType: "authorize"}}
	close(requests)

	responses, errs := swarm.StreamEvaluate(context.Background(), requests, 2)

	require.Empty(t, collectSwarmStreamResponses(responses))
	require.ErrorIs(t, firstSwarmStreamError(errs), expectedErr)
}

func TestSwarmPDPStreamEvaluateReportsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	swarm := NewSwarmPDP(NewMockPDP("v-stream"), DefaultSwarmPDPConfig())
	requests := make(chan PDPRequest)
	responses, errs := swarm.StreamEvaluate(ctx, requests, 2)

	require.Empty(t, collectSwarmStreamResponses(responses))
	require.ErrorIs(t, firstSwarmStreamError(errs), context.Canceled)
}

type swarmErrorPDP struct {
	version string
	err     error
}

func (p *swarmErrorPDP) Evaluate(context.Context, PDPRequest) (*PDPResponse, error) {
	return nil, p.err
}

func (p *swarmErrorPDP) PolicyVersion() string {
	return p.version
}

func collectSwarmStreamResponses(ch <-chan *PDPResponse) []*PDPResponse {
	responses := make([]*PDPResponse, 0)
	for response := range ch {
		responses = append(responses, response)
	}
	return responses
}

func collectSwarmStreamErrors(ch <-chan error) []error {
	errs := make([]error, 0)
	for err := range ch {
		errs = append(errs, err)
	}
	return errs
}

func firstSwarmStreamError(ch <-chan error) error {
	errs := collectSwarmStreamErrors(ch)
	if len(errs) == 0 {
		return nil
	}
	return errs[0]
}
