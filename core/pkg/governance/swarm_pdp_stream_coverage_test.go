package governance

import (
	"context"
)

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
