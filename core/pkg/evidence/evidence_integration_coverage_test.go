package evidence_test

import (
	"context"
)

// staticProber avoids external network calls in unit tests.
type staticProber struct{}

func (staticProber) Probe(ctx context.Context, url string) (lcp float64, a11y float64, err error) {
	switch url {
	case "http://good-ux.com":
		return 1.0, 100.0, nil
	case "http://bad-ux.com":
		// Trip LCP threshold while keeping A11y high to ensure deterministic failure reason.
		return 10.0, 100.0, nil
	default:
		return 0, 0, nil
	}
}
