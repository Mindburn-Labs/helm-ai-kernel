package metrics

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// scrape drives the handler and parses the body as Prometheus text exposition
// format. Parsing rather than substring-matching is the point: the handler
// concatenates families from several gatherers with the hand-written governance
// block, and a malformed join (a duplicated family, a missing newline, a
// repeated HELP) is exactly the failure mode concatenation invites. A scraper
// would reject it; so does this.
func scrape(t *testing.T, h http.HandlerFunc) map[string]bool {
	t.Helper()

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	parser := expfmt.NewTextParser(model.UTF8Validation)
	parsed, err := parser.TextToMetricFamilies(strings.NewReader(body))
	if err != nil {
		t.Fatalf("/metrics body is not valid Prometheus text format: %v\n---\n%s", err, body)
	}
	names := make(map[string]bool, len(parsed))
	for name := range parsed {
		names[name] = true
	}
	return names
}

// TestPrometheusHandlerForServesGatheredAndGovernanceFamilies is the HELM-477
// "serve the registry that already exists" half.
//
// The kernel had two disjoint metric surfaces and served only one. Everything
// registered through prometheus/client_golang was unreachable — including
// helm_kernel_decisions_total, a live promauto counter incremented on every PDP
// decision, and the go_*/process_* runtime families the kernel had none of for
// the one component whose stability matters most.
func TestPrometheusHandlerForServesGatheredAndGovernanceFamilies(t *testing.T) {
	// Stand in for the promauto-registered counters the daemon links in. Using a
	// private registry keeps the test independent of what else the test binary
	// happens to have registered globally.
	reg := prometheus.NewRegistry()
	decisions := prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "helm_kernel_decisions_total", Help: "decisions"},
		[]string{"verdict"},
	)
	reg.MustRegister(decisions)
	reg.MustRegister(collectors.NewGoCollector())
	decisions.WithLabelValues("ALLOW").Inc()

	m := NewGovernanceMetrics()
	m.RecordDecision(true, "search", "OK", "agent-1", 1500)

	names := scrape(t, m.PrometheusHandlerFor(reg))

	// The previously unreachable surface.
	for _, want := range []string{"helm_kernel_decisions_total", "go_goroutines"} {
		if !names[want] {
			t.Errorf("%s missing from /metrics — the gathered registry is not being served", want)
		}
	}
	// The governance families must survive the composition.
	for _, want := range []string{"helm_decisions_total", "helm_allows_total", "helm_active_agents"} {
		if !names[want] {
			t.Errorf("%s missing from /metrics — the governance families were dropped", want)
		}
	}
}

// TestPrometheusHandlerForSurvivesAFailingGatherer keeps /metrics readable when
// one registry misbehaves. The governance families are what an operator reads
// during an incident, and an incident is when a gatherer is most likely to be
// unhappy; failing the whole scrape would take them away at exactly that moment.
func TestPrometheusHandlerForSurvivesAFailingGatherer(t *testing.T) {
	names := scrape(t, NewGovernanceMetrics().PrometheusHandlerFor(brokenGatherer{}, nil))
	if !names["helm_decisions_total"] {
		t.Error("a failing gatherer took the governance families down with it")
	}
}

type brokenGatherer struct{}

func (brokenGatherer) Gather() ([]*dto.MetricFamily, error) {
	return nil, errors.New("registry unavailable")
}

// TestPrometheusHandlerStillServesGovernanceOnly pins the narrow behaviour of
// the legacy entrypoint, which the daemon no longer uses.
func TestPrometheusHandlerStillServesGovernanceOnly(t *testing.T) {
	names := scrape(t, NewGovernanceMetrics().PrometheusHandler())
	if !names["helm_decisions_total"] {
		t.Error("governance families missing from the legacy handler")
	}
	if names["go_goroutines"] {
		t.Error("legacy handler unexpectedly served the runtime families")
	}
}
