// Package observability — SLI Definitions.
//
// Per HELM 2030 Spec §4.9 / §5:
//
//	SLIs/SLOs tied to essential variables and autonomy health.
package observability

import (
	"fmt"
	"sync"
)

// SLISource defines where an SLI draws its data from.
type SLISource string

const (
	SLISourceMetric SLISource = "METRIC"
	SLISourceLog    SLISource = "LOG"
	SLISourceTrace  SLISource = "TRACE"
	SLISourceProbe  SLISource = "PROBE"
)

// SLI defines a Service Level Indicator tied to an essential variable.
type SLI struct {
	SLIID             string    `json:"sli_id"`
	Name              string    `json:"name"`
	Operation         string    `json:"operation"`          // compile, plan, execute, verify, etc.
	EssentialVariable string    `json:"essential_variable"` // factory essential variable ref
	Source            SLISource `json:"source"`
	Unit              string    `json:"unit"`              // ms, %, count, etc.
	GoodEventQuery    string    `json:"good_event_query"`  // what counts as good
	TotalEventQuery   string    `json:"total_event_query"` // total events
	LinkedSLOID       string    `json:"linked_slo_id,omitempty"`
}

// SLIRegistry manages SLI definitions.
type SLIRegistry struct {
	mu   sync.Mutex
	slis map[string]*SLI     // sliID → SLI
	byOp map[string][]string // operation → sliIDs
}

// NewSLIRegistry creates a new registry.
func NewSLIRegistry() *SLIRegistry {
	return &SLIRegistry{
		slis: make(map[string]*SLI),
		byOp: make(map[string][]string),
	}
}

// Register adds an SLI definition.
func (r *SLIRegistry) Register(sli *SLI) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if sli.SLIID == "" || sli.Name == "" || sli.Operation == "" {
		return fmt.Errorf("SLI requires id, name, and operation")
	}

	r.slis[sli.SLIID] = sli
	r.byOp[sli.Operation] = append(r.byOp[sli.Operation], sli.SLIID)
	return nil
}

// Get retrieves an SLI by ID.
func (r *SLIRegistry) Get(sliID string) (*SLI, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	sli, ok := r.slis[sliID]
	if !ok {
		return nil, fmt.Errorf("SLI %q not found", sliID)
	}
	return sli, nil
}

// ByOperation returns all SLIs for a given operation.
func (r *SLIRegistry) ByOperation(operation string) []*SLI {
	r.mu.Lock()
	defer r.mu.Unlock()

	var result []*SLI
	for _, id := range r.byOp[operation] {
		result = append(result, r.slis[id])
	}
	return result
}

// LinkToSLO links an SLI to an SLO.
func (r *SLIRegistry) LinkToSLO(sliID, sloID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	sli, ok := r.slis[sliID]
	if !ok {
		return fmt.Errorf("SLI %q not found", sliID)
	}
	sli.LinkedSLOID = sloID
	return nil
}

// Count returns the number of registered SLIs.
func (r *SLIRegistry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.slis)
}
