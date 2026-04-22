package evidence

import (
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
)

// NewTracePack creates a TracePack for developer telemetry.
// TracePack is NOT part of the EvidencePack — it is internal debugging data
// accumulated during a mission run and never published externally.
func NewTracePack(spec researchruntime.MissionSpec) *researchruntime.TracePack {
	return &researchruntime.TracePack{
		Mission: spec,
	}
}

// AddModelRun records a model invocation in the trace.
func AddModelRun(tp *researchruntime.TracePack, m researchruntime.ModelManifest) {
	tp.ModelRuns = append(tp.ModelRuns, m)
}

// AddToolRun records a tool invocation in the trace.
func AddToolRun(tp *researchruntime.TracePack, t researchruntime.ToolInvocationManifest) {
	tp.ToolRuns = append(tp.ToolRuns, t)
}

// AddSource records a source snapshot in the trace.
func AddSource(tp *researchruntime.TracePack, s researchruntime.SourceSnapshot) {
	tp.Sources = append(tp.Sources, s)
}

// AddScore records a score record in the trace.
func AddScore(tp *researchruntime.TracePack, s researchruntime.ScoreRecord) {
	tp.Scores = append(tp.Scores, s)
}
