package budget

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCostEstimator_SingleToolEstimate(t *testing.T) {
	e := NewCostEstimator()
	e.RecordCost("openai-gpt4", 100)

	est := e.Estimate("openai-gpt4")
	require.NotNil(t, est)
	assert.Equal(t, "openai-gpt4", est.ToolName)
	assert.Equal(t, int64(100), est.EstimatedCents)
	assert.Equal(t, 1, est.SampleCount)
	assert.Equal(t, "moving_average", est.ModelType)
}

func TestCostEstimator_MultipleObservations(t *testing.T) {
	e := NewCostEstimator()
	e.RecordCost("tool-a", 100)
	e.RecordCost("tool-a", 200)
	e.RecordCost("tool-a", 300)

	est := e.Estimate("tool-a")
	assert.Equal(t, int64(200), est.EstimatedCents, "average of 100,200,300 should be 200")
	assert.Equal(t, 3, est.SampleCount)
}

func TestCostEstimator_ConfidenceInterval(t *testing.T) {
	e := NewCostEstimator()
	// Record a spread of values.
	values := []int64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	for _, v := range values {
		e.RecordCost("spread-tool", v)
	}

	est := e.Estimate("spread-tool")
	assert.Equal(t, 10, est.SampleCount)
	assert.LessOrEqual(t, est.ConfidenceLow, est.EstimatedCents, "p10 should be <= mean")
	assert.GreaterOrEqual(t, est.ConfidenceHigh, est.EstimatedCents, "p90 should be >= mean")
	assert.LessOrEqual(t, est.ConfidenceLow, est.ConfidenceHigh, "p10 should be <= p90")
}

func TestCostEstimator_UnknownToolZeroEstimate(t *testing.T) {
	e := NewCostEstimator()

	est := e.Estimate("never-seen-tool")
	assert.Equal(t, int64(0), est.EstimatedCents)
	assert.Equal(t, int64(0), est.ConfidenceLow)
	assert.Equal(t, int64(0), est.ConfidenceHigh)
	assert.Equal(t, 0, est.SampleCount)
	assert.Equal(t, "moving_average", est.ModelType)
}

func TestCostEstimator_WorkflowEstimation(t *testing.T) {
	e := NewCostEstimator()
	e.RecordCost("tool-x", 100)
	e.RecordCost("tool-x", 200)
	e.RecordCost("tool-y", 50)
	e.RecordCost("tool-y", 150)

	est := e.EstimateWorkflow([]string{"tool-x", "tool-y"})
	assert.Equal(t, "workflow", est.ToolName)
	// tool-x avg = 150, tool-y avg = 100 → total = 250
	assert.Equal(t, int64(250), est.EstimatedCents)
	assert.Equal(t, 4, est.SampleCount)
}

func TestCostEstimator_WorkflowWithUnknownTool(t *testing.T) {
	e := NewCostEstimator()
	e.RecordCost("known-tool", 100)

	est := e.EstimateWorkflow([]string{"known-tool", "unknown-tool"})
	// unknown-tool contributes 0.
	assert.Equal(t, int64(100), est.EstimatedCents)
}

func TestCostEstimator_MaxHistoryTruncation(t *testing.T) {
	e := NewCostEstimator(WithMaxHistory(3))

	e.RecordCost("t", 1000) // will be evicted
	e.RecordCost("t", 10)
	e.RecordCost("t", 20)
	e.RecordCost("t", 30)

	est := e.Estimate("t")
	assert.Equal(t, 3, est.SampleCount, "should retain only 3 entries")
	// Average of 10, 20, 30 = 20
	assert.Equal(t, int64(20), est.EstimatedCents,
		"oldest entry (1000) should be evicted")
}

func TestCostEstimator_ConcurrentAccess(t *testing.T) {
	e := NewCostEstimator()
	var wg sync.WaitGroup
	const goroutines = 50

	// Concurrent writes.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			e.RecordCost("concurrent-tool", int64(n*10))
		}(i)
	}

	// Concurrent reads.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			est := e.Estimate("concurrent-tool")
			assert.GreaterOrEqual(t, est.EstimatedCents, int64(0))
		}()
	}

	wg.Wait()

	// After all writes complete, verify consistency.
	est := e.Estimate("concurrent-tool")
	assert.Equal(t, goroutines, est.SampleCount)
}

func TestCostEstimator_EmptyWorkflow(t *testing.T) {
	e := NewCostEstimator()

	est := e.EstimateWorkflow(nil)
	assert.Equal(t, int64(0), est.EstimatedCents)
	assert.Equal(t, 0, est.SampleCount)
}

func TestCostEstimator_SingleObservationConfidence(t *testing.T) {
	e := NewCostEstimator()
	e.RecordCost("single", 42)

	est := e.Estimate("single")
	assert.Equal(t, int64(42), est.EstimatedCents)
	// With a single observation, p10 and p90 should equal the sole value.
	assert.Equal(t, int64(42), est.ConfidenceLow)
	assert.Equal(t, int64(42), est.ConfidenceHigh)
}

func TestPercentile_EdgeCases(t *testing.T) {
	assert.Equal(t, int64(0), percentile(nil, 50))
	assert.Equal(t, int64(5), percentile([]int64{5}, 0))
	assert.Equal(t, int64(5), percentile([]int64{5}, 100))
}

func TestWithMaxHistory_IgnoresInvalid(t *testing.T) {
	e := NewCostEstimator(WithMaxHistory(0))
	assert.Equal(t, defaultMaxHistory, e.maxHistory, "zero maxHistory should be ignored")

	e2 := NewCostEstimator(WithMaxHistory(-1))
	assert.Equal(t, defaultMaxHistory, e2.maxHistory, "negative maxHistory should be ignored")
}
