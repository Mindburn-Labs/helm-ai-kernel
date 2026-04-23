package kernel

import (
	"testing"
	"time"
)

func TestEvaluationWindow(t *testing.T) {
	t.Run("Add and average", func(t *testing.T) {
		window := NewEvaluationWindow(time.Minute, 100)

		now := time.Now()
		window.Add(10, now)
		window.Add(20, now)
		window.Add(30, now)

		avg := window.Average()
		if avg != 20.0 {
			t.Errorf("Average = %f, want 20.0", avg)
		}
	})

	t.Run("Min and Max", func(t *testing.T) {
		window := NewEvaluationWindow(time.Minute, 100)

		now := time.Now()
		window.Add(5, now)
		window.Add(15, now)
		window.Add(10, now)

		min := window.Min()
		max := window.Max()
		if min != 5 {
			t.Errorf("Min = %f, want 5", min)
		}
		if max != 15 {
			t.Errorf("Max = %f, want 15", max)
		}
	})

	t.Run("Count", func(t *testing.T) {
		window := NewEvaluationWindow(time.Minute, 100)

		now := time.Now()
		window.Add(1, now)
		window.Add(2, now)
		window.Add(3, now)

		count := window.Count()
		if count != 3 {
			t.Errorf("Count = %d, want 3", count)
		}
	})

	t.Run("Empty window returns zeros", func(t *testing.T) {
		window := NewEvaluationWindow(time.Minute, 100)

		if window.Average() != 0 {
			t.Error("Average of empty window should be 0")
		}
		if window.Min() != 0 {
			t.Error("Min of empty window should be 0")
		}
		if window.Max() != 0 {
			t.Error("Max of empty window should be 0")
		}
		if window.Count() != 0 {
			t.Error("Count of empty window should be 0")
		}
	})

	t.Run("Max samples enforced", func(t *testing.T) {
		window := NewEvaluationWindow(time.Hour, 3)

		now := time.Now()
		window.Add(1, now)
		window.Add(2, now.Add(time.Millisecond))
		window.Add(3, now.Add(2*time.Millisecond))
		window.Add(4, now.Add(3*time.Millisecond))
		window.Add(5, now.Add(4*time.Millisecond))

		if window.Count() > 3 {
			t.Errorf("Count = %d, should not exceed 3", window.Count())
		}
	})
}

func TestViolationTrigger(t *testing.T) {
	t.Run("Check min threshold", func(t *testing.T) {
		trigger := &ViolationTrigger{
			VariableID:    "cpu_usage",
			ThresholdType: "min",
			MinThreshold:  10.0,
		}

		violated, reason := trigger.Check(5.0)
		if !violated {
			t.Error("Should violate min threshold")
		}
		if reason != "below_minimum" {
			t.Errorf("Reason = %q, want 'below_minimum'", reason)
		}

		violated, _ = trigger.Check(15.0)
		if violated {
			t.Error("Should not violate when above min")
		}
	})

	t.Run("Check max threshold", func(t *testing.T) {
		trigger := &ViolationTrigger{
			VariableID:    "memory_usage",
			ThresholdType: "max",
			MaxThreshold:  80.0,
		}

		violated, reason := trigger.Check(90.0)
		if !violated {
			t.Error("Should violate max threshold")
		}
		if reason != "above_maximum" {
			t.Errorf("Reason = %q, want 'above_maximum'", reason)
		}

		violated, _ = trigger.Check(50.0)
		if violated {
			t.Error("Should not violate when below max")
		}
	})

	t.Run("Check range threshold", func(t *testing.T) {
		trigger := &ViolationTrigger{
			VariableID:    "temperature",
			ThresholdType: "range",
			MinThreshold:  20.0,
			MaxThreshold:  30.0,
		}

		// Below min
		violated, reason := trigger.Check(15.0)
		if !violated {
			t.Error("Should violate below min")
		}
		if reason != "below_minimum" {
			t.Errorf("Reason = %q, want 'below_minimum'", reason)
		}

		// Above max
		violated, reason = trigger.Check(35.0)
		if !violated {
			t.Error("Should violate above max")
		}
		if reason != "above_maximum" {
			t.Errorf("Reason = %q, want 'above_maximum'", reason)
		}

		// Within range
		violated, _ = trigger.Check(25.0)
		if violated {
			t.Error("Should not violate within range")
		}
	})

	t.Run("Execute without handler", func(t *testing.T) {
		trigger := &ViolationTrigger{
			VariableID: "test",
			Handler:    nil,
		}

		err := trigger.Execute(100.0)
		if err != nil {
			t.Errorf("Execute without handler should not error: %v", err)
		}
	})
}

func TestEssentialVariableMonitor(t *testing.T) {
	t.Run("Register and record values", func(t *testing.T) {
		monitor := NewEssentialVariableMonitor()
		monitor.RegisterVariable("cpu", time.Minute, 100)

		now := time.Now()
		monitor.RecordValue("cpu", 50.0, now)
		monitor.RecordValue("cpu", 60.0, now.Add(time.Second))
		monitor.RecordValue("cpu", 70.0, now.Add(2*time.Second))

		avg, min, max, count := monitor.GetStatistics("cpu")
		if count != 3 {
			t.Errorf("Count = %d, want 3", count)
		}
		if avg != 60.0 {
			t.Errorf("Avg = %f, want 60.0", avg)
		}
		if min != 50.0 {
			t.Errorf("Min = %f, want 50.0", min)
		}
		if max != 70.0 {
			t.Errorf("Max = %f, want 70.0", max)
		}
	})

	t.Run("Get stats for unregistered variable", func(t *testing.T) {
		monitor := NewEssentialVariableMonitor()

		avg, min, max, count := monitor.GetStatistics("unknown")
		if avg != 0 || min != 0 || max != 0 || count != 0 {
			t.Error("Unregistered variable should return zeros")
		}
	})

	t.Run("Add and check triggers", func(t *testing.T) {
		monitor := NewEssentialVariableMonitor()
		monitor.RegisterVariable("latency", time.Minute, 100)

		trigger := &ViolationTrigger{
			VariableID:    "latency",
			ThresholdType: "max",
			MaxThreshold:  100.0,
			Action:        ViolationActionAlert,
		}
		monitor.AddTrigger(trigger)

		now := time.Now()
		errors := monitor.RecordValue("latency", 150.0, now) // Exceeds threshold
		if len(errors) != 0 {
			t.Logf("Got %d errors (expected if handler nil)", len(errors))
		}
	})
}
