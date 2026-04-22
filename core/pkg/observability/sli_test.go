package observability

import (
	"testing"
)

func TestSLIRegister(t *testing.T) {
	r := NewSLIRegistry()
	err := r.Register(&SLI{
		SLIID:             "sli-1",
		Name:              "Compile Latency",
		Operation:         "compile",
		EssentialVariable: "time_to_compile",
		Source:            SLISourceMetric,
		Unit:              "ms",
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Count() != 1 {
		t.Fatalf("expected 1, got %d", r.Count())
	}
}

func TestSLIRegisterMissingFields(t *testing.T) {
	r := NewSLIRegistry()
	err := r.Register(&SLI{SLIID: "sli-1"})
	if err == nil {
		t.Fatal("expected error for missing fields")
	}
}

func TestSLIByOperation(t *testing.T) {
	r := NewSLIRegistry()
	r.Register(&SLI{SLIID: "s1", Name: "a", Operation: "compile", Source: SLISourceMetric})
	r.Register(&SLI{SLIID: "s2", Name: "b", Operation: "compile", Source: SLISourceTrace})
	r.Register(&SLI{SLIID: "s3", Name: "c", Operation: "execute", Source: SLISourceLog})

	compiles := r.ByOperation("compile")
	if len(compiles) != 2 {
		t.Fatalf("expected 2 compile SLIs, got %d", len(compiles))
	}
}

func TestSLILinkToSLO(t *testing.T) {
	r := NewSLIRegistry()
	r.Register(&SLI{SLIID: "s1", Name: "a", Operation: "compile"})

	err := r.LinkToSLO("s1", "slo-1")
	if err != nil {
		t.Fatal(err)
	}

	sli, _ := r.Get("s1")
	if sli.LinkedSLOID != "slo-1" {
		t.Fatal("expected linked SLO")
	}
}

func TestSLIGetNotFound(t *testing.T) {
	r := NewSLIRegistry()
	_, err := r.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
}
