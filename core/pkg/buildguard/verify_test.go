package buildguard

import "testing"

func TestBuildGuardCleanCode(t *testing.T) {
	s := NewDefaultScanner()
	violations := s.ScanContent("main.go", "func main() {\n\treturn\n}")
	if len(violations) != 0 {
		t.Fatalf("expected no violations, got %d", len(violations))
	}
}

func TestBuildGuardMockDetection(t *testing.T) {
	s := NewDefaultScanner()
	violations := s.ScanContent("handler.go", "func mock_handler() {}")
	if len(violations) == 0 {
		t.Fatal("expected mock violation")
	}
	if violations[0].Pattern != "mock_" {
		t.Fatalf("expected mock_ pattern, got %s", violations[0].Pattern)
	}
}

func TestBuildGuardSimulatedDetection(t *testing.T) {
	s := NewDefaultScanner()
	violations := s.ScanContent("engine.go", "// This is a simulated engine")
	if len(violations) == 0 {
		t.Fatal("expected simulated violation")
	}
}

func TestBuildGuardGatePass(t *testing.T) {
	s := NewDefaultScanner()
	files := map[string]string{
		"main.go":   "func main() {}",
		"server.go": "func serve() {}",
	}
	result := s.Gate(files)
	if !result.Passed {
		t.Fatal("expected pass")
	}
}

func TestBuildGuardGateFail(t *testing.T) {
	s := NewDefaultScanner()
	files := map[string]string{
		"clean.go": "func clean() {}",
		"bad.go":   "func fake_database() {}",
	}
	result := s.Gate(files)
	if result.Passed {
		t.Fatal("expected fail")
	}
	if result.ErrorCount == 0 {
		t.Fatal("expected error count > 0")
	}
}

func TestBuildGuardVerify(t *testing.T) {
	s := NewDefaultScanner()
	err := s.Verify(map[string]string{"a.go": "func fake_service() {}"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildGuardLineNumbers(t *testing.T) {
	s := NewDefaultScanner()
	violations := s.ScanContent("f.go", "line 1\nline 2\nmock_foo\nline 4")
	if len(violations) == 0 {
		t.Fatal("expected violation")
	}
	if violations[0].Line != 3 {
		t.Fatalf("expected line 3, got %d", violations[0].Line)
	}
}
