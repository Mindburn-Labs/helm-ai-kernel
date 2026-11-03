package capability

import (
	"testing"
)

func TestResolve_NilRegistry(t *testing.T) {
	var reg *Registry
	if reg.Resolve("helm.cap.gui.gelab.tap") != nil {
		t.Fatal("nil registry must resolve nothing")
	}
	if reg.Len() != 0 {
		t.Fatal("nil registry length must be 0")
	}
}
