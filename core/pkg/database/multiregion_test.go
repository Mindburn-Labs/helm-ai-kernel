package database

import (
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// mockConnector is not needed if we test configuration logic and routing priorities
// without actual SQL connections. However, NewMultiRegionRouter calls sql.Open.

func TestMultiRegionConfig(t *testing.T) {
	cfg := MultiRegionConfig{
		Primary: ConnectionConfig{
			Host:     "localhost",
			Port:     5432,
			Database: "helm",
			Region:   RegionPrimary,
		},
		ReadPreference: ReadNearest,
	}

	if cfg.Primary.Region != RegionPrimary {
		t.Errorf("expected RegionPrimary, got %s", cfg.Primary.Region)
	}

	if cfg.ReadPreference != ReadNearest {
		t.Errorf("expected ReadNearest, got %d", cfg.ReadPreference)
	}
}

func TestRegionConstants(t *testing.T) {
	if RegionPrimary != "primary" {
		t.Error("RegionPrimary constant mismatch")
	}
	if RegionSecondary != "secondary" {
		t.Error("RegionSecondary constant mismatch")
	}
}

// TestRouterHealthStatus verifies that a new router initializes health map correctly.
// Note: We cannot easily test connection logic without a real DB or sqlmock,
// but we can ensure structural integrity.
func TestRouterInit(t *testing.T) {
	cfg := MultiRegionConfig{
		Primary:             ConnectionConfig{Host: "localhost", Database: "test"},
		HealthCheckInterval: 1 * time.Second,
	}

	router, err := NewMultiRegionRouter(cfg)
	if err != nil {
		t.Fatalf("failed to init router: %v", err)
	}

	if router != nil {
		defer func() {
			if err := router.Close(); err != nil {
				t.Logf("failed to close router: %v", err)
			}
		}()
		status := router.HealthStatus()
		if len(status) == 0 {
			// It should atleast have primary
			// But NewMultiRegionRouter logic:
			// router.connections[RegionPrimary] = primaryDB
			// router.health[RegionPrimary] = true
			// So it should have it.
			t.Error("expected non-empty health status")
		}
	}
}
