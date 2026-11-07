package registry

import (
	"encoding/json"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/manifest"
)

func newSQLMockRegistry(t *testing.T) (*PostgresRegistry, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		mock.ExpectClose()
		if err := db.Close(); err != nil {
			t.Errorf("close db: %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("sql expectations: %v", err)
		}
	})
	return NewPostgresRegistry(db), mock
}

func registryCoverageBundle(name, version string) *manifest.Bundle {
	return &manifest.Bundle{Manifest: manifest.Module{Name: name, Version: version}}
}

func registryCoverageBundleJSON(t *testing.T, bundle *manifest.Bundle) []byte {
	t.Helper()
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
