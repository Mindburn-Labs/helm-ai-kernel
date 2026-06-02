package registry

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/manifest"
)

func TestPostgresRegistryInitRegisterUnregisterAndRollout(t *testing.T) {
	registry, mock := newSQLMockRegistry(t)
	if registry.db == nil {
		t.Fatal("NewPostgresRegistry returned nil db")
	}

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS registry_bundles").
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := registry.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := registry.Register(nil); err == nil {
		t.Fatal("Register(nil) error = nil")
	}
	stable := registryCoverageBundle("app", "1.0.0")
	mock.ExpectExec("INSERT INTO registry_bundles").
		WithArgs("app", "1.0.0", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := registry.Register(stable); err != nil {
		t.Fatalf("Register: %v", err)
	}

	mock.ExpectExec("DELETE FROM registry_bundles").
		WithArgs("app").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM registry_rollouts").
		WithArgs("app").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := registry.Unregister("app"); err != nil {
		t.Fatalf("Unregister: %v", err)
	}

	if err := registry.SetRollout("app", stable, -1); err == nil {
		t.Fatal("SetRollout negative percentage error = nil")
	}
	if err := registry.SetRollout("app", stable, 101); err == nil {
		t.Fatal("SetRollout over 100 percentage error = nil")
	}
	canary := registryCoverageBundle("app", "2.0.0")
	mock.ExpectExec("INSERT INTO registry_rollouts").
		WithArgs("app", "2.0.0", sqlmock.AnyArg(), 50, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := registry.SetRollout("app", canary, 50); err != nil {
		t.Fatalf("SetRollout: %v", err)
	}
}

func TestPostgresRegistryGetAndGetForUser(t *testing.T) {
	registry, mock := newSQLMockRegistry(t)
	v1 := registryCoverageBundle("app", "1.0.0")
	v2 := registryCoverageBundle("app", "2.0.0")

	mock.ExpectQuery("SELECT version, bundle_json FROM registry_bundles WHERE name").
		WithArgs("app").
		WillReturnRows(sqlmock.NewRows([]string{"version", "bundle_json"}).
			AddRow("not-semver", registryCoverageBundleJSON(t, v1)).
			AddRow("1.0.0", registryCoverageBundleJSON(t, v1)).
			AddRow("2.0.0", registryCoverageBundleJSON(t, v2)))
	got, err := registry.Get("app")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Manifest.Version != "2.0.0" {
		t.Fatalf("Get returned version %s, want 2.0.0", got.Manifest.Version)
	}

	mock.ExpectQuery("SELECT version, bundle_json FROM registry_bundles WHERE name").
		WithArgs("missing").
		WillReturnRows(sqlmock.NewRows([]string{"version", "bundle_json"}))
	if _, err := registry.Get("missing"); !errors.Is(err, ErrModuleNotFound) {
		t.Fatalf("Get missing error = %v, want ErrModuleNotFound", err)
	}

	mock.ExpectQuery("SELECT version, bundle_json FROM registry_bundles WHERE name").
		WithArgs("bad-json").
		WillReturnRows(sqlmock.NewRows([]string{"version", "bundle_json"}).
			AddRow("1.0.0", []byte("{")))
	if _, err := registry.Get("bad-json"); err == nil {
		t.Fatal("Get malformed JSON error = nil")
	}

	canary := registryCoverageBundle("app", "3.0.0")
	mock.ExpectQuery("SELECT canary_bundle_json, percentage FROM registry_rollouts WHERE name").
		WithArgs("app").
		WillReturnRows(sqlmock.NewRows([]string{"canary_bundle_json", "percentage"}).
			AddRow(registryCoverageBundleJSON(t, canary), 100))
	got, err = registry.GetForUser("app", "any-user")
	if err != nil {
		t.Fatalf("GetForUser canary: %v", err)
	}
	if got.Manifest.Version != "3.0.0" {
		t.Fatalf("GetForUser canary version = %s, want 3.0.0", got.Manifest.Version)
	}

	mock.ExpectQuery("SELECT canary_bundle_json, percentage FROM registry_rollouts WHERE name").
		WithArgs("app").
		WillReturnRows(sqlmock.NewRows([]string{"canary_bundle_json", "percentage"}).
			AddRow([]byte("{"), 100))
	mock.ExpectQuery("SELECT version, bundle_json FROM registry_bundles WHERE name").
		WithArgs("app").
		WillReturnRows(sqlmock.NewRows([]string{"version", "bundle_json"}).
			AddRow("1.0.0", registryCoverageBundleJSON(t, v1)))
	got, err = registry.GetForUser("app", "fallback-user")
	if err != nil {
		t.Fatalf("GetForUser fallback: %v", err)
	}
	if got.Manifest.Version != "1.0.0" {
		t.Fatalf("GetForUser fallback version = %s, want 1.0.0", got.Manifest.Version)
	}
}

func TestPostgresRegistryListAndInstall(t *testing.T) {
	registry, mock := newSQLMockRegistry(t)
	bundle := registryCoverageBundle("app", "1.0.0")

	mock.ExpectQuery("SELECT DISTINCT ON").
		WillReturnRows(sqlmock.NewRows([]string{"bundle_json"}).
			AddRow(registryCoverageBundleJSON(t, bundle)).
			AddRow([]byte("{")))
	list := registry.List()
	if len(list) != 1 || list[0].Manifest.Name != "app" {
		t.Fatalf("List = %#v, want one valid app bundle", list)
	}

	mock.ExpectQuery("SELECT DISTINCT ON").
		WillReturnError(errors.New("db down"))
	if list := registry.List(); len(list) != 0 {
		t.Fatalf("List query error length = %d, want 0", len(list))
	}

	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("app").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectExec("INSERT INTO registry_installations").
		WithArgs("tenant-1", "app", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := registry.Install("tenant-1", "app"); err != nil {
		t.Fatalf("Install: %v", err)
	}

	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("missing").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	if err := registry.Install("tenant-1", "missing"); err == nil {
		t.Fatal("Install missing error = nil")
	}

	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("error").
		WillReturnError(errors.New("select failed"))
	if err := registry.Install("tenant-1", "error"); err == nil {
		t.Fatal("Install query error = nil")
	}
}

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
