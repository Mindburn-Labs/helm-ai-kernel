package connectors

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestConnectorReleaseAuthoritySchemas(t *testing.T) {
	root := connectorReleaseAuthorityRepoRoot(t)
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	for _, name := range []string{"connector_release.json", "connector_release_authority_envelope.json"} {
		filename := filepath.Join(root, "schemas", name)
		payload, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		if err := compiler.AddResource(connectorReleaseAuthorityFileURL(filename), strings.NewReader(string(payload))); err != nil {
			t.Fatal(err)
		}
		if err := compiler.AddResource("https://helm.mindburn.org/schemas/"+name, strings.NewReader(string(payload))); err != nil {
			t.Fatal(err)
		}
	}
	authoritySchema, err := compiler.Compile(connectorReleaseAuthorityFileURL(filepath.Join(root, "schemas", "connector_release.json")))
	if err != nil {
		t.Fatal(err)
	}
	envelopeSchema, err := compiler.Compile(connectorReleaseAuthorityFileURL(filepath.Join(root, "schemas", "connector_release_authority_envelope.json")))
	if err != nil {
		t.Fatal(err)
	}

	certified := readConnectorReleaseAuthorityJSON(t, filepath.Join(root, "reference_packs", "connector-release-authority-v1", "certified_authority.c14n.json"))
	revoked := readConnectorReleaseAuthorityJSON(t, filepath.Join(root, "reference_packs", "connector-release-authority-v1", "revoked_authority.c14n.json"))
	certifiedEnvelope := readConnectorReleaseAuthorityJSON(t, filepath.Join(root, "reference_packs", "connector-release-authority-v1", "certified_envelope.c14n.json"))
	revokedEnvelope := readConnectorReleaseAuthorityJSON(t, filepath.Join(root, "reference_packs", "connector-release-authority-v1", "revoked_envelope.c14n.json"))
	for name, value := range map[string]any{"certified": certified, "revoked": revoked} {
		if err := authoritySchema.Validate(value); err != nil {
			t.Fatalf("%s authority schema validation: %v", name, err)
		}
	}
	for name, value := range map[string]any{"certified": certifiedEnvelope, "revoked": revokedEnvelope} {
		if err := envelopeSchema.Validate(value); err != nil {
			t.Fatalf("%s envelope schema validation: %v", name, err)
		}
	}

	overflow := cloneConnectorReleaseAuthorityJSON(t, certified)
	overflow["registry_revision"] = float64(9007199254740992)
	if err := authoritySchema.Validate(overflow); err == nil {
		t.Fatal("authority schema accepted a registry revision above the JCS-safe integer range")
	}
	invalidRevocation := cloneConnectorReleaseAuthorityJSON(t, revoked)
	invalidRevocation["registry_revision"] = float64(1)
	delete(invalidRevocation, "previous_authority_hash")
	if err := authoritySchema.Validate(invalidRevocation); err == nil {
		t.Fatal("authority schema accepted a revision-one revocation")
	}

	var certifiedContract, revokedContract contracts.ConnectorReleaseAuthority
	decodeConnectorReleaseAuthorityJSON(t, certified, &certifiedContract)
	decodeConnectorReleaseAuthorityJSON(t, revoked, &revokedContract)
	if !sameConnectorReleaseMaterial(certifiedContract, revokedContract) ||
		revokedContract.SignedAt.Before(certifiedContract.SignedAt) ||
		revokedContract.ValidFrom.Before(certifiedContract.ValidFrom) {
		t.Fatal("reference chain violates exact-material or monotonic-timeline semantics")
	}
}

func connectorReleaseAuthorityRepoRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", "..", ".."))
}

func connectorReleaseAuthorityFileURL(filename string) string {
	return "file:///" + strings.ReplaceAll(filename, string(filepath.Separator), "/")
}

func readConnectorReleaseAuthorityJSON(t *testing.T, filename string) map[string]any {
	t.Helper()
	payload, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(payload, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func cloneConnectorReleaseAuthorityJSON(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	var clone map[string]any
	decodeConnectorReleaseAuthorityJSON(t, value, &clone)
	return clone
}

func decodeConnectorReleaseAuthorityJSON(t *testing.T, value any, target any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, target); err != nil {
		t.Fatal(err)
	}
}

func TestApplyConnectorReleaseAuthorityMigrations(t *testing.T) {
	if err := ApplyConnectorReleaseAuthorityMigrations(context.Background(), nil); err == nil {
		t.Fatal("nil migration database accepted")
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS connector_release_authorities").
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := ApplyConnectorReleaseAuthorityMigrations(context.Background(), db); err != nil {
		t.Fatalf("ApplyConnectorReleaseAuthorityMigrations(): %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestApplyConnectorReleaseAuthorityMigrationsPropagatesFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS connector_release_authorities").
		WillReturnError(errors.New("migration denied"))
	if err := ApplyConnectorReleaseAuthorityMigrations(context.Background(), db); err == nil {
		t.Fatal("migration failure was hidden")
	}
}

func TestReleaseAuthorityStoreConstructorsFailClosed(t *testing.T) {
	var db *sql.DB
	if _, err := NewPostgresReleaseAuthorityAdminStore(db, nil); !errors.Is(err, ErrReleaseAuthorityStore) {
		t.Fatalf("admin constructor error = %v", err)
	}
	if _, err := NewPostgresReleaseAuthorityStore(db, nil); !errors.Is(err, ErrReleaseAuthorityStore) {
		t.Fatalf("runtime constructor error = %v", err)
	}
}

func TestReleaseAuthorityLookupValidation(t *testing.T) {
	tests := []ReleaseAuthorityLookup{
		{},
		{ScopeKind: "unknown", ConnectorID: "connector", ConnectorVersion: "1.0.0"},
		{ScopeKind: "global", TenantID: "tenant", ConnectorID: "connector", ConnectorVersion: "1.0.0"},
		{ScopeKind: "tenant_workspace", TenantID: "tenant", ConnectorID: "connector", ConnectorVersion: "1.0.0"},
	}
	for _, lookup := range tests {
		if err := lookup.validate(); !errors.Is(err, ErrReleaseAuthorityStore) {
			t.Fatalf("lookup %+v error = %v", lookup, err)
		}
	}
}

func TestDecodeReleaseAuthorityEnvelopeRejectsNonCanonicalShape(t *testing.T) {
	for _, payload := range [][]byte{
		[]byte(`{"authority":{},"signature":"","unknown":true}`),
		[]byte(`{"authority":{},"signature":""} {}`),
	} {
		if _, err := decodeReleaseAuthorityEnvelope(payload); !errors.Is(err, ErrReleaseAuthorityStore) {
			t.Fatalf("decode error = %v", err)
		}
	}
}
