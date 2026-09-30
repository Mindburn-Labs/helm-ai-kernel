package mandates

import (
	_ "embed"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store/tenantrls"
)

//go:embed schema.sql
var schemaSQL string

// Tables are the authority rows, each under forced row security with the
// kernel's tenant policy.
var Tables = []string{
	"authority_tenants",
	"authority_principals",
	"authority_effect_types",
	"authority_mandates",
	"authority_limits",
	"authority_stops",
}

// SchemaDDL returns the idempotent statements that create the authority rows
// and put each table under forced row security. `helm-ai-kernel migrate` and
// `helm-gateway migrate` run it; the Store never runs DDL.
func SchemaDDL() string {
	var ddl strings.Builder
	ddl.WriteString(schemaSQL)
	for _, table := range Tables {
		ddl.WriteString("\n")
		ddl.WriteString(tenantrls.DDL(table))
	}
	return ddl.String()
}
