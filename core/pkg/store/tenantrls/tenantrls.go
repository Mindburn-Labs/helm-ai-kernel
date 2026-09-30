// Package tenantrls is the one row-security policy every kernel tenant table
// carries. It imports nothing, so stores outside pkg/store (the authority
// rows, the effect gateway) put their tables under the same policy that the
// kernel's catalog check compares against.
package tenantrls

// Policy is the row-security predicate, for USING and WITH CHECK alike.
// app.current_tenant is the one tenant setting the kernel's Postgres stores
// use.
const Policy = "tenant_id = current_setting('app.current_tenant', true)"

// PolicyExpr is how Postgres deparses Policy on a TEXT tenant_id. A catalog
// check compares the installed USING and WITH CHECK with it exactly, so a
// widened predicate that still mentions app.current_tenant is not mistaken for
// this one.
const PolicyExpr = "(tenant_id = current_setting('app.current_tenant'::text, true))"

// DDL returns the statements that put table under forced row security with
// the tenant policy. FORCE makes the policy bind the table owner too, and an
// unset tenant setting is NULL, which matches no row.
func DDL(table string) string {
	return `ALTER TABLE ` + table + ` ENABLE ROW LEVEL SECURITY;
ALTER TABLE ` + table + ` FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ` + table + `;
CREATE POLICY tenant_isolation ON ` + table + `
	USING (` + Policy + `)
	WITH CHECK (` + Policy + `);`
}
