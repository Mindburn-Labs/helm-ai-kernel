// quantum_posture: API receipt tests exercise a classical Ed25519 signer; no post-quantum assurance is claimed.
package api

import (
	"net/http"
)

func testAPIAuthenticator(_ *http.Request) (AuthenticatedPrincipal, error) {
	return AuthenticatedPrincipal{ID: "operator-1", TenantID: "tenant-a", Roles: []string{"admin"}}, nil
}
