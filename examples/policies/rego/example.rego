# Example HELM Rego policy: anyone may view; only admins may delete.
#
# Logical rule expressed identically in:
#   examples/policies/cel/example.cel
#   examples/policies/cedar/example.cedar
#
# Non-deterministic builtins (http.send, time.now_ns, rand.intn,
# crypto.x509.parse_certificates) are forbidden by
# core/pkg/policybundles/rego/capabilities.json so the helm-ai-kernel kernel
# can replay decisions deterministically.

package helm.policy

import rego.v1

default decision := {"verdict": "DENY", "reason": "default deny"}

decision := {"verdict": "ALLOW", "reason": "view is universally permitted"} if {
	input.action == "view"
}

decision := {"verdict": "ALLOW", "reason": "admin may delete"} if {
	input.action == "delete"
	"admin" in input.principal.roles
}
