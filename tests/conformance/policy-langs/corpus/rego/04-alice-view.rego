package helm.policy

import rego.v1

default decision := {"verdict": "DENY"}

decision := {"verdict": "ALLOW"} if {
	input.principal == "alice"
	input.action == "view"
}
