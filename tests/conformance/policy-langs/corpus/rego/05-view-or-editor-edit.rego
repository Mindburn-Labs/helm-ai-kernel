package helm.policy

import rego.v1

default decision := {"verdict": "DENY"}

decision := {"verdict": "ALLOW"} if {
	input.action == "view"
}

decision := {"verdict": "ALLOW"} if {
	input.action == "edit"
	input.context.role == "editor"
}
