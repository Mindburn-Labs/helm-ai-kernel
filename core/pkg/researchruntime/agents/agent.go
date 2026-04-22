package agents

import (
	"context"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
)

// Agent is the interface all bounded research workers implement.
// Input and output are opaque []byte — JSON-marshalled domain objects specific to each role.
type Agent interface {
	Role() researchruntime.WorkerRole
	Execute(ctx context.Context, task *researchruntime.TaskLease, input []byte) (output []byte, err error)
}
