//go:build unix

package packfs

import "syscall"

// openNonBlocking keeps open from waiting for a writer when the name turns
// out to be a named pipe. It has no effect on a regular file.
const openNonBlocking = syscall.O_NONBLOCK
