//go:build unix

package packfs

import "syscall"

// openNonBlocking keeps open from waiting for a writer when the name turns
// out to be a named pipe. It has no effect on a regular file.
const openNonBlocking = syscall.O_NONBLOCK

// openDirectoryFlags refuses non-directories during the open itself.
const openDirectoryFlags = syscall.O_DIRECTORY | syscall.O_NONBLOCK
