//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package agentruntime

// lockTurnFile has no flock(2) on this platform (windows, solaris, aix,
// plan9, js/wasm), so Append is serialized by the in-process mutex alone.
// Two Store values over the same directory, or two processes, can then race
// the read-modify-write. Single-writer deployment is the requirement on
// these platforms; adding a lock here means a platform-native primitive
// (LockFileEx on windows, fcntl on solaris), not a marker file, whose
// ownership races are what flock exists to avoid.
func lockTurnFile(path string) (unlock func(), err error) {
	return func() {}, nil
}
