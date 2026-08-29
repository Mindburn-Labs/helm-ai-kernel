//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package skillpacks

// lockProjectionFile fails closed where the standard library exposes no
// flock(2). A platform-native cross-process primitive must be added before the
// lifecycle can safely mutate a projection root there.
func lockProjectionFile(_ string) (func() error, error) {
	return nil, ErrProjectionLockUnsupported
}
