//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package siwc

import (
	"context"
	"os"
)

func ownedByCurrentUser(_ os.FileInfo) bool                { return false }
func lockFile(_ context.Context, _ string) (func(), error) { return nil, ErrStorage }
