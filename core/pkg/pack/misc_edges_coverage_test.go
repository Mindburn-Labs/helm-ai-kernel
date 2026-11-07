package pack

import (
	"context"
	"errors"
)

type coverageErrorPackRegistry struct{}

func (coverageErrorPackRegistry) GetPack(context.Context, string) (*Pack, error) {
	return nil, errors.New("get pack failed")
}

func (coverageErrorPackRegistry) FindByCapability(context.Context, string) ([]Pack, error) {
	return nil, errors.New("find capability failed")
}

func (coverageErrorPackRegistry) ListVersions(context.Context, string) ([]PackVersion, error) {
	return nil, errors.New("list versions failed")
}
