package pack

import (
	"errors"
)

type flakyJSON struct {
	count *int
}

func (f flakyJSON) MarshalJSON() ([]byte, error) {
	*f.count++
	if *f.count == 1 {
		return []byte(`"ok"`), nil
	}
	return nil, errors.New("flaky marshal failed")
}
