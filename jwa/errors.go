package jwa

import (
	"errors"
	"fmt"
)

var (
	ErrUnknownAlg = errors.New("unknown algorithm")
)

func unknownAlgErr(name string) error {
	return fmt.Errorf("%w: %s", ErrUnknownAlg, name)
}
